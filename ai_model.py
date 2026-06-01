import os
import warnings
from typing import Any, Dict, List

import joblib

try:
    import pandas as pd
except Exception:
    pd = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")
SEVERITY_MODEL_PATH = os.path.join(BASE_DIR, "severity_model.joblib")

SUSPICIOUS_PORTS = {1337, 4444, 5555, 8080, 8081, 8443, 9001, 9999}
POWERSHELL_NAMES = {"powershell.exe", "pwsh.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}

PROXY_BINARIES = {
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "wmic.exe",
}

SCRIPT_HOSTS = {"wscript.exe", "cscript.exe"}

ADDITIONAL_SUSPICIOUS_PROCESS_NAMES = {
    "cmd.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
    "regsvr32.exe", "mshta.exe", "wmic.exe", "psexec.exe",
    "certutil.exe", "bitsadmin.exe", "schtasks.exe", "wevtutil.exe",
    "vssadmin.exe", "mimikatz.exe", "procdump.exe",
}

ENCODED_REMOTE_KEYWORDS = [
    "-enc", "-encodedcommand", "encodedcommand",
    "frombase64string", "base64",
]

DOWNLOAD_KEYWORDS = [
    "downloadstring", "invoke-webrequest", "iwr ",
    "curl ", "wget ", "webclient", "bitsadmin", "certutil",
]

CREDENTIAL_KEYWORDS = [
    "mimikatz", "lsass", "procdump", "sekurlsa", "minidump",
]

EVASION_KEYWORDS = [
    "executionpolicy", "bypass", "windowstyle", "hidden",
    "noprofile", "nop", "noninteractive", "wevtutil",
    "clear-eventlog", "vssadmin", "delete shadows",
]

FEATURE_ORDER = [
    "is_powershell",
    "has_encoded_or_remote_pattern",
    "office_parent",
    "temp_or_appdata",
    "suspicious_port",
    "command_length",
    "is_proxy_binary",
    "is_script_host",
    "has_credential_keywords",
    "has_evasion_keywords",
    "has_download_behavior",
    "multi_stage_behavior",
]

SEVERITY_NAMES = {
    0: "Low",
    1: "Medium",
    2: "High",
    3: "Critical",
}


def load_joblib_model(path: str):
    if not os.path.exists(path):
        return None
    try:
        return joblib.load(path)
    except Exception as e:
        print(f"WARNING: AI model could not be loaded from {path}: {e}")
        return None


model = load_joblib_model(MODEL_PATH)
severity_model = load_joblib_model(SEVERITY_MODEL_PATH)


def _get_attr(event: Any, name: str, default=None):
    if isinstance(event, dict):
        return event.get(name, default)
    return getattr(event, name, default)


def _normalize_text(value: Any) -> str:
    return str(value or "").lower().strip()


def _normalize_port(value: Any) -> int:
    try:
        if value is None or value == "":
            return 0
        return int(value)
    except Exception:
        return 0


def _contains_any(text: str, keywords: list[str]) -> bool:
    text = _normalize_text(text)
    return any(keyword in text for keyword in keywords)


def _is_temp_or_appdata_path(file_path: str) -> bool:
    file_path = _normalize_text(file_path).replace("/", "\\")
    return any(
        marker in file_path
        for marker in [
            "\\temp\\",
            "\\windows\\temp\\",
            "\\appdata\\local\\temp\\",
            "\\appdata\\roaming\\",
            "\\downloads\\",
        ]
    )


def _is_office_parent(parent_process: str) -> bool:
    return _normalize_text(parent_process) in OFFICE_PARENTS


def _is_powershell_process(process_name: str) -> bool:
    return _normalize_text(process_name) in POWERSHELL_NAMES


def _is_proxy_binary(process_name: str) -> bool:
    return _normalize_text(process_name) in PROXY_BINARIES


def _is_script_host(process_name: str) -> bool:
    return _normalize_text(process_name) in SCRIPT_HOSTS


def extract_features(event: Any) -> List[int]:
    command_line = _normalize_text(_get_attr(event, "command_line", ""))
    process_name = _normalize_text(_get_attr(event, "process_name", ""))
    parent_process = _normalize_text(_get_attr(event, "parent_process", ""))
    file_path = _normalize_text(_get_attr(event, "file_path", ""))
    destination_port = _normalize_port(_get_attr(event, "destination_port", 0))

    is_powershell = 1 if _is_powershell_process(process_name) else 0
    has_encoded = 1 if _contains_any(command_line, ENCODED_REMOTE_KEYWORDS) else 0
    office_parent = 1 if _is_office_parent(parent_process) else 0
    temp_or_appdata = 1 if _is_temp_or_appdata_path(file_path) else 0
    suspicious_port = 1 if destination_port in SUSPICIOUS_PORTS else 0
    command_length = len(command_line)

    is_proxy_binary = 1 if _is_proxy_binary(process_name) else 0
    is_script_host = 1 if _is_script_host(process_name) else 0
    has_credential_keywords = 1 if _contains_any(command_line + " " + process_name + " " + file_path, CREDENTIAL_KEYWORDS) else 0
    has_evasion_keywords = 1 if _contains_any(command_line, EVASION_KEYWORDS) else 0
    has_download_behavior = 1 if _contains_any(command_line, DOWNLOAD_KEYWORDS) else 0

    indicator_count = sum([
        has_encoded,
        office_parent,
        temp_or_appdata,
        suspicious_port,
        is_proxy_binary,
        is_script_host,
        has_credential_keywords,
        has_evasion_keywords,
        has_download_behavior,
    ])
    multi_stage_behavior = 1 if indicator_count >= 3 else 0

    return [
        is_powershell,
        has_encoded,
        office_parent,
        temp_or_appdata,
        suspicious_port,
        command_length,
        is_proxy_binary,
        is_script_host,
        has_credential_keywords,
        has_evasion_keywords,
        has_download_behavior,
        multi_stage_behavior,
    ]


def extract_feature_map(event: Any) -> Dict[str, int]:
    values = extract_features(event)
    return dict(zip(FEATURE_ORDER, values))


def _build_model_input(features: List[int], selected_model):
    if pd is None or selected_model is None or not hasattr(selected_model, "feature_names_in_"):
        return [features]

    try:
        names = list(selected_model.feature_names_in_)
        feature_map = dict(zip(FEATURE_ORDER, features))
        return pd.DataFrame([[feature_map.get(name, 0) for name in names]], columns=names)
    except Exception:
        return [features]


def confidence_level(probability: float) -> str:
    probability = float(probability or 0)
    if probability >= 0.85:
        return "Very High"
    if probability >= 0.70:
        return "High"
    if probability >= 0.45:
        return "Medium"
    if probability >= 0.20:
        return "Low"
    return "Informational"


def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def infer_attack_category(event: Any) -> str:
    command_line = _normalize_text(_get_attr(event, "command_line", ""))
    process_name = _normalize_text(_get_attr(event, "process_name", ""))
    parent_process = _normalize_text(_get_attr(event, "parent_process", ""))
    file_path = _normalize_text(_get_attr(event, "file_path", ""))
    destination_port = _normalize_port(_get_attr(event, "destination_port", 0))

    all_text = " ".join([command_line, process_name, parent_process, file_path])

    if _contains_any(all_text, CREDENTIAL_KEYWORDS):
        return "Credential Access"
    if _contains_any(all_text, EVASION_KEYWORDS):
        return "Defense Evasion / Impact"
    if destination_port in SUSPICIOUS_PORTS or _contains_any(all_text, DOWNLOAD_KEYWORDS):
        return "Command and Control"
    if _is_office_parent(parent_process) and _is_powershell_process(process_name):
        return "Initial Execution"
    if "schtasks" in all_text or "sc create" in all_text:
        return "Persistence"
    if _is_temp_or_appdata_path(file_path):
        return "Suspicious Execution Path"
    if _is_powershell_process(process_name) or process_name in ADDITIONAL_SUSPICIOUS_PROCESS_NAMES:
        return "Execution"

    return "Benign / Informational"


def fallback_predict(features: List[int]) -> Dict[str, Any]:
    feature_map = dict(zip(FEATURE_ORDER, features))

    score = 0
    confidence = 0.0
    reasons = []

    if feature_map["is_powershell"]:
        score += 8
        confidence += 0.06
        reasons.append("PowerShell execution detected")

    if feature_map["has_encoded_or_remote_pattern"]:
        score += 25
        confidence += 0.22
        reasons.append("Encoded or obfuscated command pattern detected")

    if feature_map["office_parent"]:
        score += 18
        confidence += 0.15
        reasons.append("Office application parent process detected")

    if feature_map["temp_or_appdata"]:
        score += 16
        confidence += 0.12
        reasons.append("Execution from Temp/AppData path")

    if feature_map["suspicious_port"]:
        score += 22
        confidence += 0.18
        reasons.append("Suspicious destination port detected")

    if feature_map["is_proxy_binary"]:
        score += 18
        confidence += 0.14
        reasons.append("Living-off-the-land proxy binary detected")

    if feature_map["is_script_host"]:
        score += 16
        confidence += 0.12
        reasons.append("Windows script host activity detected")

    if feature_map["has_credential_keywords"]:
        score += 35
        confidence += 0.30
        reasons.append("Credential access keyword detected")

    if feature_map["has_evasion_keywords"]:
        score += 24
        confidence += 0.20
        reasons.append("Defense evasion behavior detected")

    if feature_map["has_download_behavior"]:
        score += 22
        confidence += 0.18
        reasons.append("Download or remote execution behavior detected")

    if feature_map["command_length"] >= 300:
        score += 16
        confidence += 0.12
        reasons.append("Very long command line detected")
    elif feature_map["command_length"] >= 150:
        score += 8
        confidence += 0.06
        reasons.append("Long command line detected")

    if feature_map["multi_stage_behavior"]:
        score += 18
        confidence += 0.18
        reasons.append("Multiple suspicious behavior indicators correlated")

    score = max(0, min(score, 100))
    probability = max(0.0, min(round(confidence, 4), 1.0))
    prediction = 1 if score >= 45 else 0

    return {
        "prediction": prediction,
        "probability": probability,
        "confidence": probability,
        "severity": _severity_from_score(score),
        "risk_score": score,
        "reasons": reasons or ["No strong suspicious AI indicators found"],
        "confidence_level": confidence_level(probability),
        "attack_category": "Behavioral Threat" if prediction else "Benign / Informational",
        "available": True,
        "fallback": True,
        "error": "AI model not loaded; used enhanced fallback AI",
        "features": feature_map,
    }


def predict_event(event: Any) -> Dict[str, Any]:
    features = extract_features(event)
    feature_map = dict(zip(FEATURE_ORDER, features))
    heuristic = fallback_predict(features)

    if model is None:
        return heuristic

    try:
        model_input = _build_model_input(features, model)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            prediction = int(model.predict(model_input)[0])

            if hasattr(model, "predict_proba"):
                probability = float(model.predict_proba(model_input)[0][1])
            else:
                probability = float(prediction)

        probability = max(0.0, min(probability, 1.0))
        heuristic_probability = float(heuristic.get("probability", 0.0) or 0.0)
        hybrid_probability = max(probability, heuristic_probability)

        risk_score = max(
            int(round(probability * 100)),
            int(heuristic.get("risk_score", 0) or 0),
        )
        risk_score = max(0, min(risk_score, 100))

        severity = _severity_from_score(risk_score)
        severity_prediction = None

        if severity_model is not None:
            try:
                severity_input = _build_model_input(features, severity_model)
                severity_prediction = int(severity_model.predict(severity_input)[0])
                severity = SEVERITY_NAMES.get(severity_prediction, severity)
            except Exception:
                pass

        hybrid_prediction = 1 if prediction == 1 or heuristic.get("prediction") == 1 or risk_score >= 45 else 0

        return {
            "prediction": hybrid_prediction,
            "probability": round(hybrid_probability, 4),
            "confidence": round(hybrid_probability, 4),
            "severity": severity,
            "risk_score": risk_score,
            "reasons": heuristic.get("reasons", []),
            "confidence_level": confidence_level(hybrid_probability),
            "attack_category": infer_attack_category(event),
            "available": True,
            "fallback": False,
            "error": None,
            "features": feature_map,
            "model_prediction": prediction,
            "model_probability": round(probability, 4),
            "severity_model_loaded": severity_model is not None,
            "severity_model_prediction": severity_prediction,
        }

    except Exception as e:
        heuristic["error"] = f"model prediction failed: {e}; used fallback AI"
        return heuristic


def explain_event(event: Any) -> List[str]:
    reasons = []
    features = extract_feature_map(event)

    for key, value in features.items():
        if key != "command_length" and value == 1:
            reasons.append(f"AI feature: {key.replace('_', ' ')} detected")

    if features.get("command_length", 0) > 180:
        reasons.append("AI feature: unusually long command line detected")

    if features.get("multi_stage_behavior") == 1:
        reasons.append("AI interpretation: multiple suspicious indicators form a correlated attack pattern")

    if not reasons:
        reasons.append("AI feature: No strong suspicious indicators found")

    return reasons


def generate_attack_explanation(event: Any, decoded_command: str | None = None) -> str:
    prediction = predict_event(event)
    category = prediction.get("attack_category", "Unknown")
    severity = prediction.get("severity", "Low")
    confidence = prediction.get("confidence_level", "Informational")
    reasons = prediction.get("reasons", [])

    explanation = (
        f"The AI classified this event as {severity} severity with {confidence} confidence. "
        f"Predicted attack category: {category}. "
    )

    if reasons:
        explanation += "Main indicators: " + "; ".join(reasons[:5]) + ". "

    if decoded_command:
        explanation += f"Decoded command reviewed safely: {decoded_command}"

    return explanation


def model_status() -> Dict[str, Any]:
    return {
        "model_path": MODEL_PATH,
        "model_exists": os.path.exists(MODEL_PATH),
        "model_loaded": model is not None,
        "severity_model_path": SEVERITY_MODEL_PATH,
        "severity_model_exists": os.path.exists(SEVERITY_MODEL_PATH),
        "severity_model_loaded": severity_model is not None,
        "feature_order": FEATURE_ORDER,
        "feature_count": len(FEATURE_ORDER),
        "model_type": type(model).__name__ if model is not None else None,
        "severity_model_type": type(severity_model).__name__ if severity_model is not None else None,
    }