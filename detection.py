import json
import base64
import binascii
import re

from ai_model import explain_event, predict_event

try:
    from ai_model import generate_attack_explanation
except Exception:
    def generate_attack_explanation(event, decoded_command=None):
        return None

SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe": {
        "score": 8,
        "reason": "PowerShell process observed",
        "technique": "T1059.001",
        "tactic": "Execution",
        "alert_type": "PowerShell Execution Observed",
    },
    "pwsh.exe": {
        "score": 8,
        "reason": "PowerShell Core process observed",
        "technique": "T1059.001",
        "tactic": "Execution",
        "alert_type": "PowerShell Execution Observed",
    },
    "cmd.exe": {
        "score": 15,
        "reason": "Command shell execution detected",
        "technique": "T1059.003",
        "tactic": "Execution",
        "alert_type": "Command Shell Execution",
    },
    "wscript.exe": {
        "score": 28,
        "reason": "Windows Script Host execution detected",
        "technique": "T1059.005",
        "tactic": "Execution",
        "alert_type": "VBScript Execution Detected",
    },
    "cscript.exe": {
        "score": 28,
        "reason": "Command-line script host execution detected",
        "technique": "T1059.005",
        "tactic": "Execution",
        "alert_type": "Script Host Execution Detected",
    },
    "rundll32.exe": {
        "score": 25,
        "reason": "Rundll32 execution detected",
        "technique": "T1218.011",
        "tactic": "Defense Evasion",
        "alert_type": "Rundll32 Proxy Execution",
    },
    "regsvr32.exe": {
        "score": 25,
        "reason": "Regsvr32 execution detected",
        "technique": "T1218.010",
        "tactic": "Defense Evasion",
        "alert_type": "Regsvr32 Proxy Execution",
    },
    "mshta.exe": {
        "score": 35,
        "reason": "MSHTA execution detected",
        "technique": "T1218.005",
        "tactic": "Defense Evasion",
        "alert_type": "MSHTA Proxy Execution",
    },
    "wmic.exe": {
        "score": 22,
        "reason": "WMI command execution detected",
        "technique": "T1047",
        "tactic": "Execution",
        "alert_type": "WMI Execution Detected",
    },
    "psexec.exe": {
        "score": 35,
        "reason": "PsExec execution detected",
        "technique": "T1021.002",
        "tactic": "Lateral Movement",
        "alert_type": "Remote Service Execution",
    },
    "certutil.exe": {
        "score": 30,
        "reason": "Certutil execution detected",
        "technique": "T1105",
        "tactic": "Command and Control",
        "alert_type": "Ingress Tool Transfer via Certutil",
    },
    "mimikatz.exe": {
        "score": 55,
        "reason": "Credential dumping tool detected",
        "technique": "T1003",
        "tactic": "Credential Access",
        "alert_type": "Credential Dumping Activity",
    },
}


# Extra common LOLBins / suspicious tools for broader educational coverage.
SUSPICIOUS_PROCESS_NAMES.update({
    "bitsadmin.exe": {
        "score": 28,
        "reason": "BITSAdmin transfer utility execution detected",
        "technique": "T1197",
        "tactic": "Defense Evasion",
        "alert_type": "BITSAdmin Suspicious Transfer",
    },
    "schtasks.exe": {
        "score": 24,
        "reason": "Scheduled task utility execution detected",
        "technique": "T1053.005",
        "tactic": "Persistence",
        "alert_type": "Scheduled Task Activity",
    },
    "at.exe": {
        "score": 22,
        "reason": "Legacy scheduled task utility execution detected",
        "technique": "T1053",
        "tactic": "Persistence",
        "alert_type": "Scheduled Task Activity",
    },
    "net.exe": {
        "score": 18,
        "reason": "Windows net utility execution detected",
        "technique": "T1087",
        "tactic": "Discovery",
        "alert_type": "Account or Network Discovery",
    },
    "net1.exe": {
        "score": 18,
        "reason": "Windows net1 utility execution detected",
        "technique": "T1087",
        "tactic": "Discovery",
        "alert_type": "Account or Network Discovery",
    },
    "whoami.exe": {
        "score": 12,
        "reason": "Identity discovery command detected",
        "technique": "T1033",
        "tactic": "Discovery",
        "alert_type": "User Discovery",
    },
    "tasklist.exe": {
        "score": 12,
        "reason": "Process discovery command detected",
        "technique": "T1057",
        "tactic": "Discovery",
        "alert_type": "Process Discovery",
    },
    "sc.exe": {
        "score": 20,
        "reason": "Service control utility execution detected",
        "technique": "T1543.003",
        "tactic": "Persistence",
        "alert_type": "Windows Service Activity",
    },
    "wevtutil.exe": {
        "score": 32,
        "reason": "Windows Event Log utility execution detected",
        "technique": "T1070.001",
        "tactic": "Defense Evasion",
        "alert_type": "Event Log Manipulation",
    },
    "vssadmin.exe": {
        "score": 35,
        "reason": "Volume shadow copy administration detected",
        "technique": "T1490",
        "tactic": "Impact",
        "alert_type": "Shadow Copy Manipulation",
    },
})

SUSPICIOUS_PORTS = {1337, 4444, 5555, 8080, 8081, 9001, 8443, 9999}

ENCODED_KEYWORDS = [
    "-enc",
    "-encodedcommand",
    "encodedcommand",
    "frombase64string",
    "base64",
]

DOWNLOAD_OR_EXEC_KEYWORDS = [
    "downloadstring",
    "invoke-webrequest",
    "iwr ",
    "wget ",
    "curl ",
    "start-process",
    "iex(",
    "invoke-expression",
    "bitsadmin",
    "certutil",
    "schtasks",
    "vssadmin",
    "wevtutil",
    "net user",
    "net localgroup",
    "whoami /all",
    "tasklist",
]

CRITICAL_CMD_BEHAVIORS = [
    ("vssadmin delete shadows", "Shadow copy deletion command detected", "T1490", "Impact"),
    ("wmic shadowcopy delete", "Shadow copy deletion command detected", "T1490", "Impact"),
    ("delete shadows", "Shadow copy deletion command detected", "T1490", "Impact"),
    ("wevtutil cl", "Event log clearing command detected", "T1070.001", "Defense Evasion"),
    ("clear-eventlog", "Event log clearing command detected", "T1070.001", "Defense Evasion"),
    ("remove-eventlog", "Event log clearing command detected", "T1070.001", "Defense Evasion"),
    ("reg save hklm\\sam", "Credential registry hive dump command detected", "T1003.002", "Credential Access"),
    ("reg save hklm\\security", "Credential registry hive dump command detected", "T1003.002", "Credential Access"),
    ("reg save hklm\\system", "Credential registry hive dump command detected", "T1003.002", "Credential Access"),
    ("procdump", "Credential dump tooling command detected", "T1003", "Credential Access"),
    ("lsass", "LSASS credential access command detected", "T1003", "Credential Access"),
    ("mimikatz", "Credential theft tooling command detected", "T1003", "Credential Access"),
]

HIGH_RISK_CMD_BEHAVIORS = [
    ("certutil -urlcache", "Certutil download command detected", "T1105", "Command and Control"),
    ("certutil.exe -urlcache", "Certutil download command detected", "T1105", "Command and Control"),
    ("bitsadmin /transfer", "BITSAdmin transfer command detected", "T1197", "Defense Evasion"),
    ("bitsadmin.exe /transfer", "BITSAdmin transfer command detected", "T1197", "Defense Evasion"),
    ("schtasks /create", "Scheduled task creation command detected", "T1053.005", "Persistence"),
    ("sc create", "Service creation command detected", "T1543.003", "Persistence"),
    ("net localgroup administrators", "Local administrator group modification command detected", "T1098", "Persistence"),
    ("powershell -enc", "PowerShell encoded command launched from cmd.exe", "T1059.001", "Execution"),
    ("powershell.exe -enc", "PowerShell encoded command launched from cmd.exe", "T1059.001", "Execution"),
    ("powershell -encodedcommand", "PowerShell encoded command launched from cmd.exe", "T1059.001", "Execution"),
    ("powershell.exe -encodedcommand", "PowerShell encoded command launched from cmd.exe", "T1059.001", "Execution"),
    ("curl http", "Command-line download command detected", "T1105", "Command and Control"),
    ("curl https", "Command-line download command detected", "T1105", "Command and Control"),
    ("curl.exe http", "Command-line download command detected", "T1105", "Command and Control"),
    ("curl.exe https", "Command-line download command detected", "T1105", "Command and Control"),
    ("wget http", "Command-line download command detected", "T1105", "Command and Control"),
    ("wget https", "Command-line download command detected", "T1105", "Command and Control"),
    ("wget.exe http", "Command-line download command detected", "T1105", "Command and Control"),
    ("wget.exe https", "Command-line download command detected", "T1105", "Command and Control"),
]

BENIGN_POWERSHELL_KEYWORDS = [
    "shellintegration.ps1",
    "vscode",
    "visual studio code",
]

BENIGN_DECODED_COMMAND_MARKERS = [
    "rust command-safety layer",
    "powershell ast parser",
    "invoke-parserequest",
    "newline-delimited json requests over stdin",
]

BENIGN_POWERSHELL_PARENTS = {
    "code.exe",
    "explorer.exe",
    "wt.exe",
    "windowsterminal.exe",
}

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}

SAFE_TEMP_APPDATA_PROCESSES = {
    "code.exe",
    "discord.exe",
    "chrome.exe",
    "msedge.exe",
    "teams.exe",
    "slack.exe",
    "spotify.exe",
    "notion.exe",
    "python.exe",
}

SYSTEM_ALERT_TYPES = {
    "CPU Spike",
    "High CPU Usage",
    "Medium CPU Usage",
    "Memory Spike",
    "High Memory Usage",
    "High Process Count",
}


def safe_json_load(value):
    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    return []


def normalize_text(value):
    return str(value or "").strip()


def normalize_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def dedupe_keep_order(items: list[str]) -> list[str]:
    return [item for item in dict.fromkeys(items) if item]


def dedupe_alerts_keep_order(alerts: list[dict]) -> list[dict]:
    seen = set()
    result = []

    for alert in alerts:
        key = (
            alert.get("alert_type"),
            alert.get("reason"),
            alert.get("technique"),
            alert.get("tactic"),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(alert)

    return result


def get_alert_priority(alert_type: str) -> int:
    priorities = {
        "Credential Dumping Activity": 100,
        "Critical Command Shell Impact Activity": 99,
        "Encoded PowerShell": 97,
        "AI Decoded Command Analysis": 98,
        "Suspicious Command": 96,
        "Office Spawned Suspicious PowerShell": 95,
        "Suspicious Download and Execute Pattern": 92,
        "High-Risk Command Shell Activity": 91,
        "MSHTA Proxy Execution": 90,
        "Rundll32 Proxy Execution": 88,
        "Regsvr32 Proxy Execution": 88,
        "Ingress Tool Transfer via Certutil": 85,
        "Remote Service Execution": 84,
        "WMI Execution Detected": 80,
        "PowerShell Execution Observed": 18,
        "PowerShell EncodedCommand Reviewed": 19,
        "AI Suspicious Process Detection": 72,
        "Suspicious Connection to High-Risk Port": 68,
        "Execution from Temp or AppData Path": 64,
        "Office Spawned Suspicious Process": 60,
        "VBScript Execution Detected": 58,
        "Script Host Execution Detected": 58,
        "Command Shell Execution": 45,
        "High Process Count": 30,
        "Medium CPU Usage": 26,
        "High CPU Usage": 24,
        "High Memory Usage": 24,
        "Memory Spike": 20,
        "CPU Spike": 29,
        "General Suspicious Activity": 5,
        "Informational": 0,
    }
    return priorities.get(alert_type, 1)


def add_alert(
    alerts: list[dict],
    reasons: list[str],
    alert_type: str,
    reason: str,
    technique: str | None,
    tactic: str | None,
):
    alerts.append(
        {
            "alert_type": alert_type,
            "reason": reason,
            "technique": technique,
            "tactic": tactic,
        }
    )
    reasons.append(reason)


def has_encoded_keywords(command_line: str) -> bool:
    command_line = (command_line or "").lower()
    return any(k in command_line for k in ENCODED_KEYWORDS)


def has_download_exec_keywords(command_line: str) -> bool:
    command_line = (command_line or "").lower()
    return any(k in command_line for k in DOWNLOAD_OR_EXEC_KEYWORDS)


def classify_cmd_command_behavior(command_line: str):
    command_line = (command_line or "").lower()

    for pattern, reason, technique, tactic in CRITICAL_CMD_BEHAVIORS:
        if pattern in command_line:
            return {
                "score": 70,
                "alert_type": "Critical Command Shell Impact Activity",
                "reason": reason,
                "technique": technique,
                "tactic": tactic,
            }

    for pattern, reason, technique, tactic in HIGH_RISK_CMD_BEHAVIORS:
        if pattern in command_line:
            return {
                "score": 55,
                "alert_type": "High-Risk Command Shell Activity",
                "reason": reason,
                "technique": technique,
                "tactic": tactic,
            }

    if "net user" in command_line and "/add" in command_line:
        return {
            "score": 55,
            "alert_type": "High-Risk Command Shell Activity",
            "reason": "Local user creation command detected",
            "technique": "T1136",
            "tactic": "Persistence",
        }

    return None


def is_benign_powershell(command_line: str, parent_process: str) -> bool:
    command_line = (command_line or "").lower()
    parent_process = (parent_process or "").lower()

    if parent_process in BENIGN_POWERSHELL_PARENTS:
        return True

    if any(keyword in command_line for keyword in BENIGN_POWERSHELL_KEYWORDS):
        return True

    return False


def is_benign_decoded_command(decoded_command: str | None) -> bool:
    decoded_text = (decoded_command or "").lower()
    if not decoded_text:
        return False

    marker_hits = sum(
        1 for marker in BENIGN_DECODED_COMMAND_MARKERS if marker in decoded_text
    )
    return marker_hits >= 2


def is_temp_or_appdata_path(file_path: str) -> bool:
    file_path = (file_path or "").lower().replace("/", "\\")
    suspicious_segments = [
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",
        "\\windows\\temp\\",
        "\\temp\\",
        "\\downloads\\",
    ]
    return any(segment in file_path for segment in suspicious_segments)


def is_meaningful_process_context(
    process_name: str,
    command_line: str,
    file_path: str,
    parent_process: str,
) -> bool:
    return any(
        [
            bool(process_name),
            bool(command_line),
            bool(file_path),
            bool(parent_process),
        ]
    )


def is_safe_temp_appdata_process(process_name: str, file_path: str = "") -> bool:
    process_name = (process_name or "").lower()
    file_path = (file_path or "").lower().replace("/", "\\")

    if process_name in SAFE_TEMP_APPDATA_PROCESSES:
        return True

    trusted_program_paths = [
        "\\appdata\\local\\programs\\python\\",
        "\\appdata\\local\\programs\\microsoft vs code\\",
        "\\appdata\\local\\discord\\",
        "\\appdata\\local\\google\\chrome\\",
        "\\appdata\\local\\microsoft\\edge\\",
        "\\appdata\\local\\programs\\notion\\",
        "\\appdata\\local\\slack\\",
        "\\appdata\\local\\spotify\\",
    ]

    return any(path in file_path for path in trusted_program_paths)


def get_process_candidate_priority(
    name: str,
    command_line: str,
    file_path: str,
    parent_process: str,
) -> int:
    name = (name or "").lower()
    command_line = (command_line or "").lower()
    file_path = (file_path or "").lower()
    parent_process = (parent_process or "").lower()

    score = 0

    if "mimikatz" in name or "mimikatz" in command_line or "mimikatz" in file_path:
        score += 100

    if name in {"powershell.exe", "pwsh.exe"} and has_encoded_keywords(command_line):
        score += 80

    if parent_process in OFFICE_PARENTS and name in {"powershell.exe", "pwsh.exe"}:
        score += 70

    if has_download_exec_keywords(command_line):
        score += 50

    if is_temp_or_appdata_path(file_path) and not is_safe_temp_appdata_process(
        name, file_path
    ):
        score += 35

    if name in SUSPICIOUS_PROCESS_NAMES:
        score += 25

    if parent_process in OFFICE_PARENTS:
        score += 10

    return score


def should_use_process_fallback(proc: dict) -> bool:
    name = str(proc.get("name", "")).lower()
    cmd = str(proc.get("command_line", "")).lower()
    path = str(proc.get("file_path", "")).lower()
    parent = str(proc.get("parent_process", "")).lower()

    if not any([name, cmd, path, parent]):
        return False

    if name in {"powershell.exe", "pwsh.exe"} and is_benign_powershell(cmd, parent):
        return False

    if name in SUSPICIOUS_PROCESS_NAMES:
        return True

    if "mimikatz" in name or "mimikatz" in cmd or "mimikatz" in path:
        return True

    if has_encoded_keywords(cmd):
        return True

    if has_download_exec_keywords(cmd):
        return True

    if parent in OFFICE_PARENTS and name:
        return True

    if is_temp_or_appdata_path(path) and not is_safe_temp_appdata_process(name, path):
        return True

    return False


def extract_direct_or_fallback(telemetry: dict, processes: list, connections: list):
    process_name = normalize_text(telemetry.get("process_name")).lower()
    command_line = normalize_text(telemetry.get("command_line")).lower()
    file_path = normalize_text(telemetry.get("file_path")).lower()
    parent_process = normalize_text(telemetry.get("parent_process")).lower()
    destination_port = normalize_int(telemetry.get("destination_port"), 0)
    destination_ip = normalize_text(telemetry.get("destination_ip"))

    direct_has_process_context = is_meaningful_process_context(
        process_name, command_line, file_path, parent_process
    )

    if not direct_has_process_context:
        best_match = None
        best_priority = -1

        for proc in processes:
            if not should_use_process_fallback(proc):
                continue

            name = str(proc.get("name", "")).lower()
            cmd = str(proc.get("command_line", "")).lower()
            path = str(proc.get("file_path", "")).lower()
            parent = str(proc.get("parent_process", "")).lower()

            priority = get_process_candidate_priority(name, cmd, path, parent)
            if priority > best_priority:
                best_priority = priority
                best_match = {
                    "process_name": name,
                    "command_line": cmd,
                    "file_path": path,
                    "parent_process": parent,
                }

        if best_match:
            process_name = best_match["process_name"]
            command_line = best_match["command_line"]
            file_path = best_match["file_path"]
            parent_process = best_match["parent_process"]

    if not destination_port:
        for conn in connections:
            port = normalize_int(conn.get("remote_port"), 0)
            remote_ip = normalize_text(
                conn.get("remote_ip") or conn.get("remote_address")
            )
            if port in SUSPICIOUS_PORTS:
                destination_port = port
                destination_ip = destination_ip or remote_ip
                break

    return {
        "process_name": process_name,
        "command_line": command_line,
        "file_path": file_path,
        "parent_process": parent_process,
        "destination_port": destination_port,
        "destination_ip": destination_ip,
    }


def classify_process_context(
    process_name: str,
    command_line: str,
    file_path: str,
    parent_process: str,
):
    process_name = (process_name or "").lower()
    command_line = (command_line or "").lower()
    file_path = (file_path or "").lower()
    parent_process = (parent_process or "").lower()

    if not is_meaningful_process_context(
        process_name, command_line, file_path, parent_process
    ):
        return None

    has_encoded = has_encoded_keywords(command_line)
    has_download_exec = has_download_exec_keywords(command_line)
    from_temp = is_temp_or_appdata_path(file_path)
    office_parent = parent_process in OFFICE_PARENTS
    is_mimikatz = (
        "mimikatz" in process_name
        or "mimikatz" in command_line
        or "mimikatz" in file_path
    )

    if is_mimikatz:
        return {
            "alert_type": "Credential Dumping Activity",
            "reason": "Credential dumping tool detected (mimikatz)",
            "technique": "T1003",
            "tactic": "Credential Access",
            "score": 55,
        }

    if process_name in {"powershell.exe", "pwsh.exe"} and has_encoded:
        return {
            "alert_type": "Encoded PowerShell",
            "reason": "Encoded PowerShell execution detected",
            "technique": "T1027",
            "tactic": "Defense Evasion",
            "score": 45,
        }

    if process_name in {"powershell.exe", "pwsh.exe"} and office_parent:
        return {
            "alert_type": "Office Spawned Suspicious PowerShell",
            "reason": "Office application spawned PowerShell",
            "technique": "T1204.002",
            "tactic": "Execution",
            "score": 40,
        }

    if process_name in {"powershell.exe", "pwsh.exe"} and is_benign_powershell(
        command_line, parent_process
    ):
        return None

    if has_download_exec:
        return {
            "alert_type": "Download/Execute Pattern",
            "reason": "Download or remote execution pattern detected",
            "technique": "T1105",
            "tactic": "Command and Control",
            "score": 30,
        }

    if from_temp and not is_safe_temp_appdata_process(process_name, file_path):
        return {
            "alert_type": "Execution from Temp or AppData Path",
            "reason": "Execution from Temp/AppData path detected",
            "technique": "T1204",
            "tactic": "Execution",
            "score": 22,
        }

    if office_parent and process_name:
        return {
            "alert_type": "Office Spawned Suspicious Process",
            "reason": "Office application spawned suspicious process",
            "technique": "T1204.002",
            "tactic": "Execution",
            "score": 20,
        }

    return None


def infer_event_category(
    primary_alert_type: str,
    cpu: float = 0,
    memory: float = 0,
    process_count: int = 0,
) -> str:
    text = str(primary_alert_type or "").lower()

    if any(k in text for k in ["cpu", "memory", "process count", "spike"]):
        return "system_resource"

    if any(
        k in text
        for k in [
            "powershell",
            "command",
            "script",
            "execution",
            "mshta",
            "rundll32",
            "regsvr32",
            "wmi",
        ]
    ):
        return "process_execution"

    if any(k in text for k in ["credential", "mimikatz", "dumping"]):
        return "credential_access"

    if any(
        k in text
        for k in ["connection", "port", "tool transfer", "command and control"]
    ):
        return "network_connection"

    if cpu >= 60 or memory >= 85 or process_count >= 300:
        return "system_resource"

    return "general_detection"


def calculate_severity(risk_score: int) -> str:
    risk_score = int(risk_score or 0)
    if risk_score <= 30:
        return "Low"
    if risk_score <= 60:
        return "Medium"
    if risk_score <= 80:
        return "High"
    return "Critical"


def infer_severity_from_score(score: int) -> str:
    return calculate_severity(score)


def infer_detection_source(rule_score: int, ai_score: int) -> str:
    if rule_score > 0 and ai_score > 0:
        return "Hybrid"
    if rule_score > 0:
        return "Rule-Based"
    if ai_score > 0:
        return "AI-Based"
    return "Informational"


BASE64_TOKEN_REGEX = re.compile(r"^[A-Za-z0-9+/=]+$")

# Stronger Base64 validation to avoid decoding normal command words into garbage.
BASE64_MIN_LENGTH = 12


def extract_base64_from_command(command_line: str) -> str | None:
    text = str(command_line or "").strip()
    if not text:
        return None

    parts = re.split(r"\s+", text)
    for i, part in enumerate(parts):
        lowered = part.lower()

        if lowered in {"-enc", "-e", "/enc", "/e"} and i + 1 < len(parts):
            candidate = parts[i + 1].strip().strip('"').strip("'")
            if len(candidate) >= 8 and BASE64_TOKEN_REGEX.match(candidate):
                return candidate

        if lowered.startswith("-enc:") or lowered.startswith("-e:"):
            candidate = part.split(":", 1)[1].strip().strip('"').strip("'")
            if len(candidate) >= 8 and BASE64_TOKEN_REGEX.match(candidate):
                return candidate

    # fallback: التقط أطول token شكله Base64
    candidates = []
    for token in parts:
        cleaned = token.strip().strip('"').strip("'")
        if len(cleaned) >= 16 and BASE64_TOKEN_REGEX.match(cleaned):
            candidates.append(cleaned)

    if candidates:
        return max(candidates, key=len)

    return None


def try_decode_base64_text(encoded: str) -> str | None:
    if not encoded:
        return None

    padded = encoded + ("=" * ((4 - len(encoded) % 4) % 4))

    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None

    # PowerShell -enc غالبًا UTF-16LE
    for encoding in ("utf-16le", "utf-8", "latin-1"):
        try:
            text = raw.decode(encoding, errors="strict").strip()
            if text:
                return text
        except Exception:
            pass

    try:
        return raw.decode("utf-8", errors="ignore").strip() or None
    except Exception:
        return None


def decode_base64_command(command_line: str) -> dict:
    extracted = extract_base64_from_command(command_line)

    if not extracted:
        return {
            "success": False,
            "extracted_base64": None,
            "decoded_text": None,
            "message": "No Base64 payload found in command",
        }

    decoded = try_decode_base64_text(extracted)

    if not decoded:
        return {
            "success": False,
            "extracted_base64": extracted,
            "decoded_text": None,
            "message": "Base64 payload found but could not be decoded",
        }

    return {
        "success": True,
        "extracted_base64": extracted,
        "decoded_text": decoded,
        "message": "Command decoded successfully",
    }


# ============================================================
# SAFE COMMAND DECODING / DEOBFUSCATION
# ============================================================
# This section does NOT execute anything. It only tries to decode common
# attacker obfuscation formats into readable text for analyst visibility.

URL_ENCODED_REGEX = re.compile(r"%[0-9a-fA-F]{2}")
HEX_BLOB_REGEX = re.compile(
    r"(?:0x[0-9a-fA-F]{2}[,\s]*){3,}|(?:\\x[0-9a-fA-F]{2}){3,}|(?:[0-9a-fA-F]{2}\s*){8,}"
)
UNICODE_ESCAPE_REGEX = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})+")

SUSPICIOUS_DECODE_KEYWORDS = [
    "invoke-expression",
    "iex",
    "downloadstring",
    "invoke-webrequest",
    "iwr",
    "webclient",
    "net.webclient",
    "frombase64string",
    "start-process",
    "new-object",
    "write-output",
    "wevtutil",
    "wevtutil cl",
    "clear-eventlog",
    "remove-eventlog",
    "vssadmin",
    "delete shadows",
    "hidden",
    "bypass",
    "nop",
    "noprofile",
    "encodedcommand",
    "mimikatz",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil",
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "http://",
    "https://",
]


def _looks_like_readable_text(value: str) -> bool:
    """Return True only for analyst-useful decoded text.

    This intentionally rejects mojibake / random printable text that can appear
    when normal command tokens are incorrectly treated as Base64.
    """
    if not value:
        return False

    value = value.strip("\x00\r\n\t ")
    if len(value) < 3:
        return False

    lowered = value.lower()

    if "\ufffd" in value or value.count("\x00") > 2:
        return False

    printable = sum(1 for ch in value if ch.isprintable() or ch in "\r\n\t")
    printable_ratio = printable / max(len(value), 1)

    ascii_printable = sum(1 for ch in value if (32 <= ord(ch) <= 126) or ch in "\r\n\t")
    ascii_ratio = ascii_printable / max(len(value), 1)

    alpha_num = sum(1 for ch in value if ch.isalnum())
    alpha_num_ratio = alpha_num / max(len(value), 1)

    command_hints = [
        "powershell", "cmd", "start-process", "start-sleep", "invoke-", "iex",
        "downloadstring", "frombase64string", "http://", "https://", "-nop",
        "-noprofile", "-encodedcommand", "new-object", "get-process",
        "get-service", "whoami", "tasklist", "rundll32", "regsvr32", "mshta",
        "certutil", "mimikatz",
    ]
    has_command_hint = any(hint in lowered for hint in command_hints)

    if printable_ratio < 0.85:
        return False

    if ascii_ratio >= 0.65 and alpha_num_ratio >= 0.20:
        return True

    return has_command_hint


def _normalize_b64_candidate(candidate: str) -> str:
    candidate = str(candidate or "").strip().strip('"').strip("'")
    # Common URL-safe base64 variants
    candidate = candidate.replace("-", "+").replace("_", "/")
    return candidate


def _decoded_text_score(text: str, encoding: str = "") -> int:
    """Score decoded text so the best-looking decode wins and garbage loses."""
    if not text:
        return -1000

    lowered = text.lower()
    score = 0

    ascii_printable = sum(1 for ch in text if (32 <= ord(ch) <= 126) or ch in "\r\n\t")
    ascii_ratio = ascii_printable / max(len(text), 1)
    alpha_num = sum(1 for ch in text if ch.isalnum())
    alpha_num_ratio = alpha_num / max(len(text), 1)

    score += int(ascii_ratio * 60)
    score += int(alpha_num_ratio * 25)

    if encoding == "utf-16le":
        score += 18

    good_keywords = [
        "start-process", "start-sleep", "powershell", "invoke-", "downloadstring",
        "iex", "frombase64string", "new-object", "cmd.exe", "http://", "https://",
        "-noprofile", "-nop", "bypass", "hidden", "write-output", "get-process",
        "get-service", "whoami", "tasklist", "rundll32", "regsvr32", "mshta",
        "certutil", "mimikatz",
    ]
    for keyword in good_keywords:
        if keyword in lowered:
            score += 25

    non_ascii = sum(1 for ch in text if ord(ch) > 126 and ch not in "\r\n\t")
    if non_ascii / max(len(text), 1) > 0.25:
        score -= 80

    weird_chars = sum(1 for ch in text if ord(ch) > 126 and not ch.isalpha())
    if weird_chars / max(len(text), 1) > 0.12:
        score -= 70

    return score


def _decode_base64_candidate(
    candidate: str, prefer_powershell: bool = False
) -> list[dict]:
    """Try multiple text encodings for a Base64 candidate and keep sane output only."""
    results = []
    candidate = _normalize_b64_candidate(candidate)
    if not candidate or len(candidate) < BASE64_MIN_LENGTH:
        return results

    compact = re.sub(r"\s+", "", candidate)
    if not BASE64_TOKEN_REGEX.match(compact):
        return results

    padded = compact + ("=" * ((4 - len(compact) % 4) % 4))

    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception:
        return results

    if len(raw) < 4:
        return results

    encodings = ("utf-16le", "utf-8", "latin-1")

    for enc in encodings:
        try:
            decoded = raw.decode(enc, errors="strict").strip("\x00\r\n\t ")
            if not decoded:
                continue

            if not _looks_like_readable_text(decoded):
                continue

            score = _decoded_text_score(decoded, enc)
            if prefer_powershell and enc == "utf-16le":
                score += 40

            if enc == "latin-1" and score < 60:
                continue

            if score < 35:
                continue

            results.append(
                {
                    "method": f"Base64 {enc}",
                    "input": compact,
                    "output": decoded,
                    "score": score,
                }
            )
        except Exception:
            continue

    if not results:
        try:
            decoded = raw.decode("utf-8", errors="ignore").strip("\x00\r\n\t ")
            if decoded and _looks_like_readable_text(decoded):
                score = _decoded_text_score(decoded, "utf-8")
                if score >= 45:
                    results.append(
                        {
                            "method": "Base64 utf-8 ignore",
                            "input": compact,
                            "output": decoded,
                            "score": score,
                        }
                    )
        except Exception:
            pass

    seen = set()
    unique = []
    for item in sorted(results, key=lambda x: x.get("score", 0), reverse=True):
        key = item["output"]
        if key in seen:
            continue
        seen.add(key)
        item.pop("score", None)
        unique.append(item)

    return unique


def extract_base64_candidates(command_line: str) -> list[str]:
    """Extract Base64 candidates while avoiding false decoding of normal commands."""
    text = str(command_line or "")
    if not text:
        return []

    candidates = []
    explicit_candidates = []
    parts = re.split(r"\s+", text)

    for i, part in enumerate(parts):
        cleaned = part.strip().strip('"').strip("'")
        lowered = cleaned.lower()

        if lowered in {
            "-enc", "-e", "/enc", "/e", "-encodedcommand", "/encodedcommand",
            "--encodedcommand",
        } and i + 1 < len(parts):
            explicit_candidates.append(parts[i + 1].strip().strip('"').strip("'"))
            continue

        for prefix in ("-enc:", "-e:", "/enc:", "/e:", "-encodedcommand:", "--encodedcommand:"):
            if lowered.startswith(prefix):
                explicit_candidates.append(cleaned.split(":", 1)[1])

    candidates.extend(explicit_candidates)

    lowered_text = text.lower()

    if any(marker in lowered_text for marker in ["frombase64string", "base64", "encodedcommand", "-enc", "/enc"]):
        generic = re.findall(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{20,}(?![A-Za-z0-9+/=_-])", text)
        candidates.extend(generic)

    result = []
    seen = set()

    for c in candidates:
        c = _normalize_b64_candidate(c)
        compact = re.sub(r"\s+", "", c)

        if len(compact) < BASE64_MIN_LENGTH:
            continue

        if not BASE64_TOKEN_REGEX.match(compact):
            continue

        lc = compact.lower()
        if lc.endswith(".exe") or "\\" in compact:
            continue

        if len(compact.replace("=", "")) % 4 == 1:
            continue

        if compact not in seen:
            seen.add(compact)
            result.append(compact)

    return result


def try_decode_url_encoding(text: str) -> str | None:
    if not text or not URL_ENCODED_REGEX.search(text):
        return None
    try:
        from urllib.parse import unquote

        decoded = unquote(text)
        if decoded != text and _looks_like_readable_text(decoded):
            return decoded
    except Exception:
        return None
    return None


def try_decode_unicode_escapes(text: str) -> str | None:
    if not text or not UNICODE_ESCAPE_REGEX.search(text):
        return None
    try:
        decoded = bytes(text, "utf-8").decode("unicode_escape", errors="ignore")
        if decoded != text and _looks_like_readable_text(decoded):
            return decoded
    except Exception:
        return None
    return None


def try_decode_hex_blob(text: str) -> str | None:
    if not text:
        return None
    match = HEX_BLOB_REGEX.search(text)
    if not match:
        return None

    blob = match.group(0)
    cleaned = blob.replace("0x", "").replace("\\x", "")
    cleaned = re.sub(r"[^0-9a-fA-F]", "", cleaned)
    if len(cleaned) < 8 or len(cleaned) % 2 != 0:
        return None

    try:
        raw = bytes.fromhex(cleaned)
    except Exception:
        return None

    for enc in ("utf-16le", "utf-8", "latin-1"):
        try:
            decoded = raw.decode(enc, errors="strict").strip("\x00\r\n\t ")
            if decoded and _looks_like_readable_text(decoded):
                return decoded
        except Exception:
            continue
    return None


def find_suspicious_decoded_keywords(text: str) -> list[str]:
    lowered = str(text or "").lower()
    found = []
    for keyword in SUSPICIOUS_DECODE_KEYWORDS:
        if keyword in lowered and keyword not in found:
            found.append(keyword)
    return found


def _is_mostly_base64_text(value: str) -> bool:
    """Return True when decoded output itself looks like another Base64 payload."""
    value = str(value or "").strip().strip('"').strip("'")
    if len(value) < 16:
        return False
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 16:
        return False
    return BASE64_TOKEN_REGEX.match(compact.replace("=", "")) is not None


def _has_explicit_encoding_marker(value: str) -> bool:
    lowered = str(value or "").lower()
    markers = [
        "-enc",
        "-encodedcommand",
        "encodedcommand",
        "frombase64string",
        "base64",
        "%",
        "\\u",
        "\\x",
        "0x",
    ]
    return any(marker in lowered for marker in markers)


def decode_suspicious_command(command_line: str, max_layers: int = 3) -> dict:
    """
    Safely decode/deobfuscate common command-line hiding techniques.

    Handles:
    - PowerShell -EncodedCommand / -enc Base64 UTF-16LE
    - Generic Base64 UTF-8 / UTF-16LE / Latin-1
    - Double Base64 only when the decoded output clearly looks encoded again
    - URL encoding
    - Unicode escape sequences
    - Hex blobs

    Important behavior:
    - It never executes decoded content.
    - It preserves Base64 casing.
    - It stops at the first analyst-readable PowerShell EncodedCommand result
      to avoid over-decoding into garbage.
    """
    original = str(command_line or "")
    if not original.strip():
        return {
            "decoded_command": None,
            "decode_success": False,
            "decode_method": None,
            "decode_layers": [],
            "decoded_suspicious_keywords": [],
        }

    layers = []
    current_texts = [original]
    final_decoded = None
    final_method = None

    for layer_index in range(max_layers):
        new_texts = []
        produced_this_layer = []

        for text in current_texts:
            prefer_powershell = any(
                x in text.lower() for x in ["-enc", "encodedcommand"]
            )

            # URL decode
            url_decoded = try_decode_url_encoding(text)
            if url_decoded and url_decoded != text:
                item = {
                    "layer": layer_index + 1,
                    "method": "URL decode",
                    "input": text,
                    "output": url_decoded,
                }
                layers.append(item)
                produced_this_layer.append(item)
                new_texts.append(url_decoded)
                final_decoded = url_decoded
                final_method = item["method"]

            # Unicode escapes
            uni_decoded = try_decode_unicode_escapes(text)
            if uni_decoded and uni_decoded != text:
                item = {
                    "layer": layer_index + 1,
                    "method": "Unicode escape decode",
                    "input": text,
                    "output": uni_decoded,
                }
                layers.append(item)
                produced_this_layer.append(item)
                new_texts.append(uni_decoded)
                final_decoded = uni_decoded
                final_method = item["method"]

            # Hex blobs
            hex_decoded = try_decode_hex_blob(text)
            if hex_decoded and hex_decoded != text:
                item = {
                    "layer": layer_index + 1,
                    "method": "Hex decode",
                    "input": text,
                    "output": hex_decoded,
                }
                layers.append(item)
                produced_this_layer.append(item)
                new_texts.append(hex_decoded)
                final_decoded = hex_decoded
                final_method = item["method"]

            # Base64 candidates
            for candidate in extract_base64_candidates(text):
                decoded_candidates = _decode_base64_candidate(
                    candidate,
                    prefer_powershell=prefer_powershell,
                )
                if not decoded_candidates:
                    continue

                # _decode_base64_candidate is already sorted best-first.
                decoded_item = decoded_candidates[0]
                output = decoded_item["output"]
                if not output or output == text:
                    continue

                method = decoded_item["method"]
                if prefer_powershell:
                    method = "PowerShell EncodedCommand " + method.replace(
                        "Base64 ", ""
                    )

                item = {
                    "layer": layer_index + 1,
                    "method": method,
                    "input": candidate,
                    "output": output,
                }
                layers.append(item)
                produced_this_layer.append(item)
                new_texts.append(output)
                final_decoded = output
                final_method = method

                # Critical fix: PowerShell -EncodedCommand normally decodes to the
                # real command in one layer. Stop here to avoid re-decoding normal
                # command text as Base64-like garbage.
                if prefer_powershell and _looks_like_readable_text(output):
                    keywords = find_suspicious_decoded_keywords(
                        "\n".join([original, output])
                    )
                    return {
                        "decoded_command": output,
                        "decode_success": True,
                        "decode_method": method,
                        "decode_layers": format_decode_layers_for_display([item]),
                        "decoded_suspicious_keywords": keywords,
                    }

        unique_new = []
        seen = set(current_texts)
        for t in new_texts:
            if t not in seen and t not in unique_new:
                # Continue to another layer only when it still looks encoded.
                if _has_explicit_encoding_marker(t) or _is_mostly_base64_text(t):
                    unique_new.append(t)

        if not unique_new:
            break
        current_texts = unique_new

    keywords = find_suspicious_decoded_keywords(
        "\n".join([original] + [str(layer.get("output") or "") for layer in layers])
    )

    return {
        "decoded_command": final_decoded,
        "decode_success": bool(final_decoded),
        "decode_method": final_method
        or (
            " -> ".join(layer.get("method", "") for layer in layers) if layers else None
        ),
        "decode_layers": format_decode_layers_for_display(layers),
        "decoded_suspicious_keywords": keywords,
    }


# Keep the old endpoint-compatible function, but power it by the smarter decoder.
def decode_base64_command(command_line: str) -> dict:
    smart = decode_suspicious_command(command_line)
    extracted = extract_base64_from_command(command_line)

    if not smart.get("decode_success"):
        return {
            "success": False,
            "extracted_base64": extracted,
            "decoded_text": None,
            "message": "No safely decodable payload found in command",
        }

    return {
        "success": True,
        "extracted_base64": extracted,
        "decoded_text": smart.get("decoded_command"),
        "message": f"Command decoded successfully using {smart.get('decode_method')}",
    }


def get_raw_command_line_for_decoding(
    telemetry: dict,
    processes: list,
    direct_process_name: str,
    fallback_command_line: str,
) -> str:
    """Return a command line without corrupting Base64 case.

    Detection logic lowercases command lines for matching, but Base64 is
    case-sensitive. This helper keeps the original casing for decoding.
    """
    raw_direct = normalize_text(telemetry.get("command_line"))
    if raw_direct:
        return raw_direct

    target_name = (direct_process_name or "").lower()
    for proc in processes:
        name = str(proc.get("name", "")).lower()
        cmd = normalize_text(proc.get("command_line"))
        if not cmd:
            continue

        if target_name and name == target_name:
            return cmd

        if has_encoded_keywords(cmd) or has_download_exec_keywords(cmd):
            return cmd

    return fallback_command_line or ""


def format_decode_layers_for_display(layers) -> list[str]:
    """Convert decode layer values to display-ready strings.

    Supports both:
    - raw layer dictionaries from decode_suspicious_command
    - already formatted strings returned by smart-stop decoding

    This prevents React from showing [object Object] and prevents layers
    from disappearing when they are already strings.
    """
    display = []

    if not layers:
        return display

    if isinstance(layers, str):
        return [layers] if layers.strip() else []

    if not isinstance(layers, list):
        return display

    for layer in layers:
        try:
            if isinstance(layer, str):
                if layer.strip():
                    display.append(layer)
                continue

            if isinstance(layer, dict):
                layer_no = layer.get("layer", "?")
                method = layer.get("method", "Unknown")
                output = str(layer.get("output") or "").replace("\r", " ").replace("\n", " ")
                if len(output) > 180:
                    output = output[:180] + "..."
                display.append(f"Layer {layer_no}: {method} -> {output}")
        except Exception:
            continue

    return display



# ============================================================
# ENTERPRISE-STYLE CORRELATION ENGINE
# ============================================================
# This layer sits above the basic rule checks. Instead of treating every
# indicator independently, it correlates process + command line + parent
# process + path + network + decoded content into meaningful attack patterns.
# It does not execute anything and it is safe for lab/demo environments.

PROXY_EXECUTION_BINARIES = {
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "certutil.exe",
    "wmic.exe",
}

C2_RELATED_PORTS = {4443, 4444, 8080, 8081, 8443, 9001, 1337, 5555}

HIGH_VALUE_ATTACK_KEYWORDS = {
    "iex",
    "invoke-expression",
    "downloadstring",
    "invoke-webrequest",
    "iwr",
    "webclient",
    "frombase64string",
    "encodedcommand",
    "mimikatz",
    "bypass",
    "hidden",
    "nop",
    "noprofile",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil",
    "wevtutil",
    "clear-eventlog",
    "remove-eventlog",
    "vssadmin",
    "delete shadows",
    "http://",
    "https://",
}


def _connection_has_suspicious_port(connections: list) -> bool:
    for conn in connections or []:
        remote_port = normalize_int(conn.get("remote_port"), 0)
        if remote_port in SUSPICIOUS_PORTS or remote_port in C2_RELATED_PORTS:
            return True
    return False


def _connection_ports(connections: list) -> list[int]:
    ports = []
    for conn in connections or []:
        port = normalize_int(conn.get("remote_port"), 0)
        if port:
            ports.append(port)
    return sorted(set(ports))


def build_detection_context(
    process_name: str,
    command_line: str,
    file_path: str,
    parent_process: str,
    destination_port: int,
    decoded_command: str | None,
    decoded_suspicious_keywords: list[str],
    powershell_flag: int,
    temp_execution: int,
    suspicious_port: int,
    connections: list,
) -> dict:
    """Create one normalized context object used by correlation rules."""
    process_name = (process_name or "").lower()
    command_line = (command_line or "").lower()
    file_path = (file_path or "").lower()
    parent_process = (parent_process or "").lower()
    decoded_text = (decoded_command or "").lower()
    benign_decoded_command = is_benign_decoded_command(decoded_text)

    all_text = " ".join([process_name, command_line, file_path, parent_process, decoded_text])
    decoded_keyword_set = {str(k).lower() for k in (decoded_suspicious_keywords or [])}
    matched_high_value_keywords = [] if benign_decoded_command else sorted(
        keyword
        for keyword in HIGH_VALUE_ATTACK_KEYWORDS
        if keyword in all_text or keyword in decoded_keyword_set
    )

    network_ports = _connection_ports(connections)
    has_network_suspicion = (
        destination_port in SUSPICIOUS_PORTS
        or destination_port in C2_RELATED_PORTS
        or suspicious_port == 1
        or _connection_has_suspicious_port(connections)
    )

    return {
        "process_name": process_name,
        "command_line": command_line,
        "file_path": file_path,
        "parent_process": parent_process,
        "destination_port": destination_port,
        "network_ports": network_ports,
        "is_powershell": process_name in {"powershell.exe", "pwsh.exe"} or powershell_flag == 1,
        "is_command_shell": process_name == "cmd.exe",
        "is_script_host": process_name in {"wscript.exe", "cscript.exe"},
        "is_proxy_binary": process_name in PROXY_EXECUTION_BINARIES,
        "is_mimikatz": "mimikatz" in all_text,
        "has_encoded": has_encoded_keywords(command_line) or "frombase64string" in decoded_text,
        "has_download_exec": has_download_exec_keywords(command_line) or any(
            k in decoded_text
            for k in [
                "downloadstring",
                "invoke-webrequest",
                "iwr",
                "wget",
                "curl",
                "invoke-expression",
                "iex",
                "webclient",
            ]
        ),
        "decoded_success": bool(decoded_command),
        "decoded_is_suspicious": bool(decoded_suspicious_keywords)
        and not benign_decoded_command,
        "decoded_suspicious_keywords": decoded_suspicious_keywords or [],
        "benign_decoded_command": benign_decoded_command,
        "matched_high_value_keywords": matched_high_value_keywords,
        "from_temp_or_appdata": is_temp_or_appdata_path(file_path) or temp_execution == 1,
        "office_parent": parent_process in OFFICE_PARENTS,
        "has_suspicious_network": has_network_suspicion,
        "is_safe_temp_process": is_safe_temp_appdata_process(process_name, file_path),
    }


def correlate_attack_patterns(ctx: dict) -> tuple[list[dict], int, list[str]]:
    """Return correlated attack alerts, bonus score, and human-readable notes."""
    correlated_alerts: list[dict] = []
    correlation_reasons: list[str] = []
    bonus_score = 0

    def add_pattern(
        alert_type: str,
        reason: str,
        technique: str,
        tactic: str,
        score: int,
        explanation: str,
    ):
        nonlocal bonus_score
        correlated_alerts.append(
            {
                "alert_type": alert_type,
                "reason": reason,
                "technique": technique,
                "tactic": tactic,
                "correlated": True,
                "explanation": explanation,
            }
        )
        correlation_reasons.append(explanation)
        bonus_score += score

    # 1) Strongest demo/real-world chain: encoded PowerShell + decoded suspicious content + network.
    if (
        ctx["is_powershell"]
        and ctx["has_encoded"]
        and ctx["decoded_success"]
        and ctx["decoded_is_suspicious"]
        and ctx["has_suspicious_network"]
    ):
        add_pattern(
            "Possible PowerShell-Based Command & Control Attack",
            "Encoded PowerShell decoded to suspicious behavior with network activity",
            "T1071",
            "Command and Control",
            45,
            "Attack chain correlation: PowerShell + encoded command + suspicious decoded keywords + suspicious network activity.",
        )

    # 2) Office spawning encoded PowerShell is a classic malicious document/macro scenario.
    if ctx["office_parent"] and ctx["is_powershell"] and ctx["has_encoded"]:
        add_pattern(
            "Office-Launched Encoded PowerShell Chain",
            "Office application spawned encoded PowerShell",
            "T1204.002",
            "Execution",
            38,
            "Attack chain correlation: Office parent process launched PowerShell with encoded content.",
        )

    # 3) Download cradle / ingress tool transfer behavior.
    if ctx["has_download_exec"] and (ctx["is_powershell"] or ctx["is_command_shell"] or ctx["is_proxy_binary"]):
        add_pattern(
            "Suspicious Download-and-Execute Chain",
            "Command line indicates download or remote execution behavior",
            "T1105",
            "Command and Control",
            30,
            "Behavior correlation: command interpreter or proxy binary is attempting download/execute behavior.",
        )

    # 4) Living-off-the-land proxy execution with risky context.
    if ctx["is_proxy_binary"] and (
        ctx["has_download_exec"]
        or ctx["from_temp_or_appdata"]
        or ctx["has_suspicious_network"]
    ):
        add_pattern(
            "Living-off-the-Land Proxy Execution Chain",
            "Trusted Windows utility used in suspicious execution context",
            "T1218",
            "Defense Evasion",
            28,
            "Behavior correlation: Windows proxy-execution binary combined with suspicious path, download, or network behavior.",
        )

    # 5) Execution from Temp/AppData becomes more important if paired with suspicious process/network.
    if (
        ctx["from_temp_or_appdata"]
        and not ctx["is_safe_temp_process"]
        and (ctx["has_suspicious_network"] or ctx["has_encoded"] or ctx["has_download_exec"])
    ):
        add_pattern(
            "Suspicious Payload Execution from User-Writable Path",
            "Executable/script ran from Temp/AppData with additional suspicious behavior",
            "T1204",
            "Execution",
            25,
            "Behavior correlation: user-writable path execution combined with suspicious command or network indicators.",
        )

    # 6) Credential dumping is high impact even without other correlations.
    if ctx["is_mimikatz"]:
        add_pattern(
            "Credential Dumping Attack Indicator",
            "Credential dumping tool or keyword observed",
            "T1003",
            "Credential Access",
            42,
            "High-confidence indicator: Mimikatz/credential dumping reference was observed in process, path, or command content.",
        )

    # Prevent one noisy telemetry snapshot from adding unrealistic bonus points.
    bonus_score = min(bonus_score, 60)
    return correlated_alerts, bonus_score, dedupe_keep_order(correlation_reasons)


def build_attack_chain(ctx: dict) -> list[str]:
    """Create a short analyst-friendly timeline/stage list for the UI/report."""
    chain = []

    if ctx.get("office_parent"):
        chain.append("Initial Execution: Office application acted as parent process")

    if ctx.get("is_powershell"):
        chain.append("Execution: PowerShell activity observed")
    elif ctx.get("is_command_shell"):
        chain.append("Execution: Command shell activity observed")
    elif ctx.get("is_proxy_binary"):
        chain.append("Defense Evasion: Living-off-the-land Windows utility observed")

    if ctx.get("has_encoded"):
        chain.append("Obfuscation: Encoded or Base64-like command content detected")

    if ctx.get("decoded_success"):
        chain.append("Analysis: Encoded content was safely decoded for analyst review")

    if ctx.get("decoded_is_suspicious"):
        keywords = ", ".join(ctx.get("decoded_suspicious_keywords", [])[:6])
        chain.append(f"Suspicious Content: decoded command contains {keywords}")

    if ctx.get("has_download_exec"):
        chain.append("Ingress Tool Transfer: download/execute behavior observed")

    if ctx.get("from_temp_or_appdata") and not ctx.get("is_safe_temp_process"):
        chain.append("Execution Path: process ran from Temp/AppData or another user-writable path")

    if ctx.get("has_suspicious_network"):
        ports = ctx.get("network_ports") or []
        if ports:
            chain.append(f"Network: suspicious/high-risk outbound port observed ({', '.join(map(str, ports[:8]))})")
        else:
            chain.append("Network: suspicious outbound network behavior observed")

    return dedupe_keep_order(chain)


def infer_attack_confidence(
    final_score: int,
    rule_score: int,
    ai_score: int,
    decoded_success: bool,
    correlated_alerts: list[dict],
    reasons: list[str],
) -> str:
    """Explain how confident the engine is, not only how severe the event is."""
    correlation_count = len(correlated_alerts or [])
    evidence_count = len(reasons or [])

    if final_score >= 90 and (correlation_count >= 1 or (decoded_success and ai_score > 0)):
        return "Very High"

    if final_score >= 75 and (correlation_count >= 1 or ai_score > 0 or decoded_success):
        return "High"

    if final_score >= 45 and evidence_count >= 2:
        return "Medium"

    if final_score >= 20:
        return "Low"

    return "Informational"


def build_attack_summary(
    primary_alert: dict,
    severity: str,
    confidence: str,
    ctx: dict,
    attack_chain: list[str],
) -> str:
    """Build a concise explanation suitable for the dashboard and professor demo."""
    alert_type = primary_alert.get("alert_type", "Informational")
    tactic = primary_alert.get("tactic") or "N/A"
    technique = primary_alert.get("technique") or "N/A"

    evidence = []
    if ctx.get("is_powershell"):
        evidence.append("PowerShell activity")
    if ctx.get("has_encoded"):
        evidence.append("encoded command content")
    if ctx.get("decoded_success"):
        evidence.append("successful safe decoding")
    if ctx.get("decoded_is_suspicious"):
        evidence.append("suspicious decoded keywords")
    if ctx.get("has_suspicious_network"):
        evidence.append("suspicious network behavior")
    if ctx.get("office_parent"):
        evidence.append("Office parent process")
    if ctx.get("from_temp_or_appdata") and not ctx.get("is_safe_temp_process"):
        evidence.append("Temp/AppData execution path")

    evidence_text = ", ".join(evidence[:6]) if evidence else "available telemetry indicators"
    chain_text = " -> ".join(attack_chain[:5]) if attack_chain else "No multi-stage chain was confirmed."

    return (
        f"{alert_type} classified as {severity.upper()} with {confidence} confidence. "
        f"Key evidence: {evidence_text}. "
        f"MITRE mapping: {tactic} / {technique}. "
        f"Observed chain: {chain_text}"
    )

def recommend_response_action(severity: str, alert_type: str, ctx: dict) -> str:
    severity = str(severity or "").lower()
    alert_type = str(alert_type or "").lower()

    if "credential" in alert_type or ctx.get("is_mimikatz"):
        return "Immediately investigate credential access, collect diagnostics, and isolate host for review."

    if severity in {"critical", "high"} and ctx.get("has_suspicious_network"):
        return "Review outbound network activity, collect diagnostics, and consider host isolation review."

    if ctx.get("has_encoded") or ctx.get("decoded_is_suspicious"):
        return "Review decoded command, collect diagnostics, and validate whether the command was authorized."

    if ctx.get("from_temp_or_appdata") and not ctx.get("is_safe_temp_process"):
        return "Inspect file path, verify file reputation, and collect endpoint diagnostics."

    if severity == "medium":
        return "Monitor the endpoint and review related telemetry events."

    return "No immediate response required. Continue monitoring."


def calculate_behavior_ai_score(ctx: dict) -> tuple[int, list[str]]:
    """
    Stronger behavior-based AI scoring layer.
    This does not replace the ML model; it adds an AI-like behavioral reasoning score
    based on correlated endpoint behavior.
    """
    score = 0
    reasons = []

    if ctx.get("is_powershell") and ctx.get("has_encoded"):
        score += 18
        reasons.append("Behavior AI: encoded PowerShell activity increases attack likelihood")

    if ctx.get("decoded_success") and ctx.get("decoded_is_suspicious"):
        score += 20
        reasons.append("Behavior AI: decoded command contains suspicious behavior indicators")

    if ctx.get("has_download_exec"):
        score += 18
        reasons.append("Behavior AI: download/execute pattern detected")

    if ctx.get("has_suspicious_network"):
        score += 18
        reasons.append("Behavior AI: suspicious outbound network behavior detected")

    if ctx.get("office_parent") and ctx.get("is_powershell"):
        score += 16
        reasons.append("Behavior AI: Office application spawned PowerShell")

    if ctx.get("from_temp_or_appdata") and not ctx.get("is_safe_temp_process"):
        score += 14
        reasons.append("Behavior AI: execution from user-writable Temp/AppData path")

    if ctx.get("is_proxy_binary"):
        score += 12
        reasons.append("Behavior AI: living-off-the-land proxy execution binary observed")

    if ctx.get("is_mimikatz"):
        score += 35
        reasons.append("Behavior AI: credential dumping indicator observed")

    # Bonus for multi-stage behavior
    chain_hits = sum([
        bool(ctx.get("has_encoded")),
        bool(ctx.get("decoded_is_suspicious")),
        bool(ctx.get("has_download_exec")),
        bool(ctx.get("has_suspicious_network")),
        bool(ctx.get("from_temp_or_appdata")),
        bool(ctx.get("office_parent")),
    ])

    if chain_hits >= 3:
        score += 15
        reasons.append("Behavior AI: multi-stage suspicious behavior chain detected")

    return min(score, 45), reasons


def calculate_risk_score(telemetry: dict) -> dict:
    rule_score = 0
    ai_score = 0
    reasons: list[str] = []
    alerts: list[dict] = []

    cpu = float(telemetry.get("cpu_percent", 0) or 0)
    memory = float(telemetry.get("memory_percent", 0) or 0)
    process_count = int(telemetry.get("process_count", 0) or 0)
    connections_count = int(telemetry.get("connections_count", 0) or 0)

    powershell_flag = int(telemetry.get("powershell_flag", 0) or 0)
    temp_execution = int(telemetry.get("temp_execution", 0) or 0)
    suspicious_port = int(telemetry.get("suspicious_port", 0) or 0)

    processes = safe_json_load(telemetry.get("top_cpu_processes"))
    connections = safe_json_load(telemetry.get("network_connections"))

    extracted = extract_direct_or_fallback(telemetry, processes, connections)

    direct_process_name = extracted["process_name"]
    direct_command_line = extracted["command_line"]
    direct_file_path = extracted["file_path"]
    direct_parent_process = extracted["parent_process"]
    direct_destination_port = extracted["destination_port"]

    # Safely decode/deobfuscate encoded command content for analyst visibility.
    # Important: use original case command line because Base64 is case-sensitive.
    raw_command_line_for_decode = get_raw_command_line_for_decoding(
        telemetry, processes, direct_process_name, direct_command_line
    )
    decoded_info = decode_suspicious_command(raw_command_line_for_decode)
    decoded_command = decoded_info.get("decoded_command")
    decode_method = decoded_info.get("decode_method")
    raw_decode_layers = decoded_info.get("decode_layers") or []
    decode_layers = format_decode_layers_for_display(raw_decode_layers)
    decoded_suspicious_keywords = decoded_info.get("decoded_suspicious_keywords") or []
    benign_decoded_command = is_benign_decoded_command(decoded_command)
    if benign_decoded_command:
        decoded_suspicious_keywords = []

    detection_context = build_detection_context(
        process_name=direct_process_name,
        command_line=direct_command_line,
        file_path=direct_file_path,
        parent_process=direct_parent_process,
        destination_port=direct_destination_port,
        decoded_command=decoded_command,
        decoded_suspicious_keywords=decoded_suspicious_keywords,
        powershell_flag=powershell_flag,
        temp_execution=temp_execution,
        suspicious_port=suspicious_port,
        connections=connections,
    )

    correlated_alerts, correlation_bonus_score, correlation_reasons = correlate_attack_patterns(detection_context)
    attack_chain = build_attack_chain(detection_context)

    behavior_ai_score, behavior_ai_reasons = calculate_behavior_ai_score(detection_context)

    if behavior_ai_score > 0:
        ai_score += behavior_ai_score
        reasons.extend(behavior_ai_reasons)
        alerts.append(
            {
                "alert_type": "Behavioral AI Threat Analysis",
                "reason": "AI analyzed correlated endpoint behavior and increased risk score",
                "technique": "T1059",
                "tactic": "Execution",
            }
        )

    if correlation_bonus_score:
        rule_score += correlation_bonus_score
        alerts.extend(correlated_alerts)
        reasons.extend(correlation_reasons)

    if decoded_command:
        reasons.append(f"Decoded command extracted using {decode_method}")
        if decoded_suspicious_keywords:
            reasons.append(
                "Suspicious decoded keywords: "
                + ", ".join(decoded_suspicious_keywords[:8])
            )

    if cpu > 90:
        rule_score += 85
        add_alert(
            alerts,
            reasons,
            "CPU Spike",
            f"Critical CPU usage ({cpu:.1f}%) - above 90%",
            "T1499",
            "Impact",
        )
    elif cpu >= 81:
        rule_score += 70
        add_alert(
            alerts,
            reasons,
            "High CPU Usage",
            f"High CPU usage ({cpu:.1f}%) – possible overload",
            "T1499",
            "Impact",
        )
        high_cpu_reason = f"High CPU usage ({cpu:.1f}%) - 81% to 90%"
        alerts[-1]["reason"] = high_cpu_reason
        reasons[-1] = high_cpu_reason
    elif cpu >= 60:
        rule_score += 45
        add_alert(
            alerts,
            reasons,
            "Medium CPU Usage",
            f"Medium CPU usage ({cpu:.1f}%) - 60% to 80%",
            "T1499",
            "Impact",
        )

    if memory >= 95:
        rule_score += 20
        add_alert(
            alerts,
            reasons,
            "Memory Spike",
            f"Critical memory usage ({memory:.1f}%)",
            "T1499",
            "Impact",
        )
    elif memory >= 90:
        rule_score += 10
        add_alert(
            alerts,
            reasons,
            "High Memory Usage",
            f"High memory usage ({memory:.1f}%) – possible pressure",
            "T1499",
            "Impact",
        )
    elif memory >= 78:
        rule_score += 5
        reasons.append(f"Elevated memory usage ({memory:.1f}%)")

    if process_count >= 380:
        rule_score += 15
        add_alert(
            alerts,
            reasons,
            "High Process Count",
            f"High process count ({process_count}) – possible process spawning",
            "T1057",
            "Discovery",
        )
    elif process_count >= 340:
        rule_score += 5
        reasons.append(f"Elevated process count ({process_count})")

    if direct_process_name in {"powershell.exe", "pwsh.exe"} and is_benign_powershell(
        direct_command_line, direct_parent_process
    ):
        pass
    elif direct_process_name in SUSPICIOUS_PROCESS_NAMES:
        item = SUSPICIOUS_PROCESS_NAMES[direct_process_name]
        rule_score += item["score"]
        add_alert(
            alerts,
            reasons,
            item["alert_type"],
            item["reason"],
            item["technique"],
            item["tactic"],
        )

    context_alert = classify_process_context(
        direct_process_name,
        direct_command_line,
        direct_file_path,
        direct_parent_process,
    )

    if context_alert:
        rule_score += context_alert["score"]
        add_alert(
            alerts,
            reasons,
            context_alert["alert_type"],
            context_alert["reason"],
            context_alert["technique"],
            context_alert["tactic"],
        )

    # Additional command-behavior detections for common ATT&CK categories.
    all_cmd_text = " ".join([
        str(direct_process_name or ""),
        str(direct_command_line or ""),
        str(decoded_command or ""),
        str(direct_file_path or ""),
    ]).lower()

    if direct_process_name == "cmd.exe":
        cmd_behavior = classify_cmd_command_behavior(all_cmd_text)
        if cmd_behavior:
            rule_score += cmd_behavior["score"]
            add_alert(
                alerts,
                reasons,
                cmd_behavior["alert_type"],
                cmd_behavior["reason"],
                cmd_behavior["technique"],
                cmd_behavior["tactic"],
            )

    if any(k in all_cmd_text for k in ["whoami /all", "net user", "net localgroup", "tasklist /svc", "get-localuser"]):
        rule_score += 16
        add_alert(
            alerts,
            reasons,
            "Discovery Command Activity",
            "User, group, or process discovery behavior detected",
            "T1087",
            "Discovery",
        )

    if any(k in all_cmd_text for k in ["schtasks", "new-scheduledtask", "create /sc", " at "]):
        rule_score += 24
        add_alert(
            alerts,
            reasons,
            "Scheduled Task Persistence",
            "Scheduled task creation or usage pattern detected",
            "T1053.005",
            "Persistence",
        )

    if any(k in all_cmd_text for k in ["wevtutil cl", "clear-eventlog", "remove-eventlog"]):
        rule_score += 34
        add_alert(
            alerts,
            reasons,
            "Log Clearing Attempt",
            "Event log clearing or tampering pattern detected",
            "T1070.001",
            "Defense Evasion",
        )

    if any(k in all_cmd_text for k in ["vssadmin delete shadows", "wmic shadowcopy delete", "delete shadows"]):
        rule_score += 40
        add_alert(
            alerts,
            reasons,
            "Shadow Copy Deletion",
            "Shadow copy deletion pattern detected",
            "T1490",
            "Impact",
        )

    if any(k in all_cmd_text for k in ["lsass", "sekurlsa", "minidump", "procdump"]):
        rule_score += 34
        add_alert(
            alerts,
            reasons,
            "Credential Access Behavior",
            "Credential access or LSASS-related behavior detected",
            "T1003",
            "Credential Access",
        )

    if (
        direct_process_name in {"powershell.exe", "pwsh.exe"}
        and has_download_exec_keywords(direct_command_line)
        and has_encoded_keywords(direct_command_line)
    ):
        rule_score += 10
        reasons.append(
            "Encoded PowerShell with download/execute behavior"
        )

    if (
        direct_parent_process in OFFICE_PARENTS
        and is_temp_or_appdata_path(direct_file_path)
        and not is_safe_temp_appdata_process(direct_process_name, direct_file_path)
    ):
        rule_score += 8
        reasons.append("Office-spawned execution from Temp/AppData path")

    if direct_destination_port in SUSPICIOUS_PORTS:
        rule_score += 20
        add_alert(
            alerts,
            reasons,
            "Suspicious Connection to High-Risk Port",
            f"Connection to suspicious port: {direct_destination_port}",
            "T1071",
            "Command and Control",
        )

    suspicious_connection_hits = 0
    seen_suspicious_ports = set()

    for conn in connections:
        remote_port = normalize_int(conn.get("remote_port"), 0)

        if remote_port in SUSPICIOUS_PORTS:
            suspicious_connection_hits += 1

            if remote_port not in seen_suspicious_ports:
                seen_suspicious_ports.add(remote_port)
                reason = f"Connection to suspicious port: {remote_port}"

                if reason not in reasons:
                    rule_score += 15
                    add_alert(
                        alerts,
                        reasons,
                        "Suspicious Connection to High-Risk Port",
                        reason,
                        "T1071",
                        "Command and Control",
                    )

    if suspicious_connection_hits >= 3:
        rule_score += 8
        reasons.append("Multiple suspicious outbound connections")

    if (
        direct_process_name in {"powershell.exe", "pwsh.exe"}
        and has_encoded_keywords(direct_command_line)
        and direct_destination_port in SUSPICIOUS_PORTS
    ):
        rule_score += 30
        add_alert(
            alerts,
            reasons,
            "Command and Control via PowerShell",
            "Encoded PowerShell communicating over suspicious port",
            "T1071",
            "Command and Control",
        )

    # ============================================================
    # Direct Agent Flags
    # These flags come directly from the Agent behavior detection.
    # They are important because the Agent may detect behavior before
    # the backend extracts it from process/network snapshots.
    # ============================================================

    if powershell_flag == 1:
        rule_score += 35
        add_alert(
            alerts,
            reasons,
            "Suspicious PowerShell Activity",
            "Suspicious PowerShell behavior detected by agent",
            "T1059.001",
            "Execution",
        )

    if temp_execution == 1:
        rule_score += 30
        add_alert(
            alerts,
            reasons,
            "Executable Running from Temp/AppData",
            "Temp/AppData execution detected by agent",
            "T1204",
            "Execution",
        )

    if suspicious_port == 1:
        rule_score += 30
        add_alert(
            alerts,
            reasons,
            "Suspicious Network Port",
            "Suspicious network port detected by agent",
            "T1071",
            "Command and Control",
        )

    if powershell_flag == 1 and suspicious_port == 1:
        rule_score += 25
        add_alert(
            alerts,
            reasons,
            "PowerShell with Suspicious Network Activity",
            "Suspicious PowerShell with network activity",
            "T1071",
            "Command and Control",
        )

    if decoded_command and decoded_suspicious_keywords:
        rule_score += 20
        add_alert(
            alerts,
            reasons,
            "Suspicious Command",
            "Suspicious command execution detected",
            "T1027",
            "Defense Evasion",
        )

    # ============================================================
    # AI Analysis
    # ============================================================
    # Run AI on the main extracted event first. This fixes the case where
    # the suspicious PowerShell/process is not inside top_cpu_processes[:5].
    ai_hits = 0
    max_ai_hits = 3
    seen_ai_signatures = set()

    main_ai_event = {
        "process_name": direct_process_name,
        "command_line": raw_command_line_for_decode or direct_command_line,
        "parent_process": direct_parent_process,
        "file_path": direct_file_path,
        "destination_port": direct_destination_port,
    }

    ai_attack_explanation = None
    ai_attack_category = None
    ai_confidence_level = None
    ai_model_details = {}
    main_ai_result = (
        {"available": False}
        if benign_decoded_command
        else predict_event(main_ai_event)
    )

    if not benign_decoded_command:
        ai_attack_explanation = generate_attack_explanation(
            main_ai_event,
            decoded_command=decoded_command,
            prediction=main_ai_result,
        )

    if main_ai_result.get("available") and main_ai_result.get("prediction") == 1:
        probability = float(main_ai_result.get("probability", 0))
        ai_attack_category = main_ai_result.get("attack_category")
        ai_confidence_level = main_ai_result.get("confidence_level")
        ai_model_details = {
            "model_prediction": main_ai_result.get("model_prediction"),
            "model_probability": main_ai_result.get("model_probability"),
            "severity_model_loaded": main_ai_result.get("severity_model_loaded"),
            "severity_model_prediction": main_ai_result.get("severity_model_prediction"),
            "severity_model_prediction_label": main_ai_result.get("severity_model_prediction_label"),
            "ai_predicted_severity": main_ai_result.get("ai_predicted_severity"),
        }
        current_ai_score = max(10, int(probability * 25))
        ai_score += current_ai_score
        ai_hits += 1

        reasons.append(
                f"AI flagged extracted event (confidence {probability:.2f}, level={ai_confidence_level}, category={ai_attack_category})"        )

        ai_reasons = explain_event(main_ai_event)
        if isinstance(ai_reasons, list):
            reasons.extend(ai_reasons[:6])

        if ai_attack_explanation:
            reasons.append("AI explanation: " + str(ai_attack_explanation))

        alerts.append(
            {
                "alert_type": "AI Suspicious Process Detection",
                "reason": "AI flagged extracted process context",
                "technique": "T1059",
                "tactic": "Execution",
            }
        )

    # Also let AI analyze the decoded command directly. This makes the AI
    # explain the hidden behavior after deobfuscation, not only the raw command.
    if decoded_command and not benign_decoded_command:
        decoded_ai_event = {
            "process_name": direct_process_name,
            "command_line": decoded_command,
            "parent_process": direct_parent_process,
            "file_path": direct_file_path,
            "destination_port": direct_destination_port,
        }
        decoded_ai_result = predict_event(decoded_ai_event)

        if decoded_ai_result.get("available") and decoded_ai_result.get("prediction") == 1:
            probability = float(decoded_ai_result.get("probability", 0))
            current_ai_score = max(5, int(probability * 15))
            ai_score += current_ai_score
            ai_hits += 1

            reasons.append(
                f"AI flagged decoded command (confidence {probability:.2f})"
            )

            decoded_ai_reasons = explain_event(decoded_ai_event)
            if isinstance(decoded_ai_reasons, list):
                reasons.extend(decoded_ai_reasons[:5])

            alerts.append(
                {
                    "alert_type": "AI Decoded Command Analysis",
                    "reason": "AI flagged behavior inside decoded command",
                    "technique": "T1027",
                    "tactic": "Defense Evasion",
                }
            )

    for proc in processes[:10]:
        name = str(proc.get("name", "")).lower()
        cmd = str(proc.get("command_line", "")).lower()
        path = str(proc.get("file_path", "")).lower()
        parent = str(proc.get("parent_process", "")).lower()

        if not should_use_process_fallback(proc):
            continue

        signature = (
            name,
            parent,
            is_temp_or_appdata_path(path),
            has_encoded_keywords(cmd),
            has_download_exec_keywords(cmd),
        )

        if signature in seen_ai_signatures:
            continue

        seen_ai_signatures.add(signature)

        ai_event = {
            "process_name": name,
            "command_line": cmd,
            "parent_process": parent,
            "file_path": path,
            "destination_port": 0,
        }

        ai_result = predict_event(ai_event)

        if ai_result.get("available") and ai_result.get("prediction") == 1:
            probability = float(ai_result.get("probability", 0))
            current_ai_score = max(5, int(probability * 15))
            ai_score += current_ai_score
            ai_hits += 1

            reasons.append(
                f"AI flagged suspicious process: {proc.get('name', 'unknown')} "
                f"(confidence {probability:.2f})"
            )

            ai_reasons = explain_event(ai_event)

            if isinstance(ai_reasons, list):
                reasons.extend(ai_reasons[:4])

            alerts.append(
                {
                    "alert_type": "AI Suspicious Process Detection",
                    "reason": f"AI flagged process {proc.get('name', 'unknown')}",
                    "technique": "T1059",
                    "tactic": "Execution",
                }
            )

            if ai_hits >= max_ai_hits:
                break

    if benign_decoded_command:
        suppressed_alert_types = {
            "AI Decoded Command Analysis",
            "AI Suspicious Process Detection",
            "Command and Control via PowerShell",
            "Encoded PowerShell",
            "Possible PowerShell-Based Command & Control Attack",
            "PowerShell with Suspicious Network Activity",
            "Suspicious Command",
            "Suspicious PowerShell Activity",
        }
        alerts = [
            alert
            for alert in alerts
            if alert.get("alert_type") not in suppressed_alert_types
            and not alert.get("correlated")
        ]
        add_alert(
            alerts,
            reasons,
            "PowerShell EncodedCommand Reviewed",
            "Decoded command matches a known internal command-safety parser; no harmful action was observed",
            "T1059.001",
            "Execution",
        )
        rule_score = min(rule_score, 25)
        ai_score = 0

    rule_score = min(rule_score, 100)
    ai_score = min(ai_score, 100)
    if rule_score > 0 and ai_score > 0:
        final_score = min(int(((rule_score + ai_score) / 2) + 0.5), 100)
    else:
        final_score = min(rule_score + ai_score, 100)

    reasons = dedupe_keep_order(reasons)
    alerts = dedupe_alerts_keep_order(alerts)

    if alerts:
        primary_alert = max(
            alerts,
            key=lambda x: get_alert_priority(x["alert_type"]),
        )
    else:
        primary_alert = {
            "alert_type": (
                "General Suspicious Activity" if final_score > 30 else "Informational"
            ),
            "reason": reasons[0] if reasons else "No specific reason",
            "technique": None,
            "tactic": None,
        }

    top_reason = primary_alert.get("reason") or (
        reasons[0] if reasons else "No specific reason"
    )

    detection_source = infer_detection_source(rule_score, ai_score)

    if primary_alert["alert_type"] in SYSTEM_ALERT_TYPES:
        event_category = "system_resource"
    else:
        event_category = infer_event_category(
            primary_alert["alert_type"],
            cpu=cpu,
            memory=memory,
            process_count=process_count,
        )

    severity = calculate_severity(final_score)

    attack_confidence = infer_attack_confidence(
        final_score=final_score,
        rule_score=rule_score,
        ai_score=ai_score,
        decoded_success=bool(decoded_command),
        correlated_alerts=[a for a in alerts if a.get("correlated")],
        reasons=reasons,
    )
    attack_summary = build_attack_summary(
        primary_alert=primary_alert,
        severity=severity,
        confidence=attack_confidence,
        ctx=detection_context,
        attack_chain=attack_chain,
    )

    recommended_action = recommend_response_action(
        severity=severity,
        alert_type=primary_alert["alert_type"],
        ctx=detection_context,
    )

    return {
        "risk_score": final_score,
        "rule_score": rule_score,
        "ai_score": ai_score,
        "risk_reasons": reasons,
        "top_reason": top_reason,
        "alert_type": primary_alert["alert_type"],
        "mitre_technique": primary_alert["technique"],
        "mitre_tactic": primary_alert["tactic"],
        "detection_source": detection_source,
        "event_category": event_category,
        "severity": severity,
        "alerts": alerts,
        "decoded_command": decoded_command,
        "decode_success": bool(decoded_command),
        "decode_method": decode_method,
        "decode_layers": decode_layers,
        "decoded_suspicious_keywords": decoded_suspicious_keywords,
        "ai_attack_explanation": ai_attack_explanation,
        "attack_confidence": attack_confidence,
        "attack_summary": attack_summary,
        "attack_chain": attack_chain,
        "correlated_alerts": [a for a in alerts if a.get("correlated")],
        "correlation_bonus_score": correlation_bonus_score,
        # Agent flags returned for debugging / DB / dashboard use
        "powershell_flag": powershell_flag,
        "temp_execution": temp_execution,
        "suspicious_port": suspicious_port,
        "connections_count": connections_count,
        "debug_extracted": extracted,
        "ai_attack_category": ai_attack_category,
        "ai_confidence_level": ai_confidence_level,
        "ai_model_details": ai_model_details,
        "recommended_action": recommended_action,
    }
