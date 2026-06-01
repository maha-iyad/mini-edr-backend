import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

DATASET_PATH = "ai_training_dataset.csv"
MODEL_PATH = "model.joblib"
SEVERITY_MODEL_PATH = "severity_model.joblib"

columns = [
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
    "label",
    "severity_label",
]

SEVERITY_NAMES = {
    0: "Low",
    1: "Medium",
    2: "High",
    3: "Critical",
}


def create_seed_dataset():
    data = [
        # Low / benign
        [0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 60, 0, 0, 0, 0, 0, 0, 0, 0],

        # Medium
        [1, 1, 0, 0, 0, 140, 0, 0, 0, 0, 0, 1, 1, 1],
        [0, 1, 0, 1, 0, 150, 0, 0, 0, 0, 1, 1, 1, 1],
        [0, 0, 0, 1, 1, 120, 0, 0, 0, 0, 0, 1, 1, 1],
        [0, 1, 0, 0, 1, 130, 0, 0, 0, 0, 1, 1, 1, 1],

        # High
        [1, 1, 1, 0, 0, 220, 0, 0, 0, 1, 1, 1, 1, 2],
        [1, 1, 0, 1, 1, 260, 0, 0, 0, 1, 1, 1, 1, 2],
        [0, 1, 0, 1, 1, 240, 1, 0, 0, 1, 1, 1, 1, 2],
        [0, 1, 1, 0, 1, 230, 1, 0, 0, 1, 1, 1, 1, 2],

        # Critical
        [1, 1, 1, 1, 1, 350, 0, 0, 1, 1, 1, 1, 1, 3],
        [0, 1, 1, 1, 1, 330, 1, 0, 1, 1, 1, 1, 1, 3],
        [1, 1, 0, 1, 1, 420, 0, 0, 1, 1, 1, 1, 1, 3],
        [0, 1, 0, 1, 1, 390, 1, 1, 1, 1, 1, 1, 1, 3],
    ]

    df = pd.DataFrame(data, columns=columns)
    df.to_csv(DATASET_PATH, index=False)
    return df


def train_binary_model(df):
    X = df.drop(["label", "severity_label"], axis=1)
    y = df["label"]

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(X, y)
    joblib.dump(model, MODEL_PATH)

    print("\nBinary Threat Detection Model")
    print("-" * 60)
    print("Cross Validation:", cross_val_score(model, X, y, cv=3))
    return model


def train_severity_model(df):
    X = df.drop(["label", "severity_label"], axis=1)
    y = df["severity_label"]

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=8,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(X, y)
    joblib.dump(model, SEVERITY_MODEL_PATH)

    print("\nSeverity Classification Model")
    print("-" * 60)
    print("Classes:", SEVERITY_NAMES)
    print("Cross Validation:", cross_val_score(model, X, y, cv=3))
    return model


def main():
    df = create_seed_dataset()

    print("=" * 60)
    print("Mini EDR Advanced AI Training")
    print("=" * 60)
    print("Dataset rows:", len(df))
    print("Features:", len(df.drop(["label", "severity_label"], axis=1).columns))

    binary_model = train_binary_model(df)
    severity_model = train_severity_model(df)

    X = df.drop(["label", "severity_label"], axis=1)

    print("\nSample Predictions")
    print("-" * 60)
    print("Threat predictions:", binary_model.predict(X).tolist())
    print("Severity predictions:", severity_model.predict(X).tolist())

    print("=" * 60)
    print(f"Saved: {MODEL_PATH}")
    print(f"Saved: {SEVERITY_MODEL_PATH}")
    print(f"Saved: {DATASET_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    main()