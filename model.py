import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier 
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline

# 1. Load datasets
df_normal = pd.read_csv("normal_dataset.csv")
df_malicious = pd.read_csv("malicious_dataset.csv")

df_normal['label'] = 'normal'
df_malicious['label'] = 'scan'

df = pd.concat([df_normal, df_malicious], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# 2. Drop unnecessary columns
drop_cols = [
    "eth.type","ip.version","ip.hdr_len","ip.tos","ip.id","ip.flags.rb",
    "ip.flags.mf","ip.frag_offset","frame_info.number","frame_info.encap_type",
    "tcp.len","tcp.urgent_pointer","tcp.options.mss_val","frame_info.time",
    "ip.dst","ip.src","frame_info.time_epoch"
]

df = df.drop(columns=[col for col in drop_cols if col in df.columns])

df = df.dropna(subset=['tcp.srcport','ip.ttl'])

# Convert hex → integer
hex_cols = ["tcp.checksum","tcp.flags","ip.dsfield","ip.checksum","ip.flags"]
for col in hex_cols:
    if col in df.columns:
        df[col] = df[col].apply(
            lambda x: int(str(x), 16) if isinstance(x, str) else x
        )

# FORCE integer type (IMPORTANT FIX)
if "tcp.flags" in df.columns:
    df["tcp.flags"] = df["tcp.flags"].astype("Int64")


# Encode labels
encoder = LabelEncoder()
df['label'] = encoder.fit_transform(df['label'])  # normal=0, scan=1

# 3. Split features & target
X = df.drop("label", axis=1)
y = df["label"]

pd.Series(X.columns).to_csv("feature_list.csv", index=False)

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y
)

scaler = StandardScaler()
smote = SMOTE(random_state=42)

models = {
    "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
    "Decision Tree": DecisionTreeClassifier(max_depth=4, min_samples_leaf=6, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42),
    
}

def evaluate_model(model, X_train, y_train, X_test, y_test):
    pipeline = ImbPipeline([
        ('scaler', scaler),
        ('smote', smote),
        ('classifier', model)
    ])
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print(f"==== {model.__class__.__name__} ====")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall: {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")

    cm = confusion_matrix(y_test, y_pred)
    
    plt.figure(figsize=(6,4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False)
    plt.title(f'Confusion Matrix - {model.__class__.__name__}', fontsize=14)
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.show()

    return pipeline

trained_models = {}
for name, model in models.items():
    trained_models[name] = evaluate_model(model, X_train, y_train, X_test, y_test)

import joblib
joblib.dump(trained_models["Random Forest"], "portscan_rf.pkl")
print("Model saved!")
