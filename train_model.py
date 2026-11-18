import pandas as pd
import numpy as np
import pickle
import os
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

def train_and_export():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_path = os.path.join(base_dir, 'phishing.csv')
    pickle_dir = os.path.join(base_dir, 'pickle')
    os.makedirs(pickle_dir, exist_ok=True)

    print(f"Loading dataset from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"Dataset shape: {df.shape}")

    # Drop Index and target column 'class'
    X = df.drop(['Index', 'class'], axis=1)
    y = df['class']

    feature_names = list(X.columns)
    print(f"Total features: {len(feature_names)}")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    # Models dictionary
    models = {
        "Gradient Boosting Classifier": GradientBoostingClassifier(max_depth=4, learning_rate=0.7, random_state=42),
        "Random Forest Classifier": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "MLP Classifier": MLPClassifier(alpha=0.001, hidden_layer_sizes=([100, 100, 100]), max_iter=500, random_state=42)
    }

    metrics_comparison = {}
    best_model_name = "Gradient Boosting Classifier"
    best_accuracy = 0
    best_model = None

    for name, clf in models.items():
        print(f"Training {name}...")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, pos_label=1)
        rec = recall_score(y_test, y_pred, pos_label=1)
        f1 = f1_score(y_test, y_pred, pos_label=1)
        cm = confusion_matrix(y_test, y_pred).tolist()

        metrics_comparison[name] = {
            "accuracy": round(float(acc) * 100, 2),
            "precision": round(float(prec) * 100, 2),
            "recall": round(float(rec) * 100, 2),
            "f1_score": round(float(f1) * 100, 2),
            "confusion_matrix": cm
        }
        print(f"  -> {name} Accuracy: {acc * 100:.2f}% | F1: {f1 * 100:.2f}%")

        if name == "Gradient Boosting Classifier" or acc > best_accuracy:
            best_accuracy = acc
            best_model = clf

    # Extract feature importances from GBC
    gbc_model = models["Gradient Boosting Classifier"]
    feature_importances = []
    if hasattr(gbc_model, 'feature_importances_'):
        for fname, imp in zip(feature_names, gbc_model.feature_importances_):
            feature_importances.append({"feature": fname, "importance": round(float(imp), 4)})
        feature_importances.sort(key=lambda x: x["importance"], reverse=True)

    # Save primary model as model.pkl exactly as original repo
    model_path = os.path.join(pickle_dir, 'model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(gbc_model, f)
    print(f"Primary model saved to {model_path}")

    # Save metadata & comparison metrics for frontend dashboards
    meta_info = {
        "dataset_rows": int(len(df)),
        "dataset_cols": int(df.shape[1]),
        "feature_names": feature_names,
        "models_evaluated": metrics_comparison,
        "primary_model": "Gradient Boosting Classifier",
        "primary_accuracy": metrics_comparison["Gradient Boosting Classifier"]["accuracy"],
        "feature_importances": feature_importances,
        "label_distribution": {
            "legitimate": int((y == 1).sum()),
            "phishing": int((y == -1).sum())
        }
    }

    meta_path = os.path.join(pickle_dir, 'meta.pkl')
    with open(meta_path, 'wb') as f:
        pickle.dump(meta_info, f)
    print(f"Training metadata saved to {meta_path}")
    print("Training pipeline finished successfully!")

if __name__ == '__main__':
    train_and_export()
