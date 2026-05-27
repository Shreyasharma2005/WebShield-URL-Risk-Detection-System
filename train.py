import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

from utils import extract_features

df = pd.read_csv("data/phishing.csv")

X = df["url"].apply(extract_features).tolist()
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

rf = RandomForestClassifier(random_state=42)
lr = LogisticRegression(max_iter=1000)

rf.fit(X_train, y_train)
lr.fit(X_train, y_train)

rf_pred = rf.predict(X_test)
lr_pred = lr.predict(X_test)

rf_acc = accuracy_score(y_test, rf_pred)
lr_acc = accuracy_score(y_test, lr_pred)

print("\n===== Random Forest Results =====")
print(classification_report(y_test, rf_pred))

print("\n===== Logistic Regression Results =====")
print(classification_report(y_test, lr_pred))

print("\n===== Model Comparison =====")
print("Random Forest Accuracy:", rf_acc)
print("Logistic Regression Accuracy:", lr_acc)

if rf_acc >= lr_acc:
    best_model = rf
    best_model_name = "Random Forest"
else:
    best_model = lr
    best_model_name = "Logistic Regression"

joblib.dump(best_model, "models/model.pkl")

print("\nBest Model Selected:", best_model_name)
print("Model saved successfully!")