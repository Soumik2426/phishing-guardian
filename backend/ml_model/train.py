import pandas as pd
import numpy as np
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from datasets import load_dataset
from ml_model.features import extract_features


# ======================================
# 1. LOAD LOCAL PHISHING DATASETS
# ======================================

phishing_files = [
    "ml_model/data/Phishing URLs.csv",
    "ml_model/data/PhiUSIIL_Phishing_URL_Dataset.csv",
    "ml_model/data/url_features_extracted1.csv"
]

local_phish_urls = []

for file in phishing_files:
    df = pd.read_csv(file)
    url_columns = [c for c in df.columns if "url" in c.lower()]
    if not url_columns:
        continue
    local_phish_urls.extend(df[url_columns[0]].dropna().tolist())

print("Local phishing URLs:", len(local_phish_urls))


# ======================================
# 2. LOAD LEGITIMATE DATASET
# ======================================

legit_df = pd.read_csv("ml_model/data/URL dataset.csv")
url_columns = [c for c in legit_df.columns if "url" in c.lower()]
legit_urls = legit_df[url_columns[0]].dropna().tolist()

print("Legitimate URLs:", len(legit_urls))


# ======================================
# 3. STREAM HUGGINGFACE PHISHING
# ======================================

print("Streaming HuggingFace dataset...")

hf_dataset = load_dataset(
    "phreshphish/phreshphish",
    split="train",
    streaming=True
)

hf_urls = []

for i, item in enumerate(hf_dataset):
    if "url" in item:
        hf_urls.append(item["url"])
    if i >= 10000:  # limit for stability
        break

print("HuggingFace phishing URLs:", len(hf_urls))


# ======================================
# 4. CREATE DATAFRAME
# ======================================

df_phish = pd.DataFrame({
    "url": local_phish_urls + hf_urls,
    "label": 1
})

df_legit = pd.DataFrame({
    "url": legit_urls,
    "label": 0
})

df = pd.concat([df_phish, df_legit])
df = df.drop_duplicates(subset="url")

# Balance dataset
min_count = min(
    df[df.label == 0].shape[0],
    df[df.label == 1].shape[0]
)

df_balanced = pd.concat([
    df[df.label == 0].sample(min_count, random_state=42),
    df[df.label == 1].sample(min_count, random_state=42)
])

print("Balanced dataset size:", df_balanced.shape)


# ======================================
# 5. FEATURE EXTRACTION
# ======================================

print("Extracting features...")

X = df_balanced["url"].apply(extract_features).tolist()
y = df_balanced["label"].tolist()

X = np.array(X)
y = np.array(y)


# ======================================
# 6. TRAIN / TEST SPLIT
# ======================================

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)


# ======================================
# 7. TRAIN MODEL (Improved Recall)
# ======================================

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=15,
    class_weight={0: 1, 1: 1.3},  # prioritize phishing
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)


# ======================================
# 8. THRESHOLD TUNING (Improve Recall)
# ======================================

probs = model.predict_proba(X_test)[:, 1]

# Lower threshold from 0.5 to 0.45
y_pred = (probs > 0.45).astype(int)

print("\nClassification Report (Threshold = 0.45):\n")
print(classification_report(y_test, y_pred))


# ======================================
# 9. SAVE MODEL
# ======================================

joblib.dump(model, "ml_model/phishing_model.pkl")

print("\nModel saved successfully!")
