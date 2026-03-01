import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# -------------------------------
# Load dataset
# -------------------------------
df = pd.read_csv(
    r"C:\Users\ASUS\Tanush\Major_Project\data\unsw_nb15_train.csv"
)

# -------------------------------
# Select Normal traffic
# -------------------------------
normal = df[df['attack_cat'] == 'Normal']

# -------------------------------
# Select HIGH-RATE DoS traffic only
# (aligns with SYN flood behavior)
# -------------------------------
dos = df[
    (df['attack_cat'] == 'DoS') &
    (df['rate'] > 1000) &
    (df['sload'] > 1e5) &
    (df['dpkts'] < 10) &
    (df['dmean'] < 10)
]

# -------------------------------
# Combine filtered dataset
# -------------------------------
df_filtered = pd.concat([normal, dos], ignore_index=True)

# Binary target
df_filtered['target'] = df_filtered['attack_cat'].map(
    {'Normal': 0, 'DoS': 1}
)

print("Dataset after filtering:")
print(df_filtered['target'].value_counts())

# -------------------------------
# Feature set
# -------------------------------
DOS_FEATURES = [
    'ct_srv_src', 'ct_dst_ltm', 'ct_srv_dst',
    'synack', 'ackdat', 'tcprtt',
    'dmean', 'dpkts',
    'rate', 'sload', 'sbytes'
]

X = df_filtered[DOS_FEATURES]
y = df_filtered['target']

# -------------------------------
# Train-test split
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# -------------------------------
# LightGBM model
# -------------------------------
model = lgb.LGBMClassifier(
    n_estimators=300,
    learning_rate=0.05,
    max_depth=6,
    num_leaves=31,
    class_weight='balanced',
    random_state=42
)

model.fit(X_train, y_train)

# -------------------------------
# Save model
# -------------------------------
joblib.dump(model, "dos_lightgbm_model.pkl")
print("\nModel saved as dos_lightgbm_model.pkl")

# -------------------------------
# Evaluation
# -------------------------------
y_pred = model.predict(X_test)

print("\n===== DoS LightGBM Results =====")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# -------------------------------
# Feature statistics (for sanity)
# -------------------------------
print("\nFeature Statistics (Mean / Std):")
print(X.describe().loc[['mean', 'std']])
