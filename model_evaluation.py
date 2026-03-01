"""
╔══════════════════════════════════════════════════════════════╗
║  IoT DoS Detection — LightGBM Model Evaluation             ║
║  For Paper: 80/20 Stratified Split Results                  ║
╚══════════════════════════════════════════════════════════════╝

Generates:
  1. Dataset summary (class distribution)
  2. Confusion matrix heatmap
  3. Classification report (Accuracy, Precision, Recall, F1)
  4. ROC curve + AUC score
  5. Precision-Recall curve + AP score
  6. Feature importance (gain-based)
  7. 5-Fold stratified cross-validation
  8. Inference time benchmark (edge-device relevance)

All figures saved to:  results/ folder (PNG, 300 DPI)
"""

import os
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import lightgbm as lgb
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    accuracy_score, precision_score, recall_score, f1_score
)
import joblib

# ─── Configuration ──────────────────────────────────────────
DATA_PATH = r"C:\Users\ASUS\Tanush\Major_Project\data\unsw_nb15_train.csv"
MODEL_PATH = r"C:\Users\ASUS\Tanush\Major_Project\dos_lightgbm_model.pkl"
RESULTS_DIR = r"C:\Users\ASUS\Tanush\Major_Project\results"
os.makedirs(RESULTS_DIR, exist_ok=True)

DOS_FEATURES = [
    'ct_srv_src', 'ct_dst_ltm', 'ct_srv_dst',
    'synack', 'ackdat', 'tcprtt',
    'dmean', 'dpkts',
    'rate', 'sload', 'sbytes'
]

# Nice labels for figures
FEATURE_LABELS = {
    'ct_srv_src': 'Conn to Same Srv (src)',
    'ct_dst_ltm': 'Conn to Same Dst',
    'ct_srv_dst': 'Conn to Same Srv (dst)',
    'synack': 'SYN-ACK RTT',
    'ackdat': 'ACK-DAT RTT',
    'tcprtt': 'TCP RTT',
    'dmean': 'Dst Pkt Size (mean)',
    'dpkts': 'Dst Packets',
    'rate': 'Packet Rate',
    'sload': 'Src Byte Rate',
    'sbytes': 'Src Bytes'
}

plt.style.use('seaborn-v0_8-whitegrid')
sns.set_palette("deep")

# ═══════════════════════════════════════════════════════════
# 1. LOAD & PREPARE DATASET
# ═══════════════════════════════════════════════════════════
print("=" * 60)
print("1. LOADING DATASET")
print("=" * 60)

df = pd.read_csv(DATA_PATH)

# Normal traffic
normal = df[df['attack_cat'] == 'Normal']

# High-rate DoS only (matches SYN flood simulation)
dos = df[
    (df['attack_cat'] == 'DoS') &
    (df['rate'] > 1000) &
    (df['sload'] > 1e5) &
    (df['dpkts'] < 10) &
    (df['dmean'] < 10)
]

df_filtered = pd.concat([normal, dos], ignore_index=True)
df_filtered['target'] = df_filtered['attack_cat'].map({'Normal': 0, 'DoS': 1})

X = df_filtered[DOS_FEATURES]
y = df_filtered['target']

print(f"Total samples:  {len(df_filtered):,}")
print(f"  Normal (0):   {(y == 0).sum():,} ({(y == 0).mean()*100:.1f}%)")
print(f"  DoS (1):      {(y == 1).sum():,} ({(y == 1).mean()*100:.1f}%)")

# ═══════════════════════════════════════════════════════════
# 2. TRAIN-TEST SPLIT (80/20 Stratified)
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("2. TRAIN-TEST SPLIT (80/20 Stratified)")
print("=" * 60)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

print(f"Training set:   {len(X_train):,} samples")
print(f"  Normal: {(y_train == 0).sum():,}  |  DoS: {(y_train == 1).sum():,}")
print(f"Test set:       {len(X_test):,} samples")
print(f"  Normal: {(y_test == 0).sum():,}  |  DoS: {(y_test == 1).sum():,}")

# ═══════════════════════════════════════════════════════════
# 3. TRAIN MODEL
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("3. TRAINING LightGBM MODEL")
print("=" * 60)

model = lgb.LGBMClassifier(
    n_estimators=300,
    learning_rate=0.05,
    max_depth=6,
    num_leaves=31,
    class_weight='balanced',
    random_state=42,
    verbose=-1
)

t_start = time.time()
model.fit(X_train, y_train)
train_time = time.time() - t_start
print(f"Training time:  {train_time:.2f}s")
print(f"Num trees:      {model.n_estimators}")
print(f"Max depth:      {model.max_depth}")
print(f"Num leaves:     {model.num_leaves}")

# Save model
joblib.dump(model, MODEL_PATH)
print(f"Model saved:    {MODEL_PATH}")

# ═══════════════════════════════════════════════════════════
# 4. PREDICTIONS
# ═══════════════════════════════════════════════════════════
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

# ═══════════════════════════════════════════════════════════
# 5. CLASSIFICATION REPORT
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("4. CLASSIFICATION REPORT")
print("=" * 60)

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec  = recall_score(y_test, y_pred)
f1   = f1_score(y_test, y_pred)

print(f"\n  Accuracy:   {acc*100:.2f}%")
print(f"  Precision:  {prec*100:.2f}%")
print(f"  Recall:     {rec*100:.2f}%")
print(f"  F1-Score:   {f1*100:.2f}%")
print()
print(classification_report(y_test, y_pred, target_names=['Normal', 'DoS']))

# Save metrics to CSV for paper table
metrics_df = pd.DataFrame({
    'Metric': ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC-ROC'],
    'Score': [acc, prec, rec, f1, auc(*roc_curve(y_test, y_proba)[:2])]
})
metrics_df['Score (%)'] = (metrics_df['Score'] * 100).round(2)
metrics_df.to_csv(os.path.join(RESULTS_DIR, 'metrics_summary.csv'), index=False)
print(f"Metrics saved to: results/metrics_summary.csv")

# ═══════════════════════════════════════════════════════════
# 6. CONFUSION MATRIX HEATMAP
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("5. CONFUSION MATRIX")
print("=" * 60)

cm = confusion_matrix(y_test, y_pred)
print(cm)

fig, ax = plt.subplots(figsize=(7, 6))
sns.heatmap(
    cm, annot=True, fmt='d', cmap='Blues',
    xticklabels=['Normal', 'DoS'],
    yticklabels=['Normal', 'DoS'],
    annot_kws={'size': 18},
    linewidths=1, linecolor='white',
    ax=ax
)
ax.set_xlabel('Predicted Label', fontsize=14, labelpad=10)
ax.set_ylabel('True Label', fontsize=14, labelpad=10)
ax.set_title('Confusion Matrix — LightGBM DoS Detection', fontsize=15, pad=15)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, 'confusion_matrix.png'), dpi=300, bbox_inches='tight')
plt.close()
print("Saved: results/confusion_matrix.png")

# ═══════════════════════════════════════════════════════════
# 7. ROC CURVE
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("6. ROC CURVE")
print("=" * 60)

fpr, tpr, _ = roc_curve(y_test, y_proba)
roc_auc = auc(fpr, tpr)
print(f"AUC-ROC: {roc_auc:.4f}")

fig, ax = plt.subplots(figsize=(7, 6))
ax.plot(fpr, tpr, color='#2c3e50', lw=2.5, label=f'LightGBM (AUC = {roc_auc:.4f})')
ax.plot([0, 1], [0, 1], color='#bdc3c7', lw=1.5, linestyle='--', label='Random (AUC = 0.5)')
ax.fill_between(fpr, tpr, alpha=0.15, color='#3498db')
ax.set_xlabel('False Positive Rate', fontsize=13)
ax.set_ylabel('True Positive Rate', fontsize=13)
ax.set_title('ROC Curve — LightGBM DoS Detection', fontsize=15, pad=15)
ax.legend(loc='lower right', fontsize=12)
ax.set_xlim([-0.02, 1.02])
ax.set_ylim([-0.02, 1.02])
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, 'roc_curve.png'), dpi=300, bbox_inches='tight')
plt.close()
print("Saved: results/roc_curve.png")

# ═══════════════════════════════════════════════════════════
# 8. PRECISION-RECALL CURVE
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("7. PRECISION-RECALL CURVE")
print("=" * 60)

precision_arr, recall_arr, _ = precision_recall_curve(y_test, y_proba)
ap = average_precision_score(y_test, y_proba)
print(f"Average Precision (AP): {ap:.4f}")

fig, ax = plt.subplots(figsize=(7, 6))
ax.plot(recall_arr, precision_arr, color='#e74c3c', lw=2.5, label=f'LightGBM (AP = {ap:.4f})')
ax.fill_between(recall_arr, precision_arr, alpha=0.15, color='#e74c3c')
ax.set_xlabel('Recall', fontsize=13)
ax.set_ylabel('Precision', fontsize=13)
ax.set_title('Precision-Recall Curve — LightGBM DoS Detection', fontsize=15, pad=15)
ax.legend(loc='lower left', fontsize=12)
ax.set_xlim([-0.02, 1.02])
ax.set_ylim([-0.02, 1.02])
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, 'precision_recall_curve.png'), dpi=300, bbox_inches='tight')
plt.close()
print("Saved: results/precision_recall_curve.png")

# ═══════════════════════════════════════════════════════════
# 9. FEATURE IMPORTANCE
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("8. FEATURE IMPORTANCE")
print("=" * 60)

importance = model.feature_importances_
feat_imp = pd.DataFrame({
    'Feature': DOS_FEATURES,
    'Label': [FEATURE_LABELS.get(f, f) for f in DOS_FEATURES],
    'Importance': importance
}).sort_values('Importance', ascending=True)

print(feat_imp[['Feature', 'Importance']].to_string(index=False))
feat_imp.to_csv(os.path.join(RESULTS_DIR, 'feature_importance.csv'), index=False)

fig, ax = plt.subplots(figsize=(9, 6))
colors = sns.color_palette("viridis", len(feat_imp))
ax.barh(feat_imp['Label'], feat_imp['Importance'], color=colors, edgecolor='white', height=0.65)
ax.set_xlabel('Split Count (Importance)', fontsize=13)
ax.set_title('Feature Importance — LightGBM DoS Detection', fontsize=15, pad=15)
for i, (val, name) in enumerate(zip(feat_imp['Importance'], feat_imp['Label'])):
    ax.text(val + max(importance) * 0.01, i, f'{val}', va='center', fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(RESULTS_DIR, 'feature_importance.png'), dpi=300, bbox_inches='tight')
plt.close()
print("Saved: results/feature_importance.png")

# ═══════════════════════════════════════════════════════════
# 10. 5-FOLD STRATIFIED CROSS-VALIDATION
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("9. 5-FOLD STRATIFIED CROSS-VALIDATION")
print("=" * 60)

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scoring = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']

cv_results = cross_validate(
    lgb.LGBMClassifier(
        n_estimators=300, learning_rate=0.05, max_depth=6,
        num_leaves=31, class_weight='balanced', random_state=42, verbose=-1
    ),
    X, y, cv=cv, scoring=scoring, return_train_score=False
)

print(f"\n{'Metric':<15} {'Mean':>8} {'± Std':>8}")
print("-" * 35)
for metric in scoring:
    key = f'test_{metric}'
    mean = cv_results[key].mean()
    std = cv_results[key].std()
    print(f"{metric:<15} {mean*100:>7.2f}% {std*100:>7.2f}%")

# Save CV results
cv_df = pd.DataFrame({
    'Metric': scoring,
    'Mean (%)': [cv_results[f'test_{m}'].mean() * 100 for m in scoring],
    'Std (%)': [cv_results[f'test_{m}'].std() * 100 for m in scoring],
})
for fold_i in range(5):
    for m in scoring:
        cv_df.loc[cv_df['Metric'] == m, f'Fold {fold_i+1} (%)'] = \
            cv_results[f'test_{m}'][fold_i] * 100
cv_df.to_csv(os.path.join(RESULTS_DIR, 'cross_validation.csv'), index=False)
print("\nSaved: results/cross_validation.csv")

# ═══════════════════════════════════════════════════════════
# 11. INFERENCE TIME BENCHMARK
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("10. INFERENCE TIME BENCHMARK")
print("=" * 60)

# Single sample inference (edge device relevance)
sample = X_test.iloc[[0]]
times = []
for _ in range(1000):
    t0 = time.perf_counter()
    model.predict_proba(sample)
    t1 = time.perf_counter()
    times.append((t1 - t0) * 1000)  # ms

times = np.array(times)
print(f"Single-sample inference (1000 runs):")
print(f"  Mean:   {times.mean():.3f} ms")
print(f"  Median: {np.median(times):.3f} ms")
print(f"  p95:    {np.percentile(times, 95):.3f} ms")
print(f"  p99:    {np.percentile(times, 99):.3f} ms")

# Batch inference
batch_sizes = [1, 10, 50, 100, 500]
print(f"\nBatch inference benchmarks:")
print(f"{'Batch':<10} {'Mean (ms)':<12} {'Per-sample (ms)'}")
print("-" * 40)
for bs in batch_sizes:
    batch = X_test.iloc[:bs]
    batch_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        model.predict_proba(batch)
        t1 = time.perf_counter()
        batch_times.append((t1 - t0) * 1000)
    mean_ms = np.mean(batch_times)
    print(f"{bs:<10} {mean_ms:<12.3f} {mean_ms/bs:.3f}")

# Estimated RPi5 inference (3x slowdown from ARM benchmarks)
rpi5_mean = times.mean() * 3.0
print(f"\nEstimated Raspberry Pi 5 (ARM Cortex-A76, 3x factor):")
print(f"  Single-sample: ~{rpi5_mean:.2f} ms")
feasible = 'YES' if rpi5_mean < 100 else 'NO'
print(f"  Feasible for real-time: {feasible} (threshold: 100ms)")

# Model size
model_size = os.path.getsize(MODEL_PATH)
print(f"\nModel file size: {model_size / 1024:.1f} KB ({model_size / (1024*1024):.2f} MB)")
print(f"RPi5 RAM budget: 512 MB -> Model uses {model_size / (512*1024*1024) * 100:.3f}% of budget")

# ═══════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("RESULTS SUMMARY (for paper)")
print("=" * 60)
print(f"""
+--------------------------------------------------+
|  Model: LightGBM (300 trees, depth=6, 31 leaves) |
|  Dataset: UNSW-NB15 (filtered high-rate DoS)      |
|  Split: 80/20 stratified, random_state=42         |
+--------------------------------------------------+
|  Accuracy:       {acc*100:.2f}%                          |
|  Precision:      {prec*100:.2f}%                          |
|  Recall:         {rec*100:.2f}%                          |
|  F1-Score:       {f1*100:.2f}%                          |
|  AUC-ROC:        {roc_auc:.4f}                          |
|  Avg Precision:  {ap:.4f}                          |
+--------------------------------------------------+
|  Inference:      {times.mean():.2f} ms (laptop)               |
|  Est. RPi5:      {rpi5_mean:.2f} ms                        |
|  Model Size:     {model_size/1024:.1f} KB                        |
+--------------------------------------------------+

Files saved in results/:
  - confusion_matrix.png
  - roc_curve.png
  - precision_recall_curve.png
  - feature_importance.png
  - metrics_summary.csv
  - feature_importance.csv
  - cross_validation.csv
""")
