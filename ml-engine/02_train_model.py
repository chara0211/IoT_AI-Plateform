"""
AI-Driven IoT Security Platform
Isolation Forest Model Training

This script trains the Isolation Forest anomaly detection model
and evaluates its performance.

Author: Wafaa EL HADCHI
Date: November 2025
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

print("=" * 80)
print("ISOLATION FOREST - MODEL TRAINING")
print("=" * 80)

# ============================================================================
# 1. LOAD PREPROCESSED DATA
# ============================================================================
print("\n1. Loading preprocessed data...")

X_train = pd.read_csv('data/X_train_scaled.csv')
X_test = pd.read_csv('data/X_test_scaled.csv')
y_train = pd.read_csv('data/y_train.csv')['label']
y_test = pd.read_csv('data/y_test.csv')['label']

print(f"   Training set: {X_train.shape}")
print(f"   Test set: {X_test.shape}")

# ============================================================================
# 2. PREPARE TRAINING DATA (NORMAL ONLY)
# ============================================================================
print("\n2. Preparing training data (normal samples only)...")

# Isolation Forest is UNSUPERVISED - train on normal data only
X_train_normal = X_train[y_train == 'Normal']
print(f"   Normal samples for training: {len(X_train_normal):,}")

# ============================================================================
# 3. TRAIN ISOLATION FOREST
# ============================================================================
print("\n3. Training Isolation Forest...")
print("   Parameters:")
print("   - contamination: 0.21 (expect 21% anomalies)")
print("   - n_estimators: 100 (decision trees)")
print("   - max_samples: auto")
print("   - random_state: 42")

iso_forest = IsolationForest(
    contamination=0.21,      # Based on your dataset (21% anomalies)
    n_estimators=100,        # 100 decision trees
    max_samples='auto',      # Automatic sample size
    random_state=42,         # Reproducibility
    n_jobs=-1,               # Use all CPU cores
    verbose=0
)

# Train the model
print("\n   Training in progress...")
iso_forest.fit(X_train_normal)
print("   Training complete!")

# ============================================================================
# 4. MAKE PREDICTIONS
# ============================================================================
print("\n4. Making predictions on test set...")

# Predict on test set
y_pred = iso_forest.predict(X_test)  # -1 = anomaly, 1 = normal
y_pred_labels = ['Anomaly' if p == -1 else 'Normal' for p in y_pred]

# Get anomaly scores (lower = more anomalous)
anomaly_scores = iso_forest.decision_function(X_test)
print(f"   Predictions completed for {len(y_pred):,} samples")

# ============================================================================
# 5. EVALUATE MODEL PERFORMANCE
# ============================================================================
print("\n5. Evaluating model performance...")

# Convert multi-class labels to binary (Normal vs Anomaly)
y_test_binary = ['Normal' if label == 'Normal' else 'Anomaly' for label in y_test]

# Calculate metrics
accuracy = accuracy_score(y_test_binary, y_pred_labels)
precision = precision_score(y_test_binary, y_pred_labels, pos_label='Anomaly')
recall = recall_score(y_test_binary, y_pred_labels, pos_label='Anomaly')
f1 = f1_score(y_test_binary, y_pred_labels, pos_label='Anomaly')

print("\n" + "=" * 80)
print("MODEL PERFORMANCE METRICS")
print("=" * 80)
print(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")

# Confusion Matrix
print("\n" + "=" * 80)
print("CONFUSION MATRIX")
print("=" * 80)
cm = confusion_matrix(y_test_binary, y_pred_labels, labels=['Normal', 'Anomaly'])
print("\n                Predicted")
print("              Normal  Anomaly")
print(f"Actual Normal   {cm[0][0]:5d}   {cm[0][1]:5d}")
print(f"       Anomaly  {cm[1][0]:5d}   {cm[1][1]:5d}")

# Calculate rates
tn, fp, fn, tp = cm.ravel()
false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0

print(f"\nTrue Negatives:  {tn:5d} (correctly identified normal)")
print(f"False Positives: {fp:5d} (normal flagged as anomaly) - {false_positive_rate*100:.2f}%")
print(f"False Negatives: {fn:5d} (missed anomalies) - {false_negative_rate*100:.2f}%")
print(f"True Positives:  {tp:5d} (correctly detected anomalies)")

# Detailed classification report
print("\n" + "=" * 80)
print("DETAILED CLASSIFICATION REPORT")
print("=" * 80)
print("\n" + classification_report(y_test_binary, y_pred_labels))

# Per-attack-type analysis
print("\n" + "=" * 80)
print("PER-ATTACK-TYPE DETECTION RATES")
print("=" * 80)

attack_types = ['Anomaly_DoS', 'Anomaly_Injection', 'Anomaly_Spoofing']
for attack in attack_types:
    # Get indices of this attack type in test set
    attack_indices = [i for i, label in enumerate(y_test) if label == attack]
    
    if len(attack_indices) > 0:
        # Check how many were detected
        detected = sum([1 for i in attack_indices if y_pred[i] == -1])
        detection_rate = (detected / len(attack_indices)) * 100
        
        print(f"\n{attack}:")
        print(f"  Total in test set: {len(attack_indices)}")
        print(f"  Detected: {detected}")
        print(f"  Detection rate: {detection_rate:.2f}%")

# ============================================================================
# 6. ANALYZE ANOMALY SCORES
# ============================================================================
print("\n" + "=" * 80)
print("ANOMALY SCORE ANALYSIS")
print("=" * 80)

# Scores for normal vs anomalies
normal_scores = anomaly_scores[np.array(y_test_binary) == 'Normal']
anomaly_scores_actual = anomaly_scores[np.array(y_test_binary) == 'Anomaly']

print(f"\nNormal samples:")
print(f"  Mean score: {normal_scores.mean():.4f}")
print(f"  Std dev:    {normal_scores.std():.4f}")
print(f"  Min score:  {normal_scores.min():.4f}")
print(f"  Max score:  {normal_scores.max():.4f}")

print(f"\nAnomaly samples:")
print(f"  Mean score: {anomaly_scores_actual.mean():.4f}")
print(f"  Std dev:    {anomaly_scores_actual.std():.4f}")
print(f"  Min score:  {anomaly_scores_actual.min():.4f}")
print(f"  Max score:  {anomaly_scores_actual.max():.4f}")

score_separation = abs(normal_scores.mean() - anomaly_scores_actual.mean())
print(f"\nScore separation: {score_separation:.4f}")
if score_separation > 0.1:
    print("  Status: EXCELLENT separation")
elif score_separation > 0.05:
    print("  Status: GOOD separation")
else:
    print("  Status: FAIR separation")

# ============================================================================
# 7. TRAIN K-MEANS CLUSTERING (OPTIONAL)
# ============================================================================
print("\n" + "=" * 80)
print("TRAINING K-MEANS CLUSTERING")
print("=" * 80)

print("\nTraining K-Means with 4 clusters (for device behavior analysis)...")
kmeans = KMeans(n_clusters=4, random_state=42, n_init=10)
kmeans.fit(X_train)

# Predict clusters
train_clusters = kmeans.predict(X_train)
test_clusters = kmeans.predict(X_test)

print(f"  K-Means trained successfully")
print(f"  Cluster distribution in training set:")
unique, counts = np.unique(train_clusters, return_counts=True)
for cluster, count in zip(unique, counts):
    print(f"    Cluster {cluster}: {count:,} samples ({count/len(train_clusters)*100:.1f}%)")

# ============================================================================
# 8. SAVE MODELS
# ============================================================================
print("\n" + "=" * 80)
print("SAVING MODELS")
print("=" * 80)

# Save Isolation Forest
joblib.dump(iso_forest, 'models/isolation_forest.pkl')
print("  Saved: models/isolation_forest.pkl")

# Save K-Means
joblib.dump(kmeans, 'models/kmeans.pkl')
print("  Saved: models/kmeans.pkl")

# Save evaluation metrics
metrics = {
    'accuracy': accuracy,
    'precision': precision,
    'recall': recall,
    'f1_score': f1,
    'false_positive_rate': false_positive_rate,
    'false_negative_rate': false_negative_rate,
    'confusion_matrix': cm.tolist()
}
joblib.dump(metrics, 'models/metrics.pkl')
print("  Saved: models/metrics.pkl")

# ============================================================================
# 9. GENERATE SUMMARY REPORT
# ============================================================================
print("\n" + "=" * 80)
print("GENERATING TRAINING REPORT")
print("=" * 80)

report = f"""
ML MODEL TRAINING REPORT
{'=' * 80}

Model: Isolation Forest
Training Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}

Dataset Information:
  - Training samples (normal only): {len(X_train_normal):,}
  - Test samples: {len(X_test):,}
  - Features: {X_train.shape[1]}
  - Contamination parameter: 0.21

Model Performance:
  - Accuracy:  {accuracy*100:.2f}%
  - Precision: {precision*100:.2f}%
  - Recall:    {recall*100:.2f}%
  - F1-Score:  {f1*100:.2f}%

Confusion Matrix:
  - True Negatives:  {tn:,}
  - False Positives: {fp:,} ({false_positive_rate*100:.2f}%)
  - False Negatives: {fn:,} ({false_negative_rate*100:.2f}%)
  - True Positives:  {tp:,}

Verdict:
"""

if accuracy >= 0.95:
    report += "  EXCELLENT! Model performs exceptionally well.\n"
elif accuracy >= 0.90:
    report += "  GREAT! Model performance is very good.\n"
elif accuracy >= 0.85:
    report += "  GOOD! Model performance is acceptable.\n"
else:
    report += "  FAIR! Consider feature engineering or more data.\n"

if false_positive_rate < 0.05:
    report += "  Low false positive rate - safe for production.\n"
elif false_positive_rate < 0.10:
    report += "  Acceptable false positive rate.\n"
else:
    report += "  High false positives - may need threshold tuning.\n"

report += f"""
Models Saved:
  - models/isolation_forest.pkl (main model)
  - models/kmeans.pkl (clustering support)
  - models/scaler.pkl (feature scaling)
  - models/metrics.pkl (performance metrics)

Next Steps:
  1. Build FastAPI ML service
  2. Test with real-time data
  3. Deploy to production
  4. Monitor performance

{'=' * 80}
"""

print(report)

# Save report
try:
    with open('models/TRAINING_REPORT.txt', 'w', encoding='utf-8') as f:
        f.write(report)
    print("\nSaved: models/TRAINING_REPORT.txt")
except:
    with open('models/TRAINING_REPORT.txt', 'w') as f:
        f.write(report.encode('ascii', 'ignore').decode())
    print("\nSaved: models/TRAINING_REPORT.txt")

print("\n" + "=" * 80)
print("MODEL TRAINING COMPLETE!")
print("=" * 80)
print("\nYour ML models are ready for deployment!")
print("Next step: Build the FastAPI ML service (Week 2)")
print("=" * 80)
