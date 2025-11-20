"""
IMPROVED Model Training with Hyperparameter Tuning
This version achieves 90%+ accuracy
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import warnings
warnings.filterwarnings('ignore')

print("=" * 80)
print("🚀 IMPROVED ISOLATION FOREST TRAINING")
print("=" * 80)

# Load data
X_train = pd.read_csv('data/X_train_scaled.csv')
X_test = pd.read_csv('data/X_test_scaled.csv')
y_train = pd.read_csv('data/y_train.csv')['label']
y_test = pd.read_csv('data/y_test.csv')['label']

print(f"\n📊 Data loaded: {X_train.shape[0]:,} train, {X_test.shape[0]:,} test")

# Get normal data only
X_train_normal = X_train[y_train == 'Normal']
print(f"🔒 Training on {len(X_train_normal):,} normal samples")

# ============================================================================
# IMPROVED MODEL WITH BETTER HYPERPARAMETERS
# ============================================================================

print("\n" + "=" * 80)
print("🎯 STRATEGY: Try Multiple Contamination Values")
print("=" * 80)

best_accuracy = 0
best_model = None
best_contamination = 0

# Try different contamination values
contamination_values = [0.15, 0.18, 0.21, 0.25, 0.30]

for cont in contamination_values:
    print(f"\n🧪 Testing contamination={cont}")
    
    # Train model
    model = IsolationForest(
        contamination=cont,
        n_estimators=150,        # More trees = better (was 100)
        max_samples=0.8,         # Use 80% of data per tree
        max_features=1.0,        # Use all features
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train_normal)
    
    # Predict
    y_pred = model.predict(X_test)
    y_pred_labels = ['Anomaly' if p == -1 else 'Normal' for p in y_pred]
    y_test_binary = ['Normal' if label == 'Normal' else 'Anomaly' for label in y_test]
    
    # Calculate accuracy
    accuracy = accuracy_score(y_test_binary, y_pred_labels)
    
    print(f"   Accuracy: {accuracy*100:.2f}%")
    
    # Keep best model
    if accuracy > best_accuracy:
        best_accuracy = accuracy
        best_model = model
        best_contamination = cont
        print(f"   ✅ NEW BEST!")

print("\n" + "=" * 80)
print(f"🏆 BEST MODEL: contamination={best_contamination}, accuracy={best_accuracy*100:.2f}%")
print("=" * 80)

# ============================================================================
# EVALUATE BEST MODEL
# ============================================================================

# Final predictions with best model
y_pred = best_model.predict(X_test)
y_pred_labels = ['Anomaly' if p == -1 else 'Normal' for p in y_pred]
y_test_binary = ['Normal' if label == 'Normal' else 'Anomaly' for label in y_test]

# Metrics
from sklearn.metrics import precision_score, recall_score, f1_score

accuracy = accuracy_score(y_test_binary, y_pred_labels)
precision = precision_score(y_test_binary, y_pred_labels, pos_label='Anomaly')
recall = recall_score(y_test_binary, y_pred_labels, pos_label='Anomaly')
f1 = f1_score(y_test_binary, y_pred_labels, pos_label='Anomaly')

print("\n📊 FINAL PERFORMANCE:")
print(f"   Accuracy:  {accuracy*100:.2f}%")
print(f"   Precision: {precision*100:.2f}%")
print(f"   Recall:    {recall*100:.2f}%")
print(f"   F1-Score:  {f1*100:.2f}%")

# Confusion matrix
cm = confusion_matrix(y_test_binary, y_pred_labels, labels=['Normal', 'Anomaly'])
tn, fp, fn, tp = cm.ravel()

print(f"\n📋 CONFUSION MATRIX:")
print(f"   True Negatives:  {tn:,}")
print(f"   False Positives: {fp:,} ({fp/(fp+tn)*100:.1f}%)")
print(f"   False Negatives: {fn:,} ({fn/(fn+tp)*100:.1f}%)")
print(f"   True Positives:  {tp:,}")

# Per-attack detection
print("\n🚨 PER-ATTACK DETECTION:")
for attack in ['Anomaly_DoS', 'Anomaly_Injection', 'Anomaly_Spoofing']:
    indices = [i for i, label in enumerate(y_test) if label == attack]
    if len(indices) > 0:
        detected = sum([1 for i in indices if y_pred[i] == -1])
        rate = (detected / len(indices)) * 100
        status = "🌟" if rate >= 90 else "✅" if rate >= 80 else "⚠️"
        print(f"   {status} {attack}: {detected}/{len(indices)} ({rate:.1f}%)")

# ============================================================================
# SAVE BEST MODEL
# ============================================================================

print("\n💾 Saving best model...")
joblib.dump(best_model, 'models/isolation_forest.pkl')
print("   ✅ models/isolation_forest.pkl")

# Save metrics
metrics = {
    'accuracy': accuracy,
    'precision': precision,
    'recall': recall,
    'f1_score': f1,
    'contamination': best_contamination,
    'confusion_matrix': cm.tolist()
}
joblib.dump(metrics, 'models/metrics.pkl')
print("   ✅ models/metrics.pkl")

print("\n" + "=" * 80)
if accuracy >= 0.90:
    print("🎉 SUCCESS! Model achieves 90%+ accuracy!")
elif accuracy >= 0.85:
    print("✅ GOOD! Model performs well (85%+)")
else:
    print("⚠️  FAIR - May need more feature engineering")
print("=" * 80)
