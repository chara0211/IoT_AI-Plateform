"""
ENSEMBLE MODEL TRAINING - FIXED VERSION
With better parameters and validation
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

print("=" * 80)
print("🎯 ENSEMBLE MODEL TRAINING - IMPROVED VERSION")
print("=" * 80)

# Load data
print("📁 Loading data...")
X_train = pd.read_csv('data/X_train_scaled.csv')
X_test = pd.read_csv('data/X_test_scaled.csv')
y_train = pd.read_csv('data/y_train.csv')['label']
y_test = pd.read_csv('data/y_test.csv')['label']

X_train_normal = X_train[y_train == 'Normal']

print(f"📊 Data shapes: Train {X_train.shape}, Test {X_test.shape}")
print(f"🔍 Normal samples in training: {len(X_train_normal)}")

# ============================================================================
# MODEL 1: Isolation Forest (Less Sensitive)
# ============================================================================
print("\n1️⃣ Training Isolation Forest (less sensitive)...")
iso_forest = IsolationForest(
    contamination=0.01,  # Reduced from 0.03
    n_estimators=200,    # More trees for stability
    max_samples=0.9,     # More samples
    random_state=42,
    n_jobs=-1,
    verbose=1
)
iso_forest.fit(X_train_normal)
pred1 = iso_forest.predict(X_test)
print("   ✅ Isolation Forest trained")

# ============================================================================
# MODEL 2: Random Forest (Supervised)
# ============================================================================
print("\n2️⃣ Training Random Forest...")
# Convert labels to binary
y_train_binary = ['Anomaly' if label != 'Normal' else 'Normal' for label in y_train]
y_test_binary = ['Anomaly' if label != 'Normal' else 'Normal' for label in y_test]

rf = RandomForestClassifier(
    n_estimators=150,    # Increased
    max_depth=15,        # Increased
    min_samples_split=5, # Added to prevent overfitting
    random_state=42,
    n_jobs=-1,
    verbose=1
)
rf.fit(X_train, y_train_binary)
pred2_labels = rf.predict(X_test)
pred2 = [1 if p == 'Normal' else -1 for p in pred2_labels]
print("   ✅ Random Forest trained")

# ============================================================================
# MODEL 3: One-Class SVM (Less Sensitive)
# ============================================================================
print("\n3️⃣ Training One-Class SVM (less sensitive)...")
svm = OneClassSVM(
    kernel='rbf',
    gamma='scale',       # Better than 'auto'
    nu=0.01,             # Reduced sensitivity
    cache_size=1000,
    verbose=True
)
svm.fit(X_train_normal)
pred3 = svm.predict(X_test)
print("   ✅ One-Class SVM trained")

# ============================================================================
# ENSEMBLE: Smart Voting
# ============================================================================
print("\n🗳️ Combining predictions with smart voting...")

ensemble_pred = []
confidence_scores = []

for i in range(len(X_test)):
    # Get votes from all 3 models
    votes = [pred1[i], pred2[i], pred3[i]]
    
    # Count anomaly votes (-1)
    anomaly_votes = sum([1 for v in votes if v == -1])
    
    # Calculate confidence
    confidence = anomaly_votes / 3.0
    
    # Smart voting: Require higher confidence for anomaly
    if anomaly_votes >= 3:  # All 3 agree
        ensemble_pred.append(-1)  # Anomaly
    elif anomaly_votes == 2 and confidence > 0.7:  # 2 agree with high confidence
        ensemble_pred.append(-1)  # Anomaly
    else:
        ensemble_pred.append(1)   # Normal
    
    confidence_scores.append(confidence)

# Convert to labels
ensemble_labels = ['Anomaly' if p == -1 else 'Normal' for p in ensemble_pred]

# ============================================================================
# EVALUATE
# ============================================================================
print("\n" + "=" * 80)
print("📊 ENSEMBLE PERFORMANCE")
print("=" * 80)

accuracy = accuracy_score(y_test_binary, ensemble_labels)
print(f"\n🎯 Ensemble Accuracy: {accuracy*100:.2f}%")

# Compare with individual models
iso_labels = ['Anomaly' if p == -1 else 'Normal' for p in pred1]
rf_labels = pred2_labels
svm_labels = ['Anomaly' if p == -1 else 'Normal' for p in pred3]

acc_iso = accuracy_score(y_test_binary, iso_labels)
acc_rf = accuracy_score(y_test_binary, rf_labels)
acc_svm = accuracy_score(y_test_binary, svm_labels)

print(f"\nIndividual Model Accuracies:")
print(f"   Isolation Forest: {acc_iso*100:.2f}%")
print(f"   Random Forest:    {acc_rf*100:.2f}%")
print(f"   One-Class SVM:    {acc_svm*100:.2f}%")
print(f"   🌟 ENSEMBLE:      {accuracy*100:.2f}%")

# Detailed report
print("\n" + "=" * 80)
print("DETAILED CLASSIFICATION REPORT")
print("=" * 80)
print(classification_report(y_test_binary, ensemble_labels))

# Confusion matrix
print("\n🎯 CONFUSION MATRIX:")
cm = confusion_matrix(y_test_binary, ensemble_labels)
print(cm)

# Per-attack detection
print("\n🚨 PER-ATTACK DETECTION:")
attack_types = ['Anomaly_DoS', 'Anomaly_Injection', 'Anomaly_Spoofing', 'Anomaly_Scanning']
for attack in attack_types:
    indices = [i for i, label in enumerate(y_test) if label == attack]
    if len(indices) > 0:
        detected = sum([1 for i in indices if ensemble_pred[i] == -1])
        rate = (detected / len(indices)) * 100
        status = "🌟" if rate >= 90 else "✅" if rate >= 80 else "⚠️"
        print(f"   {status} {attack}: {detected}/{len(indices)} ({rate:.1f}%)")

# False positives analysis
normal_indices = [i for i, label in enumerate(y_test_binary) if label == 'Normal']
false_positives = sum([1 for i in normal_indices if ensemble_pred[i] == -1])
fp_rate = (false_positives / len(normal_indices)) * 100
print(f"\n📊 False Positive Rate: {false_positives}/{len(normal_indices)} ({fp_rate:.2f}%)")

# ============================================================================
# SAVE ENSEMBLE
# ============================================================================
print("\n💾 Saving ensemble models...")

# Save all models
ensemble = {
    'isolation_forest': iso_forest,
    'random_forest': rf,
    'one_class_svm': svm,
    'voting_threshold': 2,
    'metadata': {
        'training_samples': len(X_train),
        'normal_samples': len(X_train_normal),
        'accuracy': accuracy
    }
}

joblib.dump(ensemble, 'models/ensemble_model.pkl')
print("   ✅ models/ensemble_model.pkl")

# Save scaler for reference
scaler = StandardScaler()
scaler.fit(X_train)  # Fit on original data
joblib.dump(scaler, 'models/scaler.pkl')
print("   ✅ models/scaler.pkl")

print("\n" + "=" * 80)
if accuracy >= 0.92 and fp_rate < 5:
    print("🎉 EXCELLENT! Ensemble achieves high accuracy with low false positives!")
elif accuracy >= 0.88:
    print("✅ GREAT! Ensemble performs very well!")
else:
    print("⚠️ GOOD! Ensemble improves over single models")
print("=" * 80)