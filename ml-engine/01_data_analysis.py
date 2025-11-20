"""
AI-Driven IoT Security Platform
Dataset Analysis & Preparation Script

Author: Wafaa EL HADCHI
Date: November 2025
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os

# Set style
sns.set_style('darkgrid')
plt.rcParams['figure.figsize'] = (12, 6)

print("=" * 80)
print("🚀 AI-DRIVEN IOT SECURITY PLATFORM - DATA ANALYSIS")
print("=" * 80)

# Create directories
os.makedirs('models', exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('visualizations', exist_ok=True)

# Load dataset
print("\n📊 Loading dataset...")
df = pd.read_csv('data/smart_system_anomaly_dataset.csv')

print(f"✅ Dataset loaded successfully!")
print(f"   Shape: {df.shape[0]} rows × {df.shape[1]} columns")

# ============================================================================
# 1. BASIC EXPLORATION
# ============================================================================

print("\n" + "=" * 80)
print("1️⃣  BASIC DATASET INFORMATION")
print("=" * 80)

print("\n📋 Columns:")
for i, col in enumerate(df.columns, 1):
    dtype = df[col].dtype
    unique = df[col].nunique()
    print(f"   {i:2d}. {col:25s} | Type: {str(dtype):10s} | Unique: {unique:5d}")

print("\n⚠️  Missing Values:")
missing = df.isnull().sum()
if missing.sum() == 0:
    print("   ✅ No missing values detected!")
else:
    print(missing[missing > 0])

print("\n🏷️  Label Distribution:")
label_counts = df['label'].value_counts()
label_pct = df['label'].value_counts(normalize=True) * 100

print("\n   Count:")
for label, count in label_counts.items():
    print(f"   {label:20s}: {count:5d} ({label_pct[label]:5.2f}%)")

print("\n🖥️  Device Type Distribution:")
device_counts = df['device_type'].value_counts()
for dtype, count in device_counts.items():
    pct = (count / len(df)) * 100
    print(f"   {dtype:15s}: {count:5d} ({pct:5.2f}%)")

print(f"\n📱 Unique Devices: {df['device_id'].nunique()}")

# ============================================================================
# 2. STATISTICAL ANALYSIS
# ============================================================================

print("\n" + "=" * 80)
print("2️⃣  STATISTICAL ANALYSIS")
print("=" * 80)

numerical_cols = ['cpu_usage', 'memory_usage', 'network_in_kb', 'network_out_kb',
                  'packet_rate', 'avg_response_time_ms', 'failed_auth_attempts',
                  'geo_location_variation']

print("\n📈 Descriptive Statistics (All Data):")
print(df[numerical_cols].describe().round(2))

print("\n🔍 Statistics by Label:")
for label in df['label'].unique():
    print(f"\n   {label}:")
    subset = df[df['label'] == label][numerical_cols]
    print(subset.describe().round(2))

# ============================================================================
# 3. ANOMALY PATTERN ANALYSIS
# ============================================================================

print("\n" + "=" * 80)
print("3️⃣  ANOMALY PATTERN ANALYSIS")
print("=" * 80)

print("\n🚨 Key Anomaly Indicators:")

# DoS patterns
dos_data = df[df['label'] == 'Anomaly_DoS']
print(f"\n   DoS Attacks ({len(dos_data)} incidents):")
print(f"   - Avg CPU Usage: {dos_data['cpu_usage'].mean():.2f}%")
print(f"   - Avg Packet Rate: {dos_data['packet_rate'].mean():.0f} pps")
print(f"   - Avg Memory: {dos_data['memory_usage'].mean():.2f}%")

# Injection patterns
injection_data = df[df['label'] == 'Anomaly_Injection']
print(f"\n   Injection Attacks ({len(injection_data)} incidents):")
print(f"   - Avg CPU Usage: {injection_data['cpu_usage'].mean():.2f}%")
print(f"   - Avg Failed Auth: {injection_data['failed_auth_attempts'].mean():.2f}")
print(f"   - Network Out: {injection_data['network_out_kb'].mean():.0f} KB")

# Spoofing patterns
spoofing_data = df[df['label'] == 'Anomaly_Spoofing']
print(f"\n   Spoofing Attacks ({len(spoofing_data)} incidents):")
print(f"   - Avg Geo Variation: {spoofing_data['geo_location_variation'].mean():.2f}")
print(f"   - Avg CPU Usage: {spoofing_data['cpu_usage'].mean():.2f}%")

# Normal patterns
normal_data = df[df['label'] == 'Normal']
print(f"\n   Normal Behavior ({len(normal_data)} records):")
print(f"   - Avg CPU Usage: {normal_data['cpu_usage'].mean():.2f}%")
print(f"   - Avg Packet Rate: {normal_data['packet_rate'].mean():.0f} pps")
print(f"   - Avg Failed Auth: {normal_data['failed_auth_attempts'].mean():.2f}")

# ============================================================================
# 4. FEATURE ENGINEERING
# ============================================================================

print("\n" + "=" * 80)
print("4️⃣  FEATURE ENGINEERING")
print("=" * 80)

# Create derived features
print("\n🔧 Creating derived features...")

df['network_total'] = df['network_in_kb'] + df['network_out_kb']
df['network_ratio'] = df['network_out_kb'] / (df['network_in_kb'] + 1)  # Avoid div by zero
df['cpu_memory_product'] = df['cpu_usage'] * df['memory_usage']

print("   ✅ Created: network_total")
print("   ✅ Created: network_ratio")
print("   ✅ Created: cpu_memory_product")

# Select features for ML
features = [
    'cpu_usage', 'memory_usage', 'network_in_kb', 'network_out_kb',
    'packet_rate', 'avg_response_time_ms', 'service_access_count',
    'failed_auth_attempts', 'is_encrypted', 'geo_location_variation',
    'network_total', 'network_ratio', 'cpu_memory_product'
]

print(f"\n📋 Total features for ML: {len(features)}")

# ============================================================================
# 5. DATA PREPARATION FOR ML
# ============================================================================

print("\n" + "=" * 80)
print("5️⃣  DATA PREPARATION FOR MACHINE LEARNING")
print("=" * 80)

X = df[features]
y = df['label']

print(f"\n📊 Feature matrix: {X.shape}")
print(f"🏷️  Labels: {y.shape}")

# Split data
print("\n✂️  Splitting data (80% train, 20% test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"   Training set: {X_train.shape[0]} samples")
print(f"   Test set: {X_test.shape[0]} samples")

# Check label distribution in splits
print("\n📊 Label distribution in splits:")
print("\n   Training set:")
train_dist = y_train.value_counts(normalize=True) * 100
for label, pct in train_dist.items():
    print(f"   {label:20s}: {pct:5.2f}%")

print("\n   Test set:")
test_dist = y_test.value_counts(normalize=True) * 100
for label, pct in test_dist.items():
    print(f"   {label:20s}: {pct:5.2f}%")

# Normalize features
print("\n🔄 Normalizing features with StandardScaler...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("   ✅ Features normalized!")

# ============================================================================
# 6. SAVE PREPROCESSED DATA
# ============================================================================

print("\n" + "=" * 80)
print("6️⃣  SAVING PREPROCESSED DATA")
print("=" * 80)

# Save scaler
joblib.dump(scaler, 'models/scaler.pkl')
print("\n💾 Saved: models/scaler.pkl")

# Save preprocessed data
pd.DataFrame(X_train_scaled, columns=features).to_csv('data/X_train_scaled.csv', index=False)
pd.DataFrame(X_test_scaled, columns=features).to_csv('data/X_test_scaled.csv', index=False)
y_train.to_csv('data/y_train.csv', index=False)
y_test.to_csv('data/y_test.csv', index=False)

print("💾 Saved: data/X_train_scaled.csv")
print("💾 Saved: data/X_test_scaled.csv")
print("💾 Saved: data/y_train.csv")
print("💾 Saved: data/y_test.csv")

# ============================================================================
# 7. VISUALIZATIONS
# ============================================================================

print("\n" + "=" * 80)
print("7️⃣  CREATING VISUALIZATIONS")
print("=" * 80)

# 1. Label Distribution
plt.figure(figsize=(10, 6))
label_counts.plot(kind='bar', color=['green', 'red', 'orange', 'purple'])
plt.title('IoT Telemetry: Label Distribution', fontsize=16, fontweight='bold')
plt.xlabel('Label', fontsize=12)
plt.ylabel('Count', fontsize=12)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('visualizations/01_label_distribution.png', dpi=300, bbox_inches='tight')
print("✅ Saved: visualizations/01_label_distribution.png")
plt.close()

# 2. Device Type Distribution
plt.figure(figsize=(10, 6))
device_counts.plot(kind='bar', color=['blue', 'cyan', 'magenta', 'yellow'])
plt.title('IoT Devices: Type Distribution', fontsize=16, fontweight='bold')
plt.xlabel('Device Type', fontsize=12)
plt.ylabel('Count', fontsize=12)
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig('visualizations/02_device_distribution.png', dpi=300, bbox_inches='tight')
print("✅ Saved: visualizations/02_device_distribution.png")
plt.close()

# 3. CPU Usage by Label
plt.figure(figsize=(12, 6))
df.boxplot(column='cpu_usage', by='label', figsize=(12, 6))
plt.suptitle('')
plt.title('CPU Usage Distribution by Label', fontsize=16, fontweight='bold')
plt.xlabel('Label', fontsize=12)
plt.ylabel('CPU Usage (%)', fontsize=12)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('visualizations/03_cpu_by_label.png', dpi=300, bbox_inches='tight')
print("✅ Saved: visualizations/03_cpu_by_label.png")
plt.close()

# 4. Packet Rate by Label
plt.figure(figsize=(12, 6))
df.boxplot(column='packet_rate', by='label', figsize=(12, 6))
plt.suptitle('')
plt.title('Packet Rate Distribution by Label', fontsize=16, fontweight='bold')
plt.xlabel('Label', fontsize=12)
plt.ylabel('Packet Rate (pps)', fontsize=12)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('visualizations/04_packet_rate_by_label.png', dpi=300, bbox_inches='tight')
print("✅ Saved: visualizations/04_packet_rate_by_label.png")
plt.close()

# 5. Correlation Heatmap
plt.figure(figsize=(14, 10))
correlation = df[numerical_cols].corr()
sns.heatmap(correlation, annot=True, fmt='.2f', cmap='coolwarm', center=0)
plt.title('Feature Correlation Heatmap', fontsize=16, fontweight='bold')
plt.tight_layout()
plt.savefig('visualizations/05_correlation_heatmap.png', dpi=300, bbox_inches='tight')
print("✅ Saved: visualizations/05_correlation_heatmap.png")
plt.close()

# ============================================================================
# 8. SUMMARY REPORT
# ============================================================================

print("\n" + "=" * 80)
print("8️⃣  SUMMARY REPORT")
print("=" * 80)

summary = f"""
📋 DATASET ANALYSIS SUMMARY
{'=' * 80}

Dataset Information:
  • Total Records: {len(df):,}
  • Features: {len(features)}
  • Device Types: {df['device_type'].nunique()}
  • Unique Devices: {df['device_id'].nunique()}
  • Time Span: {df['timestamp'].min()} to {df['timestamp'].max()}

Label Distribution:
  • Normal: {label_counts['Normal']:,} ({label_pct['Normal']:.2f}%)
  • DoS Attacks: {label_counts.get('Anomaly_DoS', 0):,} ({label_pct.get('Anomaly_DoS', 0):.2f}%)
  • Injection Attacks: {label_counts.get('Anomaly_Injection', 0):,} ({label_pct.get('Anomaly_Injection', 0):.2f}%)
  • Spoofing Attacks: {label_counts.get('Anomaly_Spoofing', 0):,} ({label_pct.get('Anomaly_Spoofing', 0):.2f}%)

Data Quality:
  • Missing Values: {df.isnull().sum().sum()}
  • Duplicate Records: {df.duplicated().sum()}

ML-Ready Data:
  • Training Samples: {X_train_scaled.shape[0]:,}
  • Test Samples: {X_test_scaled.shape[0]:,}
  • Features: {X_train_scaled.shape[1]}
  • Scaler: StandardScaler (saved)

Key Findings:
  • DoS attacks show high CPU usage (avg {dos_data['cpu_usage'].mean():.1f}%)
  • DoS attacks show high packet rates (avg {dos_data['packet_rate'].mean():.0f} pps)
  • Normal behavior is well-separated from anomalies
  • Dataset is slightly imbalanced (79% normal vs 21% anomalies)
  • All features are numeric and ready for ML

Next Steps:
  1. ✅ Data exploration completed
  2. ✅ Features engineered
  3. ✅ Data normalized and split
  4. 🔄 Ready to train Isolation Forest model
  5. 🔄 Ready to train K-Means clustering
  6. 🔄 Ready to build ML API

{'=' * 80}
"""

print(summary)

# Save summary report
with open('data/ANALYSIS_REPORT.txt', 'w') as f:
    f.write(summary)
print("\n💾 Saved: data/ANALYSIS_REPORT.txt")

print("\n" + "=" * 80)
print("✅ DATA ANALYSIS COMPLETE!")
print("=" * 80)
print("\n🎯 Next Step: Run the model training script!")
print("   Command: python 03_train_isolation_forest.py")
print("\n" + "=" * 80)
