# %% [markdown]
# #  IoT Security Platform - Data Analysis
# 
# **Author:** Wafaa EL HADCHI  
# **Date:** November 2025  
# **Goal:** Analyze IoT telemetry data and prepare for ML training
# 
# ---

# %% [markdown]
# ## 1️ Import Libraries

# %%
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import warnings

warnings.filterwarnings('ignore')
plt.style.use('seaborn-v0_8-darkgrid')
%matplotlib inline

print(" All libraries imported successfully!")

# %% [markdown]
# ## 2️ Load Dataset

# %%
# Load the enhanced dataset
df = pd.read_csv('../data/smart_system_anomaly_dataset.csv')

print(f" Dataset loaded successfully!")
print(f"   Shape: {df.shape}")
print(f"   Columns: {df.columns.tolist()}")

# Display first few rows
df.head()

# %% [markdown]
# ## 3️ Basic Dataset Information

# %%
# Dataset info
print(" Dataset Information:")
print(f"   Total records: {len(df):,}")
print(f"   Features: {len(df.columns)}")
print(f"   Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
print(f"\n   Missing values: {df.isnull().sum().sum()}")
print(f"   Duplicate records: {df.duplicated().sum()}")

# Data types
print("\n Data Types:")
df.dtypes

# %% [markdown]
# ## 4️ Label Distribution

# %%
# Count labels
label_counts = df['label'].value_counts()
label_pct = df['label'].value_counts(normalize=True) * 100

print("  Label Distribution:")
for label in label_counts.index:
    print(f"   {label:20s}: {label_counts[label]:5,} ({label_pct[label]:5.2f}%)")

# Visualize
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

# Bar chart
label_counts.plot(kind='bar', ax=ax1, color=['green', 'red', 'orange', 'purple'])
ax1.set_title('Label Distribution (Count)', fontsize=14, fontweight='bold')
ax1.set_xlabel('Label')
ax1.set_ylabel('Count')
ax1.tick_params(axis='x', rotation=45)

# Pie chart
label_counts.plot(kind='pie', ax=ax2, autopct='%1.1f%%', startangle=90,
                  colors=['green', 'red', 'orange', 'purple'])
ax2.set_title('Label Distribution (Percentage)', fontsize=14, fontweight='bold')
ax2.set_ylabel('')

plt.tight_layout()
plt.show()

# %% [markdown]
# ## 5️ Device Type Distribution

# %%
# Device types
device_counts = df['device_type'].value_counts()

print("  Device Type Distribution:")
for dtype in device_counts.index:
    count = device_counts[dtype]
    pct = (count / len(df)) * 100
    print(f"   {dtype:15s}: {count:5,} ({pct:5.2f}%)")

print(f"\n   Unique devices: {df['device_id'].nunique()}")

# Visualize
plt.figure(figsize=(10, 6))
device_counts.plot(kind='bar', color=['blue', 'cyan', 'magenta', 'yellow'])
plt.title('Device Type Distribution', fontsize=14, fontweight='bold')
plt.xlabel('Device Type')
plt.ylabel('Count')
plt.xticks(rotation=0)
plt.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.show()

# %% [markdown]
# ## 6️ Statistical Summary

# %%
# Numerical features
numerical_cols = ['cpu_usage', 'memory_usage', 'network_in_kb', 'network_out_kb',
                  'packet_rate', 'avg_response_time_ms', 'failed_auth_attempts',
                  'geo_location_variation']

print("Statistical Summary:")
df[numerical_cols].describe().round(2)

# %% [markdown]
# ## 7️ Compare Normal vs Anomalies

# %%
# Compare key features
comparison_features = ['cpu_usage', 'packet_rate', 'failed_auth_attempts', 'geo_location_variation']

fig, axes = plt.subplots(2, 2, figsize=(15, 12))
axes = axes.ravel()

for idx, feat in enumerate(comparison_features):
    df.boxplot(column=feat, by='label', ax=axes[idx])
    axes[idx].set_title(f'{feat} by Attack Type', fontweight='bold')
    axes[idx].set_xlabel('')
    axes[idx].set_ylabel(feat)

plt.suptitle('Feature Comparison: Normal vs Attacks', fontsize=16, fontweight='bold', y=1.00)
plt.tight_layout()
plt.show()

# %% [markdown]
# ## 8️ Attack Pattern Analysis

# %%
# Analyze each attack type
print(" ATTACK PATTERN ANALYSIS")
print("=" * 80)

for attack_type in ['Anomaly_DoS', 'Anomaly_Injection', 'Anomaly_Spoofing']:
    print(f"\n{attack_type}:")
    print("-" * 80)
    
    attack_data = df[df['label'] == attack_type]
    normal_data = df[df['label'] == 'Normal']
    
    for feat in comparison_features:
        normal_mean = normal_data[feat].mean()
        attack_mean = attack_data[feat].mean()
        diff_pct = ((attack_mean - normal_mean) / normal_mean) * 100
        
        status = "" if abs(diff_pct) > 30 else "✅" if abs(diff_pct) > 15 else "⚠️"
        
        print(f"  {status} {feat:25s}: {normal_mean:7.1f} → {attack_mean:7.1f} ({diff_pct:+6.1f}%)")

# %% [markdown]
# ## 9️ Correlation Analysis

# %%
# Correlation matrix
plt.figure(figsize=(12, 10))
correlation = df[numerical_cols].corr()
sns.heatmap(correlation, annot=True, fmt='.2f', cmap='coolwarm', center=0,
            square=True, linewidths=1, cbar_kws={"shrink": 0.8})
plt.title('Feature Correlation Heatmap', fontsize=16, fontweight='bold')
plt.tight_layout()

plt.show()

print("\n Strong Correlations (|r| > 0.5):")
for i in range(len(correlation.columns)):
    for j in range(i+1, len(correlation.columns)):
        if abs(correlation.iloc[i, j]) > 0.5:
            print(f"   {correlation.columns[i]:25s} ↔ {correlation.columns[j]:25s}: {correlation.iloc[i, j]:+.3f}")

# %% [markdown]
# ##  Feature Engineering

# %%
# Create derived features
print(" Creating derived features...")

df['network_total'] = df['network_in_kb'] + df['network_out_kb']
df['network_ratio'] = df['network_out_kb'] / (df['network_in_kb'] + 1)  # Avoid division by zero
df['cpu_memory_product'] = df['cpu_usage'] * df['memory_usage']

print(" Created 3 derived features:")
print("   - network_total")
print("   - network_ratio")
print("   - cpu_memory_product")

# Select all features for ML
features = [
    'cpu_usage', 'memory_usage', 'network_in_kb', 'network_out_kb',
    'packet_rate', 'avg_response_time_ms', 'service_access_count',
    'failed_auth_attempts', 'is_encrypted', 'geo_location_variation',
    'network_total', 'network_ratio', 'cpu_memory_product'
]

print(f"\n Total features for ML: {len(features)}")

# %% [markdown]
# ## 11 Train/Test Split

# %%
# Prepare X and y
X = df[features]
y = df['label']

print(f" Feature matrix: {X.shape}")
print(f"  Labels: {y.shape}")

# Split data (80% train, 20% test)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\n  Data split complete:")
print(f"   Training set: {X_train.shape[0]:,} samples")
print(f"   Test set: {X_test.shape[0]:,} samples")

# Check label distribution in splits
print("\n Label distribution:")
print("\n   Training set:")
train_dist = y_train.value_counts(normalize=True) * 100
for label, pct in train_dist.items():
    print(f"      {label:20s}: {pct:5.2f}%")

print("\n   Test set:")
test_dist = y_test.value_counts(normalize=True) * 100
for label, pct in test_dist.items():
    print(f"      {label:20s}: {pct:5.2f}%")

# %% [markdown]
# ## 12 Feature Scaling

# %%
# Normalize features
print(" Normalizing features with StandardScaler...")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print(" Features normalized!")
print(f"   Mean: ~0, Std: ~1")

# Convert back to DataFrame for easier handling
X_train_scaled_df = pd.DataFrame(X_train_scaled, columns=features)
X_test_scaled_df = pd.DataFrame(X_test_scaled, columns=features)

# Show sample
print("\n Sample of scaled features:")
X_train_scaled_df.head()

# %% [markdown]
# ## 13 Save Preprocessed Data

# %%
# Save everything
print(" Saving preprocessed data...")

# Save scaler
joblib.dump(scaler, '../models/scaler.pkl')
print("    models/scaler.pkl")

# Save train/test data
X_train_scaled_df.to_csv('../data/X_train_scaled.csv', index=False)
print("    data/X_train_scaled.csv")

X_test_scaled_df.to_csv('../data/X_test_scaled.csv', index=False)
print("    data/X_test_scaled.csv")

y_train.to_csv('../data/y_train.csv', index=False)
print("    data/y_train.csv")

y_test.to_csv('../data/y_test.csv', index=False)
print("    data/y_test.csv")

print("\n Data analysis complete!")
print(" Ready for model training!")

# %% [markdown]
# ##  Summary
# 
# ###  Completed Tasks:
# 1. Loaded and explored 10,000 IoT telemetry records
# 2. Analyzed label distribution (79% normal, 21% anomalies)
# 3. Examined 4 device types (cameras, sensors, thermostats, smart lights)
# 4. Created 3 derived features
# 5. Split data (80/20 train/test)
# 6. Normalized features with StandardScaler
# 7. Saved preprocessed data for training
# 
# ###  Dataset Ready:
# - **Training samples:** 8,000
# - **Test samples:** 2,000
# - **Features:** 13
# - **Attack types:** DoS, Injection, Spoofing
# 
# ###  Next Steps:
# 1. Open `02_train_model.ipynb`
# 2. Train Isolation Forest
# 3. Evaluate performance
# 4. Achieve 92%+ accuracy!
# 
# 
# 
# 


