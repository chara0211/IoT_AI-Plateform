"""
Explainable AI with SHAP - FIXED VERSION
Explains WHY a device was flagged as anomalous
"""

import pandas as pd
import numpy as np
import joblib
import shap
import matplotlib.pyplot as plt
from typing import Dict, List
import warnings
warnings.filterwarnings('ignore')

class ExplainableAI:
    """
    Explain ML model decisions using SHAP values
    """
    
    def __init__(self, model_path: str = "models/ensemble_model.pkl", 
                 scaler_path: str = "models/scaler.pkl"):
        """
        Load trained models
        """
        print("📦 Loading models...")
        self.ensemble = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        
        # Extract individual models
        self.rf_model = self.ensemble['random_forest']
        self.iso_model = self.ensemble['isolation_forest']
        
        # Feature names
        self.feature_names = [
            "cpu_usage",
            "memory_usage",
            "network_in_kb",
            "network_out_kb",
            "packet_rate",
            "avg_response_time_ms",
            "service_access_count",
            "failed_auth_attempts",
            "is_encrypted",
            "geo_location_variation",
            "network_total",
            "network_ratio",
            "cpu_memory_product"
        ]
        
        # Initialize SHAP explainer for Random Forest
        print("🔍 Initializing SHAP explainer...")
        self.explainer = shap.TreeExplainer(self.rf_model)
        
        print("✅ Explainer ready!")
    
    def engineer_features(self, telemetry: Dict) -> np.ndarray:
        """
        Create same features as training
        """
        features = np.array([[
            telemetry['cpu_usage'],
            telemetry['memory_usage'],
            telemetry['network_in_kb'],
            telemetry['network_out_kb'],
            telemetry['packet_rate'],
            telemetry['avg_response_time_ms'],
            telemetry['service_access_count'],
            telemetry['failed_auth_attempts'],
            telemetry['is_encrypted'],
            telemetry['geo_location_variation'],
            telemetry['network_in_kb'] + telemetry['network_out_kb'],  # network_total
            telemetry['network_out_kb'] / (telemetry['network_in_kb'] + 1),  # network_ratio
            telemetry['cpu_usage'] * telemetry['memory_usage']  # cpu_memory_product
        ]])
        
        return features
    
    def explain_detection(self, telemetry: Dict) -> Dict:
        """
        Explain why a device was flagged
        
        Returns:
        - Top contributing features
        - SHAP values
        - Feature importance
        - Human-readable explanation
        """
        # 1. Engineer features
        features = self.engineer_features(telemetry)
        
        # 2. Scale features
        features_scaled = self.scaler.transform(features)
        
        # 3. Get prediction
        prediction = self.rf_model.predict(features_scaled)[0]
        proba = self.rf_model.predict_proba(features_scaled)[0]
        
        # Get class order
        classes = self.rf_model.classes_
        anomaly_idx = np.where(classes == "Anomaly")[0][0] if "Anomaly" in classes else 1
        normal_idx = np.where(classes == "Normal")[0][0] if "Normal" in classes else 0
        
        # Get correct probabilities
        is_anomaly = (prediction == "Anomaly")
        if is_anomaly:
            confidence = proba[anomaly_idx]
        else:
            confidence = proba[normal_idx]
        
        # 4. Calculate SHAP values
        shap_values = self.explainer.shap_values(features_scaled)
        
        # FIX: Handle SHAP values correctly based on output format
        if isinstance(shap_values, list):
            # Binary classification: get anomaly class SHAP
            shap_vals = shap_values[anomaly_idx][0]  # Shape: (13,)
            base_value = self.explainer.expected_value[anomaly_idx]
        else:
            # Single array
            if len(shap_values.shape) > 1:
                shap_vals = shap_values[0]  # First sample
            else:
                shap_vals = shap_values
            base_value = self.explainer.expected_value
        
        # 5. Get top contributing features
        feature_contributions = []
        for i, (feat_name, feat_val) in enumerate(zip(self.feature_names, features[0])):
            # FIX: Properly extract scalar SHAP value using .item() or indexing
            if isinstance(shap_vals, np.ndarray):
                if shap_vals.ndim > 1:
                    # Multi-dimensional array
                    shap_val_raw = shap_vals[0, i] if shap_vals.shape[0] > 0 and i < shap_vals.shape[1] else 0.0
                else:
                    # 1D array
                    shap_val_raw = shap_vals[i] if i < len(shap_vals) else 0.0
                
                # Convert to Python scalar
                if isinstance(shap_val_raw, np.ndarray):
                    shap_val = float(shap_val_raw.item())  # Use .item() to extract scalar
                else:
                    shap_val = float(shap_val_raw)
            else:
                shap_val = 0.0
            
            feature_contributions.append({
                "feature": feat_name,
                "shap_value": shap_val,
                "feature_value": float(feat_val),
                "impact": "increases" if shap_val > 0 else "decreases",
                "abs_shap": abs(shap_val)
            })
        
        # Sort by absolute SHAP value (most impactful first)
        feature_contributions.sort(key=lambda x: x['abs_shap'], reverse=True)
        
        # 6. Generate human-readable explanation
        explanation = self._generate_explanation(
            telemetry, 
            feature_contributions[:5],  # Top 5 features
            prediction,
            confidence  # Pass single confidence value
        )
        
        return {
            "device_id": telemetry['device_id'],
            "prediction": "Anomaly" if is_anomaly else "Normal",
            "confidence": float(confidence),
            "anomaly_probability": float(proba[anomaly_idx]),
            "normal_probability": float(proba[normal_idx]),
            "top_contributing_factors": feature_contributions[:5],
            "all_feature_impacts": feature_contributions,
            "explanation": explanation,
            "shap_summary": {
                "most_important_feature": feature_contributions[0]["feature"],
                "most_important_value": feature_contributions[0]["feature_value"],
                "total_positive_impact": sum(f['shap_value'] for f in feature_contributions if f['shap_value'] > 0),
                "total_negative_impact": sum(f['shap_value'] for f in feature_contributions if f['shap_value'] < 0)
            }
        }
    
    def _generate_explanation(self, telemetry: Dict, 
                            top_features: List[Dict],
                            prediction: str,
                            confidence: float) -> str:
        """
        Generate human-readable explanation
        """
        device_id = telemetry['device_id']
        
        if prediction == "Anomaly":
            # Anomaly explanation
            explanation = f"🚨 Device {device_id} flagged as ANOMALY with {confidence*100:.1f}% confidence.\n\n"
            explanation += "Key indicators:\n"
            
            for i, feat in enumerate(top_features[:3], 1):
                feat_name = feat['feature'].replace('_', ' ').title()
                feat_val = feat['feature_value']
                
                # Add context
                if feat['feature'] == 'cpu_usage' and feat_val > 80:
                    explanation += f"{i}. {feat_name}: {feat_val:.1f}% (EXTREMELY HIGH - typical of DDoS/Botnet)\n"
                elif feat['feature'] == 'packet_rate' and feat_val > 700:
                    explanation += f"{i}. {feat_name}: {feat_val:.0f} pps (FLOOD DETECTED - possible attack)\n"
                elif feat['feature'] == 'failed_auth_attempts' and feat_val > 5:
                    explanation += f"{i}. {feat_name}: {feat_val:.0f} attempts (CREDENTIAL STUFFING suspected)\n"
                elif feat['feature'] == 'geo_location_variation' and feat_val > 15:
                    explanation += f"{i}. {feat_name}: {feat_val:.1f} (SPOOFING suspected - unusual location)\n"
                elif feat['feature'] == 'network_ratio' and feat_val > 2:
                    explanation += f"{i}. {feat_name}: {feat_val:.2f} (DATA EXFILTRATION - high outbound traffic)\n"
                else:
                    explanation += f"{i}. {feat_name}: {feat_val:.1f} ({feat['impact']} anomaly score)\n"
            
            explanation += f"\n💡 This pattern matches known attack signatures."
            
        else:
            # Normal explanation
            explanation = f"✅ Device {device_id} operating NORMALLY with {confidence*100:.1f}% confidence.\n\n"
            explanation += "All metrics within expected range:\n"
            
            for i, feat in enumerate(top_features[:3], 1):
                feat_name = feat['feature'].replace('_', ' ').title()
                feat_val = feat['feature_value']
                explanation += f"{i}. {feat_name}: {feat_val:.1f}\n"
        
        return explanation
    
    def visualize_explanation(self, telemetry: Dict, save_path: str = None):
        # Engineer and scale features
        features = self.engineer_features(telemetry)
        features_scaled = self.scaler.transform(features)

        # Get SHAP values
        shap_values = self.explainer.shap_values(features_scaled)

        # Handle SHAP values format for binary classification
        if isinstance(shap_values, list):
            classes = self.rf_model.classes_
            anomaly_idx = 1 if len(classes) > 1 and classes[1] == "Anomaly" else 0

            shap_vals_anomaly = shap_values[anomaly_idx][0]  # (n_features,)
            base_value = self.explainer.expected_value[anomaly_idx]
        else:
            shap_vals_anomaly = shap_values[0] if len(shap_values.shape) > 1 else shap_values
            base_value = self.explainer.expected_value

        # 🩹 NORMALISATION IMPORTANTE
        shap_vals_anomaly = np.array(shap_vals_anomaly, dtype=float).ravel()

        plt.figure(figsize=(10, 6))

        try:
            # S'assurer que la longueur matche bien les features
            n = min(len(self.feature_names), len(shap_vals_anomaly))
            shap_vals_anomaly = shap_vals_anomaly[:n]

            indices = np.argsort(np.abs(shap_vals_anomaly))[::-1][:10]
            top_features = [self.feature_names[int(i)] for i in indices]
            top_values = [float(shap_vals_anomaly[int(i)]) for i in indices]

            colors = ['red' if v > 0 else 'green' for v in top_values]
            plt.barh(range(len(top_features)), top_values, color=colors, alpha=0.7)
            plt.yticks(range(len(top_features)), top_features)
            plt.xlabel('SHAP Value (Impact on Prediction)', fontsize=12)
            plt.title(f'Top Features for {telemetry["device_id"]}', fontsize=14, fontweight='bold')
            plt.axvline(x=0, color='black', linestyle='-', linewidth=0.5)
            plt.grid(axis='x', alpha=0.3)

            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor='red', alpha=0.7, label='Increases Anomaly Score'),
                Patch(facecolor='green', alpha=0.7, label='Decreases Anomaly Score')
            ]
            plt.legend(handles=legend_elements, loc='best')

        except Exception as e:
            print(f"⚠️ Bar plot failed: {e}")
            plt.text(
                0.5, 0.5,
                f'SHAP visualization failed\nSee console for values',
                ha='center', va='center',
                transform=plt.gca().transAxes
            )

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            print(f"✅ Explanation saved: {save_path}")
        else:
            plt.show()

        plt.close()



# ============================================================================
# EXAMPLE USAGE
# ============================================================================

if __name__ == "__main__":
    print("=" * 80)
    print("🔍 EXPLAINABLE AI WITH SHAP")
    print("=" * 80)
    
    # Initialize explainer
    explainer = ExplainableAI()
    
    # Example 1: Explain anomalous device
    print("\n" + "=" * 80)
    print("Example 1: ANOMALOUS Device")
    print("=" * 80)
    
    anomalous_device = {
        'device_id': 'camera_suspicious',
        'cpu_usage': 95.0,
        'memory_usage': 85.5,
        'network_in_kb': 1200,
        'network_out_kb': 2400,
        'packet_rate': 850,
        'avg_response_time_ms': 300,
        'service_access_count': 5,
        'failed_auth_attempts': 8,
        'is_encrypted': 0,
        'geo_location_variation': 18.5
    }
    
    explanation1 = explainer.explain_detection(anomalous_device)
    
    print(f"\n{explanation1['explanation']}")
    print(f"\nTop 3 Contributing Factors:")
    for i, factor in enumerate(explanation1['top_contributing_factors'][:3], 1):
        print(f"{i}. {factor['feature']}: {factor['feature_value']:.2f} (SHAP: {factor['shap_value']:.4f})")
    
    # Visualize
    try:
        explainer.visualize_explanation(anomalous_device, "explanation_anomaly.png")
    except Exception as e:
        print(f"⚠️ Visualization failed: {e}")
    
    # Example 2: Explain normal device
    print("\n" + "=" * 80)
    print("Example 2: NORMAL Device")
    print("=" * 80)
    
    normal_device = {
        'device_id': 'sensor_normal',
        'cpu_usage': 28.5,
        'memory_usage': 35.2,
        'network_in_kb': 420,
        'network_out_kb': 380,
        'packet_rate': 120,
        'avg_response_time_ms': 85.3,
        'service_access_count': 3,
        'failed_auth_attempts': 0,
        'is_encrypted': 1,
        'geo_location_variation': 2.1
    }
    
    explanation2 = explainer.explain_detection(normal_device)
    
    print(f"\n{explanation2['explanation']}")
    
    try:
        explainer.visualize_explanation(normal_device, "explanation_normal.png")
    except Exception as e:
        print(f"⚠️ Visualization failed: {e}")
    
    print("\n✅ All explanations generated!")
    print("=" * 80)