"""
Test the fixed system
"""

import requests
import json

# Your normal data
test_data = {
    "device_id": "sensor_15",
    "device_type": "sensor", 
    "cpu_usage": 12.3,
    "memory_usage": 18.9,
    "network_in_kb": 140,
    "network_out_kb": 110,
    "packet_rate": 32,
    "avg_response_time_ms": 28,
    "service_access_count": 2,
    "failed_auth_attempts": 0,
    "is_encrypted": 1,
    "geo_location_variation": 0.2
}

def test_normal_data():
    print("🧪 Testing NORMAL device data...")
    print(f"📊 Data: CPU {test_data['cpu_usage']}%, Memory {test_data['memory_usage']}%, Packets {test_data['packet_rate']}/s")
    
    response = requests.post("http://localhost:8000/api/ml/detect", json=test_data)
    
    if response.status_code == 200:
        result = response.json()
        print("✅ Request successful!")
        print(f"🔍 Result: Anomaly: {result['is_anomaly']}")
        print(f"🎯 Confidence: {result['confidence_score']}")
        print(f"📊 Model votes: {result['model_votes']}")
        
        if not result['is_anomaly']:
            print("🎉 SUCCESS! Normal data correctly classified!")
        else:
            print("❌ Still detecting anomaly - need to investigate further")
            
    else:
        print(f"❌ Request failed: {response.status_code}")

if __name__ == "__main__":
    test_normal_data()