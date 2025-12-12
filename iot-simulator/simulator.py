import json
import random
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt
from faker import Faker
from dotenv import load_dotenv
import os

# Charger les variables d'environnement (.env si présent)
load_dotenv()

MQTT_HOST = os.getenv("MQTT_HOST", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
TOPIC_PREFIX = os.getenv("MQTT_TOPIC_PREFIX", "devices")

fake = Faker()

# ============================================================================
# CONFIG : nombre de devices + rythme d'envoi
# ============================================================================

NUM_CAMERAS = int(os.getenv("SIM_CAMERAS", "25"))
NUM_SENSORS = int(os.getenv("SIM_SENSORS", "60"))
NUM_THERMOSTATS = int(os.getenv("SIM_THERMOSTATS", "25"))
NUM_LIGHTS = int(os.getenv("SIM_LIGHTS", "40"))

BATCH_SIZE = int(os.getenv("SIM_BATCH_SIZE", "15"))      # nb messages par tick
SLEEP_SECONDS = float(os.getenv("SIM_SLEEP", "0.5"))     # pause entre ticks

# Probabilités globales
NORMAL_PROB = float(os.getenv("SIM_NORMAL_PROB", "0.85"))  # 85% normal, 15% attaques

ATTACK_TYPES = ["normal", "dos", "injection", "spoofing"]

# ============================================================================
# Générer une grande liste de devices (pas juste 4)
# ============================================================================

DEVICES = (
    [{"id": f"camera_{i:02d}", "type": "camera"} for i in range(1, NUM_CAMERAS + 1)] +
    [{"id": f"sensor_{i:02d}", "type": "sensor"} for i in range(1, NUM_SENSORS + 1)] +
    [{"id": f"thermostat_{i:02d}", "type": "thermostat"} for i in range(1, NUM_THERMOSTATS + 1)] +
    [{"id": f"smart_light_{i:02d}", "type": "smart"} for i in range(1, NUM_LIGHTS + 1)]
)

DEVICE_IDS = [d["id"] for d in DEVICES]

# ============================================================================
# Génération de telemetry
# ============================================================================

def generate_telemetry(device, attack_type="normal"):
    """
    Génère une télémétrie compatible avec ton API / ML :
    - device_id, device_type
    - cpu_usage, memory_usage
    - network_in_kb, network_out_kb
    - packet_rate, avg_response_time_ms
    - service_access_count, failed_auth_attempts
    - is_encrypted, geo_location_variation
    + attack_label (pour analyse offline)
    + comm_target (optionnel) pour créer des edges dans ton graph
    """

    # Baselines
    base_cpu = random.uniform(10, 40)
    base_mem = random.uniform(20, 60)
    base_in = random.randint(50, 400)
    base_out = random.randint(50, 400)
    base_packets = random.randint(50, 300)
    base_resp = random.uniform(30, 200)
    base_access = random.randint(1, 8)
    base_failed_auth = random.randint(0, 2)
    base_geo_var = random.uniform(0.0, 3.0)

    # Patterns d'attaque
    if attack_type == "dos":
        cpu = base_cpu + random.uniform(40, 55)
        packets = base_packets + random.randint(800, 1500)
        failed_auth = base_failed_auth
        # un DoS peut pousser plus de trafic
        base_out = min(2000, base_out + random.randint(400, 1200))

    elif attack_type == "injection":
        cpu = base_cpu + random.uniform(20, 35)
        packets = base_packets + random.randint(200, 500)
        failed_auth = random.randint(8, 20)

    elif attack_type == "spoofing":
        cpu = base_cpu + random.uniform(5, 15)
        packets = base_packets + random.randint(100, 300)
        failed_auth = base_failed_auth
        base_geo_var = random.uniform(20.0, 60.0)

    else:  # normal
        cpu = base_cpu
        packets = base_packets
        failed_auth = base_failed_auth

    # (OPTIONNEL) créer des liens "qui parle à qui"
    # 60% des messages ont une cible -> edges dans le graphe
    comm_target = None
    if random.random() < 0.6:
        # éviter que device parle à lui-même
        comm_target = random.choice([x for x in DEVICE_IDS if x != device["id"]])

    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device["id"],
        "device_type": device["type"],

        "cpu_usage": round(min(cpu, 100.0), 2),
        "memory_usage": round(min(base_mem, 100.0), 2),

        "network_in_kb": int(base_in),
        "network_out_kb": int(base_out),

        "packet_rate": int(packets),
        "avg_response_time_ms": round(base_resp, 2),

        "service_access_count": int(base_access),
        "failed_auth_attempts": int(failed_auth),

        "is_encrypted": 1 if random.random() > 0.2 else 0,
        "geo_location_variation": round(base_geo_var, 2),

        # Utile pour analyse / entrainement offline
        "attack_label": attack_type,

        # NEW: utile pour le network graph (facultatif mais recommandé)
        "comm_target": comm_target,
    }

    return payload


def pick_attack_type(device_type: str) -> str:
    """
    Optionnel: rendre les attaques un peu plus réalistes selon le type de device.
    """
    if random.random() < NORMAL_PROB:
        return "normal"

    # pondération simple
    if device_type == "camera":
        return random.choices(["dos", "spoofing", "injection"], weights=[0.55, 0.25, 0.20])[0]
    if device_type == "sensor":
        return random.choices(["dos", "spoofing", "injection"], weights=[0.35, 0.45, 0.20])[0]
    if device_type == "thermostat":
        return random.choices(["dos", "spoofing", "injection"], weights=[0.25, 0.25, 0.50])[0]
    return random.choice(["dos", "injection", "spoofing"])


def main():
    client = mqtt.Client(client_id="ai-iot-simulator")

    print(f"🔌 Connexion au broker MQTT {MQTT_HOST}:{MQTT_PORT} ...")
    print(f"📦 Devices: {len(DEVICES)} | batch={BATCH_SIZE} | sleep={SLEEP_SECONDS}s")

    client.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
    client.loop_start()

    try:
        while True:
            # Envoie en batch -> tu remplis vite la DB + l'analyse réseau
            for _ in range(BATCH_SIZE):
                device = random.choice(DEVICES)
                attack_type = pick_attack_type(device["type"])

                payload = generate_telemetry(device, attack_type)

                topic = f"{TOPIC_PREFIX}/{device['id']}/telemetry"
                msg = json.dumps(payload)

                client.publish(topic, msg, qos=0, retain=False)
                print(f"[MQTT] → {topic} | {attack_type.upper()} | target={payload.get('comm_target')}")

            time.sleep(SLEEP_SECONDS)

    except KeyboardInterrupt:
        print("\n🛑 Arrêt du simulateur MQTT")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
