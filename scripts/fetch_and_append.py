import os
import requests
import pandas as pd
from datetime import datetime, timezone
import time

ENDPOINT = os.getenv("ENDPOINT")
if not ENDPOINT:
    raise ValueError("No se encontró la variable de entorno ENDPOINT")

# Nombre del CSV (uno por mes)
now = datetime.now(timezone.utc)
csv_name = f"endpoint_history_{now.strftime('%Y-%m')}.csv"

# Intentos de descarga con reintento simple
for attempt in range(5):
    try:
        resp = requests.get(ENDPOINT, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        break
    except Exception as e:
        print(f"Intento {attempt+1} falló: {e}")
        time.sleep(5)
else:
    raise Exception("No se pudo descargar el endpoint tras varios intentos.")

# Convertir en DataFrame
df = pd.DataFrame(data)
df["timestamp_utc"] = now.isoformat()

# Crear o anexar CSV
if os.path.exists(csv_name):
    old = pd.read_csv(csv_name)
    df = pd.concat([old, df], ignore_index=True)

df.to_csv(csv_name, index=False)
print(f"Guardado {len(df)} filas en {csv_name}")
