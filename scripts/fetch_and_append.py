#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import requests
import pandas as pd
from datetime import datetime, timezone

ENDPOINT = os.getenv("ENDPOINT")
DEBUG_SAVE = os.getenv("DEBUG_SAVE", "false").lower() in ("1", "true", "yes")

if not ENDPOINT:
    raise ValueError("No se encontró la variable de entorno ENDPOINT")

def fetch_json(url):
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()

def make_hash(row):
    s = f"{row.get('scacodigo') or ''}|{row.get('source_time') or ''}|{row.get('payload') or ''}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def main():
    now = datetime.now(timezone.utc)
    csv_name = f"endpoint_history_{now.strftime('%Y-%m')}.csv"

    j = fetch_json(ENDPOINT)
    if DEBUG_SAVE:
        with open("debug_response.txt", "a", encoding="utf-8") as f:
            f.write(f"{now.isoformat()} -> {json.dumps(j, ensure_ascii=False)}\n")

    if "frames" not in j or not j["frames"]:
        print("[main] No hay frames en la respuesta. Salida sin guardar.")
        sys.exit(0)

    rows = []
    for frame in j["frames"]:
        frame_ts = frame.get("timestamp")
        if not frame_ts:
            continue
        for rec in frame.get("data", []):
            scacodigo = rec.get("ID")
            value = rec.get("VALUE")
            payload = json.dumps({"VALUE": value}, ensure_ascii=False)
            row = {
                "scacodigo": scacodigo,
                "scatipo": None,
                "scanombre": None,
                "source_time": frame_ts,
                "payload": payload,
                "timestamp_utc": now.isoformat()
            }
            row["__hash"] = make_hash(row)
            rows.append(row)

    if not rows:
        print("[main] No quedan filas para guardar después de procesar frames.")
        sys.exit(0)

    new_df = pd.DataFrame(rows)

    # Concatenar con CSV existente si existe
    if os.path.exists(csv_name):
        try:
            old = pd.read_csv(csv_name, dtype=str)
            if "__hash" not in old.columns:
                old["__hash"] = old.apply(lambda r: hashlib.sha256(
                    (str(r.get("scacodigo") or "") + "|" + str(r.get("source_time") or "") + "|" + str(r.get("payload") or "")).encode("utf-8")
                ).hexdigest(), axis=1)
            combined = pd.concat([old, new_df], ignore_index=True, sort=False)
            combined = combined.drop_duplicates(subset="__hash", keep="first")
            combined.to_csv(csv_name, index=False)
            print(f"[main] Archivo actualizado. Total filas: {len(combined)}")
        except Exception as e:
            print(f"[main] Error actualizando CSV: {e}. Se guarda solo lo nuevo.")
            new_df.to_csv(csv_name, index=False)
    else:
        new_df.to_csv(csv_name, index=False)
        print(f"[main] Nuevo CSV creado. Filas guardadas: {len(new_df)}")

if __name__ == "__main__":
    main()
