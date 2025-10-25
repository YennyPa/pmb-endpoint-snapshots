#!/usr/bin/env python3
# scripts/fetch_and_append.py
# Versión robusta con manejo de "status:false" y debug opcional.

import os
import sys
import time
import json
import hashlib
import requests
import pandas as pd
from datetime import datetime, timezone

ENDPOINT = os.getenv("ENDPOINT")
DEBUG_SAVE = os.getenv("DEBUG_SAVE", "false").lower() in ("1", "true", "yes")

if not ENDPOINT:
    raise ValueError("No se encontró la variable de entorno ENDPOINT")

def fetch_json(url, attempts=5, delay=5):
    last_exc = None
    for i in range(attempts):
        try:
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            try:
                return r.json()
            except Exception:
                return {"_raw_text": r.text}
        except Exception as e:
            last_exc = e
            print(f"[fetch_json] intento {i+1} falló: {e}", file=sys.stderr)
            time.sleep(delay)
    raise RuntimeError(f"No fue posible obtener JSON tras {attempts} intentos. Última excepción: {last_exc}")

def items_from_response(data):
    """Normaliza la respuesta en una lista de diccionarios (items)."""
    # Lista directa
    if isinstance(data, list):
        return [itm if isinstance(itm, dict) else {"value": itm} for itm in data]

    # Dict
    if isinstance(data, dict):
        # Si es {"status": False} o similar, devolver vacío y dejar que el caller detecte
        # Buscamos claves comunes que contengan listas de registros
        for k in ("data","rows","results","items","features","values","records"):
            if k in data and isinstance(data[k], list):
                return [itm if isinstance(itm, dict) else {"value": itm} for itm in data[k]]

        # Caso columnas + data
        if "columns" in data and "data" in data and isinstance(data["columns"], list) and isinstance(data["data"], list):
            cols = data["columns"]
            rows = []
            for r in data["data"]:
                if isinstance(r, list):
                    mapped = {cols[i]: r[i] if i < len(r) else None for i in range(len(cols))}
                elif isinstance(r, dict):
                    mapped = r
                else:
                    mapped = {"value": r}
                rows.append(mapped)
            return rows

        # Si es dict de dicts (ej: key -> dict), convertir a lista
        all_values_are_dicts = len(data) > 0 and all(isinstance(v, dict) for v in data.values())
        if all_values_are_dicts:
            out = []
            for k,v in data.items():
                d = v.copy()
                if "id" not in d:
                    d["_key"] = k
                out.append(d)
            return out

        # Fallback: envolver el dict como un único item
        return [data]

    # Otro tipo: envolver
    return [{"value": data}]

def find_value_case_insensitive(d, candidates):
    if not isinstance(d, dict):
        return None
    for name in candidates:
        for k in d.keys():
            if isinstance(k, str) and k.lower() == name.lower():
                return d[k]
    # búsqueda parcial (si la clave contiene el candidate)
    for name in candidates:
        for k in d.keys():
            if isinstance(k, str) and name.lower() in k.lower().replace(" ", "").replace("_",""):
                return d[k]
    return None

def try_parse_time(val):
    if val is None:
        return None
    try:
        # epoch heurístico
        if isinstance(val, (int, float)):
            v = int(val)
            if v > 1e12:
                return datetime.fromtimestamp(v/1000.0, tz=timezone.utc).isoformat()
            elif v > 1e9:
                return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
            else:
                return None
        # cadena: dejar que pandas parsee
        ts = pd.to_datetime(str(val), utc=True, errors="coerce")
        if pd.isna(ts):
            return None
        return ts.isoformat()
    except Exception:
        return None

def extract_fields(item):
    """Extrae scacodigo, scatipo, scanombre, source_time, payload (tolerante)."""
    if not isinstance(item, dict):
        payload = json.dumps(item, ensure_ascii=False)
        return {"scacodigo": None, "scatipo": None, "scanombre": None, "source_time": None, "payload": payload}

    # Unwrap comunes
    for wrapper in ("attributes","properties","fields","row"):
        if wrapper in item and isinstance(item[wrapper], dict):
            item = item[wrapper]
            break

    scacodigo = find_value_case_insensitive(item, ["SCACODIGO","scacodigo","scacod","codigo","id"])
    scatipo   = find_value_case_insensitive(item, ["SCATIPO","scatipo","tipo"])
    scanombre = find_value_case_insensitive(item, ["SCANOMBRE","scanombre","nombre","name","desc"])

    # intentar source_time
    source_time = None
    for cand in ("source_time","timestamp","time","fecha","date","created_at","hora"):
        v = find_value_case_insensitive(item, [cand])
        parsed = try_parse_time(v)
        if parsed:
            source_time = parsed
            break

    # fallback: buscar cualquier key con 'time'/'date'/'fecha' en su nombre
    if source_time is None:
        for k,v in item.items():
            if isinstance(k, str) and any(s in k.lower() for s in ("time","date","fecha","hora","timestamp")):
                parsed = try_parse_time(v)
                if parsed:
                    source_time = parsed
                    break

    try:
        payload = json.dumps(item, ensure_ascii=False)
    except Exception:
        payload = str(item)

    return {
        "scacodigo": scacodigo,
        "scatipo": scatipo,
        "scanombre": scanombre,
        "source_time": source_time,
        "payload": payload
    }

def make_hash(row):
    s = f"{row.get('scacodigo') or ''}|{row.get('source_time') or ''}|{row.get('payload') or ''}"
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def main():
    now = datetime.now(timezone.utc)
    csv_name = f"endpoint_history_{now.strftime('%Y-%m')}.csv"

    j = fetch_json(ENDPOINT)

    # Si la API devuelve {"status": false} u otro indicador de "sin datos", no crear fila
    if isinstance(j, dict) and j.get("status") is False:
        print("[main] El endpoint devolvió {'status': false} => no hay datos para guardar. Respuesta completa:")
        print(json.dumps(j, ensure_ascii=False))
        if DEBUG_SAVE:
            with open("debug_response.txt", "a", encoding="utf-8") as f:
                f.write(f"{now.isoformat()} -> {json.dumps(j, ensure_ascii=False)}\n")
        sys.exit(0)

    # Normalizar items
    items = items_from_response(j)
    if not items:
        print("[main] No se detectaron items en la respuesta. Respuesta completa:")
        print(json.dumps(j, ensure_ascii=False))
        if DEBUG_SAVE:
            with open("debug_response.txt", "a", encoding="utf-8") as f:
                f.write(f"{now.isoformat()} -> {json.dumps(j, ensure_ascii=False)}\n")
        sys.exit(0)

    rows = []
    for it in items:
        r = extract_fields(it)
        r["timestamp_utc"] = now.isoformat()
        r["__hash"] = make_hash(r)
        rows.append(r)

    new_df = pd.DataFrame(rows)

    # Si existe CSV, concatenar y dedup por __hash
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
            print(f"[main] Archivo existente actualizado. Filas previas: {len(old)}, nuevas añadidas: {len(new_df)}, total ahora: {len(combined)}")
        except Exception as e:
            print(f"[main] Error leyendo/actualizando CSV existente: {e}. Se crea un nuevo CSV con solo lo nuevo.")
            new_df.to_csv(csv_name, index=False)
            print(f"[main] Guardado {len(new_df)} filas en {csv_name}")
    else:
        new_df.to_csv(csv_name, index=False)
        print(f"[main] Guardado {len(new_df)} filas en {csv_name}")

if __name__ == "__main__":
    main()
