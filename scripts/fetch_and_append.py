# scripts/fetch_and_append.py
# Versión para endpoint que devuelve un array; imprime muestra del primer item para debug.
import os
import requests
import pandas as pd
import hashlib
import json
import time
from datetime import datetime, timezone

ENDPOINT = os.getenv("ENDPOINT")
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
            print(f"[fetch_json] intento {i+1} falló: {e}")
            time.sleep(delay)
    raise RuntimeError(f"No fue posible obtener JSON tras {attempts} intentos. Última excepción: {last_exc}")

def items_from_response(data):
    # Si es lista, devolver lista de dicts (o envolver elementos no-dict)
    if isinstance(data, list):
        return [item if isinstance(item, dict) else {"value": item} for item in data]

    # Si es dict, buscar claves comunes
    if isinstance(data, dict):
        for k in ("data","rows","results","items","features","values","records"):
            if k in data and isinstance(data[k], list):
                return [itm if isinstance(itm, dict) else {"value": itm} for itm in data[k]]

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

        all_values_are_dicts = all(isinstance(v, dict) for v in data.values())
        if all_values_are_dicts and len(data) > 0:
            subitems = []
            for k,v in data.items():
                d = v.copy()
                if "id" not in d:
                    d["_key"] = k
                subitems.append(d)
            return subitems

        return [data]

    return [{"value": data}]

def deep_find_any(item, candidates):
    """Busca recursivamente en diccionarios y listas una clave que coincida (tolerante)."""
    if item is None:
        return None
    if isinstance(item, dict):
        for k,v in item.items():
            for cand in candidates:
                if isinstance(k, str) and k.lower() == cand.lower():
                    return v
            # intentar recursión
            res = deep_find_any(v, candidates)
            if res is not None:
                return res
        return None
    if isinstance(item, list):
        for elem in item:
            res = deep_find_any(elem, candidates)
            if res is not None:
                return res
    return None

def extract_fields(item):
    """Extrae scacodigo, scatipo, scanombre, source_time y payload."""
    if not isinstance(item, dict):
        payload = json.dumps(item, ensure_ascii=False)
        return {"scacodigo": None, "scatipo": None, "scanombre": None, "source_time": None, "payload": payload}

    # unwrap common wrappers
    for wrapper in ("attributes","properties","fields","row"):
        if wrapper in item and isinstance(item[wrapper], dict):
            item = item[wrapper]
            break

    # intenta encontrar campos con varios nombres posibles (busca recursivamente)
    scacodigo = deep_find_any(item, ["SCACODIGO","scacodigo","scacod","codigo","id"])
    scatipo   = deep_find_any(item, ["SCATIPO","scatipo","tipo","category"])
    scanombre = deep_find_any(item, ["SCANOMBRE","scanombre","nombre","name","descripcion","description"])

    # tratar source_time (varios nombres)
    source_time = deep_find_any(item, ["source_time","timestamp","time","fecha","date","created_at","hora"])
    # normalizar simples timestamps numéricos o strings -> iso
    try:
        if isinstance(source_time, (int,float)):
            if source_time > 1e12:
                source_time = datetime.fromtimestamp(source_time/1000.0, tz=timezone.utc).isoformat()
            elif source_time > 1e9:
                source_time = datetime.fromtimestamp(source_time, tz=timezone.utc).isoformat()
            else:
                source_time = None
        elif isinstance(source_time, str):
            try:
                source_time = pd.to_datetime(source_time, utc=True).isoformat()
            except Exception:
                pass
    except Exception:
        source_time = None

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
    items = items_from_response(j)
    print(f"[main] Items detectados: {len(items)}")
    # imprimir muestra del primer item para debugging
    if len(items) > 0:
        try:
            sample = items[0]
            print("[main] Ejemplo primer item (formateado):")
            print(json.dumps(sample, ensure_ascii=False, indent=2))
        except Exception as e:
            print(f"[main] No pude imprimir el primer item: {e}")

    if not items:
        print("[main] No se detectaron items en la respuesta. Guardando la respuesta cruda en una fila.")
        items = [ {"_raw": j} ]

    rows = []
    for it in items:
        r = extract_fields(it)
        r["timestamp_utc"] = now.isoformat()
        r["__hash"] = make_hash(r)
        rows.append(r)

    new_df = pd.DataFrame(rows)

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
