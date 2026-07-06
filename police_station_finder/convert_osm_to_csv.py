"""
Convert existing OpenStreetMap police-station data to police_stations_master.csv
for the Police Station Finder website.

Supported inputs:
- Overpass API JSON with {"elements": [...]}
- GeoJSON FeatureCollection
- Existing CSV with common police station columns

Usage:
  python police_station_finder/convert_osm_to_csv.py input_file output_csv

Examples:
  python police_station_finder/convert_osm_to_csv.py osm_police.json police_station_finder/data/police_stations_master.csv
  python police_station_finder/convert_osm_to_csv.py osm_police.geojson police_station_finder/data/police_stations_master.csv
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Any


COLUMNS = [
    "state",
    "district",
    "police_station",
    "address",
    "phone",
    "email",
    "latitude",
    "longitude",
    "commissionerate",
    "website",
    "source_url",
    "last_updated",
    "confidence",
    "missing_coordinates",
]


def clean(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    if s.lower() in {"nan", "none", "null", "na", "n/a", "-"}:
        return ""
    return s


def valid_coord(lat: Any, lon: Any) -> bool:
    try:
        lat = float(lat)
        lon = float(lon)
    except Exception:
        return False
    return 6 <= lat <= 38.5 and 68 <= lon <= 98.5


def address_from_tags(tags: dict[str, Any]) -> str:
    parts = [
        tags.get("addr:housenumber"),
        tags.get("addr:street"),
        tags.get("addr:suburb"),
        tags.get("addr:city"),
        tags.get("addr:district"),
        tags.get("addr:postcode"),
    ]
    return ", ".join(clean(x) for x in parts if clean(x)) or clean(tags.get("address"))


def osm_element_to_row(el: dict[str, Any], default_state: str = "") -> dict[str, Any]:
    tags = el.get("tags") or {}
    lat = el.get("lat") or (el.get("center") or {}).get("lat")
    lon = el.get("lon") or (el.get("center") or {}).get("lon")
    osm_type = el.get("type", "node")
    osm_id = el.get("id", "")
    state = clean(tags.get("addr:state") or tags.get("state") or default_state)
    district = clean(tags.get("addr:district") or tags.get("district") or tags.get("is_in:district") or tags.get("addr:city"))
    name = clean(tags.get("name") or tags.get("official_name") or tags.get("name:en") or tags.get("operator") or "Police Station")
    return {
        "state": state,
        "district": district,
        "police_station": name,
        "address": address_from_tags(tags),
        "phone": clean(tags.get("phone") or tags.get("contact:phone")),
        "email": clean(tags.get("email") or tags.get("contact:email")),
        "latitude": clean(lat),
        "longitude": clean(lon),
        "commissionerate": clean(tags.get("operator") or tags.get("network")),
        "website": clean(tags.get("website") or tags.get("contact:website")),
        "source_url": f"https://www.openstreetmap.org/{osm_type}/{osm_id}" if osm_id else "",
        "last_updated": "",
        "confidence": "0.55",
        "missing_coordinates": "false" if valid_coord(lat, lon) else "true",
    }


def geojson_feature_to_row(feature: dict[str, Any]) -> dict[str, Any]:
    props = feature.get("properties") or {}
    geom = feature.get("geometry") or {}
    coords = geom.get("coordinates") or []
    lon = lat = ""
    if geom.get("type") == "Point" and len(coords) >= 2:
        lon, lat = coords[0], coords[1]
    tags = props.get("tags") if isinstance(props.get("tags"), dict) else props
    row = osm_element_to_row({"tags": tags, "lat": lat, "lon": lon, "type": props.get("type", "node"), "id": props.get("id", "")})
    # Prefer already-normalized columns if present.
    aliases = {
        "state": ["state", "addr:state"],
        "district": ["district", "addr:district", "addr_city", "addr:city"],
        "police_station": ["police_station", "police station", "name", "official_name"],
        "address": ["address", "addr:full"],
        "phone": ["phone", "contact:phone"],
        "email": ["email", "contact:email"],
        "website": ["website", "contact:website"],
        "source_url": ["source_url"],
    }
    for out_col, keys in aliases.items():
        for k in keys:
            if clean(props.get(k)):
                row[out_col] = clean(props.get(k))
                break
    row["latitude"] = clean(lat or props.get("latitude") or props.get("lat"))
    row["longitude"] = clean(lon or props.get("longitude") or props.get("lon") or props.get("lng"))
    row["missing_coordinates"] = "false" if valid_coord(row["latitude"], row["longitude"]) else "true"
    return row


def read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    output = []
    for r in rows:
        lowered = {str(k).strip().lower(): v for k, v in r.items()}
        row = {c: clean(lowered.get(c, r.get(c, ""))) for c in COLUMNS}
        row["police_station"] = row["police_station"] or clean(lowered.get("name") or lowered.get("station") or lowered.get("police station"))
        row["longitude"] = row["longitude"] or clean(lowered.get("lon") or lowered.get("lng"))
        row["latitude"] = row["latitude"] or clean(lowered.get("lat"))
        row["missing_coordinates"] = "false" if valid_coord(row["latitude"], row["longitude"]) else "true"
        row["confidence"] = row["confidence"] or "0.55"
        output.append(row)
    return output


def load_rows(input_path: Path) -> list[dict[str, Any]]:
    suffix = input_path.suffix.lower()
    if suffix == ".csv":
        return read_csv(input_path)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "elements" in data:
        return [osm_element_to_row(el) for el in data.get("elements", [])]
    if isinstance(data, dict) and data.get("type") == "FeatureCollection":
        return [geojson_feature_to_row(f) for f in data.get("features", [])]
    if isinstance(data, list):
        return [osm_element_to_row(el) for el in data]
    raise ValueError("Unsupported input format. Use Overpass JSON, GeoJSON, or CSV.")


def dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = {}
    for r in rows:
        key = "|".join([
            clean(r.get("state")).lower(),
            clean(r.get("district")).lower(),
            clean(r.get("police_station")).lower(),
            clean(r.get("latitude"))[:8],
            clean(r.get("longitude"))[:8],
        ])
        if key not in seen:
            seen[key] = r
    return list(seen.values())


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python police_station_finder/convert_osm_to_csv.py input_file output_csv")
        raise SystemExit(1)
    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    rows = dedupe(load_rows(input_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow({c: r.get(c, "") for c in COLUMNS})
    print(f"Converted {len(rows):,} records")
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
