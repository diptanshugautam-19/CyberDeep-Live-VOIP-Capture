# India Police Station Finder Website

A professional static website for your generated `police_stations_master.csv`.

## Quick Use in VS Code

1. Copy this folder into your project, for example:

   `D:\i4c 5\police_station_finder`

2. Copy your pipeline output CSV:

   PowerShell:

   ```powershell
   Copy-Item output\police_stations_master.csv police_station_finder\data\police_stations_master.csv -Force
   ```

3. Open `police_station_finder/index.html` with **Live Server** in VS Code.

   Or open `index.html` directly and use the **Upload police_stations_master.csv** button.

## Features

- Professional responsive UI
- Global police-station search
- State and district filters
- Coordinate/missing-coordinate filter
- Confidence filter
- Offline-friendly coordinate map on canvas
- Click map point to view details
- Browser geolocation nearest-station finder
- Manual latitude/longitude nearest search
- Export filtered CSV
- Statistics cards
- Dark mode
- Print-friendly layout
- Source URL and confidence display

## CSV columns supported

Works best with:

`state,district,police_station,address,phone,email,latitude,longitude,commissionerate,website,source_url,last_updated,confidence,missing_coordinates`

Extra columns are ignored safely.
