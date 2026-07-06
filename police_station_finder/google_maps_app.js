let map, infoWindow;
let markers = [];
let allRows = [];
let filteredRows = [];

const INDIA_CENTER = { lat: 22.9734, lng: 78.6569 };
const $ = id => document.getElementById(id);

initPage();

function initPage(){
  restoreTheme();
  $('themeBtn').addEventListener('click', toggleTheme);
  $('loadMapBtn').addEventListener('click', loadGoogleMaps);
  $('csvFile').addEventListener('change', handleFile);
  $('searchInput').addEventListener('input', debounce(applyFilters, 200));
  $('stateFilter').addEventListener('change', () => { populateDistricts(); applyFilters(); });
  $('districtFilter').addEventListener('change', applyFilters);
  $('markerLimit').addEventListener('change', renderMarkers);
  $('nearMeBtn').addEventListener('click', nearestToMe);
  $('exportBtn').addEventListener('click', exportFilteredCSV);
  const savedKey = localStorage.getItem('googleMapsApiKey');
  if(savedKey) $('apiKey').value = savedKey;
  autoLoadCSV();
}

async function autoLoadCSV(){
  try{
    const res = await fetch('data/police_stations_master.csv', {cache:'no-store'});
    if(!res.ok) throw new Error('CSV not found');
    const text = await res.text();
    setData(parseCSV(text), 'Auto-loaded data/police_stations_master.csv');
  }catch(e){
    setStatus('No auto CSV found. Upload police_stations_master.csv.');
  }
}

function loadGoogleMaps(){
  const key = $('apiKey').value.trim();
  if(!key){ alert('Paste Google Maps JavaScript API key first.'); return; }
  localStorage.setItem('googleMapsApiKey', key);
  if(window.google && google.maps){ initMap(); return; }
  setStatus('Loading Google Maps...');
  window.initGooglePoliceMap = initMap;
  const script = document.createElement('script');
  script.src = `https://maps.googleapis.com/maps/api/js?key=${encodeURIComponent(key)}&callback=initGooglePoliceMap`;
  script.async = true;
  script.defer = true;
  script.onerror = () => setStatus('Google Maps failed to load. Check API key, billing, API restrictions, and internet.');
  document.head.appendChild(script);
}

function initMap(){
  map = new google.maps.Map($('googleMap'), {
    center: INDIA_CENTER,
    zoom: 5,
    mapTypeControl: true,
    streetViewControl: true,
    fullscreenControl: true,
  });
  infoWindow = new google.maps.InfoWindow();
  setStatus('Google Map loaded.');
  renderMarkers();
}

function handleFile(e){
  const file = e.target.files[0];
  if(!file) return;
  const reader = new FileReader();
  reader.onload = () => setData(parseCSV(String(reader.result || '')), `Uploaded ${file.name}`);
  reader.readAsText(file);
}

function setData(rows, message){
  allRows = rows.map(normalizeRow).filter(r => r.police_station || r.address);
  populateStates();
  applyFilters();
  setStatus(`${message}. Loaded ${allRows.length.toLocaleString()} records.`);
}

function normalizeRow(row){
  const o = {};
  Object.keys(row || {}).forEach(k => o[normalizeKey(k)] = row[k]);
  return {
    state: clean(getAny(o,['state','state_name','addr_state'])),
    district: clean(getAny(o,['district','district_name','dist','police_district','addr_district','addr_city'])),
    police_station: clean(getAny(o,['police_station','police_station_name','police_station_name','station','station_name','ps_name','name','official_name','thana'])),
    address: clean(getAny(o,['address','full_address','location','office_address'])),
    phone: clean(getAny(o,['phone','phone_number','telephone','mobile','contact','contact_phone'])),
    email: clean(getAny(o,['email','email_id','contact_email'])),
    latitude: toNum(getAny(o,['latitude','lat'])),
    longitude: toNum(getAny(o,['longitude','lon','lng','long'])),
    commissionerate: clean(getAny(o,['commissionerate','operator','network'])),
    website: clean(getAny(o,['website','official_website','contact_website'])),
    source_url: clean(getAny(o,['source_url','source','source_link','osm_url'])),
    confidence: toNum(getAny(o,['confidence'])) ?? 0,
  };
}

function populateStates(){ fillSelect($('stateFilter'), unique(allRows.map(r=>r.state)), 'All states'); populateDistricts(); }
function populateDistricts(){
  const st = $('stateFilter').value;
  const current = $('districtFilter').value;
  const districts = unique(allRows.filter(r => !st || r.state === st).map(r => r.district));
  fillSelect($('districtFilter'), districts, 'All districts');
  if(districts.includes(current)) $('districtFilter').value = current;
}
function fillSelect(el, values, label){ el.innerHTML = `<option value="">${label}</option>` + values.map(v => `<option value="${escapeAttr(v)}">${escapeHtml(v)}</option>`).join(''); }

function applyFilters(){
  const q = $('searchInput').value.trim().toLowerCase();
  const st = $('stateFilter').value;
  const dist = $('districtFilter').value;
  filteredRows = allRows.filter(r => {
    if(st && r.state !== st) return false;
    if(dist && r.district !== dist) return false;
    if(q){
      const blob = [r.state,r.district,r.police_station,r.address,r.phone,r.email].join(' ').toLowerCase();
      if(!blob.includes(q)) return false;
    }
    return true;
  });
  $('countInfo').textContent = `${filteredRows.length.toLocaleString()} records`;
  renderList();
  renderMarkers();
}

function renderMarkers(){
  if(!map) return;
  markers.forEach(m => m.setMap(null));
  markers = [];
  const limit = Number($('markerLimit').value || 1000);
  const withCoords = filteredRows.filter(r => isCoord(r.latitude, r.longitude));
  const rows = withCoords.slice(0, limit);
  const bounds = new google.maps.LatLngBounds();
  rows.forEach(r => {
    const pos = {lat: Number(r.latitude), lng: Number(r.longitude)};
    const marker = new google.maps.Marker({position: pos, map, title: r.police_station || 'Police Station'});
    marker.addListener('click', () => openInfo(r, marker));
    markers.push(marker);
    bounds.extend(pos);
  });
  if(rows.length) map.fitBounds(bounds);
  const msg = `Showing ${rows.length.toLocaleString()} markers out of ${withCoords.length.toLocaleString()} coordinate records.`;
  setStatus(msg + (withCoords.length > limit ? ' Increase marker limit to show more.' : ''));
}

function openInfo(r, marker){
  const dir = isCoord(r.latitude,r.longitude) ? `<a target="_blank" href="https://www.google.com/maps/dir/?api=1&destination=${r.latitude},${r.longitude}">Directions</a>` : '';
  const source = r.source_url ? `<a target="_blank" href="${escapeAttr(r.source_url)}">Source</a>` : '';
  const html = `<div style="max-width:320px"><h3>${escapeHtml(r.police_station || 'Police Station')}</h3><p>${escapeHtml(r.address || '')}</p><p><b>${escapeHtml(r.district || '')}</b>, ${escapeHtml(r.state || '')}</p><p>Phone: ${escapeHtml(r.phone || 'N/A')}</p><p>${dir} ${source}</p></div>`;
  infoWindow.setContent(html);
  infoWindow.open(map, marker);
}

function renderList(){
  const rows = filteredRows.slice(0, 30);
  $('resultList').innerHTML = rows.map((r,i) => `<div class="gm-item"><h4>${escapeHtml(r.police_station || 'Police Station')}</h4><p>${escapeHtml(r.district || '')}, ${escapeHtml(r.state || '')}</p><p>${escapeHtml(r.address || '')}</p><p>Phone: ${escapeHtml(r.phone || 'N/A')}</p><button class="btn ghost small" data-idx="${i}" type="button">Show on map</button></div>`).join('') || '<p>No data found.</p>';
  document.querySelectorAll('[data-idx]').forEach(btn => btn.addEventListener('click', () => {
    const r = rows[Number(btn.dataset.idx)];
    if(!isCoord(r.latitude,r.longitude)){ alert('This record has no coordinates.'); return; }
    map?.setCenter({lat:Number(r.latitude),lng:Number(r.longitude)}); map?.setZoom(15);
  }));
}

function nearestToMe(){
  if(!navigator.geolocation){ alert('Geolocation not supported.'); return; }
  navigator.geolocation.getCurrentPosition(pos => {
    const lat = pos.coords.latitude, lon = pos.coords.longitude;
    const rows = allRows.filter(r=>isCoord(r.latitude,r.longitude)).map(r => ({...r, distance:haversine(lat,lon,r.latitude,r.longitude)})).sort((a,b)=>a.distance-b.distance).slice(0,5);
    $('nearestBox').innerHTML = '<h3>Nearest Stations</h3>' + rows.map(r => `<div class="gm-item"><b>${escapeHtml(r.police_station)}</b><p>${r.distance.toFixed(2)} km - ${escapeHtml(r.district)}, ${escapeHtml(r.state)}</p><a target="_blank" href="https://www.google.com/maps/dir/?api=1&destination=${r.latitude},${r.longitude}">Directions</a></div>`).join('');
    if(map){ map.setCenter({lat, lng:lon}); map.setZoom(12); new google.maps.Marker({position:{lat,lng:lon},map,title:'Your location',icon:'http://maps.google.com/mapfiles/ms/icons/blue-dot.png'}); }
  }, err => alert(err.message));
}

function exportFilteredCSV(){
  const cols = ['state','district','police_station','address','phone','email','latitude','longitude','commissionerate','website','source_url','confidence'];
  const csv = cols.join(',') + '\n' + filteredRows.map(r => cols.map(c => csvEscape(r[c])).join(',')).join('\n');
  const blob = new Blob([csv], {type:'text/csv;charset=utf-8'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'google_maps_filtered_police_stations.csv'; a.click(); URL.revokeObjectURL(a.href);
}

function parseCSV(text){
  text = String(text || '').replace(/^\uFEFF/, '');
  const lines=[]; let cur='', q=false;
  for(let i=0;i<text.length;i++){ const ch=text[i], nx=text[i+1]; if(ch==='"'&&q&&nx==='"'){cur+='"';i++;} else if(ch==='"'){q=!q;} else if((ch==='\n'||ch==='\r')&&!q){ if(cur){lines.push(cur);cur='';} if(ch==='\r'&&nx==='\n') i++; } else cur+=ch; }
  if(cur) lines.push(cur);
  if(!lines.length) return [];
  const headers = splitCSV(lines[0]).map(h=>h.trim());
  return lines.slice(1).filter(Boolean).map(line => { const vals=splitCSV(line); const o={}; headers.forEach((h,i)=>o[h]=vals[i]??''); return o; });
}
function splitCSV(line){ const out=[]; let cur='', q=false; for(let i=0;i<line.length;i++){ const ch=line[i], nx=line[i+1]; if(ch==='"'&&q&&nx==='"'){cur+='"';i++;} else if(ch==='"'){q=!q;} else if(ch===','&&!q){out.push(cur);cur='';} else cur+=ch; } out.push(cur); return out; }

function normalizeKey(k){ return String(k||'').replace(/^\uFEFF/,'').trim().toLowerCase().replace(/[^a-z0-9]+/g,'_').replace(/^_+|_+$/g,''); }
function getAny(o, keys){ for(const k of keys){ const nk=normalizeKey(k); if(o[nk] !== undefined && String(o[nk]).trim() !== '') return o[nk]; } return ''; }
function clean(v){ if(v==null) return ''; const s=String(v).replace(/\s+/g,' ').trim(); return ['nan','none','null','na','n/a','-'].includes(s.toLowerCase()) ? '' : s; }
function toNum(v){ const s=clean(v); if(!s) return null; const n=Number(String(s).replace(/[^0-9.\-]/g,'')); return Number.isFinite(n) ? n : null; }
function isCoord(lat,lon){ return Number.isFinite(Number(lat)) && Number.isFinite(Number(lon)) && lat>=6 && lat<=38.5 && lon>=68 && lon<=98.5; }
function unique(v){ return [...new Set(v.filter(Boolean))].sort((a,b)=>a.localeCompare(b)); }
function escapeHtml(s){ return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function escapeAttr(s){ return escapeHtml(s).replace(/'/g,'&#39;'); }
function csvEscape(v){ const s=v==null?'':String(v); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g,'""')}"` : s; }
function debounce(fn,ms){ let t; return (...args)=>{clearTimeout(t);t=setTimeout(()=>fn(...args),ms)}; }
function setStatus(s){ $('status').textContent = s; }
function rad(d){ return d*Math.PI/180; }
function haversine(lat1,lon1,lat2,lon2){ const R=6371,dLat=rad(lat2-lat1),dLon=rad(lon2-lon1); const a=Math.sin(dLat/2)**2 + Math.cos(rad(lat1))*Math.cos(rad(lat2))*Math.sin(dLon/2)**2; return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a)); }
function toggleTheme(){ const dark=document.documentElement.dataset.theme!=='dark'; document.documentElement.dataset.theme=dark?'dark':''; localStorage.setItem('policeFinderTheme',dark?'dark':'light'); $('themeBtn').textContent=dark?'Light Mode':'Dark Mode'; }
function restoreTheme(){ if(localStorage.getItem('policeFinderTheme')==='dark'){document.documentElement.dataset.theme='dark'; $('themeBtn').textContent='Light Mode';} }
