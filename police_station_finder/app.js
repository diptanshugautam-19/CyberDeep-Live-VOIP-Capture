const INDIA_BBOX = { minLat: 6, maxLat: 38.5, minLon: 68, maxLon: 98.5 };
const PAGE_SIZE = 24;

// Highly detailed map coordinates array of India boundary (~60 points)
const INDIA_OUTLINE = [
  [68.1, 23.7], [68.7, 24.3], [70.0, 24.6], [71.0, 25.5], [71.1, 27.0],
  [72.5, 28.5], [73.8, 29.8], [75.1, 30.3], [74.5, 31.2], [74.3, 32.3],
  [74.9, 32.7], [74.0, 34.2], [74.5, 34.8], [75.5, 34.7], [76.5, 35.5],
  [77.8, 35.5], [78.6, 34.8], [79.2, 32.7], [78.8, 32.1], [79.9, 31.0],
  [81.0, 30.2], [84.0, 28.6], [85.2, 27.5], [88.1, 27.3], [88.5, 28.0],
  [88.8, 27.3], [91.5, 27.8], [91.6, 26.9], [89.9, 26.7], [89.9, 25.2],
  [92.1, 25.1], [92.2, 26.1], [93.7, 26.1], [94.5, 27.2], [96.0, 28.2],
  [97.3, 27.9], [97.1, 27.0], [96.2, 26.0], [95.0, 25.5], [94.3, 23.7],
  [92.4, 21.9], [92.2, 20.8], [89.0, 21.7], [87.5, 21.5], [86.5, 20.3],
  [84.5, 19.1], [82.5, 17.8], [80.3, 16.1], [80.0, 13.5], [79.8, 11.2],
  [79.2, 10.3], [79.8, 9.3], [78.2, 8.8], [77.5, 8.0], [76.8, 8.5],
  [76.3, 10.0], [75.0, 12.0], [73.8, 15.0], [72.8, 18.8], [72.1, 21.0],
  [70.0, 21.0], [69.0, 22.8], [68.1, 23.7]
];

let allRows = [];
let filteredRows = [];
let page = 1;
let selectedPoint = null;

const $ = (id) => document.getElementById(id);
const els = {
  search: $('globalSearch'), state: $('stateFilter'), district: $('districtFilter'), coord: $('coordFilter'),
  sort: $('sortBy'), cards: $('cards'), canvas: $('mapCanvas'),
  status: $('dataStatus'), visible: $('visibleCount'), total: $('statTotal'), states: $('statStates'), coords: $('statCoords'),
  pageInfo: $('pageInfo'), nearest: $('nearestResult'), dialog: $('detailDialog'), detail: $('detailContent'),
  searchLocallyBtn: $('searchLocallyBtn')
};
const ctx = els.canvas.getContext('2d');

init();
async function init(){
  bindEvents();
  restoreTheme();
  const cached = localStorage.getItem('policeFinderRows');
  if(cached){
    try { setData(JSON.parse(cached), 'Loaded saved browser data.'); return; } catch {}
  }
  tryAutoLoad();
}

function bindEvents(){
  $('csvFile').addEventListener('change', handleFile);
  $('searchBtn').addEventListener('click', applyFilters);
  $('googleSearchBtn').addEventListener('click', openGoogleMapsSearch);
  if (els.searchLocallyBtn) els.searchLocallyBtn.addEventListener('click', applyFilters);
  
  els.search.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      applyFilters();
    }
  });

  [els.state, els.district, els.coord, els.sort].forEach(el => el.addEventListener('change', applyFilters));
  $('resetBtn').addEventListener('click', resetFilters);
  $('prevPage').addEventListener('click', () => { if(page>1){ page--; renderCards(); }});
  $('nextPage').addEventListener('click', () => { if(page < maxPage()){ page++; renderCards(); }});
  $('nearMeBtn').addEventListener('click', findNearMe);
  $('manualNearBtn').addEventListener('click', () => nearestFrom(Number($('manualLat').value), Number($('manualLon').value)));
  $('themeBtn').addEventListener('click', toggleTheme);
  $('printBtn').addEventListener('click', () => window.print());
  $('closeDialog').addEventListener('click', () => els.dialog.close());
  els.canvas.addEventListener('click', handleMapClick);
}

async function tryAutoLoad(){
  try{
    const res = await fetch('data/police_stations_master.csv', {cache:'no-store'});
    if(!res.ok) throw new Error('CSV not found');
    const text = await res.text();
    const rows = parseCSV(text);
    setData(rows, `Auto-loaded ${rows.length.toLocaleString()} records from data/police_stations_master.csv.`);
  }catch(e){
    setData([], 'No auto CSV found. Upload police_stations_master.csv or load demo data.');
  }
}

function handleFile(e){
  const file = e.target.files[0];
  if(!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const rows = parseCSV(String(reader.result || ''));
    setData(rows, `Uploaded ${rows.length.toLocaleString()} records from ${file.name}.`);
    try { localStorage.setItem('policeFinderRows', JSON.stringify(rows)); } catch { els.status.textContent += ' Browser storage full; data not saved.'; }
  };
  reader.readAsText(file);
}

function setData(rows, message){
  allRows = rows.map(normalizeRow).filter(r => r.police_station || r.address);
  page = 1;
  populateFilters();
  applyFilters();
  els.status.textContent = message;
}

function normalizeRow(r){
  // Accept many possible column names from different pipeline versions / official datasets.
  const out = {};
  Object.keys(r || {}).forEach(k => {
    const key = normalizeKey(k);
    out[key] = r[k];
  });
  const row = {};
  row.state = clean(getAny(out, ['state','state_name','statename','state_ut','state_or_ut']));
  row.district = clean(getAny(out, ['district','district_name','districtname','dist','police_district','policedistrict']));
  row.police_station = clean(getAny(out, [
    'police_station','policestation','police_station_name','policestationname','station','station_name','stationname',
    'ps','ps_name','psname','name','thana','thana_name','nameofpolicestation','name_of_police_station'
  ]));
  row.address = clean(getAny(out, ['address','full_address','fulladdress','location','office_address','officeaddress']));
  row.phone = clean(getAny(out, ['phone','phone_number','phonenumber','telephone','mobile','contact','contact_number','contactnumber','tel']));
  row.email = clean(getAny(out, ['email','email_id','emailid','e_mail','mail']));
  row.latitude = toNum(getAny(out, ['latitude','lat','y','ycoord','y_coordinate']));
  row.longitude = toNum(getAny(out, ['longitude','lon','lng','long','x','xcoord','x_coordinate']));
  row.commissionerate = clean(getAny(out, ['commissionerate','police_commissionerate','policecommissionerate']));
  row.website = clean(getAny(out, ['website','official_website','officialwebsite','url']));
  row.source_url = clean(getAny(out, ['source_url','sourceurl','source','source_link','sourcelink']));
  row.last_updated = clean(getAny(out, ['last_updated','lastupdated','updated','updated_date','updateddate']));
  row.confidence = toNum(getAny(out, ['confidence','confidence_level','confidencelevel'])) ?? 0;
  row.missing_coordinates = !(isCoord(row.latitude, row.longitude));
  return row;
}

function populateFilters(){
  fillSelect(els.state, unique(allRows.map(r => r.state)), 'All States');
  populateDistricts();
}
function populateDistricts(){
  const state = els.state.value;
  const districts = unique(allRows.filter(r => !state || r.state === state).map(r => r.district));
  const current = els.district.value;
  fillSelect(els.district, districts, 'All Districts');
  if(districts.includes(current)) els.district.value = current;
}
function fillSelect(el, values, label){
  el.innerHTML = `<option value="">${label}</option>` + values.map(v => `<option value="${escapeAttr(v)}">${escapeHtml(v)}</option>`).join('');
}
function unique(vals){ return [...new Set(vals.filter(Boolean))].sort((a,b)=>a.localeCompare(b)); }

function dedupeRows(rows){
  const seen = new Map();
  for(const r of rows.map(normalizeRow)){
    const key = [r.state,r.district,r.police_station,roundCoord(r.latitude),roundCoord(r.longitude)].join('|').toLowerCase();
    if(!seen.has(key)) seen.set(key,r);
  }
  return [...seen.values()];
}
function roundCoord(v){ return Number.isFinite(Number(v)) ? Number(v).toFixed(4) : ''; }
function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

function applyFilters(){
  populateDistricts();
  const q = els.search.value.trim().toLowerCase();
  const state = els.state.value;
  const district = els.district.value;
  const coord = els.coord.value;
  filteredRows = allRows.filter(r => {
    if(state && r.state !== state) return false;
    if(district && r.district !== district) return false;
    if(coord === 'with' && r.missing_coordinates) return false;
    if(coord === 'missing' && !r.missing_coordinates) return false;
    if(q){
      const blob = [r.state,r.district,r.police_station,r.address,r.phone,r.email,r.commissionerate].join(' ').toLowerCase();
      if(!blob.includes(q)) return false;
    }
    return true;
  });
  sortRows();
  page = 1;
  render();
}
function sortRows(){
  const s = els.sort.value;
  filteredRows.sort((a,b) => {
    return String(a[s] || '').localeCompare(String(b[s] || ''));
  });
}
function resetFilters(){
  els.search.value=''; els.state.value=''; els.district.value=''; els.coord.value=''; els.sort.value='police_station';
  applyFilters();
}
function openGoogleMapsSearch(){
  const parts = ['police station'];
  if(els.search.value.trim()) parts.push(els.search.value.trim());
  if(els.district.value) parts.push(els.district.value);
  if(els.state.value) parts.push(els.state.value);
  parts.push('India');
  const query = parts.join(' ');
  window.open(`https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(query)}`, '_blank', 'noopener');
}
function googleMapsSearchUrl(r){
  const query = [r.police_station, r.address, r.district, r.state, 'India'].filter(Boolean).join(' ');
  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(query)}`;
}
function render(){ updateStats(); renderMap(); renderCards(); }
function updateStats(){
  const withCoords = allRows.filter(r => !r.missing_coordinates).length;
  els.total.textContent = allRows.length.toLocaleString();
  els.states.textContent = unique(allRows.map(r=>r.state)).length.toLocaleString();
  els.coords.textContent = allRows.length ? `${Math.round(withCoords/allRows.length*100)}%` : '0%';
  els.visible.textContent = `${filteredRows.length.toLocaleString()} visible`;
}

function renderCards(){
  const start = (page-1)*PAGE_SIZE;
  const rows = filteredRows.slice(start, start + PAGE_SIZE);
  els.cards.innerHTML = rows.map((r,idx) => cardHTML(r, start+idx)).join('') || `<div class="card"><h4>No records found</h4><p>Try changing filters or loading a CSV file.</p></div>`;
  els.pageInfo.textContent = `Page ${page} of ${maxPage()}`;
  document.querySelectorAll('[data-open]').forEach(btn => btn.addEventListener('click', () => openDetail(filteredRows[Number(btn.dataset.open)])));
}
function maxPage(){ return Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE)); }
function cardHTML(r, idx){
  const phoneLink = r.phone ? `<a class="btn ghost small" href="tel:${firstPhone(r.phone)}">Call</a>` : '';
  const mapLink = !r.missing_coordinates ? `<a class="btn ghost small" target="_blank" href="https://www.google.com/maps/dir/?api=1&destination=${r.latitude},${r.longitude}">Directions</a>` : '';
  const googleLink = `<a class="btn ghost small" target="_blank" rel="noopener" href="${escapeAttr(googleMapsSearchUrl(r))}">Google Maps</a>`;
  const source = r.source_url ? `<a class="link" href="${escapeAttr(r.source_url)}" target="_blank" rel="noopener">Source</a>` : 'No source URL';
  return `<article class="card">
    <div class="meta"><span class="tag">${escapeHtml(r.state||'Unknown')}</span><span class="tag">${escapeHtml(r.district||'District N/A')}</span>${r.missing_coordinates?'<span class="tag warn">No coordinates</span>':'<span class="tag ok">Mapped</span>'}</div>
    <h4>${escapeHtml(r.police_station||'Unnamed Police Station')}</h4>
    <p>${escapeHtml(r.address||'Address not available')}</p>
    <p><b>Phone:</b> ${escapeHtml(r.phone||'N/A')}</p>
    <p><b>Email:</b> ${escapeHtml(r.email||'N/A')}</p>
    <p>${source}</p>
    <div class="card-actions"><button class="btn primary small" data-open="${idx}" type="button">Details</button>${phoneLink}${mapLink}${googleLink}</div>
  </article>`;
}

function renderMap(){
  const w = els.canvas.width, h = els.canvas.height;
  ctx.clearRect(0,0,w,h);
  const grd = ctx.createLinearGradient(0,0,0,h); grd.addColorStop(0, getCss('--surface2')); grd.addColorStop(1, getCss('--surface'));
  ctx.fillStyle = grd; ctx.fillRect(0,0,w,h);
  drawGrid(w,h);
  drawIndiaOutline(w,h);
  const pts = filteredRows.filter(r => isCoord(r.latitude,r.longitude));
  pts.forEach(r => drawPoint(r, '#1d4ed8', 4));
  if(selectedPoint) drawPoint(selectedPoint, '#dc2626', 8);
  if(!pts.length){ ctx.fillStyle = getCss('--muted'); ctx.font='22px system-ui'; ctx.fillText('No coordinate records to map', 38, 55); }
}
function drawGrid(w,h){
  ctx.strokeStyle = getCss('--line'); ctx.lineWidth=1; ctx.globalAlpha=.6;
  for(let i=1;i<8;i++){ ctx.beginPath(); ctx.moveTo(i*w/8,0); ctx.lineTo(i*w/8,h); ctx.stroke(); }
  for(let i=1;i<6;i++){ ctx.beginPath(); ctx.moveTo(0,i*h/6); ctx.lineTo(w,i*h/6); ctx.stroke(); }
  ctx.globalAlpha=1;
}
function drawIndiaOutline(w,h){
  ctx.strokeStyle = getCss('--primary'); ctx.lineWidth=3; ctx.globalAlpha=.35;
  ctx.beginPath();
  INDIA_OUTLINE.forEach(([lon,lat],i)=>{
    const p=project(lat,lon);
    i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y);
  });
  ctx.closePath();
  ctx.stroke();
  ctx.globalAlpha=1;
}
function drawPoint(r, color, size){ const p=project(r.latitude,r.longitude); ctx.beginPath(); ctx.fillStyle=color; ctx.globalAlpha=.75; ctx.arc(p.x,p.y,size,0,Math.PI*2); ctx.fill(); ctx.globalAlpha=1; }
function project(lat,lon){
  const pad = 42;
  const canvasW = els.canvas.width;
  const canvasH = els.canvas.height;
  const w = canvasW - pad * 2;
  const h = canvasH - pad * 2;

  const latRange = INDIA_BBOX.maxLat - INDIA_BBOX.minLat;
  const lonRange = INDIA_BBOX.maxLon - INDIA_BBOX.minLon;
  const cosLat = 0.92388; // cos(22.5 degrees) center latitude scaling factor
  const scaleY = Math.min(h / latRange, w / (lonRange * cosLat));
  const scaleX = scaleY * cosLat;

  const mapW = lonRange * scaleX;
  const mapH = latRange * scaleY;
  const offsetX = pad + (w - mapW) / 2;
  const offsetY = pad + (h - mapH) / 2;

  return {
    x: offsetX + (lon - INDIA_BBOX.minLon) * scaleX,
    y: offsetY + (INDIA_BBOX.maxLat - lat) * scaleY
  };
}
function handleMapClick(e){
  const rect = els.canvas.getBoundingClientRect();
  const x = (e.clientX-rect.left) * (els.canvas.width/rect.width), y=(e.clientY-rect.top)*(els.canvas.height/rect.height);
  let best=null, bestD=Infinity;
  filteredRows.filter(r=>isCoord(r.latitude,r.longitude)).forEach(r=>{ const p=project(r.latitude,r.longitude); const d=Math.hypot(p.x-x,p.y-y); if(d<bestD){bestD=d; best=r;} });
  if(best && bestD < 18){ selectedPoint=best; renderMap(); openDetail(best); }
}

function openDetail(r){
  els.detail.innerHTML = `<h2>${escapeHtml(r.police_station||'Police Station')}</h2><div class="detail-grid">
    ${detail('State',r.state)}${detail('District',r.district)}${detail('Address',r.address)}${detail('Phone',r.phone)}${detail('Email',r.email)}${detail('Latitude',r.latitude)}${detail('Longitude',r.longitude)}${detail('Commissionerate',r.commissionerate)}${detail('Website',linkOrText(r.website))}${detail('Source',linkOrText(r.source_url))}${detail('Last Updated',r.last_updated)}
  </div>`;
  els.dialog.showModal();
}
function detail(k,v){ return `<b>${escapeHtml(k)}</b><span>${v ? String(v) : 'N/A'}</span>`; }
function linkOrText(v){ return v ? `<a class="link" target="_blank" href="${escapeAttr(v)}">${escapeHtml(v)}</a>` : ''; }

function findNearMe(){
  if(!navigator.geolocation){ els.nearest.innerHTML = '<p>Geolocation is not supported. Enter latitude/longitude manually.</p>'; return; }
  els.nearest.innerHTML = '<p>Requesting location...</p>';
  navigator.geolocation.getCurrentPosition(pos => nearestFrom(pos.coords.latitude, pos.coords.longitude), err => els.nearest.innerHTML = `<p>Location failed: ${escapeHtml(err.message)}. Enter coordinates manually.</p>`, {enableHighAccuracy:true,timeout:12000});
}
function nearestFrom(lat,lon){
  if(!isCoord(lat,lon)){ els.nearest.innerHTML = '<p>Please enter valid India latitude/longitude.</p>'; return; }
  const rows = allRows.filter(r=>isCoord(r.latitude,r.longitude)).map(r => ({...r, distance: haversine(lat,lon,r.latitude,r.longitude)})).sort((a,b)=>a.distance-b.distance).slice(0,3);
  els.nearest.innerHTML = rows.length ? rows.map(r => `<div class="nearest-card"><b>${escapeHtml(r.police_station)}</b><br>${escapeHtml(r.district||'')}, ${escapeHtml(r.state||'')}<br>${r.distance.toFixed(2)} km away<br>${r.phone?`Phone: ${escapeHtml(r.phone)}<br>`:''}<a class="link" target="_blank" href="https://www.google.com/maps?q=${r.latitude},${r.longitude}">Open directions</a></div>`).join('') : '<p>No coordinate records available.</p>';
}
function haversine(lat1,lon1,lat2,lon2){ const R=6371, dLat=rad(lat2-lat1), dLon=rad(lon2-lon1); const a=Math.sin(dLat/2)**2 + Math.cos(rad(lat1))*Math.cos(rad(lat2))*Math.sin(dLon/2)**2; return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a)); }
const rad = d => d*Math.PI/180;

function parseCSV(text){
  text = String(text || '').replace(/^\uFEFF/, '');
  const rows=[], lines=[]; let cur='', inQ=false;
  for(let i=0;i<text.length;i++){ const ch=text[i], next=text[i+1]; if(ch==='"' && inQ && next==='"'){cur+='"'; i++;} else if(ch==='"'){inQ=!inQ;} else if((ch==='\n'||ch==='\r')&&!inQ){ if(cur || ch==='\n') { lines.push(cur); cur=''; } if(ch==='\r'&&next==='\n') i++; } else cur+=ch; }
  if(cur) lines.push(cur);
  if(!lines.length) return [];
  const headers = splitCSVLine(lines[0]).map(h=>h.replace(/^\uFEFF/, '').trim());
  for(const line of lines.slice(1)){ if(!line.trim()) continue; const vals=splitCSVLine(line); const obj={}; headers.forEach((h,i)=>obj[h]=vals[i] ?? ''); rows.push(obj); }
  return rows;
}
function splitCSVLine(line){ const out=[]; let cur='', inQ=false; for(let i=0;i<line.length;i++){ const ch=line[i], next=line[i+1]; if(ch==='"'&&inQ&&next==='"'){cur+='"';i++;} else if(ch==='"'){inQ=!inQ;} else if(ch===','&&!inQ){out.push(cur);cur='';} else cur+=ch; } out.push(cur); return out; }

function toggleTheme(){ const dark = document.documentElement.dataset.theme !== 'dark'; document.documentElement.dataset.theme = dark ? 'dark' : ''; localStorage.setItem('policeFinderTheme', dark ? 'dark' : 'light'); $('themeBtn').textContent = dark ? 'Light Mode' : 'Dark Mode'; renderMap(); }
function restoreTheme(){ const t=localStorage.getItem('policeFinderTheme'); if(t==='dark'){document.documentElement.dataset.theme='dark'; $('themeBtn').textContent='Light Mode';} }
function normalizeKey(k){
  return String(k || '')
    .replace(/^\uFEFF/, '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}
function getAny(obj, keys){
  for(const k of keys){
    const nk = normalizeKey(k);
    if(obj[nk] !== undefined && obj[nk] !== null && String(obj[nk]).trim() !== '') return obj[nk];
  }
  return '';
}
function clean(v){ if(v==null) return ''; const s=String(v).replace(/\s+/g,' ').trim(); return ['nan','none','null','na','n/a','-'].includes(s.toLowerCase()) ? '' : s; }
function toNum(v){ const s = clean(v); if(!s) return null; const n=Number(String(s).replace(/[^0-9.\-]/g,'')); return Number.isFinite(n) ? n : null; }
// Bounding box range check helper
function isCoord(lat,lon){ return Number.isFinite(Number(lat)) && Number.isFinite(Number(lon)) && lat>=6 && lat<=38.5 && lon>=68 && lon<=98.5; }
function firstPhone(p){ return String(p||'').split(/[;,. ]+/).find(Boolean) || ''; }
// HTML escaping utilities
function escapeHtml(s){ return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function escapeAttr(s){ return escapeHtml(s).replace(/'/g,'&#39;'); }
function debounce(fn,ms){ let t; return (...args)=>{ clearTimeout(t); t=setTimeout(()=>fn(...args),ms); }; }
function getCss(name){ return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
