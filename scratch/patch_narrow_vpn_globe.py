import pathlib
import shutil

orig_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js.orig')
file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')

if not orig_path.exists():
    print("Error: Backup file index-CgfIjOhe.js.orig does not exist.")
    exit(1)

# Restore original
shutil.copy(orig_path, file_path)
print("Restored index-CgfIjOhe.js from backup.")

content = file_path.read_text(encoding='utf-8')

# Target 1: original Gh declaration up to s={x:50,y:62};
target_1 = (
    'function Gh({targetIp:e,onSelectIp:t,hosts:n=[]}){let r=n.filter(e=>e&&e.destination_ip),i=[{left:`6%`,top:`18%`},{left:`40%`,top:`8%`},{left:`72%`,top:`28%`},{left:`40%`,top:`70%`}],a=[{x:26,y:28},{x:50,y:35},{x:68,y:30},{x:38,y:55}],o=r.slice(0,4).map((e,t)=>{let n=e.destination_ip,r=n.startsWith(`192.168.`)||n.startsWith(`10.`)||n.startsWith(`127.`)||n===`0.0.0.0`,o=e.threat_level===`critical`||e.threat_level===`high`||e.threat_level===`sus`,s=e.service&&e.service.toLowerCase().includes(`dns`)||e.service&&e.service.toLowerCase().includes(`server`),c=`public`;o?c=`malicious`:r?c=`private`:s&&(c=`server`);let l=`PUBLIC IP`,u=`border-[#00f0ff]/20 hover:border-[#00f0ff]/50 shadow-[#00f0ff]/5`,d=`bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/20`,f=`bg-[#00f0ff]`;c===`malicious`?(l=`SUSPICIOUS IP`,u=`border-red-500/20 hover:border-red-500/50 shadow-red-500/5`,d=`bg-red-500/10 text-red-400 border-red-500/20`,f=`bg-red-500`):c===`private`?(l=`PRIVATE IP`,u=`border-[#f97316]/20 hover:border-[#f97316]/50 shadow-[#f97316]/5`,d=`bg-[#f97316]/10 text-[#f97316] border-[#f97316]/20`,f=`bg-[#f97316]`):c===`server`&&(l=`SERVER IP`,u=`border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5`,d=`bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20`,f=`bg-[#c084fc]`);let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`;return{ip:n,label:l,org:p,loc:m,pos:i[t],nodePos:a[t],color:u,badgeClass:d,dotColor:f}}),s={x:50,y:62};'
)

replacement_1 = (
    'function Gh({targetIp:e,onSelectIp:t,hosts:n=[],participantIp:pIp,participantIsp:pIsp,participantCity:pCity,participantCountry:pCountry,participantPvtIp:pPvt}){ '
    'let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"Not Observable",o_list=[...r]; '
    'while(o_list.length<4)o_list.push({destination_ip:"",isEmpty:!0}); '
    'o_list.push({destination_ip:pVal,service:`Participant Terminal`,isp:pIsp||(pVal===`Not Observable`?`Not Observable`:`Resolving...`),country:pCountry||``,city:pCity||``,threat_level:`low`,isParticipant:!0}); '
    'o_list.push({destination_ip:pPvt||"Not Observable",service:`Participant Private`,isp:`Private Network`,country:``,city:``,threat_level:`low`,isParticipantPvt:!0}); '
    'let i=[{left:`6%`,top:`18%`},{left:`40%`,top:`8%`},{left:`72%`,top:`28%`},{left:`40%`,top:`70%`},{left:`6%`,top:`55%`},{left:`72%`,top:`60%`}]; '
    'let a=[{x:26,y:28},{x:50,y:35},{x:68,y:30},{x:38,y:55},{x:28,y:48},{x:70,y:52}]; '
    'let o=o_list.map((e,idx)=>{ '
    '  if(e.isEmpty) return {isEmpty:!0,nodePos:{x:0,y:0},pos:{left:0,top:0},dotColor:""}; '
    '  let classified = n.find(h => h && h.destination_ip === e.destination_ip); '
    '  if(classified){ '
    '    e.role = classified.role; '
    '    e.tier = classified.tier; '
    '    e.paired_address = classified.paired_address; '
    '    e.matched_signature = classified.matched_signature; '
    '  } '
    '  let nIp=e.destination_ip, '
    '  r=nIp.startsWith(`192.168.`)||nIp.startsWith(`10.`)||nIp.startsWith(`127.`)||nIp===`0.0.0.0`, '
    '  oVal=e.threat_level===`critical`||e.threat_level===`high`||e.threat_level===`sus`, '
    '  s=e.service&&e.service.toLowerCase().includes(`dns`)||e.service&&e.service.toLowerCase().includes(`server`), '
    '  c=`public`; '
    '  if(e.role===`VPN_INTERFACE`){c=`vpn`} '
    '  else if(e.role===`STUN_SERVER`||e.role===`TURN_SERVER`||e.role===`MEDIA_RELAY`||e.role===`DNS_SERVER`){c=`server`} '
    '  else if(e.role===`PRIVATE_NETWORK`){c=`private`} '
    '  else if(e.role===`REMOTE_PARTICIPANT`){c=`public`} '
    '  else{oVal?c=`malicious`:r?c=`private`:s&&(c=`server`)} '
    '  let l=`PUBLIC IP`,u=`border-[#00f0ff]/20 hover:border-[#00f0ff]/50 shadow-[#00f0ff]/5`,d=`bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/20`,f=`bg-[#00f0ff]`; '
    '  c===`vpn`?(l=`VPN INTERFACE`,u=`border-slate-500/40 border-dashed hover:border-slate-400 bg-slate-950/20 shadow-slate-950/20`,d=`bg-slate-900/30 text-slate-400 border-slate-800`,f=`bg-slate-500`): '
    '  c===`malicious`?(l=`SUSPICIOUS IP`,u=`border-red-500/20 hover:border-red-500/50 shadow-red-500/5`,d=`bg-red-500/10 text-red-400 border-red-500/20`,f=`bg-red-500`): '
    '  c===`private`?(l=`PRIVATE IP`,u=`border-[#f97316]/20 hover:border-[#f97316]/50 shadow-[#f97316]/5`,d=`bg-[#f97316]/10 text-[#f97316] border-[#f97316]/20`,f=`bg-[#f97316]`): '
    '  c===`server`&&(l=`SERVER IP`,u=`border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5`,d=`bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20`,f=`bg-[#c084fc]`); '
    '  let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`; '
    '  if(e.isParticipant){ '
    '    if(e.role!==`VPN_INTERFACE`){ '
    '      l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`; '
    '    } '
    '    if(nIp===`Not Observable`){p=`Not Observable`;m=`Not Observable`} '
    '  } '
    '  if(e.isParticipantPvt){ '
    '    if(e.role!==`VPN_INTERFACE`){ '
    '      l=`PARTICIPANT PVT IP`;u=`border-[#f97316]/50 hover:border-[#f97316]/80 shadow-[#f97316]/10 ring-1 ring-[#f97316]/40 bg-[#f97316]/5`;d=`bg-[#f97316]/20 text-[#f97316] border-[#f97316]/30`;f=`bg-[#f97316]`; '
    '    } '
    '    p=`Local Subnet`;m=`Private Network`; '
    '    if(nIp===`Not Observable`){p=`Not Observable`;m=`Not Observable`} '
    '  } '
    '  if(e.role===`VPN_INTERFACE`){ '
    '    p=e.matched_signature?`Capture interface (${e.matched_signature})`:"Capture internal"; '
    '    m=`Paired with ${e.paired_address||"—"}`; '
    '  } '
    '  return {ip:nIp,label:l,org:p,loc:m,pos:i[idx],nodePos:a[idx],color:u,badgeClass:d,dotColor:f}; '
    '}); '
    'let s={x:50,y:62};'
)

# Target 2, 3, 4: map loop replacements (filtering empty ones)
target_2 = 'o.map((e,t)=>{let n=(s.x+e.nodePos.x)/2,r=Math.min(s.y,e.nodePos.y)-8,i=`M ${s.x} ${s.y} Q ${n} ${r} ${e.nodePos.x} ${e.nodePos.y}`;'
replacement_2 = 'o.filter(x=>!x.isEmpty).map((e,t)=>{let n=(s.x+e.nodePos.x)/2,r=Math.min(s.y,e.nodePos.y)-8,i=`M ${s.x} ${s.y} Q ${n} ${r} ${e.nodePos.x} ${e.nodePos.y}`;'

target_3 = 'o.map((e,t)=>(0,T.jsxs)(`g`,'
replacement_3 = 'o.filter(x=>!x.isEmpty).map((e,t)=>(0,T.jsxs)(`g`,'

target_4 = 'o.map(n=>{let r=e===n.ip;return(0,T.jsxs)('
replacement_4 = 'o.filter(x=>!x.isEmpty).map(n=>{let r=e===n.ip;return(0,T.jsxs)('

# Target 5: Legend categories
target_5 = (
    'children:[(0,T.jsx)(Tg,{color:`#f97316`,label:`Private IP`}),(0,T.jsx)(Tg,{color:`#5bffa1`,label:`Public IP`}),(0,T.jsx)(Tg,{color:`#a855f7`,label:`Server IP`}),(0,T.jsx)(Tg,{color:`#ef4444`,label:`Malicious`})]'
)

replacement_5 = (
    'children:[(0,T.jsx)(Tg,{color:`#64748b`,label:`VPN Interface`}),(0,T.jsx)(Tg,{color:`#f97316`,label:`Private IP`}),(0,T.jsx)(Tg,{color:`#5bffa1`,label:`Public IP`}),(0,T.jsx)(Tg,{color:`#a855f7`,label:`Server IP`}),(0,T.jsx)(Tg,{color:`#ef4444`,label:`Malicious`})]'
)

# Target 6: Parent Call Instantiation
target_6 = (
    'className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[]},f)}'
)

replacement_6 = (
    'className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[],participantIp:c?.participant_public_ip||c?.remote_participant_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.callee),participantIsp:c?.participant_isp||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_isp),participantCity:c?.participant_city||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_city),participantCountry:c?.participant_country||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_country),participantPvtIp:c?.participant_private_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_private_ip)},f)}'
)

print("Target 1 in content:", target_1 in content)
print("Target 2 in content:", target_2 in content)
print("Target 3 in content:", target_3 in content)
print("Target 4 in content:", target_4 in content)
print("Target 5 in content:", target_5 in content)
print("Target 6 in content:", target_6 in content)

if target_1 in content and target_2 in content and target_3 in content and target_4 in content and target_5 in content and target_6 in content:
    content = content.replace(target_1, replacement_1)
    content = content.replace(target_2, replacement_2)
    content = content.replace(target_3, replacement_3)
    content = content.replace(target_4, replacement_4)
    content = content.replace(target_5, replacement_5)
    content = content.replace(target_6, replacement_6)
    file_path.write_text(content, encoding='utf-8')
    print("Success: Narrow VPN role layout patched successfully.")
else:
    print("Error: Target(s) not found.")
