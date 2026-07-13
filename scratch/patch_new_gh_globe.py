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
    'function Gh({targetIp:e,onSelectIp:t,hosts:n=[]}){ '
    'const ROLE_STYLES = { '
    '  VPN_INTERFACE: { '
    '    label: "VPN INTERFACE", '
    '    containerStyle: "border-slate-500/40 border-dashed hover:border-slate-400 bg-slate-950/20 shadow-slate-950/20", '
    '    badgeClass: "bg-slate-900/30 text-slate-400 border-slate-800", '
    '    dotColor: "bg-slate-500", '
    '  }, '
    '  STUN_SERVER: { '
    '    label: "SERVER IP", '
    '    containerStyle: "border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5", '
    '    badgeClass: "bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20", '
    '    dotColor: "bg-[#c084fc]", '
    '  }, '
    '  TURN_SERVER: { '
    '    label: "SERVER IP", '
    '    containerStyle: "border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5", '
    '    badgeClass: "bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20", '
    '    dotColor: "bg-[#c084fc]", '
    '  }, '
    '  MEDIA_RELAY: { '
    '    label: "SERVER IP", '
    '    containerStyle: "border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5", '
    '    badgeClass: "bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20", '
    '    dotColor: "bg-[#c084fc]", '
    '  }, '
    '  DNS_SERVER: { '
    '    label: "SERVER IP", '
    '    containerStyle: "border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5", '
    '    badgeClass: "bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20", '
    '    dotColor: "bg-[#c084fc]", '
    '  }, '
    '  SIP_SERVER: { '
    '    label: "SERVER IP", '
    '    containerStyle: "border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5", '
    '    badgeClass: "bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20", '
    '    dotColor: "bg-[#c084fc]", '
    '  }, '
    '  PRIVATE_NETWORK: { '
    '    label: "PRIVATE IP", '
    '    containerStyle: "border-[#f97316]/20 hover:border-[#f97316]/50 shadow-[#f97316]/5", '
    '    badgeClass: "bg-[#f97316]/10 text-[#f97316] border-[#f97316]/20", '
    '    dotColor: "bg-[#f97316]", '
    '  }, '
    '  REMOTE_PARTICIPANT: { '
    '    label: "PARTICIPANT IP", '
    '    containerStyle: "border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5", '
    '    badgeClass: "bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30", '
    '    dotColor: "bg-[#00f0ff]", '
    '  }, '
    '  RTP_ENDPOINT: { '
    '    label: "PARTICIPANT IP", '
    '    containerStyle: "border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5", '
    '    badgeClass: "bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30", '
    '    dotColor: "bg-[#00f0ff]", '
    '  }, '
    '  RTCP_ENDPOINT: { '
    '    label: "PARTICIPANT IP", '
    '    containerStyle: "border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5", '
    '    badgeClass: "bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30", '
    '    dotColor: "bg-[#00f0ff]", '
    '  }, '
    '  UNKNOWN: { '
    '    label: "UNKNOWN", '
    '    containerStyle: "border-slate-700/40 hover:border-slate-600 bg-slate-950/10 shadow-slate-950/10", '
    '    badgeClass: "bg-slate-800/30 text-slate-500 border-slate-700", '
    '    dotColor: "bg-slate-600", '
    '  }, '
    '}; '
    'let r=n.filter(e=>e&&e.destination_ip).slice(0,6); '
    'let o_list=[...r]; '
    'while(o_list.length<6) o_list.push({destination_ip:"",isEmpty:!0}); '
    'let i=[{left:`6%`,top:`18%`},{left:`40%`,top:`8%`},{left:`72%`,top:`28%`},{left:`40%`,top:`70%`},{left:`6%`,top:`55%`},{left:`72%`,top:`60%`}]; '
    'let a=[{x:26,y:28},{x:50,y:35},{x:68,y:30},{x:38,y:55},{x:28,y:48},{x:70,y:52}]; '
    'let o=o_list.map((e,idx)=>{ '
    '  if(e.isEmpty) return {isEmpty:!0,nodePos:{x:0,y:0},pos:{left:0,top:0},dotColor:""}; '
    '  const role=e.role||"UNKNOWN"; '
    '  let style=ROLE_STYLES[role]||ROLE_STYLES.UNKNOWN; '
    '  if(e.threat_level==="critical"||e.threat_level==="high"||e.threat_level==="sus"){ '
    '    style={label:"SUSPICIOUS IP",containerStyle:"border-red-500/20 hover:border-red-500/50 shadow-red-500/5",badgeClass:"bg-red-500/10 text-red-400 border-red-500/20",dotColor:"bg-red-500"}; '
    '  } '
    '  const isTier1=e.tier===1; '
    '  const org=isTier1?(e.matched_signature?`Capture interface (${e.matched_signature})`:"Capture internal"):(e.asn_org||e.isp||"Resolving..."); '
    '  const loc=isTier1?`Paired with ${e.paired_address||"—"}`:(e.country?`${e.city||"Unknown"}, ${e.country}`:"Resolving..."); '
    '  return {ip:e.destination_ip,label:style.label,org:org,loc:loc,pos:i[idx],nodePos:a[idx],color:style.containerStyle,badgeClass:style.badgeClass,dotColor:style.dotColor}; '
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

print("Target 1 in content:", target_1 in content)
print("Target 2 in content:", target_2 in content)
print("Target 3 in content:", target_3 in content)
print("Target 4 in content:", target_4 in content)
print("Target 5 in content:", target_5 in content)

if target_1 in content and target_2 in content and target_3 in content and target_4 in content and target_5 in content:
    content = content.replace(target_1, replacement_1)
    content = content.replace(target_2, replacement_2)
    content = content.replace(target_3, replacement_3)
    content = content.replace(target_4, replacement_4)
    content = content.replace(target_5, replacement_5)
    file_path.write_text(content, encoding='utf-8')
    print("Success: Bundle patched with clean role-based Gh mapping.")
else:
    print("Error: Target(s) not found.")
