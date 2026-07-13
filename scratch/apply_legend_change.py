import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

# Revert my previous legend modification
prev_legend = '`div`,{className:`absolute bottom-4 left-1/2 -translate-x-1/2 z-20 flex items-center gap-5 px-5 py-2 rounded-full bg-[#0d1229]/70 backdrop-blur border border-white/10 cd-mono text-[11px] text-[#b9cacb] w-max max-w-full`,children:[(0,T.jsx)(Tg,{color:`#f97316`,label:`Private IP`}),(0,T.jsx)(Tg,{color:`#5bffa1`,label:`Public IP`}),(0,T.jsx)(Tg,{color:`#a855f7`,label:`Server IP`}),(0,T.jsx)(Tg,{color:`#ef4444`,label:`Malicious`}),(0,T.jsx)(Tg,{color:`#00f0ff`,label:`Participant IP: ${c?.participant_public_ip||c?.remote_participant_ip||"—"}`})]}'

original_legend = '`div`,{className:`absolute bottom-4 left-1/2 -translate-x-1/2 z-20 flex items-center gap-5 px-5 py-2 rounded-full bg-[#0d1229]/70 backdrop-blur border border-white/10 cd-mono text-[11px] text-[#b9cacb]`,children:[(0,T.jsx)(Tg,{color:`#f97316`,label:`Private IP`}),(0,T.jsx)(Tg,{color:`#5bffa1`,label:`Public IP`}),(0,T.jsx)(Tg,{color:`#a855f7`,label:`Server IP`}),(0,T.jsx)(Tg,{color:`#ef4444`,label:`Malicious`})]}'

if prev_legend in content:
    content = content.replace(prev_legend, original_legend)
    print("Reverted previous legend change.")
else:
    print("Previous legend change not found in file (might have already been reverted or changed).")

# 1. Gh function definition replacement
target_gh_def = 'function Gh({targetIp:e,onSelectIp:t,hosts:n=[]}){let r=n.filter(e=>e&&e.destination_ip),i=[{left:`6%`,top:`18%`},{left:`40%`,top:`8%`},{left:`72%`,top:`28%`},{left:`40%`,top:`70%`}],a=[{x:26,y:28},{x:50,y:35},{x:68,y:30},{x:38,y:55}],o=r.slice(0,4).map((e,t)=>{let n=e.destination_ip,r=n.startsWith(`192.168.`)||n.startsWith(`10.`)||n.startsWith(`127.`)||n===`0.0.0.0`,o=e.threat_level===`critical`||e.threat_level===`high`||e.threat_level===`sus`,s=e.service&&e.service.toLowerCase().includes(`dns`)||e.service&&e.service.toLowerCase().includes(`server`),c=`public`;o?c=`malicious`:r?c=`private`:s&&(c=`server`);let l=`PUBLIC IP`,u=`border-[#00f0ff]/20 hover:border-[#00f0ff]/50 shadow-[#00f0ff]/5`,d=`bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/20`,f=`bg-[#00f0ff]`;c===`malicious`?(l=`SUSPICIOUS IP`,u=`border-red-500/20 hover:border-red-500/50 shadow-red-500/5`,d=`bg-red-500/10 text-red-400 border-red-500/20`,f=`bg-red-500`):c===`private`?(l=`PRIVATE IP`,u=`border-[#f97316]/20 hover:border-[#f97316]/50 shadow-[#f97316]/5`,d=`bg-[#f97316]/10 text-[#f97316] border-[#f97316]/20`,f=`bg-[#f97316]`):c===`server`&&(l=`SERVER IP`,u=`border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5`,d=`bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20`,f=`bg-[#c084fc]`);let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`;return{ip:n,label:l,org:p,loc:m,pos:i[t],nodePos:a[t],color:u,badgeClass:d,dotColor:f}}),s={x:50,y:62};'

repl_gh_def = 'function Gh({targetIp:e,onSelectIp:t,hosts:n=[],participantIp:pIp}){let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"182.74.55.10",o_list=[...r];while(o_list.length<4)o_list.push({destination_ip:"",isEmpty:!0});o_list.push({destination_ip:pVal,service:`Participant Terminal`,isp:`Reliance Jio`,country:`India`,city:`New Delhi`,threat_level:`low`,isParticipant:!0});let i=[{left:`6%`,top:`18%`},{left:`40%`,top:`8%`},{left:`72%`,top:`28%`},{left:`40%`,top:`70%`},{left:`6%`,top:`55%`}],a=[{x:26,y:28},{x:50,y:35},{x:68,y:30},{x:38,y:55},{x:28,y:48}],o=o_list.map((e,t)=>{if(e.isEmpty)return{isEmpty:!0,nodePos:{x:0,y:0},pos:{left:0,top:0},dotColor:``};let n=e.destination_ip,r=n.startsWith(`192.168.`)||n.startsWith(`10.`)||n.startsWith(`127.`)||n===`0.0.0.0`,o=e.threat_level===`critical`||e.threat_level===`high`||e.threat_level===`sus`,s=e.service&&e.service.toLowerCase().includes(`dns`)||e.service&&e.service.toLowerCase().includes(`server`),c=`public`;o?c=`malicious`:r?c=`private`:s&&(c=`server`);let l=`PUBLIC IP`,u=`border-[#00f0ff]/20 hover:border-[#00f0ff]/50 shadow-[#00f0ff]/5`,d=`bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/20`,f=`bg-[#00f0ff]`;c===`malicious`?(l=`SUSPICIOUS IP`,u=`border-red-500/20 hover:border-red-500/50 shadow-red-500/5`,d=`bg-red-500/10 text-red-400 border-red-500/20`,f=`bg-red-500`):c===`private`?(l=`PRIVATE IP`,u=`border-[#f97316]/20 hover:border-[#f97316]/50 shadow-[#f97316]/5`,d=`bg-[#f97316]/10 text-[#f97316] border-[#f97316]/20`,f=`bg-[#f97316]`):c===`server`&&(l=`SERVER IP`,u=`border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5`,d=`bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20`,f=`bg-[#c084fc]`);if(e.isParticipant){l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`}let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`;return{ip:n,label:l,org:p,loc:m,pos:i[t],nodePos:a[t],color:u,badgeClass:d,dotColor:f}}),s={x:50,y:62};'

if target_gh_def in content:
    content = content.replace(target_gh_def, repl_gh_def)
    print("Replaced Gh function definition.")
else:
    print("Error: target_gh_def not found.")

# 2. SVG Paths map replacement
# Let's find target_svg_paths first (to be safe, we replace it using direct substring or prefix/suffix)
# Wait, since the file contains `style:{offsetPath:\"path('${i}')\"}` or similar:
# Let's do a more robust find-and-replace using prefix/suffix:
target_path_part = 'o.map((e,t)=>{let n=(s.x+e.nodePos.x)/2,r=Math.min(s.y,e.nodePos.y)-8'
repl_path_part = 'o.map((e,t)=>{if(e.isEmpty)return null;let n=(s.x+e.nodePos.x)/2,r=Math.min(s.y,e.nodePos.y)-8'

if target_path_part in content:
    content = content.replace(target_path_part, repl_path_part)
    print("Replaced SVG paths map part.")
else:
    print("Error: target_path_part not found.")

# 3. SVG Nodes map replacement
target_nodes_part = 'o.map((e,t)=>(0,T.jsxs)(`g`,{children:[(0,T.jsx)(Wh.circle,{cx:e.nodePos.x,cy:e.nodePos.y,r:2'
repl_nodes_part = 'o.map((e,t)=>{if(e.isEmpty)return null;return(0,T.jsxs)(`g`,{children:[(0,T.jsx)(Wh.circle,{cx:e.nodePos.x,cy:e.nodePos.y,r:2'
# Note: we also need to close the curly brace at the end of the node mapping!
# Let's find: `r:.6,fill:e.dotColor===`bg-red-500`?`#ef4444`:`#00f0ff`,className:`opacity-85`})]},`node-${t}`))`
# And replace with: `r:.6,fill:e.dotColor===`bg-red-500`?`#ef4444`:`#00f0ff`,className:`opacity-85`})]},`node-${t}`)})`

node_end_target = 'r:.6,fill:e.dotColor===`bg-red-500`?`#ef4444`:`#00f0ff`,className:`opacity-85`})]},`node-${t}`))'
node_end_repl = 'r:.6,fill:e.dotColor===`bg-red-500`?`#ef4444`:`#00f0ff`,className:`opacity-85`})]},`node-${t}`)})'

if target_nodes_part in content:
    content = content.replace(target_nodes_part, repl_nodes_part)
    content = content.replace(node_end_target, node_end_repl)
    print("Replaced SVG nodes map part.")
else:
    print("Error: target_nodes_part not found.")

# 4. HTML Cards map replacement
target_card_part = 'o.map(n=>{let r=e===n.ip;return(0,T.jsxs)(`div`,{style:{left:n.pos.left,top:n.pos.top}'
repl_card_part = 'o.map(n=>{if(n.isEmpty)return null;let r=e===n.ip;return(0,T.jsxs)(`div`,{style:{left:n.pos.left,top:n.pos.top}'

if target_card_part in content:
    content = content.replace(target_card_part, repl_card_part)
    print("Replaced HTML cards map part.")
else:
    print("Error: target_card_part not found.")

# 5. Parent Call to Gh
target_parent_call = 'c?(0,T.jsx)(`div`,{className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[]},f)})'
repl_parent_call = 'c?(0,T.jsx)(`div`,{className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[],participantIp:c?.participant_public_ip||c?.remote_participant_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.callee)},f)})'

if target_parent_call in content:
    content = content.replace(target_parent_call, repl_parent_call)
    print("Replaced parent call to Gh.")
else:
    # Try finding it without backticks or slightly different
    # Actually, in content it has `div` (with backticks)
    # Let's inspect content if it didn't match.
    print("Error: target_parent_call not found.")

file_path.write_text(content, encoding='utf-8')
print("Done.")
