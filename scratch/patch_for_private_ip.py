import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

# Target 1: Gh parameters and o_list additions
target_1 = (
    'function Gh({targetIp:e,onSelectIp:t,hosts:n=[],participantIp:pIp,participantIsp:pIsp,participantCity:pCity,participantCountry:pCountry}){let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"Not Observable",o_list=[...r];while(o_list.length<4)o_list.push({destination_ip:"",isEmpty:!0});o_list.push({destination_ip:pVal,service:`Participant Terminal`,isp:pIsp||(pVal===`Not Observable`?`Not Observable`:`Resolving...`),country:pCountry||``,city:pCity||``,threat_level:`low`,isParticipant:!0});'
)

replacement_1 = (
    'function Gh({targetIp:e,onSelectIp:t,hosts:n=[],participantIp:pIp,participantIsp:pIsp,participantCity:pCity,participantCountry:pCountry,participantPvtIp:pPvt}){let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"Not Observable",o_list=[...r];while(o_list.length<4)o_list.push({destination_ip:"",isEmpty:!0});o_list.push({destination_ip:pVal,service:`Participant Terminal`,isp:pIsp||(pVal===`Not Observable`?`Not Observable`:`Resolving...`),country:pCountry||``,city:pCity||``,threat_level:`low`,isParticipant:!0});o_list.push({destination_ip:pPvt||"Not Observable",service:`Participant Private`,isp:`Private Network`,country:``,city:``,threat_level:`low`,isParticipantPvt:!0});'
)

# Target 2: positions and node coordinates arrays
target_2 = (
    'let i=[{left:`6%`,top:`18%`},{left:`40%`,top:`8%`},{left:`72%`,top:`28%`},{left:`40%`,top:`70%`},{left:`6%`,top:`55%`}],a=[{x:26,y:28},{x:50,y:35},{x:68,y:30},{x:38,y:55},{x:28,y:48}],o=o_list.map((e,t)=>{'
)

replacement_2 = (
    'let i=[{left:`6%`,top:`18%`},{left:`40%`,top:`8%`},{left:`72%`,top:`28%`},{left:`40%`,top:`70%`},{left:`6%`,top:`55%`},{left:`72%`,top:`60%`}],a=[{x:26,y:28},{x:50,y:35},{x:68,y:30},{x:38,y:55},{x:28,y:48},{x:70,y:52}],o=o_list.map((e,t)=>{'
)

# Target 3: card styles mapping (TDZ resolved version)
target_3 = (
    'let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`;if(e.isParticipant){l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`;if(n===`Not Observable`){p=`Not Observable`;m=`Not Observable`}}'
)

replacement_3 = (
    'let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`;if(e.isParticipant){l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`;if(n===`Not Observable`){p=`Not Observable`;m=`Not Observable`}}if(e.isParticipantPvt){l=`PARTICIPANT PVT IP`;u=`border-[#f97316]/50 hover:border-[#f97316]/80 shadow-[#f97316]/10 ring-1 ring-[#f97316]/40 bg-[#f97316]/5`;d=`bg-[#f97316]/20 text-[#f97316] border-[#f97316]/30`;f=`bg-[#f97316]`;p=`Local Subnet`;m=`Private Network`;if(n===`Not Observable`){p=`Not Observable`;m=`Not Observable`}}'
)

# Target 4: parent call instantiation
target_4 = (
    'className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[],participantIp:c?.participant_public_ip||c?.remote_participant_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.callee),participantIsp:c?.participant_isp||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_isp),participantCity:c?.participant_city||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_city),participantCountry:c?.participant_country||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_country)},f)}'
)

replacement_4 = (
    'className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[],participantIp:c?.participant_public_ip||c?.remote_participant_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.callee),participantIsp:c?.participant_isp||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_isp),participantCity:c?.participant_city||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_city),participantCountry:c?.participant_country||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_country),participantPvtIp:c?.participant_private_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_private_ip)},f)}'
)

print("Target 1 present:", target_1 in content)
print("Target 2 present:", target_2 in content)
print("Target 3 present:", target_3 in content)
print("Target 4 present:", target_4 in content)

if target_1 in content and target_2 in content and target_3 in content and target_4 in content:
    content = content.replace(target_1, replacement_1)
    content = content.replace(target_2, replacement_2)
    content = content.replace(target_3, replacement_3)
    content = content.replace(target_4, replacement_4)
    file_path.write_text(content, encoding='utf-8')
    print("Success: Private IP integration patched successfully in bundle.")
else:
    print("Error: Target(s) not found.")
