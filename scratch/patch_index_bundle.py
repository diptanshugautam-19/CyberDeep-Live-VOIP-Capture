import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

# Target 1: Component Definition
target_def = 'function Gh({targetIp:e,onSelectIp:t,hosts:n=[],participantIp:pIp}){let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"182.74.55.10",o_list=[...r];while(o_list.length<4)o_list.push({destination_ip:"",isEmpty:!0});o_list.push({destination_ip:pVal,service:`Participant Terminal`,isp:`Reliance Jio`,country:`India`,city:`New Delhi`,threat_level:`low`,isParticipant:!0});'

replacement_def = 'function Gh({targetIp:e,onSelectIp:t,hosts:n=[],participantIp:pIp,participantIsp:pIsp,participantCity:pCity,participantCountry:pCountry}){let r=n.filter(e=>e&&e.destination_ip).slice(0,4),pVal=pIp||"Not Observable",o_list=[...r];while(o_list.length<4)o_list.push({destination_ip:"",isEmpty:!0});o_list.push({destination_ip:pVal,service:`Participant Terminal`,isp:pIsp||(pVal===`Not Observable`?`Not Observable`:`Resolving...`),country:pCountry||``,city:pCity||``,threat_level:`low`,isParticipant:!0});'

# Target 2: Participant formatting block
target_formatting = 'if(e.isParticipant){l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`}'

replacement_formatting = 'if(e.isParticipant){l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`;if(n===`Not Observable`){p=`Not Observable`;m=`Not Observable`}}'

# Target 3: Parent Call
target_call = 'className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[],participantIp:c?.participant_public_ip||c?.remote_participant_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.callee)},f)}'

replacement_call = 'className:`absolute inset-0 z-10`,children:(0,T.jsx)(Gh,{targetIp:f,onSelectIp:he,hosts:c?.rows||[],participantIp:c?.participant_public_ip||c?.remote_participant_ip||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.callee),participantIsp:c?.participant_isp||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_isp),participantCity:c?.participant_city||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_city),participantCountry:c?.participant_country||(c?.correlation?.voip_sessions&&c?.correlation?.voip_sessions[0]?.participant_country)},f)}'

print("Target 1 present:", target_def in content)
print("Target 2 present:", target_formatting in content)
print("Target 3 present:", target_call in content)

if target_def in content and target_formatting in content and target_call in content:
    content = content.replace(target_def, replacement_def)
    content = content.replace(target_formatting, replacement_formatting)
    content = content.replace(target_call, replacement_call)
    file_path.write_text(content, encoding='utf-8')
    print("Success: Bundle patched successfully.")
else:
    print("Error: Targets not found in file.")
