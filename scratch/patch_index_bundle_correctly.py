import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
content = file_path.read_text(encoding='utf-8')

target = 'if(e.isParticipant){l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`;if(n===`Not Observable`){p=`Not Observable`;m=`Not Observable`}}let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`;'

replacement = 'let p=e.asn_org||e.isp||`Local Node`,m=e.country?`${e.city||`Unknown`}, ${e.country}`:`Local Subnet`;if(e.isParticipant){l=`PARTICIPANT IP`;u=`border-[#00f0ff]/50 hover:border-[#00f0ff]/80 shadow-[#00f0ff]/10 ring-1 ring-[#00f0ff]/40 bg-[#00f0ff]/5`;d=`bg-[#00f0ff]/20 text-[#00f0ff] border-[#00f0ff]/30`;f=`bg-[#00f0ff]`;if(n===`Not Observable`){p=`Not Observable`;m=`Not Observable`}}'

print("Target found:", target in content)

if target in content:
    content = content.replace(target, replacement)
    file_path.write_text(content, encoding='utf-8')
    print("Success: Corrected Temporal Dead Zone reference error.")
else:
    print("Error: Target not found.")
