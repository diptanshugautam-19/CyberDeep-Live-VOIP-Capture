import pathlib

file_path = pathlib.Path('app/static/assets/index-CgfIjOhe.js')
if not file_path.exists():
    print("Bundle file does not exist")
    exit(1)

content = file_path.read_text(encoding='utf-8')

target_a = (
    'let n=e.destination_ip,r=n.startsWith(`192.168.`)||n.startsWith(`10.`)||n.startsWith(`127.`)||n===`0.0.0.0`,o=e.threat_level===`critical`||e.threat_level===`high`||e.threat_level===`sus`,s=e.service&&e.service.toLowerCase().includes(`dns`)||e.service&&e.service.toLowerCase().includes(`server`),c=`public`;o?c=`malicious`:r?c=`private`:s&&(c=`server`);let l=`PUBLIC IP`,u=`border-[#00f0ff]/20 hover:border-[#00f0ff]/50 shadow-[#00f0ff]/5`,d=`bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/20`,f=`bg-[#00f0ff]`;c===`malicious`?(l=`SUSPICIOUS IP`,u=`border-red-500/20 hover:border-red-500/50 shadow-red-500/5`,d=`bg-red-500/10 text-red-400 border-red-500/20`,f=`bg-red-500`):c===`private`?(l=`PRIVATE IP`,u=`border-[#f97316]/20 hover:border-[#f97316]/50 shadow-[#f97316]/5`,d=`bg-[#f97316]/10 text-[#f97316] border-[#f97316]/20`,f=`bg-[#f97316]`):c===`server`&&(l=`SERVER IP`,u=`border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5`,d=`bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20`,f=`bg-[#c084fc]`);'
)

replacement_a = (
    'let n=e.destination_ip,r=n.startsWith(`192.168.`)||n.startsWith(`10.`)||n.startsWith(`127.`)||n===`0.0.0.0`,o=e.threat_level===`critical`||e.threat_level===`high`||e.threat_level===`sus`,s=e.service&&e.service.toLowerCase().includes(`dns`)||e.service&&e.service.toLowerCase().includes(`server`),c=`public`;if(e.role===`VPN_INTERFACE`){c=`vpn`}else if(e.role===`STUN_SERVER`||e.role===`TURN_SERVER`||e.role===`MEDIA_RELAY`||e.role===`DNS_SERVER`){c=`server`}else if(e.role===`PRIVATE_NETWORK`){c=`private`}else if(e.role===`REMOTE_PARTICIPANT`){c=`public`}else{o?c=`malicious`:r?c=`private`:s&&(c=`server`)}let l=`PUBLIC IP`,u=`border-[#00f0ff]/20 hover:border-[#00f0ff]/50 shadow-[#00f0ff]/5`,d=`bg-[#00f0ff]/10 text-[#00f0ff] border-[#00f0ff]/20`,f=`bg-[#00f0ff]`;c===`vpn`?(l=`VPN INTERFACE`,u=`border-slate-500/40 border-dashed hover:border-slate-400 bg-slate-950/20 shadow-slate-950/20`,d=`bg-slate-900/30 text-slate-400 border-slate-800`,f=`bg-slate-500`):c===`malicious`?(l=`SUSPICIOUS IP`,u=`border-red-500/20 hover:border-red-500/50 shadow-red-500/5`,d=`bg-red-500/10 text-red-400 border-red-500/20`,f=`bg-red-500`):c===`private`?(l=`PRIVATE IP`,u=`border-[#f97316]/20 hover:border-[#f97316]/50 shadow-[#f97316]/5`,d=`bg-[#f97316]/10 text-[#f97316] border-[#f97316]/20`,f=`bg-[#f97316]`):c===`server`&&(l=`SERVER IP`,u=`border-[#a855f7]/20 hover:border-[#a855f7]/50 shadow-[#a855f7]/5`,d=`bg-[#a855f7]/10 text-[#c084fc] border-[#a855f7]/20`,f=`bg-[#c084fc]`);'
)

target_b = (
    'children:[(0,T.jsx)(Tg,{color:`#f97316`,label:`Private IP`}),(0,T.jsx)(Tg,{color:`#5bffa1`,label:`Public IP`}),(0,T.jsx)(Tg,{color:`#a855f7`,label:`Server IP`}),(0,T.jsx)(Tg,{color:`#ef4444`,label:`Malicious`})]'
)

replacement_b = (
    'children:[(0,T.jsx)(Tg,{color:`#64748b`,label:`VPN Interface`}),(0,T.jsx)(Tg,{color:`#f97316`,label:`Private IP`}),(0,T.jsx)(Tg,{color:`#5bffa1`,label:`Public IP`}),(0,T.jsx)(Tg,{color:`#a855f7`,label:`Server IP`}),(0,T.jsx)(Tg,{color:`#ef4444`,label:`Malicious`})]'
)

print("Target A present:", target_a in content)
print("Target B present:", target_b in content)

if target_a in content and target_b in content:
    content = content.replace(target_a, replacement_a)
    content = content.replace(target_b, replacement_b)
    file_path.write_text(content, encoding='utf-8')
    print("Success: VPN Globe styles and legend patched successfully.")
else:
    print("Error: Target(s) not found.")
