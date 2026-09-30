function formatEBPFStatus(s){
 if(!s.running)return 'eBPF program: Not loaded\ndaemon: Stopped\n尚未运行；可先检查设备能力和已保存的 SOCKS5 上游。';
 return ['eBPF program: '+(s.programs_loaded?'Loaded':'Not loaded'),'daemon: Running (pid='+s.pid+')','listener: '+s.listener+(s.ipv6?' / ::1':''),'upstream: '+s.upstream,'target UID count: '+(s.target_uids||[]).length,'policy: '+s.policy_mode,'UDP: pass','flow map entries: '+s.flow_map_entries,'counters: '+JSON.stringify(s.counters||{}),'relay: '+JSON.stringify(s.relay||{})].join('\n');
}
async function checkEBPF(action){
 if(formDirty){toast('请先保存连接配置，再进行检测');return}
 $('ebpf-diagnostics').textContent='检测中…';
 try{const r=await fetch(API+'/api/ebpf',{method:'POST',headers:{'Content-Type':'application/json','X-Tun2proxy-Certificate':'1'},body:JSON.stringify({action})});const d=await readJSON(r);const text=d.error||d.output||'没有诊断结果';$('ebpf-diagnostics').textContent=text;$('ebpf-state').textContent=text;if(!r.ok)toast('检测未通过，详情见诊断信息')}catch(e){$('ebpf-diagnostics').textContent=e.message;toast(e.message)}
}
if(typeof module!=='undefined'&&module.exports)module.exports={formatEBPFStatus};
