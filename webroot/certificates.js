// Certificate administration shares the existing API and saved connection configuration.
let certificateData=null, yakitDiscovery=null, certificateBusy=false, testedProxyURL='';
const certHeaders={'X-Tun2proxy-Certificate':'1'};
async function certFetch(path,body){
 const r=await fetch(API+path,{method:body===undefined?'GET':'POST',headers:{...certHeaders,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body)});
 const d=await readJSON(r);if(!r.ok||d.error)throw new Error(d.error||'HTTP '+r.status);return d;
}
async function certWork(fn){
 if(certificateBusy)return;
 certificateBusy=true;document.querySelectorAll('#tab-certificates button').forEach(b=>b.disabled=true);
 try{await fn()}catch(e){$('cert-message').textContent=e.message;toast(e.message)}
 finally{certificateBusy=false;document.querySelectorAll('#tab-certificates button').forEach(b=>b.disabled=false);renderCertificatePage()}
}
async function loadCertificates(){
 try{certificateData=await certFetch('/api/certificates');renderCertificatePage()}catch(e){$('cert-message').textContent=e.message}
}
function certButton(label,fn,disabled=false){
 const b=document.createElement('button');b.className='btn btn-secondary';b.textContent=label;b.disabled=disabled;b.onclick=()=>certWork(fn);return b;
}
function certText(tag,text){const n=document.createElement(tag);n.textContent=text;return n}
function certCard(c,source){
 const cached=certificateData.entries.find(e=>e.id===c.id);
 if(cached&&source==='user')c={...c,managed:cached.managed};
 const card=document.createElement('article');card.className='card';card.style.overflowWrap='anywhere';
 card.append(certText('h3',c.subject||c.id),certText('p','SHA-256 · '+c.sha256));
 const installed=!!certificateData.mounted[c.id];
 card.append(certText('p',source==='system'?'系统证书（只读）':installed?'已挂载 · 已验证 AndroidCAStore 可用':c.managed?'已托管 · 等待重新应用/重启':'已保存 · 未加入系统'));
 card.append(certText('p',(c.algorithm||'')+' · 有效期至 '+c.notAfter));
 const gmCapability=certificateData.capabilities?.[c.id];
 if(c.certificateType==='gm')card.append(certText('p',installed?'国密 CA 已通过原生签名校验与 AndroidCAStore 验证；不保证 App 使用国密 TLS。':gmCapability?.signatureValid?'系统可以解析并验证国密签名，可尝试验证式加入系统；失败时回滚。':'国密 CA 已保存，可查看、同步或导出。当前 Android 未确认具备可用的国密签名/信任能力，不标记为系统已信任。'));
 const row=document.createElement('div');row.className='row';row.style.marginTop='12px';
 row.append(certButton('详情',async()=>{const d=await certFetch('/api/certificates/action',{action:'inspect',id:c.id,source,user:c.user||''});$('cert-details').textContent=JSON.stringify(d,null,2);$('cert-details').hidden=false}));
 if(source!=='system'){
  if(c.managed)row.append(certButton('移出系统',async()=>{await certFetch('/api/certificates/action',{action:'remove',id:c.id});$('cert-message').textContent='已移除本模块注入，用户原证书保留。运行中的 App 请关闭后重开。';await loadCertificates()}));
  else row.append(certButton('加入系统',async()=>{await certFetch('/api/certificates/action',{action:'install',id:c.id,source,user:c.user||''});$('cert-message').textContent='已加入并验证系统 CA 库。请重开目标 App；证书锁定或自带信任库不受此功能保证。';await loadCertificates()},c.certificateType==='gm'&&!gmCapability?.signatureValid));
  if(source==='user')row.append(certButton('删除用户证书',async()=>{
   if(!confirm('删除 Android 用户 '+c.user+' 中的证书？这与移出系统不同，将删除用户原证书，并在模块私有目录留一份恢复副本。\nSHA-256: '+c.id))return;
   await certFetch('/api/certificates/action',{action:'delete-user',id:c.id,user:c.user,confirm:'DELETE USER '+c.id});await loadCertificates();
  }));
  else{
   row.append(certButton('导出',async()=>{
    const r=await fetch(API+'/api/certificates/export?id='+c.id,{headers:certHeaders});if(!r.ok)throw new Error('导出失败');
    const u=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=u;a.download=c.id+'.pem';a.click();setTimeout(()=>URL.revokeObjectURL(u),10000);
   }));
   row.append(certButton('删除缓存',async()=>{
    if(!confirm('仅删除本模块缓存中的公共 CA，不删除用户证书或原厂证书。\nSHA-256: '+c.id))return;
    await certFetch('/api/certificates/action',{action:'delete',id:c.id,confirm:'DELETE CACHE '+c.id});await loadCertificates();
   },!!c.managed));
  }
 }
 card.append(row);return card;
}
function renderCertificatePage(){
 if(!certificateData)return;
 const d=certificateData;
 if(testedProxyURL!==config.proxy_url)yakitDiscovery=null;
 const p=config.proxy_url||'';
 try{const u=new URL(p);u.username='';u.password='';$('cert-upstream').textContent=(u.protocol==='http:'?'Yakit / Burp（HTTP CONNECT）':'当前上游 '+u.protocol)+' · '+u.toString()}catch(e){$('cert-upstream').textContent='尚未保存连接配置'}
 $('cert-sync').disabled=!yakitDiscovery?.recognized||certificateBusy;
 $('cert-yakit-state').textContent=yakitDiscovery?.message||'尚未测试当前已保存的上游';
 const area=$('yakit-certificates');area.replaceChildren();
 for(const [kind,title] of [['normal','Yakit 普通 MITM CA'],['gm','Yakit 国密 CA']]){
  const remote=d.yakit[kind]||{},c=d.entries.find(e=>e.id===remote.localID);
  const group=document.createElement('section');group.append(certText('h2',title));
  const update=remote.remoteID&&remote.localID&&remote.remoteID!==remote.localID;
  group.append(certText('p',update?'Yakit CA 已变化':remote.localID?'已下载 / 已同步':'未下载'));
  group.append(certText('p','本地 SHA256: '+(remote.localID||'—')),certText('p','远程 SHA256: '+(remote.remoteID||'未检查')));
  const row=document.createElement('div');row.className='row';
  row.append(certButton('检查更新',()=>yakitAction('check',kind),!yakitDiscovery?.recognized),certButton(update?'更新证书':'下载/同步',()=>yakitAction('sync',kind),!yakitDiscovery?.recognized));
  group.append(row);if(c)group.append(certCard(c,'managed'));area.append(group);
 }
 const list=$('local-certificates');list.replaceChildren();
 const category=$('cert-category').value;
 const entries=category==='user'?d.users:category==='system'?d.system:d.entries;
 for(const c of entries){list.append(certCard(c,category))}
 if(!entries.length)list.textContent='该分类暂无证书';
 $('certificate-diagnostics').textContent=JSON.stringify({yakit:yakitDiscovery,environment:d.environment,managedCA:d.entries.filter(c=>c.managed).length,mountedCA:Object.keys(d.mounted).length,pendingReboot:d.pending,errors:d.errors},null,2);
}
async function yakitAction(action,kind){
 const d=await certFetch('/api/yakit',{action,kind:kind||''});
 yakitDiscovery=d.discovery||d;testedProxyURL=config.proxy_url;
 $('cert-message').textContent=d.results?JSON.stringify(d.results,null,2):d.message;
 await loadCertificates();
}
async function importCertificate(file){
 if(!file)return;
 if(file.size>256*1024)throw new Error('证书文件不能超过256KB');
 const r=await fetch(API+'/api/certificates/import',{method:'POST',headers:certHeaders,body:await file.arrayBuffer()});
 const d=await readJSON(r);if(!r.ok)throw new Error(d.error||'导入失败');
 $('cert-message').textContent='已验证并加入模块缓存，尚未加入系统。SHA256: '+d.id;await loadCertificates();
}
$('cert-file').onchange=()=>certWork(()=>importCertificate($('cert-file').files[0]));
$('cert-category').onchange=renderCertificatePage;
$('cert-test').onclick=()=>certWork(()=>yakitAction('test'));
$('cert-sync').onclick=()=>certWork(()=>yakitAction('sync'));
$('cert-refresh').onclick=loadCertificates;
$('cert-apply').onclick=()=>certWork(async()=>{await certFetch('/api/certificates/action',{action:'apply'});await loadCertificates()});
$('copy-cert-diagnostics').onclick=async()=>{
 const text=$('certificate-diagnostics').textContent;
 try{await navigator.clipboard.writeText(text);toast('诊断已复制')}catch(e){
  const ta=document.createElement('textarea');ta.value=text;document.body.append(ta);ta.select();document.execCommand('copy');ta.remove();toast('诊断已复制');
 }
};
