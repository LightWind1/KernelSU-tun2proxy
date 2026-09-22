// Saved computers share the existing active config and certificate APIs.
let profileSet=null;
async function profileAction(action,id='',name=''){
 const r=await fetch(API+'/api/profiles',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,id,name})});
 const d=await readJSON(r);if(!r.ok||d.error)throw new Error(d.error||'连接配置操作失败');
 profileSet=d;renderProfiles();return d;
}
async function loadProfiles(){
 try{
  const r=await fetch(API+'/api/profiles'),d=await readJSON(r);
  if(!r.ok||d.error)throw new Error(d.error||'无法读取连接配置');
  profileSet=d;renderProfiles();
 }catch(e){toast(e.message)}
}
function renderProfiles(){
 if(!profileSet)return;
 for(const id of ['profile-select','cert-profile']){
  const sel=$(id),previous=sel.value;
  sel.replaceChildren();
  for(const p of profileSet.profiles){
   const o=document.createElement('option');o.value=p.id;
   let address='';
   try{const u=new URL(p.config.proxy_url);address=u.host}catch(e){}
   o.textContent=p.name+(address?' · '+address:'');sel.append(o);
  }
  sel.value=id==='profile-select'?profileSet.activeId:
   profileSet.profiles.some(p=>p.id===previous)?previous:profileSet.activeId;
 }
}
async function profileTask(fn){try{await fn()}catch(e){toast(e.message);renderProfiles()}}
$('profile-select').onchange=()=>profileTask(async()=>{
 const target=$('profile-select').value;
 if(formDirty&&!confirm('当前配置尚未保存。放弃修改并切换电脑？')){renderProfiles();return}
 await profileAction('select',target);
 formDirty=false;
 const r=await fetch(API+'/api/config');config=await readJSON(r);renderConfig();renderStats();
 $('cert-profile').value=target;
 if(typeof loadCertificates==='function')await loadCertificates();
 toast('已切换电脑；点击“保存并启动”应用到流量');
});
$('profile-create').onclick=()=>profileTask(async()=>{
 if(formDirty&&!confirm('当前修改尚未保存。放弃修改并新增电脑？'))return;
 const name=prompt('新电脑名称');if(!name)return;
 const d=await profileAction('create','',name);await profileAction('select',d.profiles[d.profiles.length-1].id);
 const r=await fetch(API+'/api/config');config=await readJSON(r);formDirty=false;renderConfig();renderStats();
 $('cert-profile').value=profileSet.activeId;await loadCertificates();
});
$('profile-clone').onclick=()=>profileTask(async()=>{
 const current=profileSet.profiles.find(p=>p.id===profileSet.activeId);
 const name=prompt('副本名称',current.name+' 副本');if(name)await profileAction('clone','',name);
});
$('profile-rename').onclick=()=>profileTask(async()=>{
 const current=profileSet.profiles.find(p=>p.id===profileSet.activeId);
 const name=prompt('电脑名称',current.name);if(name)await profileAction('rename',current.id,name);
});
$('profile-delete').onclick=()=>profileTask(async()=>{
 const others=profileSet.profiles.filter(p=>p.id!==profileSet.activeId);
 if(!others.length){toast('请先新增另一台电脑');return}
 const choice=prompt('输入要删除的编号（当前使用的配置不能删除）：\n'+others.map((p,i)=>(i+1)+'. '+p.name).join('\n'));
 if(choice===null)return;
 const n=Number(choice),target=others[n-1];
 if(!Number.isInteger(n)||!target){toast('编号无效');return}
 if(confirm('删除“'+target.name+'”的连接配置？证书缓存不会删除。'))await profileAction('delete',target.id);
});
loadProfiles();
