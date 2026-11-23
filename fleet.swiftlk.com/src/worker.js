// SwiftClean Multi-PC Dashboard – Cloudflare Worker + KV
// PCs POST health snapshots with their team key; the dashboard (same key) lists PCs and can queue "clean now".
const JSONH = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: JSONH });

async function teamHash(key) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('swiftclean-fleet:' + key));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}
const clip = (s, n = 200) => String(s ?? '').slice(0, n);

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === '/' || url.pathname === '/index.html') return new Response(DASHBOARD, { headers: { 'content-type': 'text/html; charset=utf-8', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer' } });
    if (!url.pathname.startsWith('/api/')) return new Response('Not found', { status: 404 });
    const key = req.headers.get('x-team-key') || '';
    if (key.length < 16 || key.length > 128) return json({ error: 'Missing or invalid team key' }, 401);
    const t = await teamHash(key);
    const P = `t:${t}:pc:`, C = `t:${t}:cmd:`;

    if (url.pathname === '/api/report' && req.method === 'POST') {
      const b = await req.json().catch(() => null);
      if (!b || !b.id) return json({ error: 'Bad request' }, 400);
      const id = clip(b.id, 64);
      const rec = {
        id, name: clip(b.name, 80), os: clip(b.os), version: clip(b.version, 20), cpu: clip(b.cpu), ramTotal: +b.ramTotal || 0, ramFree: +b.ramFree || 0,
        disks: (Array.isArray(b.disks) ? b.disks : []).slice(0, 12).map(d => ({ id: clip(d.id, 4), size: +d.size || 0, free: +d.free || 0 })),
        junk: +b.junk || 0, lastClean: clip(b.lastClean, 40), freedTotal: +b.freedTotal || 0, uptimeHours: +b.uptimeHours || 0, admin: !!b.admin, plan: clip(b.plan, 10),
        lastResult: clip(b.lastResult, 300), lastSeen: new Date().toISOString(),
      };
      const prev = await env.FLEET.get(P + id, 'json');
      if (prev && prev.lastResult && !rec.lastResult) rec.lastResult = prev.lastResult;
      await env.FLEET.put(P + id, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 90 });
      const cmds = (await env.FLEET.get(C + id, 'json')) || [];
      return json({ ok: true, commands: cmds });
    }
    if (url.pathname === '/api/ack' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      const id = clip(b.id, 64);
      const cmds = ((await env.FLEET.get(C + id, 'json')) || []).filter(c => !(b.commands || []).includes(c.id));
      await env.FLEET.put(C + id, JSON.stringify(cmds));
      const rec = await env.FLEET.get(P + id, 'json');
      if (rec) { rec.lastResult = clip(b.result, 300) + ' · ' + new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC'; await env.FLEET.put(P + id, JSON.stringify(rec), { expirationTtl: 60 * 60 * 24 * 90 }); }
      return json({ ok: true });
    }
    if (url.pathname === '/api/pcs' && req.method === 'GET') {
      const list = await env.FLEET.list({ prefix: P });
      const pcs = (await Promise.all(list.keys.map(k => env.FLEET.get(k.name, 'json')))).filter(Boolean);
      for (const p of pcs) p.pending = ((await env.FLEET.get(C + p.id, 'json')) || []).length;
      return json({ pcs });
    }
    if (url.pathname === '/api/command' && req.method === 'POST') {
      const b = await req.json().catch(() => ({}));
      if (!['clean', 'report'].includes(b.type)) return json({ error: 'Unknown command' }, 400);
      const id = clip(b.pcId, 64);
      if (!(await env.FLEET.get(P + id))) return json({ error: 'PC not found' }, 404);
      const cmds = (await env.FLEET.get(C + id, 'json')) || [];
      cmds.push({ id: crypto.randomUUID().slice(0, 8), type: b.type, at: new Date().toISOString() });
      await env.FLEET.put(C + id, JSON.stringify(cmds.slice(-10)));
      return json({ ok: true });
    }
    if (url.pathname === '/api/pc' && req.method === 'DELETE') {
      const id = clip(url.searchParams.get('id'), 64);
      await env.FLEET.delete(P + id); await env.FLEET.delete(C + id);
      return json({ ok: true });
    }
    return json({ error: 'Not found' }, 404);
  },
};

const DASHBOARD = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SwiftClean – Multi-PC Dashboard</title>
<meta name="robots" content="noindex">
<style>
:root{--bg:#050a1a;--panel:#0d1531;--line:#1d2850;--text:#e6ecff;--muted:#8c98c4;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--grad:linear-gradient(120deg,#2563ff,#8b5cf6)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",Inter,system-ui,sans-serif}
header{display:flex;align-items:center;gap:12px;padding:16px 24px;border-bottom:1px solid var(--line)}header b{font-size:18px}.logo{width:34px;height:34px;border-radius:9px;background:var(--grad);display:grid;place-items:center;font-weight:800}
main{max-width:1200px;margin:0 auto;padding:24px}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.spacer{flex:1}
input{background:#0a1128;border:1px solid var(--line);color:var(--text);border-radius:9px;padding:10px 12px;font:inherit;min-width:300px}
button{background:var(--grad);color:#fff;border:0;border-radius:9px;padding:9px 14px;font:inherit;font-weight:600;cursor:pointer}button.ghost{background:#111b3c;border:1px solid var(--line)}button.sm{padding:5px 10px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;margin-top:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px}.muted{color:var(--muted);font-size:13px}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block}.on{background:var(--ok);box-shadow:0 0 0 4px rgba(34,197,94,.18)}.off{background:#55607f}
.bar{height:7px;background:#16204a;border-radius:4px;overflow:hidden;margin-top:4px}.bar>div{height:100%;background:var(--grad)}.bar.w>div{background:var(--warn)}.bar.b>div{background:var(--bad)}
.kv{display:grid;grid-template-columns:1fr 1fr;gap:6px 12px;margin:12px 0;font-size:13px}.kv span{color:var(--muted)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:20px}.stats .card b{display:block;font-size:24px}
@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}input{min-width:0;width:100%}}
</style></head><body>
<header><div class="logo">S</div><div><b>SwiftClean</b><div class="muted">Multi-PC Dashboard</div></div><div class="spacer"></div><span class="muted" id="upd"></span></header>
<main>
<div class="card row" id="login"><div style="flex:1"><b>Team key</b><div class="muted">Find it in SwiftClean → Multi-PC Dashboard. It stays in this browser only.</div></div><input id="key" type="password" placeholder="sc_…"><button id="go">Open dashboard</button></div>
<div id="dash" style="display:none">
<div class="row"><h2 style="margin:0">Your PCs</h2><div class="spacer"></div><button class="ghost sm" id="refresh">Refresh</button><button class="ghost sm" id="logout">Sign out</button></div>
<div class="stats"><div class="card"><span class="muted">PCs</span><b id="sPcs">0</b></div><div class="card"><span class="muted">Online</span><b id="sOn">0</b></div><div class="card"><span class="muted">Junk waiting</span><b id="sJunk">0</b></div><div class="card"><span class="muted">Freed so far</span><b id="sFreed">0</b></div></div>
<div class="grid" id="grid"></div></div>
</main>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=b=>{b=+b||0;if(!b)return'0 B';const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(i?1:0)+' '+u[i]};
const ago=t=>{const m=Math.round((Date.now()-Date.parse(t))/60000);return m<1?'just now':m<60?m+' min ago':m<1440?Math.round(m/60)+' h ago':m<2880?'1 day ago':Math.round(m/1440)+' days ago'};
let KEY=localStorage.getItem('scKey')||'';
async function api(p,o={}){const r=await fetch(p,{...o,headers:{'content-type':'application/json','x-team-key':KEY,...(o.headers||{})}});const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
async function load(){try{const {pcs}=await api('/api/pcs');$('#login').style.display='none';$('#dash').style.display='';render(pcs);$('#upd').textContent='Updated '+new Date().toLocaleTimeString()}catch(e){alert('Could not load: '+e.message)}}
function render(pcs){pcs.sort((a,b)=>a.name.localeCompare(b.name));const on=p=>Date.now()-Date.parse(p.lastSeen)<90*60000;
$('#sPcs').textContent=pcs.length;$('#sOn').textContent=pcs.filter(on).length;$('#sJunk').textContent=fmt(pcs.reduce((a,p)=>a+p.junk,0));$('#sFreed').textContent=fmt(pcs.reduce((a,p)=>a+p.freedTotal,0));
$('#grid').innerHTML=pcs.map(p=>{const c=(p.disks||[]).find(d=>d.id==='C:')||(p.disks||[])[0];const used=c&&c.size?1-c.free/c.size:0;const ram=p.ramTotal?1-p.ramFree/p.ramTotal:0;
return '<div class="card"><div class="row"><span class="dot '+(on(p)?'on':'off')+'"></span><b>'+esc(p.name)+'</b><div class="spacer"></div><span class="muted">'+ago(p.lastSeen)+'</span></div>'+
'<div class="muted">'+esc(p.os)+' · SwiftClean '+esc(p.version)+(p.admin?'':' · not admin')+'</div>'+
(c?'<div style="margin-top:10px" class="muted">Drive '+esc(c.id)+' – '+fmt(c.free)+' free of '+fmt(c.size)+'</div><div class="bar '+(used>.9?'b':used>.8?'w':'')+'"><div style="width:'+(used*100).toFixed(0)+'%"></div></div>':'')+
'<div class="muted" style="margin-top:8px">Memory '+(ram*100).toFixed(0)+'% used of '+fmt(p.ramTotal)+'</div><div class="bar '+(ram>.85?'w':'')+'"><div style="width:'+(ram*100).toFixed(0)+'%"></div></div>'+
'<div class="kv"><span>Junk waiting</span><b>'+fmt(p.junk)+'</b><span>Last clean</span><b>'+(p.lastClean?ago(p.lastClean):'never')+'</b><span>Uptime</span><b>'+p.uptimeHours+' h</b><span>Freed total</span><b>'+fmt(p.freedTotal)+'</b></div>'+
(p.lastResult?'<div class="muted">Last remote job: '+esc(p.lastResult)+'</div>':'')+
'<div class="row" style="margin-top:12px"><button class="sm" data-clean="'+esc(p.id)+'">'+(p.pending?'Clean queued…':'Clean now')+'</button><button class="ghost sm" data-report="'+esc(p.id)+'">Refresh PC</button><div class="spacer"></div><button class="ghost sm" data-del="'+esc(p.id)+'">Remove</button></div></div>'}).join('')||'<div class="card muted">No PCs yet. In SwiftClean open Multi-PC Dashboard, paste this team key and turn it on.</div>';
document.querySelectorAll('[data-clean]').forEach(b=>b.onclick=async()=>{await api('/api/command',{method:'POST',body:JSON.stringify({pcId:b.dataset.clean,type:'clean'})});b.textContent='Clean queued…'});
document.querySelectorAll('[data-report]').forEach(b=>b.onclick=async()=>{await api('/api/command',{method:'POST',body:JSON.stringify({pcId:b.dataset.report,type:'report'})});b.textContent='Requested'});
document.querySelectorAll('[data-del]').forEach(b=>b.onclick=async()=>{if(confirm('Remove this PC from the dashboard?')){await api('/api/pc?id='+encodeURIComponent(b.dataset.del),{method:'DELETE'});load()}});}
$('#go').onclick=()=>{KEY=$('#key').value.trim();localStorage.setItem('scKey',KEY);load()};
$('#refresh').onclick=load;$('#logout').onclick=()=>{localStorage.removeItem('scKey');location.reload()};
if(KEY)load();setInterval(()=>{if(KEY&&$('#dash').style.display!=='none')load()},60000);
</script></body></html>`;
