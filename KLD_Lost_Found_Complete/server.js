'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PORT = Number(process.env.PORT || 3000);
const sessions = new Map();
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({users:[], reports:[], messages:[]}, null, 2));
function dbRead(){ try { return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); } catch { return {users:[],reports:[],messages:[]}; } }
function dbWrite(db){ fs.writeFileSync(DB_FILE, JSON.stringify(db,null,2)); }
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex'); return {salt, hash};
}
function verifyPassword(password, user){ const candidate = hashPassword(password,user.salt).hash; return crypto.timingSafeEqual(Buffer.from(candidate,'hex'),Buffer.from(user.passwordHash,'hex')); }
let db = dbRead();
if (!db.users.some(u => u.role === 'admin')) {
  const credentials = hashPassword('ChangeMe_Admin123!');
  db.users.push({id:crypto.randomUUID(),name:'KLD Administrator',email:'admin@kld.local',role:'admin',salt:credentials.salt,passwordHash:credentials.hash,createdAt:new Date().toISOString()});
  dbWrite(db);
}
function send(res,status,obj,headers={}) { res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}); res.end(JSON.stringify(obj)); }
function parseCookies(req){ return Object.fromEntries((req.headers.cookie||'').split(';').map(s=>s.trim()).filter(Boolean).map(s=>{const i=s.indexOf('=');return [s.slice(0,i),decodeURIComponent(s.slice(i+1))]})); }
function currentUser(req){const sid=parseCookies(req).kld_session; return sid ? sessions.get(sid) : null;}
function body(req){return new Promise((resolve,reject)=>{let raw='';req.on('data',chunk=>{raw+=chunk;if(raw.length>8*1024*1024){reject(new Error('Request too large'));req.destroy();}});req.on('end',()=>{try{resolve(raw?JSON.parse(raw):{});}catch{reject(new Error('Invalid JSON'));}});req.on('error',reject);});}
function cleanUser(u){return {id:u.id,name:u.name,email:u.email,role:u.role,createdAt:u.createdAt};}
function requireUser(req,res){const u=currentUser(req);if(!u){send(res,401,{error:'Please log in first.'});return null;}return u;}
function requireAdmin(req,res){const u=requireUser(req,res);if(!u)return null;if(u.role!=='admin'){send(res,403,{error:'Admin access only.'});return null;}return u;}
function safeText(value,max=160){return String(value||'').trim().slice(0,max);}
async function api(req,res,url){
  if(req.method==='GET'&&url.pathname==='/api/me'){const u=currentUser(req);return send(res,200,{user:u?cleanUser(u):null});}
  if(req.method==='POST'&&url.pathname==='/api/signup'){
    const b=await body(req),name=safeText(b.name,80),email=safeText(b.email,160).toLowerCase(),password=String(b.password||'');
    if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return send(res,400,{error:'Enter your name, a valid email, and a password with at least 8 characters.'});
    db=dbRead();if(db.users.some(u=>u.email===email))return send(res,409,{error:'An account with that email already exists.'});
    const p=hashPassword(password),u={id:crypto.randomUUID(),name,email,role:'user',salt:p.salt,passwordHash:p.hash,createdAt:new Date().toISOString()};db.users.push(u);dbWrite(db);
    const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,cleanUser(u));return send(res,201,{user:cleanUser(u)}, {'Set-Cookie':`kld_session=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`});
  }
  if(req.method==='POST'&&url.pathname==='/api/login'){
    const b=await body(req),email=safeText(b.email,160).toLowerCase(),password=String(b.password||'');db=dbRead();const u=db.users.find(x=>x.email===email);
    if(!u||!verifyPassword(password,u))return send(res,401,{error:'Incorrect email or password.'});
    const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,cleanUser(u));return send(res,200,{user:cleanUser(u)}, {'Set-Cookie':`kld_session=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`});
  }
  if(req.method==='POST'&&url.pathname==='/api/logout'){const sid=parseCookies(req).kld_session;if(sid)sessions.delete(sid);return send(res,200,{ok:true},{'Set-Cookie':'kld_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'});}
  if(req.method==='GET'&&url.pathname==='/api/reports') {db=dbRead();return send(res,200,{reports:db.reports.slice().sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).map(r=>({...r,ownerName:r.ownerName||'KLD User'}))});}
  if(req.method==='POST'&&url.pathname==='/api/reports'){
    const u=requireUser(req,res);if(!u)return;const b=await body(req);const type=['lost','found'].includes(b.type)?b.type:'';const title=safeText(b.title,100),category=safeText(b.category,60),location=safeText(b.location,160),description=safeText(b.description,1200),date=safeText(b.date,30),contact=safeText(b.contact,100),image=typeof b.image==='string'&&/^data:image\/(png|jpeg|jpg|webp);base64,/.test(b.image)&&b.image.length<2_500_000?b.image:'';
    if(!type||title.length<3||!category||!location||description.length<5)return send(res,400,{error:'Please complete the item type, title, category, location, and description.'});
    db=dbRead();const r={id:crypto.randomUUID(),type,title,category,location,description,date,contact,image,status:'Pending',ownerId:u.id,ownerName:u.name,createdAt:new Date().toISOString()};db.reports.push(r);dbWrite(db);return send(res,201,{report:r});
  }
  if(req.method==='GET'&&url.pathname==='/api/my-reports'){const u=requireUser(req,res);if(!u)return;db=dbRead();return send(res,200,{reports:db.reports.filter(r=>r.ownerId===u.id).sort((a,b)=>b.createdAt.localeCompare(a.createdAt))});}
  if(req.method==='PATCH'&&url.pathname.startsWith('/api/reports/')){const u=requireAdmin(req,res);if(!u)return;const id=url.pathname.split('/').pop(),b=await body(req);if(!['Pending','Under Review','Resolved','Archived'].includes(b.status))return send(res,400,{error:'Invalid status.'});db=dbRead();const r=db.reports.find(x=>x.id===id);if(!r)return send(res,404,{error:'Report not found.'});r.status=b.status;r.updatedAt=new Date().toISOString();dbWrite(db);return send(res,200,{report:r});}
  if(req.method==='GET'&&url.pathname==='/api/admin/stats'){const u=requireAdmin(req,res);if(!u)return;db=dbRead();return send(res,200,{users:db.users.filter(x=>x.role==='user').length,total:db.reports.length,lost:db.reports.filter(x=>x.type==='lost').length,found:db.reports.filter(x=>x.type==='found').length,pending:db.reports.filter(x=>x.status==='Pending').length});}
  if(req.method==='GET'&&url.pathname==='/api/admin/users'){const u=requireAdmin(req,res);if(!u)return;db=dbRead();return send(res,200,{users:db.users.map(cleanUser)});}
  return send(res,404,{error:'API route not found.'});
}
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.ico':'image/x-icon'};
const server=http.createServer(async(req,res)=>{try{const url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/'))return await api(req,res,url);let file=path.join(PUBLIC,decodeURIComponent(url.pathname==='/'?'/index.html':url.pathname));if(!file.startsWith(PUBLIC))return send(res,403,{error:'Forbidden'});if(!fs.existsSync(file)||fs.statSync(file).isDirectory())file=path.join(PUBLIC,'index.html');res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'application/octet-stream','Cache-Control':'no-cache'});fs.createReadStream(file).pipe(res);}catch(e){console.error(e);if(!res.headersSent)send(res,e.message==='Request too large'?413:500,{error:e.message==='Invalid JSON'?'Invalid request format.':'Server error. Please try again.'});}});
server.listen(PORT,'127.0.0.1',()=>console.log(`KLD Lost & Found is running at http://localhost:${PORT}`));
