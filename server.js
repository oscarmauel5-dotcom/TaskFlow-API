require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs').promises;
const http = require('http');
const path = require('path');
const { randomUUID } = require('crypto');
const app = express();
const PORT = 3000;
const secret = process.env.JWT_SECRET;
const tasksFile = path.join(__dirname, 'tareas.json');
const usersFile = path.join(__dirname, 'usuarios.json');
app.use(bodyParser.json({limit:'32kb'}));
app.use((req,res,next)=>{ console.log(req.method, req.path); next(); });
const wrap = fn => (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
function fail(status,message){ throw Object.assign(new Error(message),{status}); }
async function leer(file){ const data = JSON.parse(await fs.readFile(file,'utf8')); if(!Array.isArray(data)) throw new Error('Archivo JSON inválido'); return data; }
async function guardar(file,data){ const tmp=file+'.tmp'; await fs.writeFile(tmp,JSON.stringify(data,null,2),'utf8'); await fs.rename(tmp,file); }
// Serializa cambios para evitar pérdidas por escrituras concurrentes.
let cola = Promise.resolve();
function modificar(file,fn){ const job=cola.then(async()=>{const data=await leer(file); const result=await fn(data); await guardar(file,data); return result;}); cola=job.catch(()=>{}); return job; }
function credenciales(req,res,next){ const {email,password}=req.body||{}; if(typeof email!=='string'||email.length>254||!/^\S+@\S+\.\S+$/.test(email.trim())||typeof password!=='string'||password.length<8||Buffer.byteLength(password)>72) return next(Object.assign(new Error('Correo válido y contraseña de 8 caracteres mínimo, máximo 72 bytes requeridos'),{status:400})); req.credentials={email:email.trim().toLowerCase(),password}; next(); }
function autenticar(req,res,next){ const match=/^Bearer (\S+)$/i.exec(req.headers.authorization||''); if(!match)return res.status(401).json({error:'Token requerido'}); try{req.user=jwt.verify(match[1],secret,{algorithms:['HS256']});}catch{return res.status(403).json({error:'Token inválido o expirado'});} next(); }
function validar(req,res,next){ const {titulo,descripcion}=req.body||{}; if(typeof titulo!=='string'||!titulo.trim()||titulo.length>150||typeof descripcion!=='string'||!descripcion.trim()||descripcion.length>2000)return res.status(400).json({error:'Título y descripción válidos requeridos'}); req.tarea={titulo:titulo.trim(),descripcion:descripcion.trim()}; next(); }
app.get('/',(req,res)=>res.json({nombre:'TaskFlow API',estado:'En línea'}));
app.post('/register',credenciales,wrap(async(req,res)=>{const {email,password}=req.credentials; const hash=await bcrypt.hash(password,12); await modificar(usersFile,users=>{if(users.some(u=>u.email===email))fail(409,'Correo registrado'); users.push({id:randomUUID(),email,password:hash});}); res.status(201).json({mensaje:'Usuario registrado'});}));
app.post('/login',credenciales,wrap(async(req,res)=>{const {email,password}=req.credentials; const user=(await leer(usersFile)).find(u=>u.email===email); if(!user||!await bcrypt.compare(password,user.password))fail(401,'Credenciales incorrectas'); res.json({token:jwt.sign({sub:user.id},secret,{algorithm:'HS256',expiresIn:'2h'})});}));
app.use('/tareas',autenticar);
app.get('/tareas',wrap(async(req,res)=>res.json((await leer(tasksFile)).filter(t=>t.propietario===req.user.sub))));
app.post('/tareas',validar,wrap(async(req,res)=>{const tarea={id:randomUUID(),...req.tarea,propietario:req.user.sub}; await modificar(tasksFile,t=>t.push(tarea)); res.status(201).json(tarea);}));
app.put('/tareas/:id',validar,wrap(async(req,res)=>{const tarea=await modificar(tasksFile,t=>{const i=t.findIndex(x=>x.id===req.params.id&&x.propietario===req.user.sub); if(i<0)fail(404,'Tarea no encontrada'); return t[i]={...t[i],...req.tarea};}); res.json(tarea);}));
app.delete('/tareas/:id',wrap(async(req,res)=>{await modificar(tasksFile,t=>{const i=t.findIndex(x=>x.id===req.params.id&&x.propietario===req.user.sub); if(i<0)fail(404,'Tarea no encontrada'); t.splice(i,1);}); res.json({mensaje:'Tarea eliminada'});}));
app.use((req,res)=>res.status(404).json({error:'Ruta no encontrada'}));
app.use((err,req,res,next)=>{console.error(err.message); if(res.headersSent)return next(err); const status=err.status>=400&&err.status<600?err.status:500; res.status(status).json({error:status===500?'Error interno del servidor':err.message});});
async function iniciar(){if(!secret||secret.length<32)throw new Error('Configura JWT_SECRET de al menos 32 caracteres en .env'); for(const file of [tasksFile,usersFile]){try{await leer(file);}catch(e){if(e.code!=='ENOENT')throw e; await fs.writeFile(file,'[]\n',{flag:'wx'});}} const server=http.createServer(app); server.on('error',e=>{console.error(e.message);process.exitCode=1;}); server.listen(PORT,'127.0.0.1',()=>console.log(`TaskFlow API: http://localhost:${PORT}`));}
iniciar().catch(e=>{console.error(e.message);process.exitCode=1;});
