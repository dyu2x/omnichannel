import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import session from 'express-session';
import pg from 'pg';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
// express-openid-connect is CommonJS. Load it through Node's CJS loader to
// avoid Node 22's unreliable named-export detection for CommonJS packages.
const { auth } = require('express-openid-connect');
import crypto from 'node:crypto';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import nodemailer from 'nodemailer';
import { simpleParser } from 'mailparser';
import { ImapFlow } from 'imapflow';
import { v4 as uuidv4 } from 'uuid';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 15 });

const PORT = Number(process.env.PORT || 3000);
const clientIp=req=>{const raw=String(req.headers['cf-connecting-ip']||req.headers['x-forwarded-for']||req.socket?.remoteAddress||'').split(',')[0].trim();return raw.startsWith('::ffff:')?raw.slice(7):raw;};
const baseUrl = process.env.APP_BASE_URL || 'http://localhost:3000';
const key = Buffer.from(process.env.ENCRYPTION_KEY || '', 'base64');
if (key.length !== 32) console.warn('WARNING: ENCRYPTION_KEY must decode to exactly 32 bytes. Integration settings cannot be saved safely until configured.');
const encrypt = (value) => { if (!key.length || !value) throw new Error('Set a valid 32-byte ENCRYPTION_KEY'); const iv=crypto.randomBytes(12); const c=crypto.createCipheriv('aes-256-gcm',key,iv); const data=Buffer.concat([c.update(value,'utf8'),c.final()]); return [iv.toString('base64'),c.getAuthTag().toString('base64'),data.toString('base64')].join('.'); };
const decrypt = (value) => { const [iv,tag,data]=value.split('.'); const d=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(iv,'base64')); d.setAuthTag(Buffer.from(tag,'base64')); return Buffer.concat([d.update(Buffer.from(data,'base64')),d.final()]).toString('utf8'); };
app.set('trust proxy', 1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'","https://connect.facebook.net"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'","data:","https:"],connectSrc:["'self'","https:"],fontSrc:["'self'","data:"]}}}));
app.use(express.json({limit:'50mb',verify:(req,res,buf)=>{req.rawBody=Buffer.from(buf);}}));
app.use(express.urlencoded({extended:false}));
app.use(session({secret:process.env.SESSION_SECRET || 'development-only-change-me',resave:false,saveUninitialized:false,rolling:true,cookie:{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:60*60*1000}}));
const zitadelProfileCache = new Map();
const oidcReady = Boolean(process.env.ZITADEL_CLIENT_ID && process.env.ZITADEL_CLIENT_SECRET && process.env.ZITADEL_ISSUER);
if (oidcReady) app.use(auth({
  authRequired:false,
  auth0Logout:false,
  idpLogout:true,
  secret:process.env.SESSION_SECRET,
  baseURL:baseUrl,
  clientID:process.env.ZITADEL_CLIENT_ID,
  clientSecret:process.env.ZITADEL_CLIENT_SECRET,
  issuerBaseURL:process.env.ZITADEL_ISSUER,
  authorizationParams:{response_type:'code',scope:'openid profile email phone address'},
  routes:{logout:false,postLogoutRedirect:process.env.ZITADEL_LOGOUT_URL || baseUrl},
  // ZITADEL may omit profile/email claims from the ID token when an access token is issued.
  // Fetch UserInfo during the callback and persist the returned claims in the encrypted OIDC session.
  afterCallback:async (_req,_res,session)=>{
    try {
      if (session.access_token) {
        const issuer=String(process.env.ZITADEL_ISSUER||'').replace(/\/$/,'');
        const response=await fetch(`${issuer}/oidc/v1/userinfo`,{headers:{Authorization:`Bearer ${session.access_token}`,Accept:'application/json'}});
        if (response.ok) session.zitadelUserInfo=await response.json();
        else console.error('ZITADEL UserInfo request failed:',response.status);
      }
    } catch (error) { console.error('ZITADEL UserInfo request failed:',error.message); }
    return session;
  }
}));
else app.use((req,res,next)=>{req.oidc={isAuthenticated:()=>false};next();});
app.use('/widget.js', express.static(path.join(__dirname,'../public/widget.js')));
app.use('/assets', express.static(path.join(__dirname,'../public')));
app.get('/api/version',(req,res)=>res.json({version:'1.02.0',name:'Mesina Farms Unified Support'}));
app.get('/health', async (_req,res)=>{try{await pool.query('SELECT 1');res.json({ok:true,database:'connected',oidc:oidcReady});}catch(e){res.status(503).json({ok:false,error:'database unavailable'});}});
app.get('/webhooks/whatsapp', async (req,res)=>{const mode=req.query['hub.mode'];const token=req.query['hub.verify_token'];const challenge=req.query['hub.challenge'];try{const q=await pool.query('SELECT verify_token_enc FROM whatsapp_accounts WHERE enabled=true');const valid=q.rows.some(r=>decrypt(r.verify_token_enc)===token);if(mode==='subscribe'&&valid)return res.status(200).send(challenge);}catch(e){console.error('Webhook verify:',e.message);}res.sendStatus(403);});
app.post('/webhooks/whatsapp', async (req,res)=>{try{for(const entry of req.body.entry||[])for(const change of entry.changes||[]){const metadata=change.value?.metadata||{};const acct=(await pool.query('SELECT * FROM whatsapp_accounts WHERE phone_number_id=$1 AND enabled=true',[metadata.phone_number_id])).rows[0];if(acct?.app_secret_enc){const signature=String(req.headers['x-hub-signature-256']||'');const expected='sha256='+crypto.createHmac('sha256',decrypt(acct.app_secret_enc)).update(req.rawBody||Buffer.from('')).digest('hex');if(!signature||signature.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(expected)))return res.sendStatus(401);}}res.sendStatus(200);await pool.query('INSERT INTO webhook_events(provider,payload) VALUES($1,$2)', ['whatsapp',req.body]);for(const entry of req.body.entry||[])for(const change of entry.changes||[]){const value=change.value||{};const metadata=value.metadata||{};const acct=(await pool.query('SELECT * FROM whatsapp_accounts WHERE phone_number_id=$1 AND enabled=true',[metadata.phone_number_id])).rows[0];for(const m of value.messages||[]){const from=m.from;let contact=(await pool.query('SELECT * FROM contacts WHERE phone=$1',[from])).rows[0];if(!contact)contact=(await pool.query('INSERT INTO contacts(name,phone) VALUES($1,$2) RETURNING *',[value.contacts?.[0]?.profile?.name||from,from])).rows[0];let conv=(await pool.query("SELECT * FROM conversations WHERE contact_id=$1 AND channel='whatsapp' AND status IN ('open','pending') ORDER BY updated_at DESC LIMIT 1",[contact.id])).rows[0];if(!conv)conv=(await pool.query("INSERT INTO conversations(contact_id,channel,subject) VALUES($1,'whatsapp',$2) RETURNING *",[contact.id,'WhatsApp conversation'])).rows[0];const body=m.text?.body||m.button?.text||m.interactive?.button_reply?.title||`[${m.type||'unsupported'} message]`;const msg=(await pool.query("INSERT INTO messages(conversation_id,channel,direction,sender_name,sender_address,body_text,provider_message_id,raw_payload) VALUES($1,'whatsapp','inbound',$2,$3,$4,$5,$6) ON CONFLICT(channel,provider_message_id) DO NOTHING RETURNING id",[conv.id,contact.name,from,body,m.id, m])).rows[0];if(msg&&acct)await pool.query('INSERT INTO whatsapp_messages(message_id,account_id,wa_message_id,wa_from,message_type) VALUES($1,$2,$3,$4,$5) ON CONFLICT(wa_message_id) DO NOTHING',[msg.id,acct.id,m.id,from,m.type]);await pool.query('UPDATE conversations SET last_message_at=now(),updated_at=now() WHERE id=$1',[conv.id]);}for(const s of value.statuses||[])await pool.query('INSERT INTO whatsapp_message_statuses(wa_message_id,status,event_timestamp,recipient_id,payload) VALUES($1,$2,to_timestamp($3),$4,$5)',[s.id,s.status,Number(s.timestamp||0),s.recipient_id,s]);}}catch(e){console.error('WhatsApp webhook processing:',e);}});
const requireLogin=(req,res,next)=>{if(!oidcReady)return res.status(503).json({error:'ZITADEL is not configured. Set ZITADEL_CLIENT_ID and ZITADEL_CLIENT_SECRET.'});if(!req.oidc?.isAuthenticated?.())return res.status(401).json({error:'Authentication required'});next();};

// Capture successful authenticated edits with before/after values, section and client IPv4.
app.use('/api', async (req,res,next)=>{
  if(!['POST','PUT','PATCH','DELETE'].includes(req.method) || req.path.startsWith('/widget/')) return next();
  let actor=null,before=null,entityType=req.path.split('/')[2]||'system',entityId=null,section=req.path;
  try {
    const sub=req.oidc?.user?.sub;
    if(sub) actor=(await pool.query('SELECT id FROM users WHERE zitadel_sub=$1',[sub])).rows[0]||null;
    const parts=req.path.split('/').filter(Boolean);
    entityId=parts[2]||null;
    const map={contacts:'contacts',teams:'teams',agents:'users',conversations:'conversations'};
    const table=map[parts[1]];
    if(table&&entityId&&/^[0-9a-f-]{36}$/i.test(entityId))before=(await pool.query(`SELECT * FROM ${table} WHERE id=$1`,[entityId])).rows[0]||null;
    if(parts[1]==='settings'&&parts[2]==='ui')before=(await pool.query("SELECT value FROM system_settings WHERE key='ui_preferences'")).rows[0]||null;
    if(parts[1]==='settings'&&parts[2]==='branding')before=(await pool.query('SELECT * FROM branding_settings WHERE id=1')).rows[0]||null;
    if(parts[1]==='admin'&&parts[2]==='role-restrictions'&&parts[3])before=(await pool.query('SELECT r.name, array_agg(p.code) FILTER(WHERE p.code IS NOT NULL) permissions FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id LEFT JOIN permissions p ON p.id=rp.permission_id WHERE r.id=$1 GROUP BY r.id',[parts[3]])).rows[0]||null;
  } catch(e){console.error('Activity snapshot:',e.message)}
  res.once('finish', async ()=>{
    if(res.statusCode<200||res.statusCode>=400||!actor)return;
    try {
      const raw=String(req.headers['cf-connecting-ip']||req.headers['x-forwarded-for']||req.socket?.remoteAddress||'').split(',')[0].trim().replace(/^::ffff:/,'');
      const ipv4=/^(?:\d{1,3}\.){3}\d{1,3}$/.test(raw)?raw:null;
      const details={path:req.path,section,status:res.statusCode,before:before||null,after:req.body||{}};
      await pool.query('INSERT INTO agent_activity_logs(user_id,action,entity_type,entity_id,details,ip_address,public_ipv4,user_agent,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,now())',
        [actor.id,`api.${req.method.toLowerCase()}`,entityType,/^[0-9a-f-]{36}$/i.test(entityId||'')?entityId:null,details,raw||null,ipv4,req.headers['user-agent']||null]);
      await pool.query('INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,before_data,after_data,ip_address) VALUES($1,$2,$3,$4,$5,$6,$7)',
        [actor.id,`api.${req.method.toLowerCase()}`,entityType,entityId,before||null,req.body||{},raw||null]);
    } catch(e) { console.error('Activity tracking:',e.message); }
  });
  next();
});
async function currentUser(req){
  const p={...(req.oidc?.user||{})};
  const sub=p.sub||req.oidc?.user?.sub;
  const tokenValue=req.oidc?.accessToken?.access_token||req.oidc?.accessToken?.token||null;
  if(sub&&tokenValue){const cached=zitadelProfileCache.get(sub);if(cached&&cached.expires>Date.now())Object.assign(p,cached.profile);else{try{const issuer=String(process.env.ZITADEL_ISSUER||'').replace(/\/$/,'');const response=await fetch(`${issuer}/oidc/v1/userinfo`,{headers:{Authorization:`Bearer ${tokenValue}`,Accept:'application/json'}});if(response.ok){const profile=await response.json();zitadelProfileCache.set(sub,{profile,expires:Date.now()+5*60*1000});Object.assign(p,profile);}}catch(error){console.error('ZITADEL UserInfo refresh failed:',error.message);}}}
  if(!sub)throw new Error('Missing ZITADEL subject');
  const email=p.email||null;
  const displayName=p.name||[p.given_name,p.family_name].filter(Boolean).join(' ')||p.preferred_username||email||'Agent';
  const profile={
    given_name:p.given_name||null,family_name:p.family_name||null,nickname:p.nickname||null,
    preferred_username:p.preferred_username||null,phone_number:p.phone_number||null,
    phone_number_verified:typeof p.phone_number_verified==='boolean'?p.phone_number_verified:null,
    email_verified:typeof p.email_verified==='boolean'?p.email_verified:null,
    profile_url:p.profile||null,website:p.website||null,locale:p.locale||null,
    zoneinfo:p.zoneinfo||null,address:p.address||null,raw_profile:p
  };
  const values=[sub,email,displayName,p.picture||null,profile.given_name,profile.family_name,profile.nickname,profile.preferred_username,profile.phone_number,profile.phone_number_verified,profile.email_verified,profile.profile_url,profile.website,profile.locale,profile.zoneinfo,JSON.stringify(profile.address),JSON.stringify(profile.raw_profile)];
  let u=(await pool.query('SELECT * FROM users WHERE zitadel_sub=$1',[sub])).rows[0];
  if(!u){
    u=(await pool.query(`INSERT INTO users(zitadel_sub,email,display_name,avatar_url,given_name,family_name,nickname,preferred_username,phone_number,phone_number_verified,email_verified,profile_url,website,locale,zoneinfo,address,raw_profile,last_seen_at,first_login_at,last_login_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17::jsonb,now(),now(),now()) RETURNING *`,values)).rows[0];
    const roleName=(process.env.BOOTSTRAP_ADMIN_EMAIL&&email?.toLowerCase()===process.env.BOOTSTRAP_ADMIN_EMAIL.toLowerCase())?'Super Admin':'Agent';
    await pool.query('INSERT INTO user_roles(user_id,role_id) SELECT $1,id FROM roles WHERE name=$2 ON CONFLICT DO NOTHING',[u.id,roleName]);
  } else {
    u=(await pool.query(`UPDATE users SET email=$2,display_name=$3,avatar_url=COALESCE($4,avatar_url),given_name=COALESCE($5,given_name),family_name=COALESCE($6,family_name),nickname=COALESCE($7,nickname),preferred_username=COALESCE($8,preferred_username),phone_number=COALESCE($9,phone_number),phone_number_verified=COALESCE($10,phone_number_verified),email_verified=COALESCE($11,email_verified),profile_url=COALESCE($12,profile_url),website=COALESCE($13,website),locale=COALESCE($14,locale),zoneinfo=COALESCE($15,zoneinfo),address=COALESCE($16::jsonb,address),raw_profile=$17::jsonb,last_seen_at=now(),last_login_at=now(),updated_at=now() WHERE id=$1 RETURNING *`,[u.id,...values.slice(1)])).rows[0];
  }
  // Application roles are local. Repair legacy accounts that predate role assignment,
  // and always enforce the configured bootstrap administrator by ZITADEL email.
  // This also fixes users already present in the database before v1.01.4.
  const bootstrapEmail=String(process.env.BOOTSTRAP_ADMIN_EMAIL||'').trim().toLowerCase();
  if(bootstrapEmail && email && email.toLowerCase()===bootstrapEmail){
    await pool.query(
      `INSERT INTO user_roles(user_id,role_id)
       SELECT $1,id FROM roles WHERE name='Super Admin'
       ON CONFLICT(user_id,role_id) DO NOTHING`,
      [u.id]
    );
  } else {
    await pool.query(
      `INSERT INTO user_roles(user_id,role_id)
       SELECT $1,id FROM roles
       WHERE name='Agent'
         AND NOT EXISTS (SELECT 1 FROM user_roles WHERE user_id=$1)
       ON CONFLICT(user_id,role_id) DO NOTHING`,
      [u.id]
    );
  }
  if(!u.is_active) throw Object.assign(new Error('Your agent account is inactive. Contact an administrator.'),{status:403});
  return u;
}
async function access(req, permission){const u=await currentUser(req);const q=await pool.query('SELECT p.code FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id JOIN permissions p ON p.id=rp.permission_id WHERE ur.user_id=$1',[u.id]);const codes=new Set(q.rows.map(x=>x.code));return {user:u,allowed:codes.has(permission)||codes.has('settings.manage')};}
async function assertConversationAccess(req,id){const {user}=await access(req,'inbox.view');const all=await access(req,'conversation.manage_all');if(all.allowed)return user;const row=(await pool.query('SELECT assigned_user_id,assigned_team_id FROM conversations WHERE id=$1',[id])).rows[0];if(!row)throw Object.assign(new Error('Conversation not found'),{status:404});if(row.assigned_user_id===user.id||(!row.assigned_user_id&&!row.assigned_team_id))return user;if(row.assigned_team_id){const member=(await pool.query('SELECT 1 FROM team_members WHERE team_id=$1 AND user_id=$2',[row.assigned_team_id,user.id])).rowCount>0;if(member)return user;}throw Object.assign(new Error('You do not have access to this conversation'),{status:403});}
const api=(fn)=>async(req,res)=>{try{const result=await fn(req,res);if(result!==undefined&&!res.headersSent)res.json(result);}catch(e){console.error(e);if(!res.headersSent)res.status(e.status||500).json({error:e.message||'Internal error'});}};
app.get('/login',(req,res)=>oidcReady?res.oidc.login({returnTo:'/'}):res.status(503).send('Configure ZITADEL first.'));
app.get('/logout',(req,res)=>oidcReady?res.oidc.logout({returnTo:process.env.ZITADEL_LOGOUT_URL || baseUrl,logoutParams:{client_id:process.env.ZITADEL_CLIENT_ID}}):res.redirect('/'));
app.get('/callback',(req,res)=>res.redirect('/'));
app.get('/api/me',requireLogin,api(async req=>{const {user}=await access(req,'inbox.view');const roles=await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id]);return {user,roles:roles.rows.map(x=>x.name)};}));
app.get('/api/summary',requireLogin,api(async req=>{
  const {user}=await access(req,'inbox.view');
  const all=await access(req,'conversation.manage_all');
  const mine=String(req.query.mine||'')==='true';
  const args=[];let filter="status NOT IN ('closed','resolved')";
  if(mine){args.push(user.id);filter+=' AND assigned_user_id=$1';}
  else if(!all.allowed){args.push(user.id);filter+=' AND (assigned_user_id=$1 OR (assigned_user_id IS NULL AND assigned_team_id IS NULL) OR assigned_team_id IN (SELECT team_id FROM team_members WHERE user_id=$1))';}
  const q=await pool.query(`SELECT channel,status,count(*)::int count FROM conversations WHERE ${filter} GROUP BY channel,status`,args);
  return q.rows;
}));
app.get('/api/conversations',requireLogin,api(async req=>{
  const {user}=await access(req,'inbox.view');
  const all=await access(req,'conversation.manage_all');
  const args=[];let where=[];
  const poolOnly=req.query.pool==='true';
  if(poolOnly) where.push('c.assigned_user_id IS NULL AND c.assigned_team_id IS NULL');
  else if(req.query.mine==='true'){args.push(user.id);where.push(`c.assigned_user_id=$${args.length}`);}
  else if(req.query.team){if(!all.allowed){const member=(await pool.query('SELECT 1 FROM team_members WHERE team_id=$1 AND user_id=$2',[req.query.team,user.id])).rowCount>0;if(!member)throw Object.assign(new Error('You are not a member of this team'),{status:403});}args.push(req.query.team);where.push(`c.assigned_team_id=$${args.length}`);}
  else if(!all.allowed){args.push(user.id);where.push(`(c.assigned_user_id=$${args.length} OR (c.assigned_user_id IS NULL AND c.assigned_team_id IS NULL) OR c.assigned_team_id IN (SELECT team_id FROM team_members WHERE user_id=$${args.length}))`);}
  if(req.query.status){args.push(req.query.status);where.push(`c.status=$${args.length}`);} else where.push("c.status NOT IN ('closed','resolved')");
  if(req.query.channel){args.push(req.query.channel);where.push(`c.channel=$${args.length}`);}
  if(req.query.q){args.push(`%${String(req.query.q).slice(0,120)}%`);where.push(`(coalesce(co.name,'') ILIKE $${args.length} OR coalesce(co.email,'') ILIKE $${args.length} OR coalesce(co.phone,'') ILIKE $${args.length} OR coalesce(c.subject,'') ILIKE $${args.length} OR EXISTS(SELECT 1 FROM messages sm WHERE sm.conversation_id=c.id AND sm.body_text ILIKE $${args.length}))`);}
  const sql=`SELECT c.*,co.name contact_name,co.email contact_email,co.phone contact_phone,co.company contact_company,
    u.display_name assigned_name,u.avatar_url assigned_avatar,t.name assigned_team_name,
    (SELECT m.body_text FROM messages m WHERE m.conversation_id=c.id AND m.direction<>'internal' ORDER BY m.created_at DESC LIMIT 1) last_message,
    (SELECT m.created_at FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_message_created_at,
    (SELECT count(*)::int FROM messages um WHERE um.conversation_id=c.id AND um.direction='inbound' AND um.created_at>coalesce((SELECT max(om.created_at) FROM messages om WHERE om.conversation_id=c.id AND om.direction IN ('outbound','internal')), 'epoch'::timestamptz)) unread_count
    FROM conversations c LEFT JOIN contacts co ON co.id=c.contact_id LEFT JOIN users u ON u.id=c.assigned_user_id LEFT JOIN teams t ON t.id=c.assigned_team_id
    ${where.length?'WHERE '+where.join(' AND '):''} ORDER BY coalesce(c.last_message_at,c.updated_at) DESC LIMIT 500`;
  return (await pool.query(sql,args)).rows;
}));
app.get('/api/conversations/:id',requireLogin,api(async req=>{
  await assertConversationAccess(req,req.params.id);
  const row=(await pool.query(`SELECT c.*,co.name contact_name,co.email contact_email,co.phone contact_phone,co.company contact_company,
    co.first_name contact_first_name,co.last_name contact_last_name,co.notes contact_notes,
    u.display_name assigned_name,u.avatar_url assigned_avatar,t.name assigned_team_name
    FROM conversations c LEFT JOIN contacts co ON co.id=c.contact_id LEFT JOIN users u ON u.id=c.assigned_user_id LEFT JOIN teams t ON t.id=c.assigned_team_id WHERE c.id=$1`,[req.params.id])).rows[0];
  if(!row)throw Object.assign(new Error('Conversation not found'),{status:404});
  const [messages,notes,events,assignments,tags]=await Promise.all([
    pool.query("SELECT m.*,u.display_name created_by_name,u.avatar_url created_by_avatar,COALESCE((SELECT json_agg(json_build_object('id',a.id,'file_name',a.file_name,'mime_type',a.mime_type,'size_bytes',a.size_bytes)) FROM message_attachments a WHERE a.message_id=m.id),'[]'::json) attachments FROM messages m LEFT JOIN users u ON u.id=m.created_by WHERE m.conversation_id=$1 ORDER BY m.created_at",[req.params.id]),
    pool.query('SELECT n.*,u.display_name author_name,u.avatar_url author_avatar FROM conversation_notes n LEFT JOIN users u ON u.id=n.author_user_id WHERE n.conversation_id=$1 ORDER BY n.created_at',[req.params.id]),
    pool.query('SELECT e.*,u.display_name actor_name FROM conversation_events e LEFT JOIN users u ON u.id=e.actor_user_id WHERE e.conversation_id=$1 ORDER BY e.created_at DESC LIMIT 100',[req.params.id]),
    pool.query('SELECT a.*,f.display_name from_name,to_u.display_name to_name,by_u.display_name assigned_by_name FROM conversation_assignments a LEFT JOIN users f ON f.id=a.from_user_id LEFT JOIN users to_u ON to_u.id=a.to_user_id LEFT JOIN users by_u ON by_u.id=a.assigned_by WHERE a.conversation_id=$1 ORDER BY a.created_at DESC',[req.params.id]),
    pool.query('SELECT t.* FROM tags t JOIN conversation_tags ct ON ct.tag_id=t.id WHERE ct.conversation_id=$1 ORDER BY t.name',[req.params.id])
  ]);
  return {conversation:row,messages:messages.rows,notes:notes.rows,events:events.rows,assignments:assignments.rows,tags:tags.rows};
}));
app.get('/api/attachments/:id',requireLogin,async(req,res)=>{
 try{
  const row=(await pool.query('SELECT a.*,m.conversation_id FROM message_attachments a JOIN messages m ON m.id=a.message_id WHERE a.id=$1',[req.params.id])).rows[0];
  if(!row)return res.status(404).json({error:'Attachment not found'});
  await assertConversationAccess(req,row.conversation_id);
  if(!row.content)return res.status(404).json({error:'Attachment content unavailable'});
  res.setHeader('Content-Type',row.mime_type||'application/octet-stream');
  res.setHeader('Content-Disposition',`attachment; filename*=UTF-8''${encodeURIComponent(row.file_name||'attachment')}`);
  res.setHeader('X-Content-Type-Options','nosniff');
  return res.send(row.content);
 }catch(e){return res.status(e.status||403).json({error:e.message||'Unable to retrieve attachment'});}
});
app.get('/api/conversations/:id/messages',requireLogin,api(async req=>{await assertConversationAccess(req,req.params.id);return (await pool.query('SELECT * FROM messages WHERE conversation_id=$1 ORDER BY created_at',[req.params.id])).rows;}));
app.post('/api/conversations/:id/claim',requireLogin,api(async req=>{
  const {user,allowed}=await access(req,'conversation.claim');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});
  const client=await pool.connect();try{await client.query('BEGIN');
    const row=(await client.query('SELECT * FROM conversations WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];
    if(!row)throw Object.assign(new Error('Conversation not found'),{status:404});
    if(row.assigned_team_id){const member=(await client.query('SELECT 1 FROM team_members WHERE team_id=$1 AND user_id=$2',[row.assigned_team_id,user.id])).rowCount>0;if(!member)throw Object.assign(new Error('This conversation belongs to a team you are not part of'),{status:403});}
    if(row.assigned_user_id&&row.assigned_user_id!==user.id)throw Object.assign(new Error('Conversation has already been claimed by another agent'),{status:409});
    if(row.assigned_user_id===user.id){await client.query('COMMIT');return {ok:true,already_claimed:true};}
    await client.query('UPDATE conversations SET assigned_user_id=$2,updated_at=now() WHERE id=$1',[row.id,user.id]);
    await client.query("INSERT INTO conversation_assignments(conversation_id,from_user_id,to_user_id,assigned_by,action) VALUES($1,$2,$3,$3,'claimed')",[row.id,row.assigned_user_id,user.id]);
    await client.query("INSERT INTO conversation_events(conversation_id,actor_user_id,event_type,old_value,new_value) VALUES($1,$2,'claimed',$3,$4)",[row.id,user.id,{assigned_user_id:row.assigned_user_id},{assigned_user_id:user.id}]);
    await client.query("INSERT INTO agent_activity_logs(user_id,action,entity_type,entity_id) VALUES($1,'conversation.claim','conversation',$2)",[user.id,row.id]);
    await client.query('COMMIT');return {ok:true};
  }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
}));
app.post('/api/conversations/:id/assign',requireLogin,api(async req=>{
  const {user,allowed}=await access(req,'conversation.assign');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});
  const target=req.body.user_id||null,team=req.body.team_id||null;
  const client=await pool.connect();try{await client.query('BEGIN');
    const old=(await client.query('SELECT * FROM conversations WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];if(!old)throw Object.assign(new Error('Conversation not found'),{status:404});
    if(target){const exists=(await client.query('SELECT id FROM users WHERE id=$1 AND is_active=true',[target])).rows[0];if(!exists)throw new Error('Selected agent does not exist or is inactive');}
    if(team){const exists=(await client.query('SELECT id FROM teams WHERE id=$1',[team])).rows[0];if(!exists)throw new Error('Selected team does not exist');}
    await client.query('UPDATE conversations SET assigned_user_id=$2,assigned_team_id=$3,updated_at=now() WHERE id=$1',[req.params.id,target,team]);
    await client.query("INSERT INTO conversation_assignments(conversation_id,from_user_id,to_user_id,assigned_by,action,note) VALUES($1,$2,$3,$4,$5,$6)",[req.params.id,old.assigned_user_id,target,user.id,target||team?'assigned':'unassigned',req.body.note||null]);
    await client.query("INSERT INTO conversation_events(conversation_id,actor_user_id,event_type,old_value,new_value) VALUES($1,$2,'assignment_changed',$3,$4)",[req.params.id,user.id,{user_id:old.assigned_user_id,team_id:old.assigned_team_id},{user_id:target,team_id:team}]);
    await client.query("INSERT INTO agent_activity_logs(user_id,action,entity_type,entity_id,details) VALUES($1,'conversation.assign','conversation',$2,$3)",[user.id,req.params.id,{from_user:old.assigned_user_id,to_user:target,from_team:old.assigned_team_id,to_team:team}]);
    await client.query('COMMIT');return {ok:true};
  }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
}));
app.post('/api/conversations/:id/note',requireLogin,api(async req=>{
  const {user,allowed}=await access(req,'conversation.note');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});
  await assertConversationAccess(req,req.params.id);const body=String(req.body.body||'').trim();if(!body||body.length>10000)throw new Error('Internal note is required (maximum 10,000 characters)');
  const client=await pool.connect();try{await client.query('BEGIN');const exists=(await client.query('SELECT id FROM conversations WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];if(!exists)throw Object.assign(new Error('Conversation not found'),{status:404});
    const note=(await client.query('INSERT INTO conversation_notes(conversation_id,author_user_id,body) VALUES($1,$2,$3) RETURNING *',[req.params.id,user.id,body])).rows[0];
    await client.query("INSERT INTO conversation_events(conversation_id,actor_user_id,event_type,new_value) VALUES($1,$2,'internal_note_added',$3)",[req.params.id,user.id,{note_id:note.id}]);
    await client.query('UPDATE conversations SET updated_at=now() WHERE id=$1',[req.params.id]);await client.query("INSERT INTO agent_activity_logs(user_id,action,entity_type,entity_id) VALUES($1,'conversation.note','conversation',$2)",[user.id,req.params.id]);await client.query('COMMIT');return {ok:true,note};
  }catch(e){await client.query('ROLLBACK').catch(()=>{});throw e;}finally{client.release();}
}));
app.get('/api/contacts',requireLogin,api(async req=>{
  await access(req,'contacts.view');const args=[];let where='';if(req.query.q){args.push(`%${String(req.query.q).slice(0,120)}%`);where=`WHERE coalesce(c.name,'') ILIKE $1 OR coalesce(c.email,'') ILIKE $1 OR coalesce(c.phone,'') ILIKE $1 OR coalesce(c.company,'') ILIKE $1`;}
  const limit=Math.min(Math.max(Number(req.query.limit||100),1),250);args.push(limit);
  return (await pool.query(`SELECT c.*,count(DISTINCT v.id)::int conversation_count,max(v.updated_at) last_contact_at FROM contacts c LEFT JOIN conversations v ON v.contact_id=c.id ${where} GROUP BY c.id ORDER BY coalesce(max(v.updated_at),c.updated_at) DESC,c.name LIMIT $${args.length}`,args)).rows;
}));
app.post('/api/contacts',requireLogin,api(async req=>{
  const {user,allowed}=await access(req,'contacts.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const x=req.body;
  const name=String(x.name||[x.first_name,x.last_name].filter(Boolean).join(' ')).trim();if(!name)throw new Error('Contact name is required');
  const row=(await pool.query(`INSERT INTO contacts(name,first_name,last_name,email,phone,company,notes,source,custom_fields) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) RETURNING *`,[name,x.first_name||null,x.last_name||null,x.email||null,x.phone||null,x.company||null,x.notes||null,x.source||'manual',JSON.stringify(x.custom_fields||{})])).rows[0];
  await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'contact.created','contact',$2,$3)",[user.id,row.id,row]);return row;
}));
app.delete('/api/contacts/:id',requireLogin,api(async req=>{const {user}=await access(req,'inbox.view');const roles=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id])).rows.map(x=>x.name);if(!roles.includes('Super Admin'))throw Object.assign(new Error('Only Super Admin can delete customer directory records'),{status:403});const row=(await pool.query('DELETE FROM contacts WHERE id=$1 RETURNING id',[req.params.id])).rows[0];if(!row)throw Object.assign(new Error('Contact not found'),{status:404});await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,ip_address) VALUES($1,'contact.deleted','contact',$2,$3)",[user.id,row.id,clientIp(req)]);return {ok:true};}));
app.get('/api/contacts/:id',requireLogin,api(async req=>{
  await access(req,'contacts.view');const contact=(await pool.query('SELECT * FROM contacts WHERE id=$1',[req.params.id])).rows[0];if(!contact)throw Object.assign(new Error('Contact not found'),{status:404});
  const conversations=(await pool.query(`SELECT c.*,u.display_name assigned_name,u.avatar_url assigned_avatar,(SELECT body_text FROM messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC LIMIT 1) last_message FROM conversations c LEFT JOIN users u ON u.id=c.assigned_user_id WHERE c.contact_id=$1 ORDER BY c.updated_at DESC`,[req.params.id])).rows;
  return {contact,conversations};
}));
app.put('/api/contacts/:id',requireLogin,api(async req=>{
  const {user,allowed}=await access(req,'contacts.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const x=req.body;
  const row=(await pool.query(`UPDATE contacts SET name=$2,first_name=$3,last_name=$4,email=$5,phone=$6,company=$7,notes=$8,custom_fields=$9::jsonb,updated_at=now() WHERE id=$1 RETURNING *`,[req.params.id,String(x.name||[x.first_name,x.last_name].filter(Boolean).join(' ')).trim(),x.first_name||null,x.last_name||null,x.email||null,x.phone||null,x.company||null,x.notes||null,JSON.stringify(x.custom_fields||{})])).rows[0];
  if(!row)throw Object.assign(new Error('Contact not found'),{status:404});await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'contact.updated','contact',$2,$3)",[user.id,row.id,row]);return row;
}));
app.get('/api/teams',requireLogin,api(async req=>{const {user}=await access(req,'inbox.view');const all=await access(req,'teams.manage');const filter=all.allowed?'':'WHERE EXISTS(SELECT 1 FROM team_members mine WHERE mine.team_id=t.id AND mine.user_id=$1)';const args=all.allowed?[]:[user.id];return (await pool.query(`SELECT t.*,count(tm.user_id)::int member_count,array_remove(array_agg(jsonb_build_object('id',u.id,'display_name',u.display_name,'avatar_url',u.avatar_url)) FILTER(WHERE u.id IS NOT NULL),NULL) members FROM teams t LEFT JOIN team_members tm ON tm.team_id=t.id LEFT JOIN users u ON u.id=tm.user_id ${filter} GROUP BY t.id ORDER BY t.name`,args)).rows;}));
app.post('/api/teams',requireLogin,api(async req=>{
  const {user,allowed}=await access(req,'teams.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const name=String(req.body.name||'').trim();if(!name)throw new Error('Team name is required');
  const team=(await pool.query('INSERT INTO teams(name) VALUES($1) RETURNING *',[name])).rows[0];for(const id of (req.body.member_ids||[]))await pool.query('INSERT INTO team_members(team_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[team.id,id]);await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'team.created','team',$2,$3)",[user.id,team.id,team]);return team;
}));
app.put('/api/teams/:id',requireLogin,api(async req=>{const {user,allowed}=await access(req,'teams.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const name=String(req.body.name||'').trim();if(!name)throw new Error('Team name is required');const row=(await pool.query('UPDATE teams SET name=$2,routing_email=$3 WHERE id=$1 RETURNING *',[req.params.id,name,req.body.routing_email||null])).rows[0];if(!row)throw Object.assign(new Error('Team not found'),{status:404});await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'team.updated','team',$2,$3)",[user.id,row.id,row]);return row;}));
app.put('/api/teams/:id/members',requireLogin,api(async req=>{
  const {user,allowed}=await access(req,'teams.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const ids=Array.isArray(req.body.member_ids)?req.body.member_ids:[];const client=await pool.connect();try{await client.query('BEGIN');const exists=await client.query('SELECT id FROM teams WHERE id=$1 FOR UPDATE',[req.params.id]);if(!exists.rowCount)throw Object.assign(new Error('Team not found'),{status:404});await client.query('DELETE FROM team_members WHERE team_id=$1',[req.params.id]);for(const id of ids)await client.query('INSERT INTO team_members(team_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[req.params.id,id]);await client.query('COMMIT');await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'team.members_updated','team',$2,$3)",[user.id,req.params.id,{member_ids:ids}]);return {ok:true};}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
}));
app.delete('/api/teams/:id',requireLogin,api(async req=>{const {user,allowed}=await access(req,'teams.delete');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const client=await pool.connect();let row;try{await client.query('BEGIN');row=(await client.query('SELECT id,name FROM teams WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];if(!row)throw Object.assign(new Error('Team not found'),{status:404});await client.query('UPDATE conversations SET assigned_team_id=NULL,updated_at=now() WHERE assigned_team_id=$1',[req.params.id]);await client.query('DELETE FROM teams WHERE id=$1',[req.params.id]);await client.query('COMMIT');}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'team.deleted','team',$2,$3)",[user.id,row.id,row]);return {ok:true};}));
app.get('/api/agents',requireLogin,api(async req=>{const {user}=await access(req,'inbox.view');const roles=await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id]);return {agents:(await pool.query('SELECT u.id,u.display_name,u.email,u.avatar_url,u.given_name,u.family_name,u.nickname,u.preferred_username,u.phone_number,u.phone_number_verified,u.email_verified,u.profile_url,u.website,u.locale,u.zoneinfo,u.address,u.is_active,u.first_login_at,u.last_login_at,u.is_online,array_agg(r.name) FILTER(WHERE r.name IS NOT NULL) roles FROM users u LEFT JOIN user_roles ur ON ur.user_id=u.id LEFT JOIN roles r ON r.id=ur.role_id GROUP BY u.id ORDER BY u.display_name')).rows,available_roles:(await pool.query('SELECT name FROM roles ORDER BY CASE name WHEN \'Super Admin\' THEN 1 WHEN \'Admin\' THEN 2 WHEN \'Manager\' THEN 3 ELSE 4 END')).rows.map(x=>x.name),can_manage:roles.rows.some(x=>['Super Admin','Admin'].includes(x.name)),is_super_admin:roles.rows.some(x=>x.name==='Super Admin')};}));
app.put('/api/agents/:id/roles',requireLogin,api(async req=>{const {user}=await access(req,'inbox.view');const actorRoles=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id])).rows.map(x=>x.name);const isSuper=actorRoles.includes('Super Admin');const isAdmin=actorRoles.includes('Admin');if(!isSuper&&!isAdmin)throw Object.assign(new Error('Permission denied'),{status:403});if(!isSuper){if(req.params.id===user.id)throw Object.assign(new Error('Admins cannot change their own roles.'),{status:403});const targetRoles=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[req.params.id])).rows.map(x=>x.name);if(targetRoles.some(x=>['Super Admin','Admin'].includes(x)))throw Object.assign(new Error('Only a Super Admin can modify an Admin or Super Admin account.'),{status:403});}const names=[...new Set((Array.isArray(req.body.roles)?req.body.roles:[]).map(x=>String(x)))];if(!names.length)throw new Error('At least one role must be assigned');if(names.some(x=>!['Super Admin','Admin','Manager','Agent'].includes(x)))throw new Error('Unknown role');if(!isSuper&&names.some(x=>['Super Admin','Admin'].includes(x)))throw Object.assign(new Error('Admins cannot assign the Super Admin or Admin role.'),{status:403});if(req.params.id===user.id&&!isSuper&&names.some(x=>!['Admin','Manager','Agent'].includes(x)))throw Object.assign(new Error('You cannot assign this role.'),{status:403});const client=await pool.connect();try{await client.query('BEGIN');const exists=await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[req.params.id]);if(!exists.rowCount)throw Object.assign(new Error('Agent not found'),{status:404});await client.query('DELETE FROM user_roles WHERE user_id=$1',[req.params.id]);for(const name of names)await client.query('INSERT INTO user_roles(user_id,role_id,assigned_by) SELECT $1,id,$2 FROM roles WHERE name=$3',[req.params.id,user.id,name]);await client.query('COMMIT');}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'agent.roles_updated','agent',$2,$3)",[user.id,req.params.id,{roles:names}]);return {ok:true};}));
app.put('/api/agents/:id/active',requireLogin,api(async req=>{const {user}=await access(req,'inbox.view');const actorRoles=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id])).rows.map(x=>x.name);if(!actorRoles.some(x=>['Super Admin','Admin'].includes(x)))throw Object.assign(new Error('Permission denied'),{status:403});const active=Boolean(req.body.is_active);if(!actorRoles.includes('Super Admin')){const targetRoles=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[req.params.id])).rows.map(x=>x.name);if(targetRoles.some(x=>['Super Admin','Admin'].includes(x)))throw Object.assign(new Error('Only a Super Admin can change the active status of an Admin or Super Admin account.'),{status:403});}if(req.params.id===user.id&&!active)throw Object.assign(new Error('You cannot deactivate your own account.'),{status:400});const row=(await pool.query('UPDATE users SET is_active=$2,updated_at=now() WHERE id=$1 RETURNING id,is_active',[req.params.id,active])).rows[0];if(!row)throw Object.assign(new Error('Agent not found'),{status:404});await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'agent.active_updated','agent',$2,$3)",[user.id,row.id,row]);return row;}));
app.post('/api/conversations/:id/reply',requireLogin,api(async req=>{const {user,allowed}=await access(req,'conversation.reply');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});await assertConversationAccess(req,req.params.id);const body=String(req.body.body||'').trim();if(!body)throw new Error('Message cannot be empty');const c=(await pool.query('SELECT * FROM conversations WHERE id=$1',[req.params.id])).rows[0];if(!c)throw new Error('Conversation not found');const msg=(await pool.query("INSERT INTO messages(conversation_id,channel,direction,body_text,created_by) VALUES($1,$2,'outbound',$3,$4) RETURNING *",[c.id,c.channel,body,user.id])).rows[0];if(c.channel==='whatsapp'){const acct=(await pool.query('SELECT * FROM whatsapp_accounts WHERE enabled=true ORDER BY created_at LIMIT 1')).rows[0];if(!acct)throw new Error('No enabled WhatsApp account');const token=decrypt(acct.access_token_enc);const url=`https://graph.facebook.com/${acct.graph_api_version}/${acct.phone_number_id}/messages`;const contact=(await pool.query('SELECT phone FROM contacts WHERE id=$1',[c.contact_id])).rows[0];const r=await fetch(url,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({messaging_product:'whatsapp',to:contact.phone,type:'text',text:{body}})});const data=await r.json();if(!r.ok)throw new Error(data.error?.message||'WhatsApp send failed');await pool.query('UPDATE messages SET provider_message_id=$2,raw_payload=$3 WHERE id=$1',[msg.id,data.messages?.[0]?.id||null,data]);await pool.query('INSERT INTO whatsapp_messages(message_id,account_id,wa_message_id,wa_from,message_type,status) VALUES($1,$2,$3,$4,$5,$6)',[msg.id,acct.id,data.messages?.[0]?.id,contact.phone,'text','sent']);}else if(c.channel==='email'){
 const contact=(await pool.query('SELECT email,name FROM contacts WHERE id=$1',[c.contact_id])).rows[0];
 if(!contact?.email)throw new Error('This contact does not have an email address.');
 const prior=(await pool.query(`SELECT em.account_id,em.internet_message_id,em.references_header
   FROM email_messages em JOIN messages m ON m.id=em.message_id
   WHERE m.conversation_id=$1 AND em.account_id IS NOT NULL
   ORDER BY m.created_at DESC LIMIT 1`,[c.id])).rows[0];
 const acct=(prior?.account_id
   ? (await pool.query('SELECT * FROM email_accounts WHERE id=$1 AND enabled=true',[prior.account_id])).rows[0]
   : null) || (await pool.query('SELECT * FROM email_accounts WHERE enabled=true ORDER BY created_at LIMIT 1')).rows[0];
 if(!acct)throw new Error('No enabled email account is available for this conversation.');
 const secure=Boolean(acct.smtp_port===465 && acct.smtp_tls);
 const transporter=nodemailer.createTransport({host:acct.smtp_host,port:acct.smtp_port,secure,requireTLS:Boolean(acct.smtp_tls && !secure),tls:{rejectUnauthorized:true},auth:{user:acct.smtp_user,pass:decrypt(acct.smtp_secret_enc)}});
 const previousId=prior?.internet_message_id||null;
 const references=[...(String(prior?.references_header||'').match(/<[^>]+>/g)||[]),...(previousId?[previousId]:[])];
 const subject=/^re:/i.test(c.subject||'')?(c.subject||'Re: Support request'):`Re: ${c.subject||'Support request'}`;
 const outgoingAttachments=Array.isArray(req.body.attachments)?req.body.attachments:[];
 if(outgoingAttachments.length>10)throw new Error('Maximum 10 attachments per email.');
 let totalAttachmentBytes=0;
 const smtpAttachments=outgoingAttachments.map(att=>{
  const content=Buffer.from(String(att.contentBase64||''),'base64');
  totalAttachmentBytes+=content.length;
  if(!att.fileName||content.length>10*1024*1024||totalAttachmentBytes>20*1024*1024)throw new Error('Each attachment must be under 10 MB and the total must be under 20 MB.');
  return {filename:String(att.fileName).slice(0,255),content,contentType:String(att.mimeType||'application/octet-stream').slice(0,150)};
 });
 let info;try{info=await transporter.sendMail({from:{name:acct.name,address:acct.email_address},to:contact.email,subject,text:body,attachments:smtpAttachments,inReplyTo:previousId||undefined,references:references.length?references:undefined});}catch(sendError){await pool.query("UPDATE messages SET provider_status='failed' WHERE id=$1",[msg.id]);throw sendError;}
 // Serialize JSONB arrays/objects explicitly; passing a JS array directly makes pg encode it as a PostgreSQL array.
 await pool.query("INSERT INTO email_messages(message_id,account_id,internet_message_id,in_reply_to,references_header,from_address,to_addresses,subject,reply_to,headers) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10::jsonb)",[msg.id,acct.id,info.messageId||null,previousId,references.join(' ')||null,acct.email_address,JSON.stringify([contact.email]),subject,acct.email_address,JSON.stringify({messageId:info.messageId||null})]);
 await pool.query('UPDATE messages SET provider_message_id=$2,provider_status=$3,raw_payload=$4 WHERE id=$1',[msg.id,info.messageId,'sent',{accepted:info.accepted,rejected:info.rejected,response:info.response}]);
 for(let i=0;i<smtpAttachments.length;i++){const att=smtpAttachments[i];await pool.query('INSERT INTO message_attachments(message_id,file_name,mime_type,size_bytes,content,disposition) VALUES($1,$2,$3,$4,$5,$6)',[msg.id,att.filename,att.contentType,att.content.length,att.content,'attachment']);}
}else{await pool.query('UPDATE messages SET provider_status=$2 WHERE id=$1',[msg.id,'sent']);}await pool.query("UPDATE conversations SET updated_at=now(),last_message_at=now(),status='open' WHERE id=$1",[c.id]);await pool.query("INSERT INTO agent_activity_logs(user_id,action,entity_type,entity_id) VALUES($1,'message.sent','conversation',$2)",[user.id,c.id]);return {ok:true,message:msg};}));
app.post('/api/conversations/:id/status',requireLogin,api(async req=>{const {user,allowed}=await access(req,'conversation.status');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});await assertConversationAccess(req,req.params.id);const status=req.body.status;if(!['open','pending','resolved','closed'].includes(status))throw new Error('Invalid status');const old=(await pool.query('SELECT status FROM conversations WHERE id=$1',[req.params.id])).rows[0];if(!old)throw new Error('Conversation not found');await pool.query('UPDATE conversations SET status=$2,closed_at=CASE WHEN $2 IN (\'resolved\',\'closed\') THEN now() ELSE NULL END,updated_at=now() WHERE id=$1',[req.params.id,status]);await pool.query("INSERT INTO conversation_events(conversation_id,actor_user_id,event_type,old_value,new_value) VALUES($1,$2,'status_changed',$3,$4)",[req.params.id,user.id,{status:old.status},{status}]);await pool.query("INSERT INTO agent_activity_logs(user_id,action,entity_type,entity_id,details) VALUES($1,'conversation.status','conversation',$2,$3)",[user.id,req.params.id,{from:old.status,to:status}]);return {ok:true};}));
app.get('/api/settings/ui',requireLogin,api(async()=>{const row=(await pool.query("SELECT value FROM system_settings WHERE key='ui_preferences'")).rows[0];return {settings:row?.value||{icon_color:'#dbeafe',icon_background:'#263958',icon_shape:'rounded'}};}));
app.put('/api/settings/ui',requireLogin,api(async req=>{const {user,allowed}=await access(req,'branding.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const x=req.body||{};const validColor=v=>/^#[0-9a-fA-F]{6}$/.test(v||'');const icons={};for(const id of ['inbox','mine','pool','contacts','teams','agents','admin']){const p=x.icons?.[id]||{};icons[id]={color:validColor(p.color)?p.color:null,background:validColor(p.background)?p.background:null,shape:['rounded','circle','square'].includes(p.shape)?p.shape:null};}const settings={icon_color:validColor(x.icon_color)?x.icon_color:'#dbeafe',icon_background:validColor(x.icon_background)?x.icon_background:'#263958',icon_shape:['rounded','circle','square'].includes(x.icon_shape)?x.icon_shape:'rounded',icons};await pool.query("INSERT INTO system_settings(key,value,updated_by,updated_at) VALUES('ui_preferences',$1,$2,now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()",[settings,user.id]);return {settings};}));
app.get('/api/settings/branding',requireLogin,api(async()=>({branding:(await pool.query('SELECT * FROM branding_settings WHERE id=1')).rows[0]})));
app.put('/api/settings/branding',requireLogin,api(async req=>{const {user,allowed}=await access(req,'branding.manage');if(!allowed)throw new Error('Permission denied');const b=req.body;const row=(await pool.query('UPDATE branding_settings SET company_name=$1,primary_color=$2,secondary_color=$3,footer_text=$4,updated_at=now() WHERE id=1 RETURNING *',[b.company_name||'Mesina Farms',b.primary_color||'#2563eb',b.secondary_color||'#0f172a',b.footer_text||''])).rows[0];await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'branding.updated','branding','1',$2)",[user.id,row]);return {branding:row};}));
app.get('/api/settings/email',requireLogin,api(async()=>({accounts:(await pool.query('SELECT id,name,email_address,imap_host,imap_port,imap_tls,imap_user,smtp_host,smtp_port,smtp_tls,smtp_user,folder_name,enabled,last_sync_at,last_error,last_uid FROM email_accounts ORDER BY created_at')).rows})));
app.post('/api/settings/email',requireLogin,api(async req=>{const {user,allowed}=await access(req,'integrations.manage');if(!allowed)throw new Error('Permission denied');const x=req.body;const row=(await pool.query(`INSERT INTO email_accounts(name,email_address,imap_host,imap_port,imap_tls,imap_user,imap_secret_enc,smtp_host,smtp_port,smtp_tls,smtp_user,smtp_secret_enc,folder_name,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id,name,email_address,enabled`,[x.name,x.email_address,x.imap_host,Number(x.imap_port||993),x.imap_tls!==false,x.imap_user,encrypt(x.imap_password),x.smtp_host,Number(x.smtp_port||587),x.smtp_tls!==false,x.smtp_user,encrypt(x.smtp_password),x.folder_name||'INBOX',x.enabled!==false])).rows[0];await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES($1,'email_account.created','email_account',$2)",[user.id,row.id]);return {account:row};}));
app.delete('/api/settings/email/:id',requireLogin,api(async req=>{const {user,allowed}=await access(req,'integrations.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});const client=await pool.connect();let row;try{await client.query('BEGIN');row=(await client.query('SELECT id,name,email_address FROM email_accounts WHERE id=$1 FOR UPDATE',[req.params.id])).rows[0];if(!row)throw Object.assign(new Error('Email account not found'),{status:404});await client.query('UPDATE email_messages SET account_id=NULL WHERE account_id=$1',[req.params.id]);await client.query('UPDATE email_sync_logs SET account_id=NULL WHERE account_id=$1',[req.params.id]);await client.query('DELETE FROM email_accounts WHERE id=$1',[req.params.id]);await client.query('COMMIT');}catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data) VALUES($1,'email_account.deleted','email_account',$2,$3)",[user.id,row.id,row]);return {ok:true};}));
app.post('/api/settings/email/:id/sync',requireLogin,api(async req=>{
 const {allowed}=await access(req,'integrations.manage');if(!allowed)throw Object.assign(new Error('Permission denied'),{status:403});
 const account=(await pool.query('SELECT id FROM email_accounts WHERE id=$1 AND enabled=true',[req.params.id])).rows[0];
 if(!account)throw Object.assign(new Error('Enabled email account not found'),{status:404});
 await syncEmailAccountById(account.id);
 const state=(await pool.query('SELECT last_sync_at,last_error FROM email_accounts WHERE id=$1',[account.id])).rows[0];
 if(state?.last_error)throw Object.assign(new Error(state.last_error),{status:502});
 return {ok:true,message:'Mailbox synchronization completed.',...state};
}));
app.post('/api/settings/email/:id/test',requireLogin,api(async req=>{const {allowed}=await access(req,'integrations.manage');if(!allowed)throw new Error('Permission denied');const a=(await pool.query('SELECT * FROM email_accounts WHERE id=$1',[req.params.id])).rows[0];if(!a)throw new Error('Account not found');const imap=new ImapFlow({host:a.imap_host,port:a.imap_port,secure:a.imap_tls,auth:{user:a.imap_user,pass:decrypt(a.imap_secret_enc)},logger:false});await imap.connect();await imap.logout();const secure=Boolean(a.smtp_port===465 && a.smtp_tls);const smtp=nodemailer.createTransport({host:a.smtp_host,port:a.smtp_port,secure,requireTLS:Boolean(a.smtp_tls && !secure),tls:{rejectUnauthorized:true},auth:{user:a.smtp_user,pass:decrypt(a.smtp_secret_enc)}});await smtp.verify();return {ok:true,message:'IMAP and SMTP connections successful'};}));

app.get('/api/admin/email-routing',requireLogin,api(async req=>{
 const {user}=await access(req,'inbox.view');const names=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id])).rows.map(x=>x.name);
 if(!names.some(n=>['Super Admin','Admin'].includes(n)))throw Object.assign(new Error('Permission denied'),{status:403});
 return {teams:(await pool.query('SELECT id,name,routing_email FROM teams ORDER BY name')).rows,emails:(await pool.query('SELECT email_address FROM email_accounts WHERE enabled=true ORDER BY email_address')).rows.map(x=>x.email_address)};
}));
app.put('/api/admin/email-routing/:teamId',requireLogin,api(async req=>{
 const {user}=await access(req,'inbox.view');const names=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id])).rows.map(x=>x.name);
 if(!names.some(n=>['Super Admin','Admin'].includes(n)))throw Object.assign(new Error('Permission denied'),{status:403});
 const email=req.body?.email||null;const team=(await pool.query('SELECT id FROM teams WHERE id=$1',[req.params.teamId])).rows[0];if(!team)throw Object.assign(new Error('Team not found'),{status:404});
 if(email&&!((await pool.query('SELECT 1 FROM email_accounts WHERE enabled=true AND lower(email_address)=lower($1)',[email])).rowCount))throw Object.assign(new Error('Choose an enabled email address from Email Settings.'),{status:400});
 if(email&&(await pool.query('SELECT 1 FROM teams WHERE lower(routing_email)=lower($1) AND id<>$2',[email,req.params.teamId])).rowCount)throw Object.assign(new Error('This email address is already routed to another team.'),{status:409});
 const row=(await pool.query('UPDATE teams SET routing_email=$2 WHERE id=$1 RETURNING id,name,routing_email',[req.params.teamId,email])).rows[0];
 await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data,ip_address) VALUES($1,'team.email_routing_updated','team',$2,$3,$4)",[user.id,row.id,row,clientIp(req)]);
 return {team:row};
}));
app.get('/api/settings/whatsapp',requireLogin,api(async()=>({accounts:(await pool.query('SELECT id,name,phone_number_id,business_account_id,app_id,graph_api_version,enabled FROM whatsapp_accounts ORDER BY created_at')).rows})));
app.post('/api/settings/whatsapp',requireLogin,api(async req=>{const {user,allowed}=await access(req,'integrations.manage');if(!allowed)throw new Error('Permission denied');const x=req.body;const row=(await pool.query(`INSERT INTO whatsapp_accounts(name,phone_number_id,business_account_id,app_id,app_secret_enc,access_token_enc,verify_token_enc,graph_api_version,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,name,phone_number_id,enabled`,[x.name,x.phone_number_id,x.business_account_id||null,x.app_id||null,x.app_secret?encrypt(x.app_secret):null,encrypt(x.access_token),encrypt(x.verify_token),x.graph_api_version||'v23.0',x.enabled!==false])).rows[0];await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES($1,'whatsapp_account.created','whatsapp_account',$2)",[user.id,row.id]);return {account:row,webhook_url:`${baseUrl}/webhooks/whatsapp`};}));
app.post('/api/livechat/sites',requireLogin,api(async req=>{const {user,allowed}=await access(req,'integrations.manage');if(!allowed)throw new Error('Permission denied');const x=req.body;const w=(await pool.query('INSERT INTO livechat_websites(name,domain) VALUES($1,$2) RETURNING *',[x.name,x.domain])).rows[0];await pool.query('INSERT INTO livechat_inboxes(website_id,name,welcome_message) VALUES($1,$2,$3)',[w.id,x.name,x.welcome_message||'Hello! How can we help?']);await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id) VALUES($1,'livechat_site.created','livechat_website',$2)",[user.id,w.id]);return {website:w,install_snippet:`<script src=\"${baseUrl}/widget.js\" data-inbox=\"${w.public_key}\" async></script>`};}));
app.get('/api/livechat/sites',requireLogin,api(async()=> (await pool.query('SELECT w.*,i.name inbox_name FROM livechat_websites w LEFT JOIN livechat_inboxes i ON i.website_id=w.id ORDER BY w.created_at DESC')).rows));


app.get('/api/admin/role-restrictions',requireLogin,api(async req=>{
 const {user}=await access(req,'inbox.view');const names=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id])).rows.map(x=>x.name);
 if(!names.some(n=>['Super Admin','Admin'].includes(n)))throw Object.assign(new Error('Permission denied'),{status:403});
 const roles=(await pool.query('SELECT id,name,description FROM roles ORDER BY name')).rows;
 const permissions=(await pool.query('SELECT id,code,description FROM permissions ORDER BY code')).rows;
 const grants=(await pool.query('SELECT role_id,permission_id FROM role_permissions')).rows;
 return {roles,permissions,grants};
}));
app.put('/api/admin/role-restrictions/:roleId',requireLogin,api(async req=>{
 const {user}=await access(req,'inbox.view');const names=(await pool.query('SELECT r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1',[user.id])).rows.map(x=>x.name);
 if(!names.some(n=>['Super Admin','Admin'].includes(n)))throw Object.assign(new Error('Permission denied'),{status:403});
 const target=(await pool.query('SELECT name FROM roles WHERE id=$1',[req.params.roleId])).rows[0];if(!target)throw Object.assign(new Error('Role not found'),{status:404});
 if(target.name==='Super Admin'&&!names.includes('Super Admin'))throw Object.assign(new Error('Only Super Admin can change Super Admin restrictions'),{status:403});
 const ids=Array.isArray(req.body?.permission_ids)?req.body.permission_ids:[];
 const c=await pool.connect();try{await c.query('BEGIN');await c.query('DELETE FROM role_permissions WHERE role_id=$1',[req.params.roleId]);if(ids.length)await c.query('INSERT INTO role_permissions(role_id,permission_id) SELECT $1,id FROM permissions WHERE id=ANY($2::uuid[]) ON CONFLICT DO NOTHING',[req.params.roleId,ids]);await c.query('COMMIT')}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}
 await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data,ip_address) VALUES($1,'role.permissions_updated','role',$2,$3,$4)",[user.id,req.params.roleId,{permission_ids:ids},clientIp(req)]);
 return {ok:true};
}));
const requireSuperAdmin=async req=>{const {user}=await access(req,'inbox.view');const r=(await pool.query("SELECT 1 FROM user_roles ur JOIN roles ro ON ro.id=ur.role_id WHERE ur.user_id=$1 AND ro.name='Super Admin'",[user.id])).rowCount;if(!r)throw Object.assign(new Error('Super Admin only'),{status:403});return user;};
app.get('/api/admin/database/export.sql',requireLogin,async(req,res,next)=>{try{
 const user=await requireSuperAdmin(req);
 const tables=['roles','permissions','users','role_permissions','user_roles','teams','team_members','contacts','conversations','messages','message_attachments','conversation_assignments','conversation_events','conversation_notes','tags','conversation_tags','email_accounts','email_messages','email_ingest_receipts','email_sync_logs','whatsapp_accounts','whatsapp_templates','whatsapp_messages','whatsapp_webhook_events','whatsapp_message_statuses','livechat_websites','livechat_inboxes','livechat_visitors','livechat_sessions','livechat_events','agent_activity_logs','audit_logs','system_settings','branding_settings','webhook_events','integration_logs'];
 const literal=v=>v===null?'NULL':typeof v==='number'||typeof v==='boolean'?String(v):`'${String(typeof v==='object'?JSON.stringify(v):v).replace(/'/g,"''")}'`;
 let schema=await readFile(path.join(__dirname,'../db/init.sql'),'utf8');
 schema=schema.replace(/^INSERT INTO (roles|permissions|role_permissions|branding_settings).*;\s*$/gm,'');
 let dump='-- Mesina Farms Unified Support database export\\n-- Generated '+new Date().toISOString()+'\\n'+schema+'\\nBEGIN;\\n';
 for(const table of tables){const rows=(await pool.query(table==='system_settings'?`SELECT * FROM "${table}" WHERE key<>'truncate_export_armed'`:`SELECT * FROM "${table}"`)).rows;for(const row of rows){const cols=Object.keys(row);dump+=`INSERT INTO "${table}" (${cols.map(c=>`"${c}"`).join(',')}) VALUES (${cols.map(c=>literal(row[c])).join(',')});\\n`;}}
 dump+='COMMIT;\\n';
 await pool.query("INSERT INTO system_settings(key,value,updated_by,updated_at) VALUES('truncate_export_armed',$1,$2,now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()",[JSON.stringify({expires_at:Date.now()+180000}),user.id]);
 res.setHeader('Content-Type','application/sql');res.setHeader('Content-Disposition',`attachment; filename="mesina-support-export-${new Date().toISOString().replace(/[:.]/g,'-')}.sql"`);res.send(dump);
 }catch(e){next(e);}});

app.post('/api/admin/database/import.sql',requireLogin,api(async req=>{
 const user=await requireSuperAdmin(req);
 const sql=String(req.body?.sql||'');
 if(sql.length<30||sql.length>50*1024*1024||!sql.includes('-- Mesina Farms Unified Support database export')||!/\bBEGIN\s*;/i.test(sql)||!/\bCOMMIT\s*;/i.test(sql))throw Object.assign(new Error('Invalid SQL export file. Import a SQL file exported by this application.'),{status:400});
 // SQL imports are deliberately restricted to the app's own generated export format.
 // Run as a single transaction; PostgreSQL rolls back the import on any error.
 const client=await pool.connect();
 try {
   await client.query('BEGIN');
   const restoreTables=['conversation_tags','conversation_assignments','conversation_events','conversation_notes','message_attachments','email_messages','email_ingest_receipts','email_sync_logs','whatsapp_messages','whatsapp_templates','whatsapp_webhook_events','whatsapp_message_statuses','livechat_sessions','livechat_events','livechat_visitors','livechat_inboxes','livechat_websites','messages','conversations','contacts','team_members','teams','user_roles','role_permissions','users','roles','permissions','email_accounts','whatsapp_accounts','agent_activity_logs','audit_logs','system_settings','branding_settings','webhook_events','integration_logs','tags'];
   await client.query(`TRUNCATE TABLE ${restoreTables.map(t=>`"${t}"`).join(',')} RESTART IDENTITY CASCADE`);
   const normalized=sql.replace(/^\s*BEGIN\s*;/im,'').replace(/COMMIT\s*;\s*$/im,'');
   await client.query(normalized);
   await client.query('COMMIT');
 }
 catch(e){await client.query('ROLLBACK').catch(()=>{});throw Object.assign(new Error('SQL import failed: '+e.message),{status:400});}
 finally {client.release();}
 const restoredActor=(await pool.query('SELECT id FROM users WHERE zitadel_sub=$1',[user.zitadel_sub])).rows[0];
 await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,after_data,ip_address) VALUES($1,'database.imported','database','sql-import',$2,$3)",[restoredActor?.id||null,{filename:String(req.body?.filename||'uploaded SQL')},clientIp(req)]);
 return {ok:true};
}));
app.post('/api/admin/database/truncate',requireLogin,api(async req=>{const user=await requireSuperAdmin(req);const armed=(await pool.query("SELECT value FROM system_settings WHERE key='truncate_export_armed'")).rows[0]?.value;if(!armed||Number(armed.expires_at)<Date.now())throw Object.assign(new Error('Export first. The truncate authorization expires after 3 minutes.'),{status:403});
 const tables=['conversation_tags','conversation_assignments','conversation_events','conversation_notes','message_attachments','tags','whatsapp_webhook_events','email_messages','email_ingest_receipts','email_sync_logs','whatsapp_messages','whatsapp_message_statuses','livechat_sessions','livechat_events','livechat_visitors','messages','conversations','contacts','agent_activity_logs','audit_logs','webhook_events','integration_logs'];
 await pool.query(`TRUNCATE TABLE ${tables.map(t=>`"${t}"`).join(',')} RESTART IDENTITY CASCADE`);
 await pool.query("DELETE FROM system_settings WHERE key='truncate_export_armed'");
 await pool.query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,ip_address) VALUES($1,'database.truncated','database','operational-data',$2)",[user.id,clientIp(req)]);
 return {ok:true};}));
app.get('/api/audit',requireLogin,api(async req=>{const {allowed}=await access(req,'audit.view');if(!allowed)throw new Error('Permission denied');return (await pool.query(`SELECT a.id,a.created_at,a.action,a.entity_type,a.entity_id,a.details,a.public_ipv4,a.before_data,a.after_data,u.display_name,a.entity_type AS section FROM (SELECT id,created_at,action,entity_type,entity_id,details,public_ipv4,NULL::jsonb before_data,NULL::jsonb after_data,user_id FROM agent_activity_logs UNION ALL SELECT id,created_at,action,entity_type,entity_id,jsonb_build_object('section',entity_type),NULL::text public_ipv4,before_data,after_data,actor_user_id user_id FROM audit_logs) a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 500`)).rows;}));
// Public live-chat bootstrap and message endpoints. The public key is scoped to an enabled website.
app.get('/api/widget/:key/config',async(req,res)=>{const w=(await pool.query('SELECT w.id,w.name,i.name inbox_name,i.welcome_message,i.offline_message,i.primary_color,i.logo_url FROM livechat_websites w LEFT JOIN livechat_inboxes i ON i.website_id=w.id WHERE w.public_key=$1 AND w.enabled=true LIMIT 1',[req.params.key])).rows[0];if(!w)return res.status(404).json({error:'Unknown inbox'});res.json(w);});
app.post('/api/widget/:key/start',async(req,res)=>{try{const w=(await pool.query('SELECT id FROM livechat_websites WHERE public_key=$1 AND enabled=true',[req.params.key])).rows[0];if(!w)return res.status(404).json({error:'Unknown inbox'});const token=String(req.body.visitor_token||uuidv4());let v=(await pool.query('SELECT * FROM livechat_visitors WHERE visitor_token=$1',[token])).rows[0];if(!v)v=(await pool.query('INSERT INTO livechat_visitors(website_id,visitor_token,name,email,page_url) VALUES($1,$2,$3,$4,$5) RETURNING *',[w.id,token,req.body.name||null,req.body.email||null,req.body.page_url||null])).rows[0];let c=(await pool.query("SELECT c.* FROM conversations c JOIN livechat_sessions s ON s.conversation_id=c.id WHERE s.visitor_id=$1 AND c.status IN ('open','pending') ORDER BY c.created_at DESC LIMIT 1",[v.id])).rows[0];if(!c){const contact=(await pool.query('INSERT INTO contacts(name,email,external_ids) VALUES($1,$2,$3) RETURNING *',[v.name,v.email,{livechat_visitor:token}])).rows[0];c=(await pool.query("INSERT INTO conversations(contact_id,channel,subject) VALUES($1,'livechat','Website live chat') RETURNING *",[contact.id])).rows[0];await pool.query('INSERT INTO livechat_sessions(visitor_id,conversation_id) VALUES($1,$2)',[v.id,c.id]);}res.json({visitor_token:token,conversation_id:c.id});}catch(e){res.status(500).json({error:e.message});}});
app.post('/api/widget/:key/message',async(req,res)=>{try{const w=(await pool.query('SELECT id FROM livechat_websites WHERE public_key=$1 AND enabled=true',[req.params.key])).rows[0];if(!w)return res.status(404).json({error:'Unknown inbox'});const v=(await pool.query('SELECT * FROM livechat_visitors WHERE visitor_token=$1 AND website_id=$2',[req.body.visitor_token,w.id])).rows[0];if(!v)return res.status(403).json({error:'Invalid visitor'});const s=(await pool.query('SELECT conversation_id FROM livechat_sessions WHERE visitor_id=$1 AND ended_at IS NULL ORDER BY started_at DESC LIMIT 1',[v.id])).rows[0];if(!s)return res.status(404).json({error:'No active chat'});const body=String(req.body.body||'').trim();if(!body||body.length>5000)return res.status(400).json({error:'Message required (max 5000 characters)'});await pool.query("INSERT INTO messages(conversation_id,channel,direction,sender_name,sender_address,body_text) VALUES($1,'livechat','inbound',$2,$3,$4)",[s.conversation_id,v.name||'Website visitor',v.email||v.visitor_token,body]);await pool.query('UPDATE conversations SET updated_at=now(),last_message_at=now() WHERE id=$1',[s.conversation_id]);res.json({ok:true});}catch(e){res.status(500).json({error:e.message});}});
app.get('/api/widget/:key/messages',async(req,res)=>{try{const v=(await pool.query('SELECT id FROM livechat_visitors WHERE visitor_token=$1',[req.query.visitor_token])).rows[0];if(!v)return res.status(404).json({error:'Visitor not found'});const s=(await pool.query('SELECT conversation_id FROM livechat_sessions WHERE visitor_id=$1 ORDER BY started_at DESC LIMIT 1',[v.id])).rows[0];if(!s)return res.json([]);res.json((await pool.query("SELECT direction,body_text,created_at FROM messages WHERE conversation_id=$1 AND direction<>'internal' ORDER BY created_at",[s.conversation_id])).rows);}catch(e){res.status(500).json({error:e.message});}});
app.use('/',express.static(path.join(__dirname,'../public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'../public/index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(err.status||500).json({error:err.message||'Server error'});});

// IMAP inbound poller. Each mailbox delivery is tracked by account + folder + UIDVALIDITY + UID.
// Routing is based on the actual To/Cc recipients, never merely on the mailbox being polled.
let emailSyncBusy=false;
async function syncEmailAccounts(accountId=null){
 if(emailSyncBusy)return false;
 if(!key.length)throw new Error('ENCRYPTION_KEY is not configured correctly.');
 emailSyncBusy=true;
 try{
  const accounts=(await pool.query('SELECT * FROM email_accounts WHERE enabled=true AND ($1::uuid IS NULL OR id=$1) ORDER BY created_at',[accountId])).rows;
  for(const a of accounts){
   let client;
   try{
    client=new ImapFlow({host:a.imap_host,port:a.imap_port,secure:a.imap_tls,auth:{user:a.imap_user,pass:decrypt(a.imap_secret_enc)},logger:false});
    await client.connect();
    const folder=a.folder_name||'INBOX';
    const lock=await client.getMailboxLock(folder);
    try{
     const uidvalidity=String(client.mailbox?.uidValidity??'unknown');
     let lastUid=Number(a.last_uid||0);
     if(String(a.last_uidvalidity||'')!==uidvalidity){
      lastUid=0;
      await pool.query('UPDATE email_accounts SET last_uid=0,last_uidvalidity=$2,updated_at=now() WHERE id=$1',[a.id,uidvalidity]);
     }
     for await(const item of client.fetch({uid:`${lastUid+1}:*`},{uid:true,source:true,flags:true})){
      const uid=Number(item.uid);
      if(!uid)continue;
      const folderKey=String(folder);
      const receiptKey=`${a.id}:${folderKey}:${uidvalidity}:${uid}`;
      const clientDb=await pool.connect();
      try{
       await clientDb.query('BEGIN');
       await clientDb.query('SELECT pg_advisory_xact_lock(hashtext($1))',[receiptKey]);
       const already=(await clientDb.query('SELECT 1 FROM email_ingest_receipts WHERE account_id=$1 AND folder_name=$2 AND uidvalidity=$3 AND uid=$4',[a.id,folderKey,uidvalidity,uid])).rowCount>0;
       if(already){
        await clientDb.query('UPDATE email_accounts SET last_uid=GREATEST(last_uid,$2),last_uidvalidity=$3,updated_at=now() WHERE id=$1',[a.id,uid,uidvalidity]);
        await clientDb.query('COMMIT');
        continue;
       }
       if(!item.source){
        await clientDb.query('INSERT INTO email_ingest_receipts(account_id,folder_name,uidvalidity,uid) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[a.id,folderKey,uidvalidity,uid]);
        await clientDb.query('UPDATE email_accounts SET last_uid=GREATEST(last_uid,$2),last_uidvalidity=$3,updated_at=now() WHERE id=$1',[a.id,uid,uidvalidity]);
        await clientDb.query('COMMIT');
        continue;
       }
       const parsed=await simpleParser(item.source);
       const from=parsed.from?.value?.[0];
       const address=String(from?.address||'').trim().toLowerCase();
       if(!address){
        await clientDb.query('INSERT INTO email_ingest_receipts(account_id,folder_name,uidvalidity,uid) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[a.id,folderKey,uidvalidity,uid]);
        await clientDb.query('UPDATE email_accounts SET last_uid=GREATEST(last_uid,$2),last_uidvalidity=$3,updated_at=now() WHERE id=$1',[a.id,uid,uidvalidity]);
        await clientDb.query('COMMIT');
        continue;
       }
       const msgId=String(parsed.messageId||`imap-${a.id}-${uidvalidity}-${uid}`).trim();
       await clientDb.query('SELECT pg_advisory_xact_lock(hashtext($1))',[`email-message:${msgId}`]);
       // If this Internet Message-ID was already received through another configured mailbox,
       // attach this mailbox UID to the existing message rather than creating a second copy.
       let existing=(await clientDb.query("SELECT id,conversation_id FROM messages WHERE channel='email' AND provider_message_id=$1 LIMIT 1",[msgId])).rows[0];
       let conversationId=existing?.conversation_id;
       let insertedMessageId=existing?.id;
       if(!existing){
        let contact=(await clientDb.query('SELECT * FROM contacts WHERE lower(email)=lower($1) LIMIT 1',[address])).rows[0];
        if(!contact)contact=(await clientDb.query('INSERT INTO contacts(name,email) VALUES($1,$2) RETURNING *',[from.name||address,address])).rows[0];
        const threadIds=[...(parsed.references||[]),parsed.inReplyTo].map(x=>String(x||'').trim()).filter(Boolean);
        const rootThreadId=String((parsed.references||[])[0]||parsed.inReplyTo||msgId).trim();
        let conv=null;
        if(threadIds.length){
         conv=(await clientDb.query(`SELECT c.* FROM conversations c
          WHERE c.channel='email' AND (
           c.external_thread_id=ANY($1::text[]) OR
           EXISTS (SELECT 1 FROM messages emsg JOIN email_messages em ON em.message_id=emsg.id
                   WHERE emsg.conversation_id=c.id AND em.internet_message_id=ANY($1::text[]))
          ) ORDER BY c.updated_at DESC LIMIT 1`,[threadIds])).rows[0];
        }
        if(!conv)conv=(await clientDb.query("INSERT INTO conversations(contact_id,channel,subject,external_thread_id) VALUES($1,'email',$2,$3) RETURNING *",[contact.id,parsed.subject||'Email conversation',rootThreadId])).rows[0];
        conversationId=conv.id;
        const recipients=[...(parsed.to?.value||[]),...(parsed.cc?.value||[])].map(v=>String(v.address||'').trim().toLowerCase()).filter(Boolean);
        if(recipients.length){
         const route=(await clientDb.query('SELECT id FROM teams WHERE routing_email IS NOT NULL AND lower(routing_email)=ANY($1::text[]) ORDER BY name LIMIT 1',[recipients])).rows[0];
         if(route)await clientDb.query('UPDATE conversations SET assigned_team_id=$2 WHERE id=$1 AND assigned_team_id IS NULL AND assigned_user_id IS NULL',[conversationId,route.id]);
        }
        const inserted=(await clientDb.query("INSERT INTO messages(conversation_id,channel,direction,sender_name,sender_address,body_text,body_html,provider_message_id,raw_payload) VALUES($1,'email','inbound',$2,$3,$4,$5,$6,$7) ON CONFLICT(channel,provider_message_id) DO NOTHING RETURNING id",[conversationId,from.name||address,address,parsed.text||'',parsed.html||null,msgId,{messageId:msgId,subject:parsed.subject||''}])).rows[0];
        if(inserted){
         insertedMessageId=inserted.id;
         // JSONB columns must receive JSON text, not node-postgres' PostgreSQL-array encoding.
         await clientDb.query('INSERT INTO email_messages(message_id,account_id,internet_message_id,in_reply_to,references_header,from_address,to_addresses,cc_addresses,subject) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9) ON CONFLICT(message_id) DO NOTHING',[inserted.id,a.id,msgId,parsed.inReplyTo||null,(parsed.references||[]).join(' ')||null,address,JSON.stringify((parsed.to?.value||[]).map(v=>v.address)),JSON.stringify((parsed.cc?.value||[]).map(v=>v.address)),parsed.subject||'']);
          for(const attachment of (parsed.attachments||[])){
           if(!attachment.content||attachment.size>15*1024*1024)continue;
           await clientDb.query(`INSERT INTO message_attachments(message_id,file_name,mime_type,size_bytes,content,content_id,disposition)
            VALUES($1,$2,$3,$4,$5,$6,$7)`,[inserted.id,String(attachment.filename||'attachment').slice(0,255),attachment.contentType||'application/octet-stream',attachment.size||attachment.content.length,attachment.content,attachment.contentId||null,attachment.contentDisposition||'attachment']);
          }
         await clientDb.query('UPDATE conversations SET updated_at=now(),last_message_at=now() WHERE id=$1',[conversationId]);
        }else{
         const prior=(await clientDb.query("SELECT id,conversation_id FROM messages WHERE channel='email' AND provider_message_id=$1 LIMIT 1",[msgId])).rows[0];
         if(prior){insertedMessageId=prior.id;conversationId=prior.conversation_id;}
        }
       }
       await clientDb.query('INSERT INTO email_ingest_receipts(account_id,folder_name,uidvalidity,uid,message_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING',[a.id,folderKey,uidvalidity,uid,insertedMessageId||null]);
       await clientDb.query('UPDATE email_accounts SET last_uid=GREATEST(last_uid,$2),last_uidvalidity=$3,updated_at=now() WHERE id=$1',[a.id,uid,uidvalidity]);
       await clientDb.query('COMMIT');
      }catch(e){await clientDb.query('ROLLBACK').catch(()=>{});throw e;}
      finally{clientDb.release();}
     }
    }finally{lock.release();}
    await client.logout();
    await pool.query('UPDATE email_accounts SET last_sync_at=now(),last_error=NULL,updated_at=now() WHERE id=$1',[a.id]);
   }catch(e){
    console.error(`Email sync ${a.email_address}:`,e.message);
    await pool.query('UPDATE email_accounts SET last_error=$2,updated_at=now() WHERE id=$1',[a.id,String(e.message).slice(0,2000)]).catch(()=>{});
    await pool.query("INSERT INTO email_sync_logs(account_id,level,message) VALUES($1,'error',$2)",[a.id,e.message]).catch(()=>{});
    try{await client?.logout();}catch{}
   }
  }
 }catch(e){console.error('Email sync worker:',e.message);}
 finally{emailSyncBusy=false;}
 return true;
}
const syncEmailAccountById=async(id)=>{const completed=await syncEmailAccounts(id);if(!completed)throw new Error('An email synchronization is already running. Please try again shortly.');return completed;};
setTimeout(()=>syncEmailAccounts().catch(e=>console.error('Initial email sync:',e.message)),15000).unref();
setInterval(syncEmailAccounts,60000).unref();

// Idempotent compatibility migration for existing persistent databases.
// This runs before serving requests and does not alter Zitadel/OIDC configuration.
await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS first_login_at timestamptz;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at timestamptz;
  ALTER TABLE users ADD COLUMN IF NOT EXISTS is_online boolean NOT NULL DEFAULT false;`);
await pool.query(`ALTER TABLE teams ADD COLUMN IF NOT EXISTS routing_email text;
ALTER TABLE agent_activity_logs ADD COLUMN IF NOT EXISTS public_ipv4 text;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS before_data jsonb;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS after_data jsonb;`);
await pool.query(`ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS last_uidvalidity text;
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS last_sync_at timestamptz;
ALTER TABLE email_accounts ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE email_messages ADD COLUMN IF NOT EXISTS reply_to text;
ALTER TABLE email_messages ADD COLUMN IF NOT EXISTS headers jsonb NOT NULL DEFAULT '{}';
ALTER TABLE message_attachments ADD COLUMN IF NOT EXISTS content bytea;
ALTER TABLE message_attachments ADD COLUMN IF NOT EXISTS content_id text;
ALTER TABLE message_attachments ADD COLUMN IF NOT EXISTS disposition text;
CREATE TABLE IF NOT EXISTS email_ingest_receipts (
  account_id uuid NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
  folder_name text NOT NULL,
  uidvalidity text NOT NULL,
  uid bigint NOT NULL,
  message_id uuid REFERENCES messages(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(account_id,folder_name,uidvalidity,uid)
);
CREATE INDEX IF NOT EXISTS email_ingest_receipts_message_idx ON email_ingest_receipts(message_id);`);
await pool.query('SELECT 1');
app.listen(PORT,()=>console.log(`Mesina Farms Unified Support v1.02.1 listening on ${PORT}`));
