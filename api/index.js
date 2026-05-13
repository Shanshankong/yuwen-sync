// 博瑞语文云同步后端 · Vercel 版
// 部署在 Vercel Serverless Functions + Vercel KV (Upstash)
// 与 Cloudflare Workers 原版 API 100% 兼容,前端无需改动

import { kv } from '@vercel/kv';
import crypto from 'crypto';

const SECRET = process.env.SECRET || 'change-me-please';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

// ============== 工具函数 ==============

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

function hmac(s) {
  return crypto.createHmac('sha256', SECRET).update(String(s)).digest('hex');
}

function makeToken(username) {
  const exp = Date.now() + 90 * 24 * 60 * 60 * 1000;
  const payload = `${username}.${exp}`;
  return `${payload}.${hmac(payload)}`;
}

function verifyToken(token) {
  if (!token) return null;
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  const [username, exp, sig] = parts;
  if (hmac(`${username}.${exp}`) !== sig) return null;
  if (Date.now() > Number(exp)) return null;
  return { username };
}

function makeAdminToken() {
  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const payload = `admin.${exp}`;
  return `${payload}.${hmac(payload)}`;
}

function verifyAdminToken(token) {
  if (!token) return false;
  const parts = String(token).split('.');
  if (parts.length !== 3) return false;
  const [role, exp, sig] = parts;
  if (role !== 'admin') return false;
  if (hmac(`${role}.${exp}`) !== sig) return false;
  if (Date.now() > Number(exp)) return false;
  return true;
}

function validUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_-]{2,40}$/.test(u);
}

function validPassword(p) {
  return typeof p === 'string' && p.length >= 4 && p.length <= 100;
}

async function readBody(req) {
  if (req.body) return req.body;
  return await new Promise((resolve, reject) => {
    let chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf-8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

// ============== 路由处理函数 ==============

async function health(req, res) {
  return res.status(200).json({
    ok: true,
    service: '语文 36 天闯关 · 云同步 v2 (Vercel)',
    time: new Date().toISOString(),
  });
}

async function register(req, res) {
  const body = await readBody(req);
  const { username, password } = body || {};
  if (!validUsername(username)) {
    return res.status(400).json({ error: '账号格式: 2-40位字母/数字/下划线/横线' });
  }
  if (!validPassword(password)) {
    return res.status(400).json({ error: '密码至少 4 位' });
  }
  const existing = await kv.get(`user:${username}`);
  if (existing) return res.status(400).json({ error: '账号已存在' });

  const now = Date.now();
  const user = {
    username,
    passHash: sha256(password + ':' + SECRET),
    plan: 'free',
    createdAt: now,
    paidAt: null,
    note: '',
  };
  await kv.set(`user:${username}`, user);
  await kv.set(`data:${username}`, {});

  const token = makeToken(username);
  return res.status(200).json({
    token,
    username,
    user: { username, plan: user.plan, createdAt: now },
  });
}

async function login(req, res) {
  const body = await readBody(req);
  const { username, password } = body || {};
  if (!username || !password) {
    return res.status(400).json({ error: '请输入账号和密码' });
  }
  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(400).json({ error: '账号不存在' });
  if (user.passHash !== sha256(password + ':' + SECRET)) {
    return res.status(400).json({ error: '密码错误' });
  }
  const token = makeToken(username);
  return res.status(200).json({
    token,
    username,
    user: {
      username,
      plan: user.plan,
      createdAt: user.createdAt,
      paidAt: user.paidAt,
    },
  });
}

function authFromReq(req) {
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? verifyToken(m[1]) : null;
}

async function sync(req, res) {
  const auth = authFromReq(req);
  if (!auth) return res.status(401).json({ error: '请重新登录' });
  const body = await readBody(req);
  const { data } = body || {};
  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: '数据格式错误' });
  }
  const now = Date.now();
  await kv.set(`data:${auth.username}`, data);
  await kv.set(`meta:${auth.username}`, { updatedAt: now });
  return res.status(200).json({ ok: true, syncedAt: now });
}

async function load(req, res) {
  const auth = authFromReq(req);
  if (!auth) return res.status(401).json({ error: '请重新登录' });
  const [user, data, meta] = await Promise.all([
    kv.get(`user:${auth.username}`),
    kv.get(`data:${auth.username}`),
    kv.get(`meta:${auth.username}`),
  ]);
  if (!user) return res.status(401).json({ error: '账号不存在' });
  return res.status(200).json({
    ok: true,
    user: {
      username: user.username,
      plan: user.plan,
      createdAt: user.createdAt,
      paidAt: user.paidAt,
    },
    data: data || {},
    updatedAt: (meta && meta.updatedAt) || 0,
  });
}

// ============== 管理端 ==============

async function adminLogin(req, res) {
  const body = await readBody(req);
  const { password } = body || {};
  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ error: '后端未配置 ADMIN_PASSWORD' });
  }
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: '管理员密码错误' });
  }
  return res.status(200).json({ adminToken: makeAdminToken() });
}

function adminAuth(req, res) {
  const token = req.headers['x-admin-token'];
  if (!verifyAdminToken(token)) {
    res.status(401).json({ error: '管理员登录已过期' });
    return false;
  }
  return true;
}

async function adminList(req, res) {
  if (!adminAuth(req, res)) return;
  const keys = await kv.keys('user:*');
  const users = await Promise.all(
    keys.map(async (k) => {
      const u = await kv.get(k);
      if (!u) return null;
      return {
        username: u.username,
        plan: u.plan,
        createdAt: u.createdAt,
        paidAt: u.paidAt,
        note: u.note || '',
      };
    })
  );
  const filtered = users.filter(Boolean).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
  return res.status(200).json({ users: filtered });
}

async function adminGrant(req, res) {
  if (!adminAuth(req, res)) return;
  const body = await readBody(req);
  const { username, plan, note } = body || {};
  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(404).json({ error: '账号不存在' });
  user.plan = plan || 'paid';
  user.paidAt = Date.now();
  if (note !== undefined && note !== null) user.note = String(note);
  await kv.set(`user:${username}`, user);
  return res.status(200).json({ ok: true });
}

async function adminRevoke(req, res) {
  if (!adminAuth(req, res)) return;
  const body = await readBody(req);
  const { username } = body || {};
  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(404).json({ error: '账号不存在' });
  user.plan = 'free';
  user.paidAt = null;
  await kv.set(`user:${username}`, user);
  return res.status(200).json({ ok: true });
}

async function adminSetNote(req, res) {
  if (!adminAuth(req, res)) return;
  const body = await readBody(req);
  const { username, note } = body || {};
  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(404).json({ error: '账号不存在' });
  user.note = String(note || '');
  await kv.set(`user:${username}`, user);
  return res.status(200).json({ ok: true });
}

// ============== 主路由器 ==============

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const path = (req.url || '/').split('?')[0].replace(/\/$/, '') || '/';

  try {
    if (path === '/' || path === '/health') return await health(req, res);
    if (path === '/register' && req.method === 'POST') return await register(req, res);
    if (path === '/login' && req.method === 'POST') return await login(req, res);
    if (path === '/sync' && req.method === 'POST') return await sync(req, res);
    if (path === '/load') return await load(req, res);

    if (path === '/admin/login' && req.method === 'POST') return await adminLogin(req, res);
    if (path === '/admin/list') return await adminList(req, res);
    if (path === '/admin/grant' && req.method === 'POST') return await adminGrant(req, res);
    if (path === '/admin/revoke' && req.method === 'POST') return await adminRevoke(req, res);
    if (path === '/admin/setNote' && req.method === 'POST') return await adminSetNote(req, res);

    return res.status(404).json({ error: 'not found', path });
  } catch (e) {
    console.error('Handler error:', e);
    return res.status(500).json({ error: e.message || '服务器错误' });
  }
}
