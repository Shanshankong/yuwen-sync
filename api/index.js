// 博瑞语文云同步后端 · Vercel 版
// 部署在 Vercel Serverless Functions + Vercel KV (Upstash)
// v3:加助力(boost)功能,3 次解锁 Day 1-7, 5 次解锁全部 36 天

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

// Token: 简单自签名 token,格式 "<username>.<expireMs>.<sig>"
function makeToken(username) {
  const exp = Date.now() + 90 * 24 * 60 * 60 * 1000; // 90 天有效期
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

// ============== 助力相关工具 ==============

// 获取请求的 IP
function getIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.headers['x-real-ip']
    || (req.socket && req.socket.remoteAddress)
    || 'unknown';
}

// 生成助力者指纹(基于 IP + UA),用来防止同一人多次助力
function makeFingerprint(req) {
  const ip = getIP(req);
  const ua = (req.headers['user-agent'] || '').slice(0, 200);
  return sha256(ip + '||' + ua).slice(0, 24);
}

// 助力解锁阈值
const BOOST_THRESHOLD_PARTIAL = 3;  // 3 个解锁 Day 1-7
const BOOST_THRESHOLD_FULL = 5;     // 5 个解锁全部

// 根据助力数算 plan(只升不降;已 paid 不会降级)
function planFromBoost(currentPlan, boostCount) {
  if (currentPlan === 'paid') return 'paid';
  if (boostCount >= BOOST_THRESHOLD_FULL) return 'paid';  // 5 个 = 全部解锁
  if (boostCount >= BOOST_THRESHOLD_PARTIAL) return 'boost7';  // 3 个 = Day 1-7
  return currentPlan || 'free';
}

// ============== 路由处理函数 ==============

async function health(req, res) {
  return res.status(200).json({
    ok: true,
    service: '语文 36 天闯关 · 云同步 v3 (Vercel + Boost)',
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
    boostCount: 0,
    boostUnlockedAt: null,
  };
  await kv.set(`user:${username}`, user);
  await kv.set(`data:${username}`, {});

  const token = makeToken(username);
  return res.status(200).json({
    token,
    username,
    user: {
      username,
      plan: user.plan,
      createdAt: now,
      boostCount: 0,
    },
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
      boostCount: user.boostCount || 0,
    },
  });
}

async function changePassword(req, res) {
  const body = await readBody(req);
  const { username, oldPassword, newPassword } = body || {};
  if (!username || !oldPassword || !newPassword) {
    return res.status(400).json({ error: '参数缺失' });
  }
  if (!validPassword(newPassword)) {
    return res.status(400).json({ error: '新密码至少 4 位' });
  }
  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(400).json({ error: '账号不存在' });
  if (user.passHash !== sha256(oldPassword + ':' + SECRET)) {
    return res.status(400).json({ error: '原密码错误' });
  }
  user.passHash = sha256(newPassword + ':' + SECRET);
  user.passwordChangedAt = Date.now();
  await kv.set(`user:${username}`, user);
  return res.status(200).json({ ok: true });
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
      boostCount: user.boostCount || 0,
    },
    data: data || {},
    updatedAt: (meta && meta.updatedAt) || 0,
  });
}

// ============== 助力(boost)API ==============

// GET /boost/status?username=xxx  公开接口,查某用户的助力进度
async function boostStatus(req, res) {
  const url = new URL(req.url, 'http://x');
  const username = url.searchParams.get('username');
  if (!username) return res.status(400).json({ error: '缺少 username 参数' });
  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(404).json({ error: '账号不存在' });
  const boostCount = user.boostCount || 0;
  const plan = user.plan || 'free';
  return res.status(200).json({
    username: user.username,
    boostCount,
    thresholdPartial: BOOST_THRESHOLD_PARTIAL,
    thresholdFull: BOOST_THRESHOLD_FULL,
    plan,
    isFullyUnlocked: plan === 'paid' || boostCount >= BOOST_THRESHOLD_FULL,
    isPartiallyUnlocked: boostCount >= BOOST_THRESHOLD_PARTIAL,
  });
}

// POST /boost  body: {username, selfUsername?}
// 朋友给指定 username 助力一次。selfUsername 用于防止给自己助力
async function boost(req, res) {
  const body = await readBody(req);
  const { username, selfUsername } = body || {};
  if (!username) return res.status(400).json({ error: '缺少 username' });

  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(404).json({ error: '账号不存在' });

  // 不能给自己助力
  if (selfUsername && selfUsername === username) {
    return res.status(400).json({ error: '不能给自己助力,要请朋友帮忙才行' });
  }

  // 已经全部解锁了就不需要再助力
  if (user.plan === 'paid' && (user.boostCount || 0) >= BOOST_THRESHOLD_FULL) {
    return res.status(400).json({
      error: 'TA 已经解锁全部内容了,不用再助力啦',
      boostCount: user.boostCount || 0,
    });
  }

  const fingerprint = makeFingerprint(req);
  const ip = getIP(req);
  const ua = (req.headers['user-agent'] || '').slice(0, 200);
  const now = Date.now();

  // 检查这个指纹是否已经为该用户助力过
  const boostKey = `boost:${username}:${fingerprint}`;
  const existed = await kv.get(boostKey);
  if (existed) {
    return res.status(400).json({
      error: '你已经为 TA 助力过了,不能重复',
      boostCount: user.boostCount || 0,
      alreadyBoosted: true,
    });
  }

  // 写入助力记录
  await kv.set(boostKey, {
    fingerprint, ip, ua, at: now, forUsername: username,
  });
  // 把这个 fingerprint 加到 user 的助力者列表(便于 admin 审计)
  const listKey = `boostList:${username}`;
  const list = (await kv.get(listKey)) || [];
  list.push({ fingerprint, ip, ua, at: now });
  await kv.set(listKey, list);

  // 更新用户的 boostCount + plan
  user.boostCount = (user.boostCount || 0) + 1;
  const oldPlan = user.plan;
  user.plan = planFromBoost(user.plan, user.boostCount);
  if (user.plan !== oldPlan) {
    user.boostUnlockedAt = now;
  }
  await kv.set(`user:${username}`, user);

  return res.status(200).json({
    ok: true,
    boostCount: user.boostCount,
    thresholdPartial: BOOST_THRESHOLD_PARTIAL,
    thresholdFull: BOOST_THRESHOLD_FULL,
    unlocked: user.plan !== oldPlan ? user.plan : null,
    plan: user.plan,
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
        boostCount: u.boostCount || 0,
        boostUnlockedAt: u.boostUnlockedAt || null,
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

// GET /admin/boost/list?username=xxx 查看某用户的助力明细
async function adminBoostList(req, res) {
  if (!adminAuth(req, res)) return;
  const url = new URL(req.url, 'http://x');
  const username = url.searchParams.get('username');
  if (!username) return res.status(400).json({ error: '缺少 username' });
  const list = (await kv.get(`boostList:${username}`)) || [];
  const user = await kv.get(`user:${username}`);
  return res.status(200).json({
    username,
    boostCount: (user && user.boostCount) || 0,
    plan: user && user.plan,
    list,  // [{fingerprint, ip, ua, at}, ...]
  });
}

// POST /admin/boost/revoke body: {username, fingerprint}
// 取消某次助力(用于审核作弊)
async function adminBoostRevoke(req, res) {
  if (!adminAuth(req, res)) return;
  const body = await readBody(req);
  const { username, fingerprint } = body || {};
  if (!username || !fingerprint) {
    return res.status(400).json({ error: '参数缺失' });
  }
  const user = await kv.get(`user:${username}`);
  if (!user) return res.status(404).json({ error: '账号不存在' });
  // 删除单条 boost 记录
  await kv.del(`boost:${username}:${fingerprint}`);
  // 从 list 里删
  const list = (await kv.get(`boostList:${username}`)) || [];
  const newList = list.filter(x => x.fingerprint !== fingerprint);
  await kv.set(`boostList:${username}`, newList);
  // 减少 boostCount
  user.boostCount = Math.max(0, (user.boostCount || 0) - 1);
  // 重新计算 plan(只在不是手动 paid 的情况下降级)
  // 如果当前是 paid 但是是通过助力 5 次解锁的(没有 paidAt),那么数量降回 < 5 就降级
  if (user.plan === 'paid' && !user.paidAt) {
    if (user.boostCount < BOOST_THRESHOLD_FULL) {
      user.plan = user.boostCount >= BOOST_THRESHOLD_PARTIAL ? 'boost7' : 'free';
    }
  } else if (user.plan === 'boost7') {
    if (user.boostCount < BOOST_THRESHOLD_PARTIAL) {
      user.plan = 'free';
    }
  }
  await kv.set(`user:${username}`, user);
  return res.status(200).json({
    ok: true,
    boostCount: user.boostCount,
    plan: user.plan,
  });
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
    if (path === '/changePassword' && req.method === 'POST') return await changePassword(req, res);
    if (path === '/sync' && req.method === 'POST') return await sync(req, res);
    if (path === '/load') return await load(req, res);

    // 助力相关
    if (path === '/boost' && req.method === 'POST') return await boost(req, res);
    if (path === '/boost/status') return await boostStatus(req, res);

    // 管理端
    if (path === '/admin/login' && req.method === 'POST') return await adminLogin(req, res);
    if (path === '/admin/list') return await adminList(req, res);
    if (path === '/admin/grant' && req.method === 'POST') return await adminGrant(req, res);
    if (path === '/admin/revoke' && req.method === 'POST') return await adminRevoke(req, res);
    if (path === '/admin/setNote' && req.method === 'POST') return await adminSetNote(req, res);
    if (path === '/admin/boost/list') return await adminBoostList(req, res);
    if (path === '/admin/boost/revoke' && req.method === 'POST') return await adminBoostRevoke(req, res);

    return res.status(404).json({ error: 'not found', path });
  } catch (e) {
    console.error('Handler error:', e);
    return res.status(500).json({ error: e.message || '服务器错误' });
  }
}
