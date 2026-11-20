const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const required = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'TELEGRAM_BOT_TOKEN'];
for (const name of required) {
  if (!process.env[name]) {
    console.error(`Missing environment variable: ${name}`);
    process.exit(1);
  }
}
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
function verifyTelegram(initData) {
  if (!initData || typeof initData !== 'string' || initData.length > 10000) throw new Error('اطلاعات ورود تلگرام دریافت نشد. بازی را از داخل ربات باز کن.');
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash || !/^[a-f0-9]{64}$/i.test(hash)) throw new Error('امضای ورود تلگرام معتبر نیست.');
  const authDate = Number(params.get('auth_date'));
  if (!authDate || Math.abs(Date.now() / 1000 - authDate) > 86400) throw new Error('اطلاعات ورود تلگرام منقضی شده؛ بازی را دوباره باز کن.');
  const pairs = [];
  for (const [key, value] of params.entries()) if (key !== 'hash' && key !== 'signature') pairs.push(`${key}=${value}`);
  pairs.sort();
  const dataCheckString = pairs.join('\n');
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(process.env.TELEGRAM_BOT_TOKEN).digest();
  const calculated = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  const a = Buffer.from(calculated, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error('تأیید هویت تلگرام ناموفق بود.');
  const userRaw = params.get('user');
  if (!userRaw) throw new Error('شناسه کاربر تلگرام پیدا نشد.');
  const user = JSON.parse(userRaw);
  if (!user.id) throw new Error('شناسه کاربر معتبر نیست.');
  return user;
}
function auth(req, res, next) {
  try {
    req.telegramUser = verifyTelegram(req.get('X-Telegram-Init-Data'));
    next();
  } catch (e) { res.status(401).json({ error: e.message }); }
}
app.get('/api/state', auth, async (req, res) => {
  const { data, error } = await supabase.from('players').select('game_state').eq('telegram_id', String(req.telegramUser.id)).maybeSingle();
  if (error) return res.status(500).json({ error: 'خواندن اطلاعات از دیتابیس ناموفق بود.' });
  return res.json({ state: data?.game_state || null });
});
app.post('/api/state', auth, async (req, res) => {
  const s = req.body;
  if (!s || typeof s !== 'object' || Array.isArray(s) || typeof s.teamName !== 'string' || !s.teamName.trim() || typeof s.coachName !== 'string') {
    return res.status(400).json({ error: 'اطلاعات تیم کامل نیست.' });
  }
  if (!Array.isArray(s.players) || s.players.length > 25 || s.players.length < 11) return res.status(400).json({ error: 'فهرست بازیکنان معتبر نیست.' });
  const row = {
    telegram_id: String(req.telegramUser.id),
    team_name: s.teamName.trim().slice(0, 60),
    coach_name: s.coachName.trim().slice(0, 60),
    budget: Math.max(0, Math.min(1000000000, Math.floor(Number(s.money) || 0))),
    fans: Math.max(0, Math.min(1000000000, Math.floor(Number(s.fans) || 0))),
    game_state: s
  };
  const { error } = await supabase.from('players').upsert(row, { onConflict: 'telegram_id' });
  if (error) return res.status(500).json({ error: 'ذخیره اطلاعات در دیتابیس ناموفق بود.' });
  return res.json({ ok: true });
});
app.get('/health', (_req, res) => res.json({ ok: true, service: 'Ostore Football' }));
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Ostore Football server listening on ${port}`));
