const express = require('express');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const {
  createUser,
  getUserByEmail,
  getUserById,
  saveVerificationChallenge,
  verifyVerificationCode,
  completeEmailVerification,
  setPendingGmailEmail,
  completeGmailEmailUpdate,
  savePasswordResetToken,
  completePasswordReset,
  listUsers,
  getWorkspace,
  saveWorkspace,
  initializeDatabase
} = require('./db');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;
const JWT_SECRET = process.env.JWT_SECRET || 'inventify-dev-secret-key';
const CODE_HASH_SECRET = process.env.VERIFICATION_CODE_SECRET || JWT_SECRET;
const CODE_TTL_MS = 5 * 60 * 1000;
const SEND_COOLDOWN_MS = 60 * 1000;
const SEND_WINDOW_MS = 60 * 60 * 1000;
const MAX_SENDS_PER_WINDOW = 5;
const MAX_CODE_ATTEMPTS = 5;
const ipRateLimits = new Map();
let mailTransport = null;

function rateLimitByIp(req, res, scope, limit, windowMs) {
  const now = Date.now();
  const key = `${scope}:${req.ip}`;
  const current = ipRateLimits.get(key);
  if (!current || now >= current.resetAt) {
    ipRateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  current.count += 1;
  if (current.count > limit) {
    res.set('Retry-After', String(Math.ceil((current.resetAt - now) / 1000)));
    res.status(429).json({ message: 'Too many requests. Please try again later.' });
    return true;
  }
  return false;
}

function createRequestError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function hashVerificationCode(code, salt) {
  return crypto.createHmac('sha256', CODE_HASH_SECRET).update(`${salt}:${code}`).digest('hex');
}

function getMailTransport() {
  const user = process.env.GMAIL_USER;
  const password = String(process.env.GMAIL_APP_PASSWORD || '').replace(/\s/g, '');
  if (!user || !password) {
    throw new Error('GMAIL_USER and GMAIL_APP_PASSWORD must be configured to send verification emails.');
  }
  if (!mailTransport) {
    mailTransport = nodemailer.createTransport({
      service: 'gmail',
      auth: { user, pass: password }
    });
  }
  return { transport: mailTransport, user };
}

async function issueVerificationCode(user, purpose) {
  const recipient = purpose === 'gmail_change' ? user.pendingGmailEmail : user.gmailEmail;
  if (!recipient) {
    throw createRequestError('This account does not have a recovery Gmail address. Contact support.', 400);
  }
  const { transport, user: sender } = getMailTransport();
  const now = Date.now();
  const code = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
  const codeSalt = crypto.randomBytes(16).toString('hex');
  const challenge = {
    recipientEmail: recipient,
    codeHash: hashVerificationCode(code, codeSalt),
    codeSalt,
    expiresAt: now + CODE_TTL_MS,
    sentAt: now
  };
  const saved = await saveVerificationChallenge(user.id, purpose, challenge, {
    cooldownMs: SEND_COOLDOWN_MS,
    windowMs: SEND_WINDOW_MS,
    maxSends: MAX_SENDS_PER_WINDOW
  });
  if (saved.status === 'cooldown') {
    throw createRequestError(`Please wait ${saved.retryAfterSeconds} seconds before requesting another code.`, 429);
  }
  if (saved.status === 'rate_limited') {
    throw createRequestError('Too many verification emails were requested. Try again in an hour.', 429);
  }

  const subject = purpose === 'signup'
    ? 'Verify your Inventify account'
    : purpose === 'gmail_change'
      ? 'Verify your Inventify recovery Gmail'
      : 'Reset your Inventify password';
  await transport.sendMail({
    from: sender,
    to: recipient,
    subject,
    text: `Your Inventify verification code is ${code}. It expires in 5 minutes. If you did not request this, you can ignore this email.`
  });
}

async function checkVerificationCode(user, purpose, code) {
  const recipient = purpose === 'gmail_change' ? user.pendingGmailEmail : user.gmailEmail;
  const result = await verifyVerificationCode(
    user.id,
    purpose,
    recipient,
    code,
    Date.now(),
    MAX_CODE_ATTEMPTS,
    salt => hashVerificationCode(code, salt)
  );
  if (result.status === 'invalid' || result.status === 'expired') {
    throw createRequestError('That code is invalid or expired. Request a new code.', 400);
  }
  if (result.status === 'locked') {
    throw createRequestError('Too many incorrect attempts. Request a new code.', 429);
  }
  if (result.status === 'incorrect') {
    const remaining = result.attemptsRemaining;
    throw createRequestError(
      remaining ? `Incorrect code. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.` : 'Too many incorrect attempts. Request a new code.',
      remaining ? 400 : 429
    );
  }
}

function hashPassword(password) {
  return crypto
    .pbkdf2Sync(password, 'inventify-salt', 100000, 64, 'sha512')
    .toString('hex');
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      businessName: user.businessName,
      fullName: user.fullName
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (error) {
    return res.status(401).json({ message: 'Session expired or invalid token.' });
  }
}

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static(ROOT_DIR));

app.get('/', (req, res) => {
  res.sendFile(path.join(ROOT_DIR, 'test.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'inventify-api' });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const user = await getUserById(req.user.id);

  if (!user) {
    return res.status(404).json({ message: 'User not found.' });
  }

  return res.json({
    user: {
      id: user.id,
      businessName: user.businessName,
      fullName: user.fullName,
      email: user.email
    }
  });
});

app.get('/api/workspace', authMiddleware, async (req, res) => {
  try {
    const workspace = await getWorkspace(req.user.id);
    return res.json({ workspace });
  } catch (error) {
    console.error('Unable to load workspace:', error);
    return res.status(500).json({ message: 'Unable to load workspace.' });
  }
});

app.put('/api/workspace', authMiddleware, async (req, res) => {
  const workspace = req.body;
  if (!workspace || typeof workspace !== 'object' || Array.isArray(workspace)) {
    return res.status(400).json({ message: 'Workspace data must be a JSON object.' });
  }

  try {
    await saveWorkspace(req.user.id, workspace);
    return res.json({ success: true });
  } catch (error) {
    console.error('Unable to save workspace:', error);
    return res.status(500).json({ message: 'Unable to save workspace.' });
  }
});

app.get('/api/users', authMiddleware, async (req, res) => {
  const users = await listUsers();
  res.json({ users });
});

app.post('/api/signup', async (req, res) => {
  if (rateLimitByIp(req, res, 'signup', 5, 15 * 60 * 1000)) return;
  const { businessName, fullName, email, gmailEmail, password } = req.body || {};

  if (!businessName || !fullName || !email || !gmailEmail || !password) {
    return res.status(400).json({ message: 'Please complete all signup fields.' });
  }

  if (!/^\S+@\S+\.\S+$/.test(String(email))) {
    return res.status(400).json({ message: 'Use a valid email address.' });
  }

  const normalizedGmail = String(gmailEmail).trim().toLowerCase();
  if (!/^[^\s@]+@gmail\.com$/.test(normalizedGmail)) {
    return res.status(400).json({ message: 'Enter a valid @gmail.com address for verification and password recovery.' });
  }

  if (String(password).length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const existingUser = await getUserByEmail(normalizedEmail);

  if (existingUser) {
    return res.status(409).json({ message: 'An account with that email already exists.' });
  }

  const newUser = {
    id: `user-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    businessName: String(businessName).trim(),
    fullName: String(fullName).trim(),
    email: normalizedEmail,
    gmailEmail: normalizedGmail,
    emailVerified: false,
    passwordHash: hashPassword(String(password))
  };

  let accountCreated = false;
  try {
    await createUser(newUser);
    accountCreated = true;
    await issueVerificationCode(newUser, 'signup');
    return res.status(201).json({ success: true, verificationRequired: true });
  } catch (error) {
    if (error.statusCode) {
      return res.status(error.statusCode).json({ message: error.message, accountCreated });
    }
    console.error('Unable to create account or send verification email:', error);
    return res.status(503).json({
      message: accountCreated
        ? 'Your account was created, but the verification email could not be sent. Please request a new code.'
        : 'Unable to create your account right now. Please try again later.',
      accountCreated
    });
  }
});

app.post('/api/verification/resend', async (req, res) => {
  if (rateLimitByIp(req, res, 'verification-send', 10, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ message: 'Enter your business email.' });

  try {
    const user = await getUserByEmail(email);
    if (!user || user.emailVerified) {
      return res.json({ success: true, message: 'If the account needs verification, a code will be sent.' });
    }
    await issueVerificationCode(user, 'signup');
    return res.json({ success: true, message: 'A new verification code was sent to your Gmail address.' });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ message: error.message });
    console.error('Unable to resend verification email:', error);
    return res.status(503).json({ message: 'Unable to send a verification email right now. Please try again later.' });
  }
});

app.post('/api/verification/confirm', async (req, res) => {
  if (rateLimitByIp(req, res, 'verification-check', 20, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.code || '').trim();
  if (!email || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ message: 'Enter your business email and the 6-digit code.' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user) return res.status(400).json({ message: 'That code is invalid or expired. Request a new code.' });
    if (user.emailVerified) return res.json({ success: true, message: 'This account is already verified.' });
    await checkVerificationCode(user, 'signup', code);
    await completeEmailVerification(user.id);
    return res.json({ success: true, message: 'Email verified. You can now sign in with your business email.' });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ message: error.message });
    console.error('Unable to verify account email:', error);
    return res.status(500).json({ message: 'Unable to verify your account right now.' });
  }
});

app.post('/api/recovery-email/start', async (req, res) => {
  if (rateLimitByIp(req, res, 'verification-send', 10, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const gmailEmail = String(req.body?.gmailEmail || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!email || !password || !gmailEmail) {
    return res.status(400).json({ message: 'Enter your business email, password, and recovery Gmail.' });
  }
  if (!/^[^\s@]+@gmail\.com$/.test(gmailEmail)) {
    return res.status(400).json({ message: 'Enter a valid @gmail.com recovery address.' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user || !user.emailVerified || user.passwordHash !== hashPassword(password)) {
      return res.status(401).json({ message: 'Check your business email and password.' });
    }
    await setPendingGmailEmail(user.id, gmailEmail);
    await issueVerificationCode({ ...user, pendingGmailEmail: gmailEmail }, 'gmail_change');
    return res.json({ success: true, message: 'A verification code was sent to the new Gmail address.' });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ message: error.message });
    console.error('Unable to send recovery Gmail verification:', error);
    return res.status(503).json({ message: 'Unable to send a verification email right now. Please try again later.' });
  }
});

app.post('/api/recovery-email/resend', async (req, res) => {
  if (rateLimitByIp(req, res, 'verification-send', 10, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ message: 'Enter your business email.' });

  try {
    const user = await getUserByEmail(email);
    if (!user || !user.pendingGmailEmail) {
      return res.json({ success: true, message: 'If a Gmail address is pending verification, a code will be sent.' });
    }
    await issueVerificationCode(user, 'gmail_change');
    return res.json({ success: true, message: 'A new verification code was sent to the pending Gmail address.' });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ message: error.message });
    console.error('Unable to resend recovery Gmail verification:', error);
    return res.status(503).json({ message: 'Unable to send a verification email right now. Please try again later.' });
  }
});

app.post('/api/recovery-email/verify', async (req, res) => {
  if (rateLimitByIp(req, res, 'verification-check', 20, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.code || '').trim();
  if (!email || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ message: 'Enter your business email and the 6-digit code.' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user || !user.pendingGmailEmail) {
      return res.status(400).json({ message: 'That code is invalid or expired. Request a new code.' });
    }
    await checkVerificationCode(user, 'gmail_change', code);
    const updated = await completeGmailEmailUpdate(user.id);
    if (!updated) return res.status(400).json({ message: 'That code is invalid or expired. Request a new code.' });
    return res.json({ success: true, message: 'Recovery Gmail verified and saved.' });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ message: error.message });
    console.error('Unable to verify recovery Gmail:', error);
    return res.status(500).json({ message: 'Unable to verify the recovery Gmail right now.' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  if (rateLimitByIp(req, res, 'password-reset-send', 10, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email) return res.status(400).json({ message: 'Enter your business email.' });

  try {
    const user = await getUserByEmail(email);
    if (user && user.emailVerified && user.gmailEmail) {
      await issueVerificationCode(user, 'password_reset');
    }
    return res.json({ success: true, message: 'If the account is eligible, a password reset code was sent to its recovery Gmail.' });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ message: error.message });
    console.error('Unable to send password reset email:', error);
    return res.status(503).json({ message: 'Unable to send a recovery email right now. Please try again later.' });
  }
});

app.post('/api/forgot-password/verify', async (req, res) => {
  if (rateLimitByIp(req, res, 'password-reset-check', 20, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const code = String(req.body?.code || '').trim();
  if (!email || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ message: 'Enter your business email and the 6-digit code.' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user || !user.emailVerified) {
      return res.status(400).json({ message: 'That code is invalid or expired. Request a new code.' });
    }
    await checkVerificationCode(user, 'password_reset', code);
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    await savePasswordResetToken(user.id, resetTokenHash, Date.now() + 10 * 60 * 1000, Date.now());
    return res.json({ success: true, resetToken });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ message: error.message });
    console.error('Unable to verify password reset code:', error);
    return res.status(500).json({ message: 'Unable to verify the reset code right now.' });
  }
});

app.post('/api/forgot-password/reset', async (req, res) => {
  if (rateLimitByIp(req, res, 'password-reset-complete', 10, 15 * 60 * 1000)) return;
  const email = String(req.body?.email || '').trim().toLowerCase();
  const resetToken = String(req.body?.resetToken || '');
  const password = String(req.body?.password || '');
  if (!email || !resetToken || password.length < 6) {
    return res.status(400).json({ message: 'Enter a new password with at least 6 characters.' });
  }

  try {
    const user = await getUserByEmail(email);
    if (!user) return res.status(400).json({ message: 'The reset session is invalid or expired. Request a new code.' });
    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const updated = await completePasswordReset(user.id, tokenHash, hashPassword(password), Date.now());
    if (!updated) {
      return res.status(400).json({ message: 'The reset session is invalid or expired. Request a new code.' });
    }
    return res.json({ success: true, message: 'Password updated. Sign in with your business email and new password.' });
  } catch (error) {
    console.error('Unable to reset password:', error);
    return res.status(500).json({ message: 'Unable to reset your password right now.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ message: 'Enter your email and password to sign in.' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  const user = await getUserByEmail(normalizedEmail);

  if (!user || user.passwordHash !== hashPassword(String(password))) {
    return res.status(401).json({
      message: 'No matching account found. Create a new account or check your password.'
    });
  }

  if (!user.emailVerified) {
    return res.status(403).json({ message: 'Verify your Gmail address before signing in.', verificationRequired: true });
  }

  const token = createToken(user);

  return res.json({
    success: true,
    token,
    user: {
      id: user.id,
      businessName: user.businessName,
      fullName: user.fullName,
      email: user.email
    }
  });
});

async function startServer() {
  await initializeDatabase();

  app.listen(PORT, () => {
    console.log(`Inventify backend running at http://localhost:${PORT}`);
  });
}

startServer();
