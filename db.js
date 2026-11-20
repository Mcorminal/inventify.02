const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const initSqlJs = require('sql.js');

const dbDir = path.join(__dirname, 'data');
const dbPath = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(dbDir, 'inventify.db');
const usersSeedPath = path.join(dbDir, 'users.json');

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}
fs.mkdirSync(path.dirname(dbPath), { recursive: true });

let dbPromise = null;

function readSeedUsers() {
  if (!fs.existsSync(usersSeedPath)) {
    return [];
  }

  try {
    const raw = fs.readFileSync(usersSeedPath, 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    return [];
  }
}

function writeSeedUsers(users) {
  const tempPath = `${usersSeedPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(users, null, 2));
  fs.renameSync(tempPath, usersSeedPath);
}

function updateSeedUser(userId, updates) {
  const users = readSeedUsers();
  const index = users.findIndex(user => user && String(user.id) === String(userId));
  if (index < 0) return;
  users[index] = { ...users[index], ...updates };
  writeSeedUsers(users);
}

function persistDatabase(db) {
  const data = db.export();
  const tempPath = `${dbPath}.${process.pid}.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(tempPath, Buffer.from(data));
    fs.renameSync(tempPath, dbPath);
  } catch (error) {
    if (fs.existsSync(tempPath)) {
      fs.unlinkSync(tempPath);
    }
    throw error;
  }
}

function statementExists(db, sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const exists = stmt.step();
  stmt.reset();
  return exists;
}

function createDefaultSeedData(db) {
  const categoryRows = [
    ['Electronics'],
    ['Consumables'],
    ['Hardware']
  ];

  categoryRows.forEach(([name]) => {
    if (!statementExists(db, 'SELECT 1 FROM categories WHERE name = ?', [name])) {
      db.run('INSERT INTO categories (name) VALUES (?)', [name]);
    }
  });

  const supplierRows = [
    ['Apex Tech Global', 'hello@apextech.com', '0800-123-456', 'Singapore'],
    ['PackPro Supply', 'support@packpro.com', '0800-654-321', 'Manila'],
    ['Northwind Industrial', 'sales@northwind.com', '0800-987-654', 'Jakarta']
  ];

  supplierRows.forEach(([name, email, phone, location]) => {
    if (!statementExists(db, 'SELECT 1 FROM suppliers WHERE name = ?', [name])) {
      db.run('INSERT INTO suppliers (name, email, phone, location) VALUES (?, ?, ?, ?)', [name, email, phone, location]);
    }
  });

  const seedUsers = readSeedUsers();
  seedUsers.forEach((user) => {
    if (!user || !user.email) {
      return;
    }

    const normalizedEmail = String(user.email).trim().toLowerCase();
    const payload = [
      user.id || `user-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      String(user.businessName || '').trim(),
      String(user.fullName || '').trim(),
      normalizedEmail,
      String(user.passwordHash || ''),
      user.gmailEmail ? String(user.gmailEmail).trim().toLowerCase() : null,
      user.emailVerified === false ? 0 : 1
    ];

    if (!statementExists(db, 'SELECT 1 FROM users WHERE LOWER(email) = LOWER(?)', [normalizedEmail])) {
      db.run(
        'INSERT INTO users (id, businessName, fullName, email, passwordHash, gmailEmail, emailVerified) VALUES (?, ?, ?, ?, ?, ?, ?)',
        payload
      );
    }
  });
}

async function initializeDatabase() {
  if (!dbPromise) {
    dbPromise = initSqlJs().then(SQL => {
      let db;
      if (fs.existsSync(dbPath)) {
        const fileBuffer = fs.readFileSync(dbPath);
        db = new SQL.Database(fileBuffer);
        const integrityCheck = db.exec('PRAGMA integrity_check');
        if (integrityCheck[0]?.values[0]?.[0] !== 'ok') {
          throw new Error('Database disk image is malformed');
        }
      } else {
        db = new SQL.Database();
      }

      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          businessName TEXT NOT NULL,
          fullName TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          passwordHash TEXT NOT NULL,
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);

      const userColumns = db.exec('PRAGMA table_info(users)')[0]?.values.map(row => row[1]) || [];
      if (!userColumns.includes('gmailEmail')) {
        db.run('ALTER TABLE users ADD COLUMN gmailEmail TEXT');
      }
      if (!userColumns.includes('emailVerified')) {
        db.run('ALTER TABLE users ADD COLUMN emailVerified INTEGER NOT NULL DEFAULT 1');
      }
      if (!userColumns.includes('pendingGmailEmail')) {
        db.run('ALTER TABLE users ADD COLUMN pendingGmailEmail TEXT');
      }

      db.run(`
        CREATE TABLE IF NOT EXISTS email_verification_challenges (
          userId TEXT NOT NULL,
          purpose TEXT NOT NULL,
          recipientEmail TEXT NOT NULL,
          codeHash TEXT NOT NULL,
          codeSalt TEXT NOT NULL,
          expiresAt INTEGER NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          sentAt INTEGER NOT NULL,
          windowStartedAt INTEGER NOT NULL,
          sendCount INTEGER NOT NULL DEFAULT 1,
          consumedAt INTEGER,
          resetTokenHash TEXT,
          resetTokenExpiresAt INTEGER,
          PRIMARY KEY (userId, purpose),
          FOREIGN KEY(userId) REFERENCES users(id)
        );
      `);

      const challengeColumns = db.exec('PRAGMA table_info(email_verification_challenges)')[0]?.values.map(row => row[1]) || [];
      if (!challengeColumns.includes('recipientEmail')) {
        db.run('ALTER TABLE email_verification_challenges ADD COLUMN recipientEmail TEXT');
      }

      db.run(`
        CREATE TABLE IF NOT EXISTS workspaces (
          user_id TEXT PRIMARY KEY,
          data TEXT NOT NULL,
          updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS categories (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS suppliers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          email TEXT,
          phone TEXT,
          location TEXT,
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS products (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          sku TEXT NOT NULL UNIQUE,
          name TEXT NOT NULL,
          category TEXT NOT NULL,
          stock_quantity INTEGER NOT NULL DEFAULT 0,
          min_stock INTEGER NOT NULL DEFAULT 0,
          price REAL NOT NULL DEFAULT 0,
          cost REAL NOT NULL DEFAULT 0,
          icon TEXT,
          location TEXT,
          unit TEXT NOT NULL DEFAULT 'pcs',
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS purchase_orders (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          po_number TEXT NOT NULL UNIQUE,
          item_name TEXT NOT NULL,
          supplier_name TEXT NOT NULL,
          quantity INTEGER NOT NULL,
          unit TEXT NOT NULL,
          cost REAL NOT NULL DEFAULT 0,
          lead_days INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'urgent',
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS inventory_transactions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          product_sku TEXT NOT NULL,
          movement_type TEXT NOT NULL,
          quantity INTEGER NOT NULL,
          reason TEXT,
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(product_sku) REFERENCES products(sku)
        );
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS sales (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          sale_number TEXT NOT NULL UNIQUE,
          customer_name TEXT,
          total_amount REAL NOT NULL DEFAULT 0,
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);

      db.run(`
        CREATE TABLE IF NOT EXISTS sale_items (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          sale_id INTEGER NOT NULL,
          product_sku TEXT NOT NULL,
          quantity INTEGER NOT NULL,
          unit_price REAL NOT NULL,
          createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(sale_id) REFERENCES sales(id),
          FOREIGN KEY(product_sku) REFERENCES products(sku)
        );
      `);

      const countStmt = db.prepare('SELECT COUNT(*) as total FROM products');
      countStmt.step();
      const rowCount = countStmt.getAsObject().total;
      countStmt.reset();

      if (rowCount === 0) {
        createDefaultSeedData(db);
      }

      persistDatabase(db);
      return db;
    }).catch(error => {
      const isCorrupt = /database disk image is malformed|file is not a database/i.test(error.message);
      if (!isCorrupt || !fs.existsSync(dbPath)) {
        throw error;
      }

      const backupPath = path.join(dbDir, `inventify.db.corrupt-${Date.now()}`);
      fs.renameSync(dbPath, backupPath);
      console.warn(`Malformed database preserved at ${backupPath}; rebuilding from saved account records.`);
      dbPromise = null;
      return initializeDatabase();
    });
  }

  return dbPromise;
}

async function createUser({ id, businessName, fullName, email, gmailEmail, passwordHash, emailVerified = false }) {
  const db = await initializeDatabase();
  const normalizedEmail = String(email).trim().toLowerCase();
  const existingUsers = readSeedUsers();
  const hasSeededUser = existingUsers.some((user) => String(user.email || '').trim().toLowerCase() === normalizedEmail);

  db.run(
    'INSERT INTO users (id, businessName, fullName, email, passwordHash, gmailEmail, emailVerified) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, businessName, fullName, normalizedEmail, passwordHash, gmailEmail, emailVerified ? 1 : 0]
  );

  if (!hasSeededUser) {
    const nextUsers = [
      ...existingUsers,
      {
        id,
        businessName,
        fullName,
        email: normalizedEmail,
        gmailEmail,
        emailVerified: Boolean(emailVerified),
        passwordHash
      }
    ];
    writeSeedUsers(nextUsers);
  }

  persistDatabase(db);
}

async function getUserByEmail(email) {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)');
  stmt.bind([email]);

  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.reset();
    return row;
  }

  stmt.reset();
  return null;
}

async function getUserById(id) {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
  stmt.bind([id]);

  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.reset();
    return row;
  }

  stmt.reset();
  return null;
}

async function saveVerificationChallenge(userId, purpose, challenge, limits) {
  const db = await initializeDatabase();
  const stmt = db.prepare(
    'SELECT sentAt, windowStartedAt, sendCount FROM email_verification_challenges WHERE userId = ? AND purpose = ?'
  );
  stmt.bind([userId, purpose]);
  const hasExisting = stmt.step();
  const existing = hasExisting ? stmt.getAsObject() : null;
  stmt.reset();
  const now = challenge.sentAt;

  if (existing && now - existing.sentAt < limits.cooldownMs) {
    return {
      status: 'cooldown',
      retryAfterSeconds: Math.ceil((limits.cooldownMs - (now - existing.sentAt)) / 1000)
    };
  }

  const inWindow = existing && now - existing.windowStartedAt < limits.windowMs;
  const sendCount = inWindow ? existing.sendCount : 0;
  if (sendCount >= limits.maxSends) return { status: 'rate_limited' };

  db.run(
    `INSERT INTO email_verification_challenges
      (userId, purpose, recipientEmail, codeHash, codeSalt, expiresAt, attempts, sentAt, windowStartedAt, sendCount, consumedAt, resetTokenHash, resetTokenExpiresAt)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, NULL, NULL, NULL)
     ON CONFLICT(userId, purpose) DO UPDATE SET
       recipientEmail = excluded.recipientEmail,
       codeHash = excluded.codeHash,
       codeSalt = excluded.codeSalt,
       expiresAt = excluded.expiresAt,
       attempts = 0,
       sentAt = excluded.sentAt,
       windowStartedAt = excluded.windowStartedAt,
       sendCount = excluded.sendCount,
       consumedAt = NULL,
       resetTokenHash = NULL,
       resetTokenExpiresAt = NULL`,
    [
      userId,
      purpose,
      challenge.recipientEmail,
      challenge.codeHash,
      challenge.codeSalt,
      challenge.expiresAt,
      challenge.sentAt,
      inWindow ? existing.windowStartedAt : now,
      sendCount + 1
    ]
  );
  persistDatabase(db);
  return { status: 'sent' };
}

async function verifyVerificationCode(userId, purpose, recipientEmail, code, now, maxAttempts, hashCode) {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT * FROM email_verification_challenges WHERE userId = ? AND purpose = ?');
  stmt.bind([userId, purpose]);
  const hasChallenge = stmt.step();
  const challenge = hasChallenge ? stmt.getAsObject() : null;
  stmt.reset();

  if (!challenge || challenge.consumedAt || challenge.recipientEmail !== recipientEmail) return { status: 'invalid' };
  if (challenge.expiresAt <= now) return { status: 'expired' };
  if (challenge.attempts >= maxAttempts) return { status: 'locked' };

  const expected = Buffer.from(challenge.codeHash, 'hex');
  const actual = Buffer.from(hashCode(challenge.codeSalt), 'hex');
  const matches = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  if (matches) {
    db.run(
      `UPDATE email_verification_challenges SET consumedAt = ?
       WHERE userId = ? AND purpose = ? AND consumedAt IS NULL AND expiresAt > ? AND attempts < ?`,
      [now, userId, purpose, now, maxAttempts]
    );
    if (!db.getRowsModified()) return { status: 'locked' };
    persistDatabase(db);
    return { status: 'verified' };
  }

  db.run(
    `UPDATE email_verification_challenges SET attempts = attempts + 1
     WHERE userId = ? AND purpose = ? AND consumedAt IS NULL AND expiresAt > ? AND attempts < ?`,
    [userId, purpose, now, maxAttempts]
  );
  if (!db.getRowsModified()) return { status: 'locked' };
  persistDatabase(db);
  const attempts = challenge.attempts + 1;
  return { status: 'incorrect', attemptsRemaining: Math.max(0, maxAttempts - attempts) };
}

async function completeEmailVerification(userId) {
  const db = await initializeDatabase();
  updateSeedUser(userId, { emailVerified: true });
  db.run('UPDATE users SET emailVerified = 1 WHERE id = ?', [userId]);
  persistDatabase(db);
}

async function setPendingGmailEmail(userId, gmailEmail) {
  const db = await initializeDatabase();
  db.run('UPDATE users SET pendingGmailEmail = ? WHERE id = ?', [gmailEmail, userId]);
  persistDatabase(db);
}

async function completeGmailEmailUpdate(userId) {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT pendingGmailEmail FROM users WHERE id = ?');
  stmt.bind([userId]);
  const exists = stmt.step();
  const pendingGmailEmail = exists ? stmt.getAsObject().pendingGmailEmail : null;
  stmt.reset();
  if (!pendingGmailEmail) return false;

  updateSeedUser(userId, { gmailEmail: pendingGmailEmail, emailVerified: true });
  db.run(
    'UPDATE users SET gmailEmail = pendingGmailEmail, pendingGmailEmail = NULL WHERE id = ?',
    [userId]
  );
  db.run(
    `UPDATE email_verification_challenges
     SET resetTokenHash = NULL, resetTokenExpiresAt = NULL
     WHERE userId = ? AND purpose = 'password_reset'`,
    [userId]
  );
  persistDatabase(db);
  return true;
}

async function savePasswordResetToken(userId, tokenHash, expiresAt, now) {
  const db = await initializeDatabase();
  db.run(
    `UPDATE email_verification_challenges
     SET consumedAt = ?, resetTokenHash = ?, resetTokenExpiresAt = ?
     WHERE userId = ? AND purpose = ?`,
    [now, tokenHash, expiresAt, userId, 'password_reset']
  );
  persistDatabase(db);
}

async function completePasswordReset(userId, tokenHash, passwordHash, now) {
  const db = await initializeDatabase();
  const stmt = db.prepare(
    `SELECT 1 FROM email_verification_challenges
     WHERE userId = ? AND purpose = 'password_reset'
       AND resetTokenHash = ? AND resetTokenExpiresAt > ?`
  );
  stmt.bind([userId, tokenHash, now]);
  const valid = stmt.step();
  stmt.reset();
  if (!valid) return false;

  updateSeedUser(userId, { passwordHash });
  db.run('UPDATE users SET passwordHash = ? WHERE id = ?', [passwordHash, userId]);
  db.run(
    `UPDATE email_verification_challenges
     SET resetTokenHash = NULL, resetTokenExpiresAt = NULL
     WHERE userId = ? AND purpose = 'password_reset'`,
    [userId]
  );
  persistDatabase(db);
  return true;
}

async function listUsers() {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT id, businessName, fullName, email, createdAt FROM users ORDER BY createdAt DESC');
  const rows = [];

  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }

  stmt.reset();
  return rows;
}

async function getWorkspace(userId) {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT data FROM workspaces WHERE user_id = ?');
  stmt.bind([userId]);

  if (!stmt.step()) {
    stmt.reset();
    return null;
  }

  const row = stmt.getAsObject();
  stmt.reset();
  return JSON.parse(row.data);
}

async function saveWorkspace(userId, workspace) {
  const db = await initializeDatabase();
  const data = JSON.stringify(workspace);
  db.run(
    `INSERT INTO workspaces (user_id, data, updatedAt)
     VALUES (?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updatedAt = CURRENT_TIMESTAMP`,
    [userId, data]
  );
  persistDatabase(db);
}

async function listProducts() {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT * FROM products ORDER BY createdAt DESC');
  const rows = [];

  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }

  stmt.reset();
  return rows;
}

async function createProduct(product) {
  const db = await initializeDatabase();
  const { sku, name, category, stock_quantity, min_stock, price, cost, icon, location, unit } = product;
  db.run(
    'INSERT INTO products (sku, name, category, stock_quantity, min_stock, price, cost, icon, location, unit) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [sku, name, category, stock_quantity || 0, min_stock || 0, price || 0, cost || 0, icon || '📦', location || 'Receiving', unit || 'pcs']
  );
  persistDatabase(db);
}

async function listSuppliers() {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT * FROM suppliers ORDER BY createdAt DESC');
  const rows = [];

  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }

  stmt.reset();
  return rows;
}

async function listPurchaseOrders() {
  const db = await initializeDatabase();
  const stmt = db.prepare('SELECT * FROM purchase_orders ORDER BY createdAt DESC');
  const rows = [];

  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }

  stmt.reset();
  return rows;
}

module.exports = {
  initializeDatabase,
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
  listProducts,
  createProduct,
  listSuppliers,
  listPurchaseOrders
};
