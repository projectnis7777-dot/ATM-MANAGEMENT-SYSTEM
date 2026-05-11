// =====================================================
//   ATM MANAGEMENT SYSTEM — BACKEND (server.js)
//   Node.js + Express + MySQL2
//
//   STEP 1: npm init -y
//   STEP 2: npm install express mysql2 cors dotenv jsonwebtoken
//   STEP 3: Create .env file (see bottom of this file)
//   STEP 4: node server.js
// =====================================================

const express    = require('express');
const mysql      = require('mysql2/promise');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const crypto     = require('crypto');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));   // serves index.html from /public folder

// ─────────────────────────────────────────────────
//  DATABASE POOL
// ─────────────────────────────────────────────────
const db = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASS     || 'J#7pL9$mN2&vR*qZ',
  database:           process.env.DB_NAME     || 'atm_db',
  waitForConnections: true,
  connectionLimit:    10,
});

// Helper: SHA256 hash (same as MySQL SHA2(str,256))
const sha256 = (str) =>
  crypto.createHash('sha256').update(str).digest('hex');

// ─────────────────────────────────────────────────
//  JWT MIDDLEWARE
// ─────────────────────────────────────────────────
const SECRET = process.env.JWT_SECRET || 'atm_secret_2025';

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token. Please login.' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(403).json({ error: 'Session expired. Please login again.' });
  }
}

// ─────────────────────────────────────────────────
//  ROUTE 1 — LOGIN
//  POST /api/login
//  Body: { account_number, pin }
//  SQL:  SELECT + JOIN (customers + accounts)
// ─────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { account_number, pin } = req.body;

  if (!account_number || !pin)
    return res.status(400).json({ error: 'Account number and PIN are required.' });

  try {
    const [rows] = await db.query(
      `SELECT a.account_id, a.account_number, a.account_type,
              a.balance, a.is_active,
              c.full_name, c.email, c.phone
       FROM   accounts  a
       JOIN   customers c ON a.customer_id = c.customer_id
       WHERE  a.account_number = ?
         AND  a.pin_hash       = SHA2(?, 256)
         AND  a.is_active      = 1`,
      [account_number, pin]
    );

    if (!rows.length)
      return res.status(401).json({ error: 'Invalid account number or PIN.' });

    const user  = rows[0];
    const token = jwt.sign(
      { account_id: user.account_id, account_number: user.account_number },
      SECRET,
      { expiresIn: '30m' }
    );

    res.json({
      token,
      name:         user.full_name,
      email:        user.email,
      account_type: user.account_type,
      account_number: user.account_number,
      balance:      user.balance,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────
//  ROUTE 2 — BALANCE ENQUIRY
//  GET /api/balance
//  SQL: SELECT balance FROM accounts WHERE account_id = ?
// ─────────────────────────────────────────────────
app.get('/api/balance', auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT a.balance, a.account_type, a.account_number,
              c.full_name
       FROM   accounts  a
       JOIN   customers c ON a.customer_id = c.customer_id
       WHERE  a.account_id = ?`,
      [req.user.account_id]
    );

    if (!rows.length) return res.status(404).json({ error: 'Account not found.' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────
//  ROUTE 3 — WITHDRAWAL
//  POST /api/withdraw
//  Body: { amount, atm_id }
//  SQL:  SELECT FOR UPDATE → UPDATE → INSERT → COMMIT
// ─────────────────────────────────────────────────
app.post('/api/withdraw', auth, async (req, res) => {
  const { amount, atm_id = 1 } = req.body;
  const amt = parseFloat(amount);

  if (!amt || amt <= 0)   return res.status(400).json({ error: 'Invalid amount.' });
  if (amt > 20000)        return res.status(400).json({ error: 'Max withdrawal per transaction: ₹20,000.' });
  if (amt % 100 !== 0)    return res.status(400).json({ error: 'Amount must be a multiple of ₹100.' });

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    // Lock the account row
    const [[account]] = await conn.query(
      'SELECT balance FROM accounts WHERE account_id = ? FOR UPDATE',
      [req.user.account_id]
    );
    if (account.balance < amt)
      throw new Error(`Insufficient balance. Available: ₹${account.balance.toFixed(2)}`);

    // Check ATM cash
    const [[atm]] = await conn.query(
      'SELECT cash_available FROM atm_machines WHERE atm_id = ? AND is_online = 1 FOR UPDATE',
      [atm_id]
    );
    if (!atm)            throw new Error('ATM is offline. Try another machine.');
    if (atm.cash_available < amt) throw new Error('ATM has insufficient cash. Try another machine.');

    // Deduct from account
    await conn.query(
      'UPDATE accounts SET balance = balance - ? WHERE account_id = ?',
      [amt, req.user.account_id]
    );

    // Deduct from ATM
    await conn.query(
      'UPDATE atm_machines SET cash_available = cash_available - ? WHERE atm_id = ?',
      [amt, atm_id]
    );

    // Get new balance
    const [[updated]] = await conn.query(
      'SELECT balance FROM accounts WHERE account_id = ?',
      [req.user.account_id]
    );

    // Record transaction
    await conn.query(
      `INSERT INTO transactions (account_id, atm_id, txn_type, amount, balance_after, status)
       VALUES (?, ?, 'withdrawal', ?, ?, 'success')`,
      [req.user.account_id, atm_id, amt, updated.balance]
    );

    await conn.commit();
    res.json({ success: true, withdrawn: amt, new_balance: updated.balance });

  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ─────────────────────────────────────────────────
//  ROUTE 4 — DEPOSIT
//  POST /api/deposit
//  Body: { amount, atm_id }
//  SQL:  UPDATE balance + INSERT transaction
// ─────────────────────────────────────────────────
app.post('/api/deposit', auth, async (req, res) => {
  const { amount, atm_id = 1 } = req.body;
  const amt = parseFloat(amount);

  if (!amt || amt <= 0)  return res.status(400).json({ error: 'Invalid amount.' });
  if (amt > 200000)      return res.status(400).json({ error: 'Max deposit: ₹2,00,000 per transaction.' });

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    await conn.query(
      'UPDATE accounts SET balance = balance + ? WHERE account_id = ?',
      [amt, req.user.account_id]
    );

    const [[updated]] = await conn.query(
      'SELECT balance FROM accounts WHERE account_id = ?',
      [req.user.account_id]
    );

    await conn.query(
      `INSERT INTO transactions (account_id, atm_id, txn_type, amount, balance_after, status)
       VALUES (?, ?, 'deposit', ?, ?, 'success')`,
      [req.user.account_id, atm_id, amt, updated.balance]
    );

    await conn.commit();
    res.json({ success: true, deposited: amt, new_balance: updated.balance });

  } catch (err) {
    await conn.rollback();
    res.status(500).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ─────────────────────────────────────────────────
//  ROUTE 5 — TRANSFER
//  POST /api/transfer
//  Body: { to_account_number, amount }
//  SQL:  SELECT FOR UPDATE (2 rows) → 2x UPDATE → INSERT → COMMIT
// ─────────────────────────────────────────────────
app.post('/api/transfer', auth, async (req, res) => {
  const { to_account_number, amount } = req.body;
  const amt = parseFloat(amount);

  if (!to_account_number) return res.status(400).json({ error: 'Recipient account number required.' });
  if (!amt || amt <= 0)   return res.status(400).json({ error: 'Invalid transfer amount.' });

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    // Find recipient
    const [[toAcc]] = await conn.query(
      'SELECT account_id, balance FROM accounts WHERE account_number = ? AND is_active = 1 FOR UPDATE',
      [to_account_number]
    );
    if (!toAcc) throw new Error('Recipient account not found or inactive.');
    if (toAcc.account_id === req.user.account_id)
      throw new Error('Cannot transfer to the same account.');

    // Lock sender
    const [[fromAcc]] = await conn.query(
      'SELECT balance FROM accounts WHERE account_id = ? FOR UPDATE',
      [req.user.account_id]
    );
    if (fromAcc.balance < amt)
      throw new Error(`Insufficient balance. Available: ₹${fromAcc.balance.toFixed(2)}`);

    // Deduct sender
    await conn.query(
      'UPDATE accounts SET balance = balance - ? WHERE account_id = ?',
      [amt, req.user.account_id]
    );

    // Credit receiver
    await conn.query(
      'UPDATE accounts SET balance = balance + ? WHERE account_id = ?',
      [amt, toAcc.account_id]
    );

    // New sender balance
    const [[senderUpdated]] = await conn.query(
      'SELECT balance FROM accounts WHERE account_id = ?',
      [req.user.account_id]
    );

    // Record transaction
    await conn.query(
      `INSERT INTO transactions (account_id, txn_type, amount, balance_after, to_account_id, status)
       VALUES (?, 'transfer', ?, ?, ?, 'success')`,
      [req.user.account_id, amt, senderUpdated.balance, toAcc.account_id]
    );

    await conn.commit();
    res.json({ success: true, transferred: amt, new_balance: senderUpdated.balance });

  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// ─────────────────────────────────────────────────
//  ROUTE 6 — TRANSACTION HISTORY
//  GET /api/history?limit=10
//  SQL: SELECT * FROM transactions WHERE account_id = ?
// ─────────────────────────────────────────────────
app.get('/api/history', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);
  try {
    const [rows] = await db.query(
      `SELECT t.txn_id, t.txn_type, t.amount, t.balance_after,
              t.status, t.txn_date,
              m.location AS atm_location,
              a.account_number AS to_account
       FROM   transactions  t
       LEFT JOIN atm_machines m ON t.atm_id = m.atm_id
       LEFT JOIN accounts    a ON t.to_account_id = a.account_id
       WHERE  t.account_id = ?
       ORDER  BY t.txn_date DESC
       LIMIT  ?`,
      [req.user.account_id, limit]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────
//  ROUTE 7 — CHANGE PIN
//  PUT /api/change-pin
//  Body: { old_pin, new_pin }
//  SQL:  UPDATE pin_hash WHERE old_pin matches
// ─────────────────────────────────────────────────
app.put('/api/change-pin', auth, async (req, res) => {
  const { old_pin, new_pin } = req.body;
  if (!old_pin || !new_pin)         return res.status(400).json({ error: 'Both PINs required.' });
  if (new_pin.length < 4)          return res.status(400).json({ error: 'New PIN must be 4-6 digits.' });
  if (!/^\d+$/.test(new_pin))      return res.status(400).json({ error: 'PIN must contain only digits.' });

  try {
    const [result] = await db.query(
      `UPDATE accounts
       SET    pin_hash = SHA2(?, 256)
       WHERE  account_id = ?
         AND  pin_hash   = SHA2(?, 256)`,
      [new_pin, req.user.account_id, old_pin]
    );

    if (!result.affectedRows)
      return res.status(401).json({ error: 'Incorrect current PIN.' });

    res.json({ success: true, message: 'PIN changed successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────
//  ROUTE 8 — ADMIN: ALL ATMs
//  GET /api/admin/atms
// ─────────────────────────────────────────────────
app.get('/api/admin/atms', async (req, res) => {
  const [rows] = await db.query(
    `SELECT atm_id, location, cash_available, is_online,
       CASE
         WHEN cash_available < 10000 THEN 'CRITICAL'
         WHEN cash_available < 50000 THEN 'LOW'
         WHEN is_online = 0          THEN 'OFFLINE'
         ELSE 'OPERATIONAL'
       END AS status
     FROM atm_machines`
  );
  res.json(rows);
});

// ─────────────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅ ATM Server running at http://localhost:${PORT}`);
  console.log(`📋 API Endpoints:`);
  console.log(`   POST   /api/login`);
  console.log(`   GET    /api/balance`);
  console.log(`   POST   /api/withdraw`);
  console.log(`   POST   /api/deposit`);
  console.log(`   POST   /api/transfer`);
  console.log(`   GET    /api/history`);
  console.log(`   PUT    /api/change-pin`);
  console.log(`   GET    /api/admin/atms\n`);
});

// =====================================================
//  .env file (create this in same folder as server.js)
// =====================================================
//
//  DB_HOST=localhost
//  DB_USER=root
//  DB_PASS=your_mysql_password
//  DB_NAME=atm_db
//  JWT_SECRET=atm_super_secret_key_2025
//  PORT=3001
//
// =====================================================