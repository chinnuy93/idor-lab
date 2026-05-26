const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── In-Memory Data ──────────────────────────────────────────────

const users = [
  { id: 1, username: 'alice', email: 'alice@example.com', role: 'user', secret: 'FLAG{IDOR_READ_USER_001}' },
  { id: 2, username: 'bob', email: 'bob@example.com', role: 'user', secret: 'Just a regular user secret' },
  { id: 3, username: 'carol', email: 'carol@example.com', role: 'user', secret: 'Carol\'s hidden note: buy milk' },
  { id: 4, username: 'dave', email: 'dave@admin.com', role: 'admin', secret: 'FLAG{ADMIN_MASTER_KEY_999}' }
];

const orders = [
  { id: 101, userId: 1, item: 'Laptop', total: 1200, flag: 'FLAG{IDOR_ORDER_ENUM_101}' },
  { id: 102, userId: 2, item: 'Phone', total: 800, flag: 'Just a regular order' },
  { id: 103, userId: 3, item: 'Tablet', total: 500, flag: 'Nothing special here' },
  { id: 104, userId: 4, item: 'Server', total: 3000, flag: 'FLAG{IDOR_ORDER_ENUM_104}' }
];

const invoices = [
  { id: 'INV-001', userId: 1, amount: 1200, content: 'Invoice for Laptop' },
  { id: 'INV-002', userId: 2, amount: 800, content: 'Invoice for Phone' },
  { id: 'INV-003', userId: 3, amount: 500, content: 'Invoice for Tablet' },
  { id: 'INV-ADM', userId: 4, amount: 9999, content: 'FLAG{BYPASS_403_ADMIN_INVOICE}' }
];

const adminNotes = [
  { id: 1, note: 'FLAG{BROKEN_ACCESS_CONTROL_NO_SSRF}', content: 'Server-side role check missing. Anyone can read this.' },
  { id: 2, note: 'Deploy patch Tuesday', content: 'Remember to update dependencies.' }
];

// ─── Helper: Get current user from token header ────────────────

function getUserFromToken(req) {
  const token = req.headers['x-user-token'];
  if (!token) return null;
  const user = users.find(u => u.username === token);
  return user || null;
}

// ─── Challenge 1: IDOR Read - GET /api/user/:id ────────────────
// No ownership check — enumerate IDs to steal admin secret

app.get('/api/user/:id', (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    secret: user.secret
  });
});

// ─── Challenge 2: IDOR Read - GET /api/order/:id ───────────────
// Sequential IDs (101-104), no ownership validation

app.get('/api/order/:id', (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  const order = orders.find(o => o.id === orderId);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json({
    id: order.id,
    userId: order.userId,
    item: order.item,
    total: order.total,
    flag: order.flag
  });
});

// ─── Challenge 3: IDOR Write - PUT /api/user/update ──────────────
// Accepts user id in body, allows updating any account's email

app.put('/api/user/update', (req, res) => {
  const { id, email } = req.body;
  if (!id || !email) {
    return res.status(400).json({ error: 'Missing id or email' });
  }
  const userId = parseInt(id, 10);
  const user = users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const oldEmail = user.email;
  user.email = email;
  res.json({
    message: 'User updated',
    id: user.id,
    username: user.username,
    oldEmail,
    newEmail: user.email,
    flag: user.role === 'admin' ? 'FLAG{IDOR_WRITE_ACCOUNT_TAKEOVER}' : null
  });
});

// ─── Challenge 4: IDOR POST Body - POST /api/invoice/download ─────
// IDOR via POST body parameter instead of URL

app.post('/api/invoice/download', (req, res) => {
  const { invoiceId } = req.body;
  if (!invoiceId) {
    return res.status(400).json({ error: 'Missing invoiceId in body' });
  }
  const invoice = invoices.find(i => i.id === invoiceId);
  if (!invoice) return res.status(404).json({ error: 'Invoice not found' });
  res.json({
    invoiceId: invoice.id,
    amount: invoice.amount,
    content: invoice.content,
    flag: invoice.id === 'INV-ADM' ? 'FLAG{IDOR_POST_BODY_INVOICE}' : null
  });
});

// ─── Challenge 5: 403 Bypass - GET /api/invoice/INV-ADM ───────────
// Returns 403 to normal users, bypassable via 4 specific headers

app.get('/api/invoice/INV-ADM', (req, res) => {
  const user = getUserFromToken(req);
  const roleHeader = req.headers['x-user-role'];
  const originalUrl = req.headers['x-original-url'];
  const referer = req.headers['referer'];
  const forwardedFor = req.headers['x-forwarded-for'];

  const isBypass = (
    roleHeader === 'admin' &&
    originalUrl === '/' &&
    referer === 'http://localhost' &&
    forwardedFor === '127.0.0.1'
  );

  if (user && user.role === 'admin') {
    const invoice = invoices.find(i => i.id === 'INV-ADM');
    return res.json({
      invoiceId: invoice.id,
      amount: invoice.amount,
      content: invoice.content,
      flag: 'FLAG{BYPASS_403_ADMIN_INVOICE}'
    });
  }

  if (isBypass) {
    const invoice = invoices.find(i => i.id === 'INV-ADM');
    return res.json({
      invoiceId: invoice.id,
      amount: invoice.amount,
      content: invoice.content,
      flag: 'FLAG{BYPASS_403_ADMIN_INVOICE}'
    });
  }

  res.status(403).json({ error: 'Forbidden: Admin access required' });
});

// ─── Challenge 6: Broken Access Control - GET /api/admin/notes ────
// Role check only in frontend UI, server has no server-side enforcement

app.get('/api/admin/notes', (req, res) => {
  // NO server-side role check — anyone can access
  res.json({
    notes: adminNotes,
    flag: 'FLAG{BROKEN_ACCESS_CONTROL_NO_SSRF}'
  });
});

// ─── Challenge 7: Broken Access Control - POST /api/user/register ─
// Accepts "role" field from body, allowing self-assignment of admin

app.post('/api/user/register', (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const newId = users.length + 1;
  const newUser = {
    id: newId,
    username,
    email,
    role: role || 'user',
    secret: 'Welcome! Your account is ready.',
    password
  };
  users.push(newUser);
  res.status(201).json({
    message: 'User registered successfully',
    user: {
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      role: newUser.role
    },
    flag: newUser.role === 'admin' ? 'FLAG{PRIVILEGE_ESCALATION_REGISTER}' : null
  });
});

// ─── Auth helpers ────────────────────────────────────────────────

app.post('/api/auth/login', (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid username' });
  res.json({
    token: user.username,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    }
  });
});

app.get('/api/auth/me', (req, res) => {
  const user = getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });
  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role
  });
});

// ─── Static files ──────────────────────────────────────────────

app.use(express.static(path.join(__dirname, '../public')));

// ─── Health check ────────────────────────────────────────────────

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', challenges: 7 });
});

module.exports = app;
