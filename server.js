const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { randomUUID } = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('./db');
require('dotenv').config();
const { Expo } = require('expo-server-sdk');
const expo = new Expo();

// Send push notification to a user via their stored Expo push token
async function sendPushToUser(userId, title, body) {
  try {
    const tokenResult = await db.query('SELECT push_token FROM users WHERE user_id = $1', [userId]);
    const token = tokenResult.rows[0]?.push_token;
    if (!token || !Expo.isExpoPushToken(token)) return;
    await expo.sendPushNotificationsAsync([{ to: token, title, body, sound: 'default' }]);
  } catch (_) {}
}

const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (_req, res) => {
  res.status(200).json({
    success: true,
    message: 'HR backend is running.',
    health: '/health',
    apiBase: '/api/v1',
  });
});

app.get('/health', (_req, res) => {
  res.status(200).json({ success: true, status: 'ok' });
});

// Save / update Expo push token for a user
app.post('/api/v1/users/:userId/push-token', async (req, res) => {
  const { userId } = req.params;
  const { pushToken } = req.body;
  if (!pushToken) return res.status(400).json({ error: 'pushToken is required.' });
  try {
    await db.query('UPDATE users SET push_token = $1 WHERE user_id = $2', [pushToken, userId]);
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to save push token.', detail: error.message });
  }
});

function normalizeRole(role) {
  return String(role || '').trim().toLowerCase();
}

function isManagerialRole(role) {
  const normalized = normalizeRole(role);
  return normalized === 'manager' || normalized === 'account_manager' || normalized === 'hr';
}

function deriveNameFromEmail(email) {
  const local = (email || '').split('@')[0] || '';
  return local
    .split('.')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(' ');
}

async function getUsersTableColumns() {
  const result = await db.query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'users'`
  );
  return new Set(result.rows.map((row) => row.column_name));
}

async function getDefaultUserRole(preferredRole = 'staff') {
  const result = await db.query(
    `SELECT e.enumlabel
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     WHERE t.typname = 'rbac_role'
     ORDER BY e.enumsortorder ASC`
  );
  const labels = result.rows.map((r) => String(r.enumlabel || ''));
  const preferred = labels.find((label) => label.toLowerCase() === String(preferredRole).toLowerCase());
  return preferred || labels[0] || String(preferredRole);
}

async function ensureOperationalTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS project_assignments (
      assignment_id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      project_code TEXT NOT NULL REFERENCES projects(project_code) ON DELETE CASCADE,
      assigned_by UUID REFERENCES users(user_id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (user_id, project_code)
    );
  `);

  // Ensure password_hash column exists on users
  await db.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
  `);

  // Ensure email column exists for email/password auth
  await db.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
  `);

  // Notifications table
  await db.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      notification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Hour allocations table
  await db.query(`
    CREATE TABLE IF NOT EXISTS hour_allocations (
      allocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      project_code TEXT NOT NULL REFERENCES projects(project_code) ON DELETE CASCADE,
      hours_per_week NUMERIC(6,2) NOT NULL,
      allocated_by UUID REFERENCES users(user_id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await db.query(`ALTER TABLE hour_allocations ADD COLUMN IF NOT EXISTS manager_status TEXT NOT NULL DEFAULT 'APPROVED';`);
  await db.query(`ALTER TABLE hour_allocations ADD COLUMN IF NOT EXISTS account_manager_status TEXT NOT NULL DEFAULT 'PENDING';`);
  await db.query(`ALTER TABLE hour_allocations ADD COLUMN IF NOT EXISTS account_manager_reviewer_id UUID REFERENCES users(user_id);`);
  await db.query(`ALTER TABLE hour_allocations ADD COLUMN IF NOT EXISTS account_manager_reviewed_at TIMESTAMPTZ;`);

  // Projects: support multiple managers
  await db.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS manager_ids TEXT[] DEFAULT '{}';`);

  // Projects: status column
  await db.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE';`);

  // Account approval system
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'pending';`);
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;`);

  // Leave applications: ensure table and all columns exist
  await db.query(`
    CREATE TABLE IF NOT EXISTS leave_applications (
      leave_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      category TEXT NOT NULL,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      mc_file_url TEXT,
      is_late_submission BOOLEAN NOT NULL DEFAULT FALSE,
      reviewer_remarks TEXT,
      workflow_status TEXT NOT NULL DEFAULT 'PENDING',
      reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS mc_file_url TEXT;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS is_late_submission BOOLEAN NOT NULL DEFAULT FALSE;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reviewer_remarks TEXT;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS workflow_status TEXT NOT NULL DEFAULT 'PENDING';`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reason TEXT;`);

  // Ensure gen_random_uuid() defaults on primary key columns (in case tables were created externally without defaults)
  await db.query(`ALTER TABLE leave_applications ALTER COLUMN leave_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE notifications ALTER COLUMN notification_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE budget_requests ALTER COLUMN request_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE password_reset_requests ALTER COLUMN request_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS push_token TEXT;`);

  // Budget requests table
  await db.query(`
    CREATE TABLE IF NOT EXISTS budget_requests (
      request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      project_code TEXT NOT NULL REFERENCES projects(project_code) ON DELETE CASCADE,
      requested_hours NUMERIC(6,2) NOT NULL,
      justification TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'PENDING',
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      reviewed_by UUID REFERENCES users(user_id),
      reviewed_at TIMESTAMPTZ,
      reviewer_remarks TEXT
    );
  `);

  // Password reset requests table
  await db.query(`
    CREATE TABLE IF NOT EXISTS password_reset_requests (
      request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      email TEXT NOT NULL,
      new_password_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      reviewed_at TIMESTAMPTZ,
      reviewed_by UUID REFERENCES users(user_id)
    );
  `);
}

async function tableExists(tableName) {
  const result = await db.query('SELECT to_regclass($1) AS regclass', [tableName]);
  return !!result.rows?.[0]?.regclass;
}

async function applyDailyProgressBaselineForReporter(reporterId, projectCode = null) {
  if (!reporterId) return;

  const params = [reporterId];
  const projectFilter = projectCode ? 'AND ppl.project_code = $2' : '';
  if (projectCode) params.push(projectCode);

  const latestLogsQuery = `
    SELECT DISTINCT ON (ppl.project_code)
      ppl.project_code,
      ppl.reporter_id,
      ppl.completion_percentage,
      ppl.logged_at
    FROM project_progress_logs ppl
    WHERE ppl.reporter_id = $1
      ${projectFilter}
    ORDER BY ppl.project_code, ppl.logged_at DESC
  `;

  const latestLogs = await db.query(latestLogsQuery, params);

  for (const row of latestLogs.rows) {
    const lastPercent = Number(row.completion_percentage || 0);
    const daysSinceLastLog = Math.floor(
      (Date.now() - new Date(row.logged_at).getTime()) / (1000 * 60 * 60 * 24)
    );

    if (daysSinceLastLog <= 0 || lastPercent >= 100) {
      continue;
    }

    const incremented = Math.min(100, lastPercent + daysSinceLastLog * 10);
    if (incremented <= lastPercent) {
      continue;
    }

    await db.query(
      `INSERT INTO project_progress_logs
         (log_id, project_code, reporter_id, completion_percentage, progress_summary, logged_at)
       VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)`,
      [
        randomUUID(),
        row.project_code,
        row.reporter_id,
        incremented,
        'Auto-progress baseline applied (+10% per day).',
      ]
    );
  }
}

async function applyDailyProgressBaselineForManagerTeam(managerId) {
  const reporters = await db.query(
    `SELECT user_id FROM users WHERE supervisor_id = $1 OR user_id = $1`,
    [managerId]
  );

  for (const reporter of reporters.rows) {
    await applyDailyProgressBaselineForReporter(reporter.user_id);
  }
}

// ========================================================================
// ROUTE: EMAIL/PASSWORD SIGNUP
// ========================================================================
app.post('/api/v1/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const normalized = email.trim().toLowerCase();
  if (!normalized.endsWith('@nextan.com.sg')) {
    return res.status(403).json({ error: 'Only @nextan.com.sg emails are allowed.' });
  }
  try {
    const columns = await getUsersTableColumns();
    if (!columns.has('email')) {
      return res.status(500).json({ error: 'Users table is missing email column.' });
    }

    const existing = columns.has('email')
      ? (await db.query('SELECT user_id, full_name, user_role, email FROM users WHERE LOWER(email) = $1 LIMIT 1', [normalized])).rows[0]
      : null;

    if (existing) {
      return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
    }

    // Use role sent by the portal, fallback to 'staff'
    const requestedRole = String(req.body.userRole || 'staff').trim().toLowerCase();
    const allowedSignupRoles = ['manager', 'account_manager', 'hr', 'staff'];
    const signupRole = allowedSignupRoles.includes(requestedRole) ? requestedRole : 'staff';

    const passwordHash = await bcrypt.hash(password, 10);
    const userId = randomUUID();
    const fullName = deriveNameFromEmail(normalized);
    const resolvedRole = await getDefaultUserRole(signupRole);

    const insertCols = ['user_id', 'full_name', 'user_role', 'email', 'password_hash', 'account_status'];
    const insertVals = [userId, fullName, resolvedRole, normalized, passwordHash, 'pending'];
    if (columns.has('phone')) {
      insertCols.push('phone');
      insertVals.push('');
    }
    if (columns.has('home_office_country')) {
      insertCols.push('home_office_country');
      insertVals.push('SG');
    }

    const placeholders = insertVals.map((_, i) => `$${i + 1}`).join(', ');
    const result = await db.query(
      `INSERT INTO users (${insertCols.join(', ')}) VALUES (${placeholders}) RETURNING user_id, full_name, user_role, email`,
      insertVals
    );
    return res.status(201).json({
      success: true,
      pending: true,
      message: 'Account created. Awaiting admin approval before you can sign in.',
      data: result.rows[0],
    });
  } catch (error) {
    return res.status(500).json({ error: 'Signup failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: RESET PASSWORD REQUEST (queued for admin approval)
// ========================================================================
app.post('/api/v1/auth/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return res.status(400).json({ error: 'Email and newPassword are required.' });
  }
  const normalized = email.trim().toLowerCase();
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }

  try {
    const userRes = await db.query('SELECT user_id FROM users WHERE LOWER(email) = $1 LIMIT 1', [normalized]);
    const user = userRes.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'No account found for this email.' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    // Cancel any previous pending request for this user
    await db.query(`DELETE FROM password_reset_requests WHERE user_id = $1 AND status = 'pending'`, [user.user_id]);
    await db.query(
      `INSERT INTO password_reset_requests (request_id, user_id, email, new_password_hash) VALUES (gen_random_uuid(), $1, $2, $3)`,
      [user.user_id, normalized, hash]
    );
    return res.status(200).json({
      success: true,
      pending: true,
      message: 'Reset request submitted. An admin will approve it shortly.',
    });
  } catch (error) {
    return res.status(500).json({ error: 'Password reset request failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: EMAIL/PASSWORD LOGIN
// ========================================================================
app.post('/api/v1/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const normalized = email.trim().toLowerCase();
  try {
    const result = await db.query(
      'SELECT user_id, full_name, user_role, email, password_hash, account_status FROM users WHERE LOWER(email) = $1 LIMIT 1',
      [normalized]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'No account found for this email. Please sign up first.' });
    // Check approval status (allow null/missing = legacy active users)
    const status = String(user.account_status || 'active').toLowerCase();
    if (status === 'pending') {
      return res.status(403).json({ error: 'Your account is pending admin approval. Please wait for Rebecca Lau or hr.admin@nextan.com.sg to approve your account.' });
    }
    if (status === 'rejected') {
      return res.status(403).json({ error: 'Your account registration was not approved. Please contact hr.admin@nextan.com.sg.' });
    }
    if (!user.password_hash) {
      const hash = await bcrypt.hash(password, 10);
      await db.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [hash, user.user_id]);
    } else {
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) return res.status(401).json({ error: 'Incorrect password.' });
    }
    const { password_hash, account_status, ...safeUser } = user;
    safeUser.full_name = deriveNameFromEmail(normalized);
    return res.status(200).json({ success: true, data: safeUser });
  } catch (error) {
    return res.status(500).json({ error: 'Login failed.', detail: error.message });
  }
});

// ========================================================================
// ADMIN ROUTES (is_admin = true required)
// ========================================================================

// Helper: verify requester is admin
async function requireAdmin(adminId, res) {
  if (!adminId) { res.status(400).json({ error: 'adminId is required.' }); return false; }
  const r = await db.query('SELECT is_admin FROM users WHERE user_id = $1 LIMIT 1', [adminId]);
  if (!r.rows[0]?.is_admin) { res.status(403).json({ error: 'Admin access required.' }); return false; }
  return true;
}

// GET pending accounts
app.get('/api/v1/admin/pending-accounts', async (req, res) => {
  const { adminId } = req.query;
  if (!await requireAdmin(adminId, res)) return;
  try {
    const result = await db.query(
      `SELECT user_id, full_name, email, user_role, account_status, created_at
       FROM users
       WHERE account_status = 'pending'
       ORDER BY created_at ASC`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch pending accounts.', detail: err.message });
  }
});

// PATCH approve/reject account
app.patch('/api/v1/admin/approve-account', async (req, res) => {
  const { adminId, userId, action } = req.body; // action: 'approve' | 'reject'
  if (!await requireAdmin(adminId, res)) return;
  if (!userId || !['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: 'userId and action (approve|reject) are required.' });
  }
  try {
    const newStatus = action === 'approve' ? 'active' : 'rejected';
    await db.query('UPDATE users SET account_status = $1 WHERE user_id = $2', [newStatus, userId]);
    return res.status(200).json({ success: true, message: `Account ${newStatus}.` });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update account status.', detail: err.message });
  }
});

// GET pending password reset requests
app.get('/api/v1/admin/pending-resets', async (req, res) => {
  const { adminId } = req.query;
  if (!await requireAdmin(adminId, res)) return;
  try {
    const result = await db.query(
      `SELECT r.request_id, r.email, r.status, r.requested_at, u.full_name, u.user_role
       FROM password_reset_requests r
       JOIN users u ON u.user_id = r.user_id
       WHERE r.status = 'pending'
       ORDER BY r.requested_at ASC`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch pending resets.', detail: err.message });
  }
});

// PATCH approve/reject password reset
app.patch('/api/v1/admin/approve-reset', async (req, res) => {
  const { adminId, requestId, action } = req.body;
  if (!await requireAdmin(adminId, res)) return;
  if (!requestId || !['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: 'requestId and action (approve|reject) are required.' });
  }
  try {
    const reqRes = await db.query(
      `SELECT user_id, new_password_hash FROM password_reset_requests WHERE request_id = $1 AND status = 'pending' LIMIT 1`,
      [requestId]
    );
    const row = reqRes.rows[0];
    if (!row) return res.status(404).json({ error: 'Reset request not found or already processed.' });

    if (action === 'approve') {
      await db.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [row.new_password_hash, row.user_id]);
    }
    await db.query(
      `UPDATE password_reset_requests SET status = $1, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = $2 WHERE request_id = $3`,
      [action === 'approve' ? 'approved' : 'rejected', adminId, requestId]
    );
    return res.status(200).json({ success: true, message: `Password reset ${action === 'approve' ? 'approved' : 'rejected'}.` });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to process reset request.', detail: err.message });
  }
});

// GET account history (approved/rejected)
app.get('/api/v1/admin/account-history', async (req, res) => {
  const { adminId } = req.query;
  if (!await requireAdmin(adminId, res)) return;
  try {
    const result = await db.query(
      `SELECT user_id, full_name, email, user_role, account_status, created_at
       FROM users WHERE account_status IN ('active','rejected')
       ORDER BY created_at DESC LIMIT 100`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch account history.', detail: err.message });
  }
});

// GET reset history (approved/rejected)
app.get('/api/v1/admin/reset-history', async (req, res) => {
  const { adminId } = req.query;
  if (!await requireAdmin(adminId, res)) return;
  try {
    const result = await db.query(
      `SELECT r.request_id, r.email, r.status, r.requested_at, r.reviewed_at, u.full_name, u.user_role
       FROM password_reset_requests r JOIN users u ON u.user_id = r.user_id
       WHERE r.status IN ('approved','rejected')
       ORDER BY r.reviewed_at DESC LIMIT 100`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch reset history.', detail: err.message });
  }
});

// ========================================================================
// ROUTE: NOTIFICATIONS
// ========================================================================
app.get('/api/v1/notifications/:userId', async (req, res) => {
  try {
    const result = await db.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.params.userId]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch notifications.', detail: error.message });
  }
});

app.post('/api/v1/notifications', async (req, res) => {
  const { userId, title, body } = req.body;
  if (!userId || !title || !body) return res.status(400).json({ error: 'userId, title and body are required.' });
  try {
    const result = await db.query(
      'INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3) RETURNING *',
      [userId, title, body]
    );
    return res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to create notification.', detail: error.message });
  }
});

app.patch('/api/v1/notifications/:notifId/read', async (req, res) => {
  try {
    await db.query('UPDATE notifications SET is_read = TRUE WHERE notification_id = $1', [req.params.notifId]);
    return res.status(200).json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to mark notification read.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: HOUR ALLOCATIONS
// ========================================================================
app.post('/api/v1/allocations', async (req, res) => {
  const { managerId, userId, projectCode, hoursPerWeek } = req.body;
  if (!managerId || !userId || !projectCode || !hoursPerWeek) {
    return res.status(400).json({ error: 'managerId, userId, projectCode and hoursPerWeek are required.' });
  }
  const numericHours = Number(hoursPerWeek);
  if (!Number.isFinite(numericHours) || numericHours <= 0) {
    return res.status(400).json({ error: 'hoursPerWeek must be a valid positive number.' });
  }
  try {
    const mgrCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (!mgrCheck.rows[0] || !isManagerialRole(mgrCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Only managers can allocate hours.' });
    }
    const userRow = await db.query('SELECT user_id, full_name FROM users WHERE user_id = $1', [userId]);
    if (!userRow.rows[0]) return res.status(404).json({ error: 'Target user not found.' });

    const result = await db.query(
      `INSERT INTO hour_allocations (
         user_id, project_code, hours_per_week, allocated_by,
         manager_status, account_manager_status
       )
       VALUES ($1, $2, $3, $4, 'APPROVED', 'PENDING')
       RETURNING *`,
      [userId, projectCode, numericHours, managerId]
    );

    const mgrRow = await db.query('SELECT full_name FROM users WHERE user_id = $1', [managerId]);
    const mgrName = mgrRow.rows[0]?.full_name || 'Manager';
    await db.query(
      'INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)',
      [userId, 'Allocation Submitted', `${mgrName} submitted ${numericHours} hrs/week for ${projectCode}. Waiting for Account Manager approval.`]
    );

    return res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Allocation failed.', detail: error.message });
  }
});

app.get('/api/v1/allocations/pending-account-manager', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT
         ha.*,
         p.project_name,
         u.full_name AS staff_name,
         u.email AS staff_email,
         m.full_name AS manager_name,
         m.email AS manager_email
       FROM hour_allocations ha
       JOIN projects p ON p.project_code = ha.project_code
       JOIN users u ON u.user_id = ha.user_id
       LEFT JOIN users m ON m.user_id = ha.allocated_by
       WHERE ha.account_manager_status = 'PENDING'
       ORDER BY ha.created_at ASC`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch pending allocations.', detail: error.message });
  }
});

app.get('/api/v1/allocations/history-account-manager', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT
         ha.*,
         p.project_name,
         u.full_name AS staff_name,
         u.email AS staff_email,
         m.full_name AS manager_name,
         m.email AS manager_email
       FROM hour_allocations ha
       JOIN projects p ON p.project_code = ha.project_code
       JOIN users u ON u.user_id = ha.user_id
       LEFT JOIN users m ON m.user_id = ha.allocated_by
       WHERE ha.account_manager_status IN ('APPROVED','REJECTED')
       ORDER BY ha.account_manager_reviewed_at DESC NULLS LAST`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch allocation history.', detail: error.message });
  }
});

app.patch('/api/v1/allocations/:allocationId/account-manager-review', async (req, res) => {
  const { allocationId } = req.params;
  const { reviewerId, action } = req.body;
  const normalizedAction = String(action || '').toUpperCase();

  if (!reviewerId || !['APPROVED', 'REJECTED'].includes(normalizedAction)) {
    return res.status(400).json({ error: 'reviewerId and valid action (APPROVED/REJECTED) are required.' });
  }

  try {
    const reviewer = await db.query('SELECT user_role, full_name FROM users WHERE user_id = $1 LIMIT 1', [reviewerId]);
    if (!reviewer.rows[0]) {
      return res.status(404).json({ error: 'Reviewer not found.' });
    }

    const reviewerRole = normalizeRole(reviewer.rows[0].user_role);
    if (reviewerRole !== 'account_manager' && reviewerRole !== 'hr') {
      return res.status(403).json({ error: 'Only account managers can review allocation submissions.' });
    }

    const updated = await db.query(
      `UPDATE hour_allocations
       SET account_manager_status = $1,
           account_manager_reviewer_id = $2,
           account_manager_reviewed_at = CURRENT_TIMESTAMP
       WHERE allocation_id = $3
       RETURNING *`,
      [normalizedAction, reviewerId, allocationId]
    );

    if (!updated.rows[0]) {
      return res.status(404).json({ error: 'Allocation request not found.' });
    }

    const row = updated.rows[0];
    const reviewerName = reviewer.rows[0].full_name || 'Account Manager';
    const statusWord = normalizedAction === 'APPROVED' ? 'approved' : 'rejected';

    await db.query(
      'INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)',
      [row.user_id, `Allocation ${normalizedAction}`, `${reviewerName} ${statusWord} your allocation for ${row.project_code} (${row.hours_per_week} hrs/week).`]
    );

    if (row.allocated_by) {
      await db.query(
        'INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)',
        [row.allocated_by, `Allocation ${normalizedAction}`, `${reviewerName} ${statusWord} your allocation request for ${row.project_code}.`]
      );
    }

    return res.status(200).json({ success: true, data: row });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to review allocation.', detail: error.message });
  }
});

app.get('/api/v1/allocations/:userId', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT ha.*, p.project_name FROM hour_allocations ha
       JOIN projects p ON p.project_code = ha.project_code
       WHERE ha.user_id = $1
         AND ha.manager_status = 'APPROVED'
         AND ha.account_manager_status = 'APPROVED'
       ORDER BY ha.created_at DESC`,
      [req.params.userId]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch allocations.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: OUTLOOK LOGIN HANDSHAKE + USER UPSERT
// ========================================================================
app.post('/api/v1/auth/outlook-login', async (req, res) => {
  const { email, displayName } = req.body;

  if (!email || !email.toLowerCase().endsWith('@nextan.com.sg')) {
    return res.status(403).json({ error: 'Only @nextan.com.sg emails are allowed.' });
  }

  try {
    const columns = await getUsersTableColumns();

    let existing = null;
    if (columns.has('email')) {
      const lookup = await db.query(
        `SELECT user_id, full_name, user_role, supervisor_id${columns.has('email') ? ', email' : ''}${columns.has('phone') ? ', phone' : ''}
         FROM users
         WHERE LOWER(email) = LOWER($1)
         LIMIT 1`,
        [email]
      );
      existing = lookup.rows[0] || null;
    }

    if (existing) {
      return res.status(200).json({
        success: true,
        data: { ...existing, full_name: deriveNameFromEmail(email) },
      });
    }

    const fullName = (displayName && displayName.trim()) || deriveNameFromEmail(email);
    const userId = randomUUID();

    const insertCols = ['user_id', 'full_name', 'user_role'];
    const insertVals = [userId, fullName, await getDefaultUserRole('staff')];

    if (columns.has('email')) {
      insertCols.push('email');
      insertVals.push(email.toLowerCase());
    }
    if (columns.has('phone')) {
      insertCols.push('phone');
      insertVals.push('');
    }
    if (columns.has('home_office_country')) {
      insertCols.push('home_office_country');
      insertVals.push('SG');
    }

    const placeholders = insertVals.map((_, idx) => `$${idx + 1}`).join(', ');
    const result = await db.query(
      `INSERT INTO users (${insertCols.join(', ')})
       VALUES (${placeholders})
       RETURNING user_id, full_name, user_role, supervisor_id${columns.has('email') ? ', email' : ''}${columns.has('phone') ? ', phone' : ''}`,
      insertVals
    );

    return res.status(201).json({
      success: true,
      data: { ...result.rows[0], full_name: deriveNameFromEmail(email) },
    });
  } catch (error) {
    return res.status(500).json({ error: 'Outlook login synchronization failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: USER PROFILE READ / UPDATE
// ========================================================================
app.get('/api/v1/users/:userId/profile', async (req, res) => {
  const { userId } = req.params;

  try {
    const columns = await getUsersTableColumns();
    const result = await db.query(
      `SELECT user_id, full_name, user_role${columns.has('email') ? ', email' : ''}${columns.has('phone') ? ', phone' : ''}
       FROM users
       WHERE user_id = $1`,
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found.' });
    }

    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch user profile.', detail: error.message });
  }
});

app.patch('/api/v1/users/:userId/profile', async (req, res) => {
  const { userId } = req.params;
  const { phone } = req.body;

  try {
    const columns = await getUsersTableColumns();
    if (!columns.has('phone')) {
      return res.status(400).json({ error: 'Phone field is not available in users table.' });
    }

    const returningFields = ['user_id', 'full_name', 'user_role'];
    if (columns.has('email')) returningFields.push('email');
    if (columns.has('phone')) returningFields.push('phone');

    const result = await db.query(
      `UPDATE users SET phone = $1 WHERE user_id = $2 RETURNING ${returningFields.join(', ')}`,
      [phone || '', userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found.' });
    }

    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to update profile.', detail: error.message });
  }
});

// ========================================================================
// ========================================================================
// ROUTE: USER INBOX FEED (LEAVE + BUDGET + NOTIFICATIONS)
// ========================================================================
app.get('/api/v1/users/:userId/inbox', async (req, res) => {
  const { userId } = req.params;

  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    const budgetUnion = hasBudgetRequestsTable
      ? `
         UNION ALL

         SELECT
           'BUDGET' AS category,
           CASE br.status
             WHEN 'PENDING' THEN 'Budget request submitted'
             WHEN 'MANAGER_APPROVED' THEN 'Budget request approved by Manager'
             WHEN 'APPROVED' THEN 'Budget request fully approved'
             WHEN 'REJECTED' THEN 'Budget request rejected'
             ELSE CONCAT('Budget request ', br.status)
           END AS title,
           CONCAT(br.project_code, ' • ', br.requested_hours, ' hrs') AS subtitle,
           br.status AS status,
           br.created_at AS created_at
         FROM budget_requests br
         WHERE br.user_id = $1
      `
      : '';

    const result = await db.query(
      `SELECT * FROM (
         SELECT
           'LEAVE' AS category,
           CASE la.workflow_status::TEXT
             WHEN 'PENDING' THEN 'Leave request submitted'
             WHEN 'APPROVED' THEN 'Leave request approved'
             WHEN 'REJECTED' THEN 'Leave request rejected'
             ELSE CONCAT('Leave request ', la.workflow_status::TEXT)
           END AS title,
           CONCAT(la.category::TEXT, ' leave • ', TO_CHAR(la.start_date, 'DD Mon YYYY'), ' → ', TO_CHAR(la.end_date, 'DD Mon YYYY'), ' • ', CASE la.workflow_status::TEXT WHEN 'PENDING' THEN 'Pending manager approval' WHEN 'APPROVED' THEN 'Approved' WHEN 'REJECTED' THEN 'Rejected' ELSE la.workflow_status::TEXT END) AS subtitle,
           la.workflow_status::TEXT AS status,
           la.created_at AS created_at
         FROM leave_applications la
         WHERE la.user_id = $1
         ${budgetUnion}
         UNION ALL
         SELECT
           'NOTIFICATION' AS category,
           n.title AS title,
           n.body AS subtitle,
           CASE WHEN n.is_read THEN 'READ' ELSE 'UNREAD' END AS status,
           n.created_at AS created_at
         FROM notifications n
         WHERE n.user_id = $1
       ) q
       ORDER BY created_at DESC
       LIMIT 100`,
      [userId]
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch inbox feed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: FETCH USER LEAVE REQUEST HISTORY
// ========================================================================
app.get('/api/v1/leave/my-requests/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    const result = await db.query(
      `SELECT leave_id, category, start_date, end_date, workflow_status, reviewer_remarks, created_at
       FROM leave_applications
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId]
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch leave requests.', detail: error.message });
  }
});

// ========================================================================
// CORE UTILITY: AUDIT INTERCEPTOR (Void-and-Replace)
// ========================================================================
async function auditInterceptor(tableName, recordId, userId, postValue) {
    try {
        // Determine the correct ID column based on table
        const idCol = tableName === 'projects'
          ? 'project_code'
          : tableName === 'leave_applications'
            ? 'leave_id'
            : tableName === 'budget_requests'
              ? 'request_id'
              : 'id';
        const oldRecord = await db.query(`SELECT * FROM ${tableName} WHERE ${idCol} = $1`, [recordId]);
        
        // NOTE: audit_logs.pre_value and audit_logs.post_value should be JSONB in PostgreSQL
        await db.query(
            'INSERT INTO audit_logs (table_name, record_id, altered_by, pre_value, post_value, created_at) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)',
            [tableName, recordId.toString(), userId, JSON.stringify(oldRecord.rows[0]), JSON.stringify(postValue)]
        );
    } catch (err) {
        console.error("Audit Interceptor Failure:", err.message);
    }
}

// ========================================================================
// HELPER: GEOSPATIAL REVERSE GEOCODING WORKER
// ========================================================================
async function resolveGeospatialMetrics(lat, lng, homeCountry) {
  try {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    
    if (!apiKey || apiKey === '' || apiKey.startsWith('YOUR_')) {
      throw new Error('Google Maps API key is unconfigured or invalid.');
    }

    const url = `https://maps.googleapis.com/maps/api/geocode/json?latlng=${lat},${lng}&key=${apiKey}`;
    const response = await axios.get(url);
    
    if (response.data.status && response.data.status !== "OK") {
      throw new Error(`Google API Status Error: ${response.data.status} - ${response.data.error_message || 'Check credentials'}`);
    }
    
    if (!response.data.results || response.data.results.length === 0) {
      throw new Error('Geocoding engine returned no results');
    }

    const firstResult = response.data.results[0];
    const locationName = firstResult.formatted_address;
    let countryCode = homeCountry;

    for (const component of firstResult.address_components) {
      if (component.types.includes('country')) {
        countryCode = component.short_name;
        break;
      }
    }

    const home = homeCountry.toUpperCase();
    const current = countryCode.toUpperCase();
    const isDomestic = home.startsWith(current) || current.startsWith(home);

    const travelMode = isDomestic ? 'DOMESTIC_ATTENDANCE' : 'OVERSEAS_ATTENDANCE';

    return { locationName, countryCode, travelMode };
  } catch (error) {
    console.error('Spatial Geocoding Live Engine Warning:', error.message);
    return {
      locationName: 'Kuala Lumpur, Malaysia (Local Network Test)',
      countryCode: homeCountry,
      travelMode: 'DOMESTIC_ATTENDANCE'
    };
  }
}

// ========================================================================
// ROUTE: PRE-FETCH LIVE ADDRESS NAME
// ========================================================================
app.post('/api/v1/attendance/pre-fetch-address', async (req, res) => {
  const { latitude, longitude } = req.body;

  if (!latitude || !longitude) {
    return res.status(400).json({ error: "Missing latitude or longitude parameters." });
  }

  try {
    const geoData = await resolveGeospatialMetrics(latitude, longitude, 'MY'); 
    res.status(200).json({
      success: true,
      locationName: geoData.locationName
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to resolve preview address", detail: error.message });
  }
});

// ========================================================================
// ROUTE: CLOCK-IN ENDPOINT 
// ========================================================================
app.post('/api/v1/attendance/clock-in', async (req, res) => {
  const { userId, projectCode, latitude, longitude, isManualLocation, manualLocationText } = req.body;

  try {
    const userProfile = await db.query('SELECT home_office_country FROM users WHERE user_id = $1', [userId]);
    if (userProfile.rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }
    
    const homeCountry = userProfile.rows[0].home_office_country;
    let locationName = manualLocationText || 'Kuala Lumpur, Malaysia (Local Network Test)';
    let countryCode = homeCountry;
    let travelMode = 'DOMESTIC_ATTENDANCE';

    if (!isManualLocation && latitude && longitude) {
      const geoData = await resolveGeospatialMetrics(latitude, longitude, homeCountry);
      locationName = geoData.locationName;
      countryCode = geoData.countryCode;
      travelMode = geoData.travelMode;
    }

    const insertQuery = `
      INSERT INTO attendance_logs (
        attendance_id, user_id, project_code, clock_in_time, raw_coordinates, 
        location_name, country_code, is_manual_location, travel_mode, status, created_at
      ) VALUES (
        $1, $2, $3, CURRENT_TIMESTAMP, 
        CASE WHEN $4::numeric IS NOT NULL AND $5::numeric IS NOT NULL 
             THEN ST_SetSRID(ST_MakePoint($5::numeric, $4::numeric), 4326) ELSE NULL END, 
        $6, $7, $8, $9, 'ACTIVE', CURRENT_TIMESTAMP
      ) RETURNING *;
    `;

    const result = await db.query(insertQuery, [
      randomUUID(), userId, projectCode, latitude, longitude, locationName, countryCode, isManualLocation || false, travelMode
    ]);

    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    console.error("Database Insert Failure Error Detail:", error.message);
    res.status(500).json({ error: 'Clock-In transaction failure', detail: error.message });
  }
});

// ========================================================================
// ROUTE: CLOCK-OUT ENDPOINT 
// ========================================================================
app.post('/api/v1/attendance/clock-out', async (req, res) => {
  const { userId, attendanceId } = req.body;

  try {
    const logCheck = await db.query(
      "SELECT clock_in_time FROM attendance_logs WHERE attendance_id = $1 AND user_id = $2",
      [attendanceId, userId]
    );

    if (logCheck.rows.length === 0) {
      return res.status(404).json({ error: 'No active clock-in entry found matching your device session state.' });
    }

    const updateQuery = `
      WITH TimeCalculations AS (
        SELECT 
          attendance_id,
          clock_in_time,
          CURRENT_TIMESTAMP AS current_out,
          EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - clock_in_time)) / 3600 AS raw_hours,
          EXTRACT(HOUR FROM CURRENT_TIMESTAMP) AS out_hour
        FROM attendance_logs
        WHERE attendance_id = $1
      )
      UPDATE attendance_logs
      SET 
        clock_out_time = TC.current_out,
        daily_worktime_hours = CASE 
          WHEN TC.raw_hours > 1.00 THEN ROUND((TC.raw_hours - 1.00)::numeric, 2)
          ELSE ROUND(TC.raw_hours::numeric, 2)
        END,
        ot_hours_accrued = CASE 
          WHEN TC.raw_hours > 9.50 AND TC.out_hour >= 18 THEN ROUND((TC.raw_hours - 9.50)::numeric, 2)
          ELSE 0.00
        END
      FROM TimeCalculations TC
      WHERE attendance_logs.attendance_id = $1
      RETURNING attendance_logs.attendance_id, attendance_logs.daily_worktime_hours, attendance_logs.ot_hours_accrued;
    `;

    const result = await db.query(updateQuery, [attendanceId]);
    res.status(200).json({ success: true, data: result.rows[0] });

  } catch (error) {
    res.status(500).json({ error: 'Clock-Out transaction failure', detail: error.message });
  }
});

// ========================================================================
// ROUTE: HIDDEN HOURLY LOCATION TRACKING (EMPLOYEE-FACING UI NOT USED)
// ========================================================================
app.post('/api/v1/attendance/track-location', async (req, res) => {
  const { userId, attendanceId, latitude, longitude, locationName } = req.body;

  if (!userId || !attendanceId) {
    return res.status(400).json({ error: 'Missing userId or attendanceId for location telemetry.' });
  }

  try {
    const updateQuery = `
      UPDATE attendance_logs
      SET
        raw_coordinates = CASE
          WHEN $3::numeric IS NOT NULL AND $4::numeric IS NOT NULL
          THEN ST_SetSRID(ST_MakePoint($4::numeric, $3::numeric), 4326)
          ELSE raw_coordinates
        END,
        location_name = COALESCE($5, location_name)
      WHERE attendance_id = $1 AND user_id = $2
      RETURNING attendance_id;
    `;

    const result = await db.query(updateQuery, [attendanceId, userId, latitude, longitude, locationName || null]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No matching attendance session found for telemetry update.' });
    }

    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Location tracking update failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: HR REGISTER NEW PROJECT CODE & STRUCTURAL ASSIGNMENTS 
// ========================================================================
app.post('/api/v1/hr/projects/create', async (req, res) => {
  const { hrUserId, projectCode, projectName, accountManagerId } = req.body;

  try {
    // RBAC Check: Ensure requesting client belongs to HR classification rules
    const hrCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [hrUserId]);
    if (hrCheck.rows.length === 0 || normalizeRole(hrCheck.rows[0].user_role) !== 'hr') {
      return res.status(403).json({ error: "Access Denied: Only HR personnel can issue new project configurations." });
    }

    // Verify assigned Account Manager exists in database before establishing link
    const amCheck = await db.query("SELECT user_role FROM users WHERE user_id = $1", [accountManagerId]);
    if (amCheck.rows.length === 0 || normalizeRole(amCheck.rows[0].user_role) !== 'account_manager') {
      return res.status(400).json({ error: "Validation Error: Assigned Account Manager must hold an ACCOUNT_MANAGER system profile role." });
    }

    const insertProjectQuery = `
      INSERT INTO projects (project_code, project_name, account_manager_id, budget_hours, total_tracked_hours, created_at)
      VALUES ($1, $2, $3, 0.00, 0.00, CURRENT_TIMESTAMP)
      RETURNING *;
    `;

    const result = await db.query(insertProjectQuery, [projectCode.toUpperCase().trim(), projectName.trim(), accountManagerId]);
    res.status(201).json({ success: true, message: "Project created. Budget allocation pending Account Manager signoff.", data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'HR Pipeline execution error.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: ACCOUNT MANAGER HOURS ALLOCATION & BUDGET CONTROL 
// ========================================================================
app.patch('/api/v1/account-manager/projects/allocate-budget', async (req, res) => {
  const { accountManagerId, projectCode, additionalHours } = req.body;
  const hoursNum = parseFloat(additionalHours);

  if (!accountManagerId || !projectCode || isNaN(hoursNum) || hoursNum <= 0) {
    return res.status(400).json({ error: "Validation Failure: accountManagerId, projectCode, and a positive additionalHours value are required." });
  }

  try {
    const projectCheck = await db.query('SELECT account_manager_id FROM projects WHERE project_code = $1', [projectCode]);
    if (projectCheck.rows.length === 0) {
      return res.status(404).json({ error: `Project reference lookup failed for code: ${projectCode}` });
    }

    if (projectCheck.rows[0].account_manager_id !== accountManagerId) {
      return res.status(403).json({ error: "Access Denied: You are not designated as the Account Manager managing this project matrix." });
    }

    const updateBudgetHoursQuery = `
      UPDATE projects 
      SET budget_hours = budget_hours + $1 
      WHERE project_code = $2 
      RETURNING *;
    `;

    const result = await db.query(updateBudgetHoursQuery, [hoursNum, projectCode]);
    const updatedProject = result.rows[0];

    await auditInterceptor('projects', projectCode, accountManagerId, updatedProject);

    res.status(200).json({ success: true, message: "Project resource budget updated successfully.", data: updatedProject });
  } catch (error) {
    res.status(500).json({ error: 'Budget engine adjustment transaction failure.', detail: error.message });
  }
});

// NEW: BUDGET REQUEST WORKFLOW
app.post('/api/v1/projects/budget-request', async (req, res) => {
  const { userId, projectCode, requestedHours, justification } = req.body;
  const requestedNumber = parseFloat(requestedHours);

  if (!userId || !projectCode || isNaN(requestedNumber) || requestedNumber <= 0) {
    return res.status(400).json({ error: 'Validation Failure: userId, projectCode, and a positive requestedHours value are required.' });
  }

  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(503).json({ error: 'budget_requests table is not initialized in this environment.' });
    }

    const projectCheck = await db.query('SELECT project_code FROM projects WHERE project_code = $1', [projectCode]);
    if (projectCheck.rows.length === 0) {
      return res.status(404).json({ error: `Project reference lookup failed for code: ${projectCode}` });
    }

    const result = await db.query(
      'INSERT INTO budget_requests (request_id, user_id, project_code, requested_hours, justification, status, created_at) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, CURRENT_TIMESTAMP) RETURNING *',
      [userId, projectCode, requestedNumber, justification || null, 'PENDING']
    );

    // Notify the requester
    try {
      const notifTitle = 'Hours Request Submitted';
      const notifBody = `You have just requested for additional hours of ${requestedNumber}hrs for project ${projectCode}. It will be reviewed by your manager and account manager.`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [userId, notifTitle, notifBody]);
      await sendPushToUser(userId, notifTitle, notifBody);
    } catch (_) {}

    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Budget request submission failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: FETCH MANAGER'S DIRECT TEAM PENDING LEAVE REQUESTS 
// ========================================================================
// GET all leave (not just pending) for history view
app.get('/api/v1/manager/:supervisorId/leave-all', async (req, res) => {
  const { supervisorId } = req.params;
  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [supervisorId]);
    if (managerCheck.rows.length === 0 || normalizeRole(managerCheck.rows[0].user_role) === 'staff') {
      return res.status(403).json({ error: 'Unauthorized.' });
    }
    const result = await db.query(
      `SELECT la.leave_id, la.user_id, u.full_name, la.category, la.start_date, la.end_date,
              la.workflow_status, la.reviewer_remarks, la.is_late_submission
       FROM leave_applications la
       JOIN users u ON la.user_id = u.user_id
       WHERE (u.supervisor_id = $1 OR la.workflow_status != 'PENDING')
         AND la.workflow_status != 'PENDING'
       ORDER BY la.created_at DESC`,
      [supervisorId]
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch leave history.', detail: error.message });
  }
});

app.get('/api/v1/manager/:supervisorId/leave-pending', async (req, res) => {
  const { supervisorId } = req.params;

  try {
    // Assert reviewer is a manager
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [supervisorId]);
    if (managerCheck.rows.length === 0 || normalizeRole(managerCheck.rows[0].user_role) === 'staff') {
      return res.status(403).json({ error: "Unauthorized access path." });
    }

    const fetchPendingQuery = `
      SELECT la.leave_id, la.user_id, u.full_name, la.category, la.start_date, la.end_date, la.is_late_submission, la.workflow_status
      FROM leave_applications la
      JOIN users u ON la.user_id = u.user_id
      WHERE u.supervisor_id = $1 AND la.workflow_status = 'PENDING'
      ORDER BY la.created_at ASC;
    `;

    const result = await db.query(fetchPendingQuery, [supervisorId]);
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch manager pending records.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: SUBMIT LEAVE REQUEST (Staff Interface Core Endpoint) 
// ========================================================================
app.post('/api/v1/leave/apply', async (req, res) => {
  const { userId, category, startDate, endDate, mcFileUrl, reason } = req.body;

  const validCategories = ['ANNUAL', 'EMERGENCY', 'SICK'];
  if (!validCategories.includes(category?.toUpperCase())) {
    return res.status(400).json({ error: "Invalid category. Must be 'ANNUAL', 'EMERGENCY', or 'SICK'." });
  }

  try {
    const leaveStartTimestamp = new Date(startDate);
    const currentTimestamp = new Date();
    const hoursPastStart = (currentTimestamp.getTime() - leaveStartTimestamp.getTime()) / (1000 * 60 * 60);
    const isLateSubmission = hoursPastStart > 24;

    const leaveInsertQuery = `
      INSERT INTO leave_applications (
        leave_id, user_id, category, start_date, end_date, mc_file_url, is_late_submission, workflow_status, reviewer_remarks, reason, created_at
      ) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'PENDING', NULL, $7, CURRENT_TIMESTAMP)
      RETURNING leave_id, user_id, category, start_date, end_date, is_late_submission, workflow_status;
    `;

    const result = await db.query(leaveInsertQuery, [
      userId, category.toUpperCase(), startDate, endDate,
      category.toUpperCase() === 'SICK' ? mcFileUrl : null,
      isLateSubmission, reason || null
    ]);

    // Notify the requester
    try {
      const notifTitle = 'Leave Request Submitted';
      const notifBody = `You have just submitted a ${category.toLowerCase()} leave request from ${startDate} to ${endDate}. It is pending manager review.`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [userId, notifTitle, notifBody]);
      await sendPushToUser(userId, notifTitle, notifBody);
    } catch (_) {}

    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Internal server state processing breakdown processing your request.', detail: error.message });
  }
});

// ========================================================================
// ========================================================================
// ROUTE: LEAVE BALANCE FOR A USER
// ========================================================================
app.get('/api/v1/leave/balance/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await db.query(
      `SELECT COALESCE(SUM(end_date - start_date + 1), 0) AS used_days
       FROM leave_applications
       WHERE user_id = $1
         AND category::TEXT IN ('ANNUAL', 'EMERGENCY')
         AND workflow_status::TEXT = 'APPROVED'`,
      [userId]
    );
    const usedDays = parseInt(result.rows[0]?.used_days || 0);
    const totalDays = 12;
    const remainingDays = Math.max(0, totalDays - usedDays);
    return res.status(200).json({ success: true, data: { totalDays, usedDays, remainingDays } });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to calculate leave balance.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: UNIFIED LEAVE WORKFLOW REVIEW (Manager Restrictions Enforced) 
// ========================================================================
// PATCH /api/v1/leave/re-review - re-review an already-reviewed leave request
app.patch('/api/v1/leave/re-review', async (req, res) => {
  const { leaveId, reviewerId, action, reviewerRemarks } = req.body;
  const validActions = ['APPROVED', 'REJECTED'];
  if (!validActions.includes(action?.toUpperCase())) {
    return res.status(400).json({ error: 'Invalid action. Must be APPROVED or REJECTED.' });
  }
  try {
    const reviewerProfile = await db.query('SELECT user_role FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
    const role = normalizeRole(reviewerProfile.rows[0].user_role);
    if (role === 'staff') return res.status(403).json({ error: 'Staff users cannot review leave.' });
    const result = await db.query(
      `UPDATE leave_applications SET workflow_status = $1, reviewer_remarks = $2 WHERE leave_id = $3 RETURNING *`,
      [action.toUpperCase(), reviewerRemarks || '', leaveId]
    );
    const updated = result.rows[0];
    if (!updated) return res.status(404).json({ error: 'Leave request not found.' });
    try {
      const notifTitle = action.toUpperCase() === 'APPROVED' ? 'Leave Decision Updated (Approved)' : 'Leave Decision Updated (Rejected)';
      const notifBody = `Your leave request has been re-reviewed and is now ${action.toLowerCase()}${reviewerRemarks ? ': ' + reviewerRemarks : '.'}`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [updated.user_id, notifTitle, notifBody]);
    } catch (_) {}
    res.status(200).json({ success: true, data: updated });
  } catch (error) {
    res.status(500).json({ error: 'Re-review failed.', detail: error.message });
  }
});

app.patch('/api/v1/leave/review', async (req, res) => {
  const { leaveId, reviewerId, action, reviewerRemarks } = req.body;

  const approvedActions = ['APPROVED', 'REJECTED', 'FORWARD_TO_ACCOUNT_MANAGER'];
  if (!approvedActions.includes(action?.toUpperCase())) {
    return res.status(400).json({ error: "Invalid review action." });
  }

  try {
    const reviewerProfile = await db.query('SELECT user_role FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) {
      return res.status(404).json({ error: 'Reviewer profile not found in system directory.' });
    }

    const role = normalizeRole(reviewerProfile.rows[0].user_role);

    // Strict Rule Boundary: HR users and Staff members are blocked from approving leave logs
    if (role === 'hr' || role === 'staff') {
      return res.status(403).json({ error: `Access Denied: Users holding a ${role} profile cannot process workflow leave decisions.` });
    }

    // Verify the leave belongs to a staff member in this manager's team
    const ownershipCheck = await db.query(
      `SELECT la.leave_id FROM leave_applications la
       JOIN users u ON la.user_id = u.user_id
       WHERE la.leave_id = $1 AND u.supervisor_id = $2`,
      [leaveId, reviewerId]
    );
    if (ownershipCheck.rows.length === 0) {
      return res.status(403).json({ error: 'This leave request does not belong to a member of your team. Use the Approvals page to manage it, or first add this staff member to your team via My Team on the Dashboard.' });
    }

   const reviewQuery = `
      UPDATE leave_applications
      SET workflow_status = $1, reviewer_remarks = $2
      WHERE leave_id = $3 AND workflow_status = 'PENDING'
      RETURNING *;
    `;

    const result = await db.query(reviewQuery, [action.toUpperCase(), reviewerRemarks || 'Processed via Manager Dashboard.', leaveId]);
    const updatedLeave = result.rows[0];

    if (!updatedLeave) {
      return res.status(404).json({ error: 'No pending leave request found or it has already been processed.' });
    }

    await auditInterceptor('leave_applications', leaveId, reviewerId, updatedLeave);

    // Notify the leave applicant
    try {
      const startStr = updatedLeave.start_date
        ? new Date(updatedLeave.start_date).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
        : '';
      const endStr = updatedLeave.end_date
        ? new Date(updatedLeave.end_date).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
        : '';
      const category = updatedLeave.category || 'ANNUAL';
      const hasCustomRemark = reviewerRemarks && reviewerRemarks !== 'Processed via Manager Dashboard.';
      const notifTitle = action.toUpperCase() === 'APPROVED' ? 'Leave Application Approved' : 'Leave Application Rejected';
      const notifBody = action.toUpperCase() === 'APPROVED'
        ? `${category} • ${startStr} → ${endStr} • Approved${hasCustomRemark ? '\nNote: ' + reviewerRemarks : ''}`
        : `${category} • ${startStr} → ${endStr} • Rejected${hasCustomRemark ? '\nReason: ' + reviewerRemarks : ''}`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [updatedLeave.user_id, notifTitle, notifBody]);
      await sendPushToUser(updatedLeave.user_id, notifTitle, notifBody);
    } catch (_) {}

    res.status(200).json({ success: true, message: `Workflow state updated successfully.`, data: updatedLeave });
  } catch (error) {
  // This will print the exact line and file that is failing
  console.error("--- CRITICAL ERROR ---");
  console.error(error); 
  res.status(500).json({ error: 'Internal system routing execution breakdown.', detail: error.message });
}
});

// ========================================================================
// ROUTE: PROJECT PROGRESS UPDATE ENDPOINT 
// ========================================================================
app.post('/api/v1/projects/progress-log', async (req, res) => {
  const { projectCode, reporterId, completionPercentage, progressSummary } = req.body;

  const percentage = parseFloat(completionPercentage);
  if (isNaN(percentage) || percentage < 0 || percentage > 100) {
    return res.status(400).json({ error: "Validation Exception: metrics must sit strictly between 0.00% and 100.00%." });
  }

  try {
    const projectCheck = await db.query('SELECT project_code FROM projects WHERE project_code = $1', [projectCode]);
    if (projectCheck.rows.length === 0) {
      return res.status(404).json({ error: `Routing Error: Project with code '${projectCode}' does not exist.` });
    }

    await applyDailyProgressBaselineForReporter(reporterId, projectCode);

    const latestProgress = await db.query(
      `SELECT completion_percentage
       FROM project_progress_logs
       WHERE project_code = $1 AND reporter_id = $2
       ORDER BY logged_at DESC
       LIMIT 1`,
      [projectCode, reporterId]
    );

    const baseline = latestProgress.rows.length > 0 ? Number(latestProgress.rows[0].completion_percentage || 0) : 0;
    const effectivePercentage = Math.max(percentage, baseline);

    const insertLogQuery = `
      INSERT INTO project_progress_logs (log_id, project_code, reporter_id, completion_percentage, progress_summary, logged_at)
      VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
      RETURNING log_id, project_code, completion_percentage, progress_summary, logged_at;
    `;

    const result = await db.query(insertLogQuery, [randomUUID(), projectCode, reporterId, effectivePercentage, progressSummary]);
    res.status(201).json({
      success: true,
      message: "Project log entered successfully.",
      data: result.rows[0],
      baselineApplied: baseline,
      effectiveCompletionPercentage: effectivePercentage,
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal pipeline transaction block failure.', detail: error.message });
  }
});

// FETCH ACTIVE PROJECT LIST FOR A USER
app.get('/api/v1/projects/active-list', async (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res.status(400).json({ error: 'userId query parameter is required.' });
  }

  try {
    const userRoleResult = await db.query(
      `SELECT user_role FROM users WHERE user_id = $1 LIMIT 1`,
      [userId]
    );

    if (userRoleResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const normalizedRole = normalizeRole(userRoleResult.rows[0].user_role);

    if (isManagerialRole(normalizedRole)) {
      const managerialProjects = await db.query(
        `SELECT
           p.project_code,
           p.project_name,
           p.account_manager_id,
           p.budget_hours,
           p.total_tracked_hours,
           p.created_at,
           CASE WHEN p.account_manager_id = $1 THEN true ELSE false END AS is_assigned_manager,
           false AS is_direct_assignment
         FROM projects p
         ORDER BY p.project_code ASC`,
        [userId]
      );

      return res.status(200).json({ success: true, data: managerialProjects.rows });
    }

    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    const budgetRequestsClause = hasBudgetRequestsTable
      ? `OR EXISTS (
            SELECT 1
            FROM budget_requests br
            WHERE br.user_id = $1
              AND br.project_code = p.project_code
          )`
      : '';

    const result = await db.query(
      `SELECT
         p.project_code,
         p.project_name,
         p.account_manager_id,
         p.budget_hours,
         p.total_tracked_hours,
         p.created_at,
         CASE WHEN p.account_manager_id = $1 THEN true ELSE false END AS is_assigned_manager,
         CASE WHEN pa.assignment_id IS NOT NULL THEN true ELSE false END AS is_direct_assignment
       FROM projects p
       LEFT JOIN project_assignments pa
         ON pa.project_code = p.project_code
        AND pa.user_id = $1
       WHERE pa.assignment_id IS NOT NULL
          ${budgetRequestsClause}
       ORDER BY p.project_code ASC`,
      [userId]
    );

    if (result.rows.length > 0) {
      return res.status(200).json({ success: true, data: result.rows });
    }

    const fallbackResult = await db.query(
      `SELECT
         project_code,
         project_name,
         account_manager_id,
         budget_hours,
         total_tracked_hours,
         created_at,
         false AS is_assigned_manager,
         false AS is_direct_assignment
       FROM projects
       ORDER BY project_code ASC`
    );

    return res.status(200).json({ success: true, data: fallbackResult.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch active projects.', detail: error.message });
  }
});

// FETCH PROGRESS HISTORY FOR A USER
app.get('/api/v1/projects/progress-history/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    await applyDailyProgressBaselineForReporter(userId);

    const result = await db.query(
      `SELECT
         ppl.log_id,
         ppl.project_code,
         p.project_name,
         ppl.completion_percentage,
         ppl.progress_summary,
         ppl.logged_at,
         ppl.reporter_id
       FROM project_progress_logs ppl
       LEFT JOIN projects p ON p.project_code = ppl.project_code
       WHERE ppl.reporter_id = $1
       ORDER BY ppl.logged_at DESC
       LIMIT 200`,
      [userId]
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch progress history.', detail: error.message });
  }
});

app.post('/api/v1/projects/progress-baseline/apply', async (req, res) => {
  const { userId, managerId } = req.body || {};

  if (!userId && !managerId) {
    return res.status(400).json({ error: 'Either userId or managerId is required.' });
  }

  try {
    if (userId) {
      await applyDailyProgressBaselineForReporter(userId);
      return res.status(200).json({ success: true, scope: 'user', userId });
    }

    await applyDailyProgressBaselineForManagerTeam(managerId);
    return res.status(200).json({ success: true, scope: 'manager', managerId });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to apply progress baseline.', detail: error.message });
  }
});

// FETCH ALL PROJECTS AND CODES
app.get('/api/v1/projects', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT p.project_code, p.project_name, p.account_manager_id, p.manager_ids,
             p.budget_hours, p.total_tracked_hours, p.status,
             u.full_name AS account_manager_name
      FROM projects p
      LEFT JOIN users u ON u.user_id = p.account_manager_id
      ORDER BY p.project_code ASC
    `);
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch project codes.', detail: error.message });
  }
});

app.get('/api/v1/projects/suggestions', async (req, res) => {
  const query = `%${(req.query.q || '').trim()}%`;
  try {
    const result = await db.query(
      'SELECT project_code, project_name FROM projects WHERE project_code ILIKE $1 OR project_name ILIKE $1 ORDER BY project_code ASC LIMIT 20',
      [query]
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch project suggestions.', detail: error.message });
  }
});

app.post('/api/v1/projects/create', async (req, res) => {
  const { creatorId, projectCode, projectName, accountManagerId, managerIds, budgetHours } = req.body;

  if (!creatorId || !projectCode || !projectName) {
    return res.status(400).json({ error: 'creatorId, projectCode and projectName are required.' });
  }

  try {
    const creatorCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [creatorId]);
    if (creatorCheck.rows.length === 0 || normalizeRole(creatorCheck.rows[0].user_role) === 'staff') {
      return res.status(403).json({ error: 'Access Denied: Only authorized HR or manager users may issue new project codes.' });
    }

    const primaryManager = (Array.isArray(managerIds) && managerIds.length > 0) ? managerIds[0] : (accountManagerId || creatorId);
    const allManagerIds = Array.isArray(managerIds) && managerIds.length > 0 ? managerIds : [primaryManager];

    const insertResult = await db.query(
      `INSERT INTO projects (project_code, project_name, account_manager_id, manager_ids, budget_hours, total_tracked_hours, created_at)
       VALUES ($1, $2, $3, $4, $5, 0.00, CURRENT_TIMESTAMP)
       RETURNING *;`,
      [projectCode.toUpperCase().trim(), projectName.trim(), primaryManager, allManagerIds, parseFloat(budgetHours) || 0]
    );

    res.status(201).json({ success: true, data: insertResult.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create project code.', detail: error.message });
  }
});

// PATCH /api/v1/projects/:projectCode - edit an existing project
app.patch('/api/v1/projects/:projectCode', async (req, res) => {
  const { projectCode } = req.params;
  const { projectName, managerIds, budgetHours, editorId } = req.body;
  if (!editorId) return res.status(400).json({ error: 'editorId is required.' });
  try {
    const editorCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || normalizeRole(editorCheck.rows[0].user_role) === 'staff') {
      return res.status(403).json({ error: 'Access Denied.' });
    }
    const updates = [];
    const values = [];
    let idx = 1;
    if (projectName !== undefined) { updates.push(`project_name = $${idx++}`); values.push(projectName.trim()); }
    if (budgetHours !== undefined) { updates.push(`budget_hours = $${idx++}`); values.push(parseFloat(budgetHours) || 0); }
    if (Array.isArray(managerIds) && managerIds.length > 0) {
      updates.push(`account_manager_id = $${idx++}`); values.push(managerIds[0]);
      updates.push(`manager_ids = $${idx++}`); values.push(managerIds);
    }
    if (updates.length === 0) return res.status(400).json({ error: 'No fields to update.' });
    values.push(projectCode.toUpperCase().trim());
    const result = await db.query(
      `UPDATE projects SET ${updates.join(', ')} WHERE project_code = $${idx} RETURNING *`,
      values
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update project.', detail: error.message });
  }
});

// DELETE /api/v1/projects/:projectCode - delete a project (HR/manager only)
app.delete('/api/v1/projects/:projectCode', async (req, res) => {
  const { projectCode } = req.params;
  const { editorId } = req.body;
  if (!editorId) return res.status(400).json({ error: 'editorId is required.' });
  try {
    const editorCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || normalizeRole(editorCheck.rows[0].user_role) === 'staff') {
      return res.status(403).json({ error: 'Access Denied.' });
    }
    await db.query('DELETE FROM projects WHERE project_code = $1', [projectCode.toUpperCase().trim()]);
    res.status(200).json({ success: true, message: `Project ${projectCode} deleted.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete project.', detail: error.message });
  }
});

// FETCH ALL PENDING BUDGET REQUESTS
app.get('/api/v1/projects/budget-requests', async (req, res) => {
  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(200).json({ success: true, data: [] });
    }

    const result = await db.query(
      `SELECT br.*, p.project_name, u.full_name AS requester_name, u.email AS requester_email
       FROM budget_requests br
       JOIN projects p ON br.project_code = p.project_code
       LEFT JOIN users u ON u.user_id = br.user_id
       WHERE br.status = 'PENDING'
       ORDER BY br.created_at ASC`
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending budget requests.', detail: error.message });
  }
});

// FETCH BUDGET REQUEST HISTORY (non-pending)
app.get('/api/v1/projects/budget-requests/history', async (req, res) => {
  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(200).json({ success: true, data: [] });
    }

    const result = await db.query(
      `SELECT br.*, p.project_name, u.full_name AS requester_name, u.email AS requester_email
       FROM budget_requests br
       JOIN projects p ON br.project_code = p.project_code
       LEFT JOIN users u ON u.user_id = br.user_id
       WHERE br.status != 'PENDING'
       ORDER BY br.reviewed_at DESC NULLS LAST, br.created_at DESC`
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch budget request history.', detail: error.message });
  }
});

// UPDATED: APPROVE/REJECT BUDGET REQUEST (Manager step — sets MANAGER_APPROVED, not final)
app.patch('/api/v1/projects/budget-request/review', async (req, res) => {
  const { requestId, reviewerId, action } = req.body; 
  
  const validActions = ['MANAGER_APPROVED', 'REJECTED', 'REFER_TO_AM'];
  if (!validActions.includes(action?.toUpperCase())) {
    return res.status(400).json({ error: "Invalid action. Must be MANAGER_APPROVED or REJECTED." });
  }

  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(503).json({ error: 'budget_requests table is not initialized in this environment.' });
    }

    const result = await db.query(
      "UPDATE budget_requests SET status = $1, reviewed_by = $2, reviewed_at = CURRENT_TIMESTAMP WHERE request_id = $3 AND status = 'PENDING' RETURNING *",
      [action.toUpperCase(), reviewerId, requestId]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Request not found or already processed." });

    const budgetRow = result.rows[0];

    await auditInterceptor('budget_requests', requestId, reviewerId, budgetRow);

    try {
      if (budgetRow.user_id) {
        const notifTitle = action.toUpperCase() === 'MANAGER_APPROVED'
          ? 'Request for Additional Hours — Manager Approved'
          : 'Request for Additional Hours Rejected';
        const notifBody = action.toUpperCase() === 'MANAGER_APPROVED'
          ? `Your request for additional hours of ${budgetRow.requested_hours}hrs for project ${budgetRow.project_code} has been approved by your manager, and is pending Account Manager approval.`
          : `Your request for additional hours for project ${budgetRow.project_code} has been rejected by the manager.`;
        await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [budgetRow.user_id, notifTitle, notifBody]);
        await sendPushToUser(budgetRow.user_id, notifTitle, notifBody);
      }
    } catch (_) {}

    res.status(200).json({ success: true, data: budgetRow });
  } catch (error) {
    res.status(500).json({ error: 'Review process failed', detail: error.message });
  }
});

// GET budget requests pending Account Manager final approval (status = MANAGER_APPROVED)
app.get('/api/v1/projects/budget-requests/pending-am', async (req, res) => {
  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(200).json({ success: true, data: [] });
    }
    const result = await db.query(
      `SELECT br.*, p.project_name, u.full_name AS requester_name, u.email AS requester_email
       FROM budget_requests br
       JOIN projects p ON br.project_code = p.project_code
       LEFT JOIN users u ON u.user_id = br.user_id
       WHERE br.status = 'MANAGER_APPROVED'
       ORDER BY br.created_at ASC`
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending AM budget requests.', detail: error.message });
  }
});

// Account Manager final approval of budget requests (MANAGER_APPROVED → APPROVED/REJECTED)
app.patch('/api/v1/projects/budget-request/am-review', async (req, res) => {
  const { requestId, reviewerId, action } = req.body;
  const validActions = ['APPROVED', 'REJECTED'];
  if (!validActions.includes(action?.toUpperCase())) {
    return res.status(400).json({ error: "Invalid action. Must be APPROVED or REJECTED." });
  }
  try {
    const reviewerProfile = await db.query('SELECT user_role FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
    const role = normalizeRole(reviewerProfile.rows[0].user_role);
    if (role !== 'account_manager') return res.status(403).json({ error: 'Only Account Managers can perform final budget approval.' });

    const result = await db.query(
      "UPDATE budget_requests SET status = $1, reviewed_by = $2, reviewed_at = CURRENT_TIMESTAMP WHERE request_id = $3 AND status = 'MANAGER_APPROVED' RETURNING *",
      [action.toUpperCase(), reviewerId, requestId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Budget request not found or not awaiting AM approval.' });

    const budgetRow = result.rows[0];

    if (action.toUpperCase() === 'APPROVED') {
      await db.query('UPDATE projects SET budget_hours = budget_hours + $1 WHERE project_code = $2', [budgetRow.requested_hours, budgetRow.project_code]);
    }

    await auditInterceptor('budget_requests', requestId, reviewerId, budgetRow);

    try {
      if (budgetRow.user_id) {
        const notifTitle = action.toUpperCase() === 'APPROVED' ? 'Request for Additional Hours — Fully Approved!' : 'Request for Additional Hours Rejected';
        const notifBody = action.toUpperCase() === 'APPROVED'
          ? `Your request for additional hours of ${budgetRow.requested_hours}hrs for project ${budgetRow.project_code} has been fully approved!`
          : `Your request for additional hours for project ${budgetRow.project_code} has been rejected by the Account Manager.`;
        await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [budgetRow.user_id, notifTitle, notifBody]);
        await sendPushToUser(budgetRow.user_id, notifTitle, notifBody);
      }
    } catch (_) {}

    res.status(200).json({ success: true, data: budgetRow });
  } catch (error) {
    res.status(500).json({ error: 'AM review failed', detail: error.message });
  }
});

// DEACTIVATE PROJECT (sets INACTIVE, removes assignments)
app.patch('/api/v1/projects/:projectCode/deactivate', async (req, res) => {
  const { projectCode } = req.params;
  const { editorId } = req.body;
  if (!editorId) return res.status(400).json({ error: 'editorId is required.' });
  try {
    const editorCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || normalizeRole(editorCheck.rows[0].user_role) === 'staff') {
      return res.status(403).json({ error: 'Access Denied.' });
    }
    const code = projectCode.toUpperCase().trim();
    // Remove all project assignments
    await db.query('DELETE FROM project_assignments WHERE project_code = $1', [code]);
    // Set project status to INACTIVE
    const result = await db.query(
      `UPDATE projects SET status = 'INACTIVE' WHERE project_code = $1 RETURNING *`,
      [code]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    res.status(200).json({ success: true, message: `Project ${code} deactivated and assignments removed.`, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to deactivate project.', detail: error.message });
  }
});

app.get('/api/v1/users', async (req, res) => {
  const role = normalizeRole(req.query.role);

  try {
    if (role) {
      const filtered = await db.query(
        `SELECT user_id, full_name, email, user_role::text AS user_role, supervisor_id
         FROM users
         WHERE LOWER(user_role::text) = $1
         ORDER BY full_name ASC`,
        [role]
      );
      return res.status(200).json({ success: true, data: filtered.rows });
    }

    const result = await db.query(
      `SELECT user_id, full_name, email, user_role, supervisor_id
       FROM users
       ORDER BY full_name ASC`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch users.', detail: error.message });
  }
});

// PATCH /api/v1/users/set-supervisor — manager claims a staff member into their team
app.patch('/api/v1/users/set-supervisor', async (req, res) => {
  const { managerId, staffIds } = req.body;
  if (!managerId || !Array.isArray(staffIds) || staffIds.length === 0) {
    return res.status(400).json({ error: 'managerId and staffIds (array) are required.' });
  }
  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !isManagerialRole(managerCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Only manager-role users can set supervisor assignments.' });
    }
    await db.query(
      `UPDATE users SET supervisor_id = $1 WHERE user_id = ANY($2::uuid[])`,
      [managerId, staffIds]
    );
    res.status(200).json({ success: true, message: `${staffIds.length} staff member(s) linked to your account.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update supervisor assignments.', detail: error.message });
  }
});

// PATCH /api/v1/users/remove-from-team — unlink a staff member from a manager's team
app.patch('/api/v1/users/remove-from-team', async (req, res) => {
  const { managerId, staffId } = req.body;
  if (!managerId || !staffId) {
    return res.status(400).json({ error: 'managerId and staffId are required.' });
  }
  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !isManagerialRole(managerCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Only manager-role users can modify team assignments.' });
    }
    await db.query(
      `UPDATE users SET supervisor_id = NULL WHERE user_id = $1 AND supervisor_id = $2`,
      [staffId, managerId]
    );
    res.status(200).json({ success: true, message: 'Staff member removed from your team.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove staff from team.', detail: error.message });
  }
});

app.get('/api/v1/projects/assignments', async (req, res) => {
  const userId = req.query.userId;

  if (!userId) {
    return res.status(400).json({ error: 'userId query parameter is required.' });
  }

  try {
    const result = await db.query(
      `SELECT
         pa.assignment_id,
         pa.user_id,
         pa.project_code,
         pa.assigned_by,
         pa.created_at,
         p.project_name
       FROM project_assignments pa
       JOIN projects p ON p.project_code = pa.project_code
       WHERE pa.user_id = $1
       ORDER BY pa.created_at DESC`,
      [userId]
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch project assignments.', detail: error.message });
  }
});

// POST /api/v1/projects/assign-bulk - assign multiple staff to a project at once
app.post('/api/v1/projects/assign-bulk', async (req, res) => {
  const { managerId, userIds, projectCode } = req.body;
  if (!managerId || !Array.isArray(userIds) || userIds.length === 0 || !projectCode) {
    return res.status(400).json({ error: 'managerId, userIds (array) and projectCode are required.' });
  }
  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !isManagerialRole(managerCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Only managers can assign projects.' });
    }
    const projectCheck = await db.query('SELECT project_code FROM projects WHERE project_code = $1 LIMIT 1', [projectCode]);
    if (projectCheck.rows.length === 0) return res.status(404).json({ error: 'Project code not found.' });
    const results = [];
    for (const userId of userIds) {
      const r = await db.query(
        `INSERT INTO project_assignments (assignment_id, user_id, project_code, assigned_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, project_code) DO UPDATE SET assigned_by = EXCLUDED.assigned_by
         RETURNING *`,
        [randomUUID(), userId, projectCode, managerId]
      );
      results.push(r.rows[0]);
      // Notify staff
      try {
        await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)',
          [userId, 'Project Assigned', `You have been assigned to project ${projectCode}.`]);
      } catch (_) {}
    }
    return res.status(201).json({ success: true, data: results, count: results.length });
  } catch (error) {
    return res.status(500).json({ error: 'Bulk assignment failed.', detail: error.message });
  }
});

app.post('/api/v1/projects/assign', async (req, res) => {
  const { managerId, userId, projectCode } = req.body;

  if (!managerId || !userId || !projectCode) {
    return res.status(400).json({ error: 'managerId, userId and projectCode are required.' });
  }

  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !isManagerialRole(managerCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Only manager-level users can assign project codes.' });
    }

    const userCheck = await db.query('SELECT user_id FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Target user not found.' });
    }

    const projectCheck = await db.query('SELECT project_code FROM projects WHERE project_code = $1 LIMIT 1', [projectCode]);
    if (projectCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Project code not found.' });
    }

    const result = await db.query(
      `INSERT INTO project_assignments (assignment_id, user_id, project_code, assigned_by)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, project_code)
       DO UPDATE SET assigned_by = EXCLUDED.assigned_by
       RETURNING *`,
      [randomUUID(), userId, projectCode, managerId]
    );

    return res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to assign project code.', detail: error.message });
  }
});

app.get('/api/v1/manager/:managerId/attendance-logs', async (req, res) => {
  const { managerId } = req.params;

  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !isManagerialRole(managerCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Unauthorized manager access.' });
    }

    const result = await db.query(
      `SELECT
         al.attendance_id,
         al.user_id,
         u.full_name,
         al.project_code,
         al.clock_in_time,
         al.clock_out_time,
         ST_Y(al.raw_coordinates::geometry) AS latitude,
         ST_X(al.raw_coordinates::geometry) AS longitude,
         al.location_name,
         al.country_code,
         al.is_manual_location,
         al.travel_mode,
         al.daily_worktime_hours,
         al.ot_hours_accrued,
         al.status,
         al.created_at
       FROM attendance_logs al
       JOIN users u ON u.user_id = al.user_id
       WHERE u.supervisor_id = $1 OR u.user_id = $1
       ORDER BY al.created_at DESC
       LIMIT 500`,
      [managerId]
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch attendance logs.', detail: error.message });
  }
});

app.get('/api/v1/manager/:managerId/progress-logs', async (req, res) => {
  const { managerId } = req.params;

  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !isManagerialRole(managerCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Unauthorized manager access.' });
    }

    await applyDailyProgressBaselineForManagerTeam(managerId);

    const result = await db.query(
      `SELECT
         ppl.log_id,
         ppl.project_code,
         p.project_name,
         ppl.reporter_id,
         u.full_name,
         ppl.completion_percentage,
         ppl.progress_summary,
         ppl.logged_at
       FROM project_progress_logs ppl
       JOIN users u ON u.user_id = ppl.reporter_id
       LEFT JOIN projects p ON p.project_code = ppl.project_code
       WHERE u.supervisor_id = $1 OR u.user_id = $1
       ORDER BY ppl.logged_at DESC
       LIMIT 200`,
      [managerId]
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch progress logs.', detail: error.message });
  }
});

app.get('/api/v1/manager/:managerId/audit-logs', async (req, res) => {
  const { managerId } = req.params;

  try {
    const managerCheck = await db.query('SELECT user_role FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !isManagerialRole(managerCheck.rows[0].user_role)) {
      return res.status(403).json({ error: 'Unauthorized manager access.' });
    }

    const result = await db.query(
      `SELECT audit_id, table_name, record_id, altered_by, pre_value, post_value, created_at
       FROM audit_logs
       ORDER BY created_at DESC
       LIMIT 200`
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch audit logs.', detail: error.message });
  }
});

app.get('/api/v1/admin/audit-logs', async (req, res) => {
  try {
    const logs = await db.query(
      "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50"
    );
    res.status(200).json({ success: true, data: logs.rows });
  } catch (error) {
    res.status(500).json({ error: 'Audit trail access failure.' });
  }
});

// In server.js
const PORT = process.env.PORT || 5000; // Changed from 3000
ensureOperationalTables()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Backend API Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to initialize required database tables:', error?.message || error);
    if (error?.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  });