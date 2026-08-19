const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { randomUUID } = require('crypto');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const db = require('./db');

const isRenderEnvironment = Boolean(process.env.RENDER) || Boolean(process.env.RENDER_SERVICE_NAME);
if (!isRenderEnvironment) {
  dotenv.config();
}

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
app.use(express.json({ limit: '10mb' })); // raised to accommodate base64-encoded MC document uploads

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

// Multi-role helper: checks both legacy user_role and new user_roles[]
function userHasRole(userRow, role) {
  const normalized = normalizeRole(role);
  if (normalizeRole(userRow.user_role) === normalized) return true;
  if (Array.isArray(userRow.user_roles) && userRow.user_roles.length > 0) {
    return userRow.user_roles.some((r) => normalizeRole(r) === normalized);
  }
  return false;
}

function userIsManagerial(userRow) {
  if (isManagerialRole(userRow.user_role)) return true;
  if (Array.isArray(userRow.user_roles) && userRow.user_roles.length > 0) {
    return userRow.user_roles.some((r) => isManagerialRole(r));
  }
  return false;
}

// Standard date format used across all notification/inbox text (matches the "DD Mon YYYY" TO_CHAR format used elsewhere)
function formatDateDMY(dateLike) {
  if (!dateLike) return '';
  const d = dateLike instanceof Date ? dateLike : new Date(dateLike);
  if (Number.isNaN(d.getTime())) return String(dateLike);
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
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

  // Projects: support multiple Account Managers as its own field, separate from manager_ids
  await db.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS account_manager_ids TEXT[] DEFAULT '{}';`);
  await db.query(`
    UPDATE projects SET account_manager_ids = ARRAY[account_manager_id]
    WHERE (account_manager_ids IS NULL OR account_manager_ids = '{}') AND account_manager_id IS NOT NULL;
  `);

  // Projects: status column
  await db.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'ACTIVE';`);

  // Projects: start/end dates (project kickoff date and deadline/contract end date)
  await db.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS start_date DATE;`);
  await db.query(`ALTER TABLE projects ADD COLUMN IF NOT EXISTS end_date DATE;`);

  // Account approval system
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'pending';`);
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;`);
  // Tester/super-admin accounts: fully functional logins, but excluded from directory-style
  // listings (Users page, Hierarchy, Team member lists, AM/Manager assignment dropdowns) —
  // NOT excluded from their own transactional data (leave, attendance, progress), since those
  // need to keep flowing to real approvers for the account to actually be usable for testing.
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN NOT NULL DEFAULT FALSE;`);

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
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ
    );
  `);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS mc_file_url TEXT;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS is_late_submission BOOLEAN NOT NULL DEFAULT FALSE;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reviewer_remarks TEXT;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS workflow_status TEXT NOT NULL DEFAULT 'PENDING';`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reason TEXT;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(user_id);`);

  // workflow_status is actually a Postgres enum (leave_workflow_status) on the live table, not
  // the TEXT the ADD COLUMN IF NOT EXISTS above assumes — that ALTER is a no-op once the column
  // already exists, so it never widens the type. The enum only had PENDING/APPROVED/REJECTED,
  // so cancelling a leave request (DELETE /api/v1/leave/:leaveId) always 500'd. Add the missing
  // label; ADD VALUE IF NOT EXISTS requires Postgres 12+ and is a no-op if already present.
  try {
    await db.query(`ALTER TYPE leave_workflow_status ADD VALUE IF NOT EXISTS 'CANCELLED';`);
  } catch (_) {
    // Column may genuinely be TEXT on some environments (no enum type exists) — safe to ignore.
  }

  // Cancelling a leave now hard-deletes the row (see DELETE /api/v1/leave/:leaveId), so a
  // CANCELLED row should never exist going forward — this sweeps up any left behind by the
  // old soft-cancel behavior. Runs on every boot; a no-op once the backlog is cleared.
  await db.query(`DELETE FROM leave_applications WHERE workflow_status = 'CANCELLED';`);

  // Ensure gen_random_uuid() defaults on primary key columns (in case tables were created externally without defaults)
  await db.query(`ALTER TABLE leave_applications ALTER COLUMN leave_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE notifications ALTER COLUMN notification_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE budget_requests ALTER COLUMN request_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE password_reset_requests ALTER COLUMN request_id SET DEFAULT gen_random_uuid();`);
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS push_token TEXT;`);

  // Multi-role support: additive roles array alongside legacy single role
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS user_roles TEXT[] DEFAULT '{}';`);

  // Project-scoped role: what function does this person serve within this specific project?
  // Values: 'account_manager' | 'manager' | 'staff' (independent of global user_roles)
  await db.query(`ALTER TABLE project_assignments ADD COLUMN IF NOT EXISTS project_role TEXT NOT NULL DEFAULT 'staff';`);

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

  // HR-configurable per-employee leave entitlement (replaces hardcoded 12-day balance)
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS leave_entitlement_days INTEGER NOT NULL DEFAULT 12;`);

  // Log Time: remarks + general (non-project) vs project entries + manual entry flag
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS remark TEXT;`);
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS entry_type TEXT NOT NULL DEFAULT 'PROJECT';`);
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS is_manual_entry BOOLEAN NOT NULL DEFAULT FALSE;`);
  await db.query(`ALTER TABLE attendance_logs ALTER COLUMN project_code DROP NOT NULL;`);

  // Multi-project time allocation per clock-in session: staff can split one session's
  // planned hours across several projects (or General), add projects mid-session, and
  // mark/extend individual allocations without re-splitting time already used up.
  await db.query(`
    CREATE TABLE IF NOT EXISTS attendance_allocations (
      allocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      attendance_id UUID NOT NULL REFERENCES attendance_logs(attendance_id) ON DELETE CASCADE,
      project_code TEXT REFERENCES projects(project_code),
      allocated_hours NUMERIC(5,2) NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'PENDING',
      seq INTEGER NOT NULL DEFAULT 0,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      notified_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Audit trail for edits/reopens that happen after a block was already marked complete —
  // surfaced to managers/HR so a post-completion correction is distinguishable from the
  // original plan, without adding any extra steps for staff.
  await db.query(`ALTER TABLE attendance_allocations ADD COLUMN IF NOT EXISTS last_edited_at TIMESTAMPTZ;`);
  await db.query(`ALTER TABLE attendance_allocations ADD COLUMN IF NOT EXISTS edited_after_completion BOOLEAN NOT NULL DEFAULT FALSE;`);

  // Time actually tracked before the most recent pause/completion — preserved across a
  // reopen or a demotion back to PENDING (e.g. reopening a different block) so switching
  // between projects mid-session never silently discards progress already tracked.
  await db.query(`ALTER TABLE attendance_allocations ADD COLUMN IF NOT EXISTS accumulated_hours NUMERIC(6,2) NOT NULL DEFAULT 0;`);
}

const STANDARD_WORKDAY_HOURS = 8;
const DEFAULT_SINGLE_BLOCK_HOURS = 4;

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

    // Support both single userRole and multi-role userRoles array
    const allowedSignupRoles = ['manager', 'account_manager', 'hr', 'staff'];
    const rawRoles = Array.isArray(req.body.userRoles)
      ? req.body.userRoles.map((r) => String(r).trim().toLowerCase()).filter((r) => allowedSignupRoles.includes(r))
      : [String(req.body.userRole || 'staff').trim().toLowerCase()].filter((r) => allowedSignupRoles.includes(r));
    const allRoles = rawRoles.length > 0 ? rawRoles : ['staff'];
    const signupRole = allRoles[0]; // primary role

    const passwordHash = await bcrypt.hash(password, 10);
    const userId = randomUUID();
    const fullName = deriveNameFromEmail(normalized);
    const resolvedRole = await getDefaultUserRole(signupRole);

    const insertCols = ['user_id', 'full_name', 'user_role', 'user_roles', 'email', 'password_hash', 'account_status'];
    const insertVals = [userId, fullName, resolvedRole, allRoles, normalized, passwordHash, 'pending'];
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
      `INSERT INTO users (${insertCols.join(', ')}) VALUES (${placeholders}) RETURNING user_id, full_name, user_role, user_roles, email`,
      insertVals
    );
    return res.status(201).json({
      success: true,
      pending: true,
      message: 'Account created. Awaiting admin approval from rebecca.lau@nextan.com.sg to approve before signing in.',
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
      'SELECT user_id, full_name, user_role, user_roles, email, password_hash, account_status FROM users WHERE LOWER(email) = $1 LIMIT 1',
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
    // Ensure user_roles is always an array in the response
    safeUser.user_roles = Array.isArray(safeUser.user_roles) && safeUser.user_roles.length > 0
      ? safeUser.user_roles
      : [safeUser.user_role].filter(Boolean);
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
  const r = await db.query('SELECT user_role, user_roles, is_admin FROM users WHERE user_id = $1 LIMIT 1', [adminId]);
  const row = r.rows[0];
  if (!row || (!row.is_admin && !userHasRole(row, 'hr'))) {
    res.status(403).json({ error: 'Admin access required.' });
    return false;
  }
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
      `SELECT user_id, full_name, email, user_role, user_roles, account_status, created_at
       FROM users WHERE account_status IN ('active','rejected')
       ORDER BY created_at DESC LIMIT 100`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch account history.', detail: err.message });
  }
});

// ========================================================================
// ROLE-SCOPED REGISTRATION APPROVAL ROUTES
// ========================================================================

// Helper: verify requester holds a given role (supports multi-role)
async function requireRoleCheck(requesterId, role, res) {
  if (!requesterId) { res.status(400).json({ error: 'requesterId is required.' }); return null; }
  const r = await db.query('SELECT user_role, user_roles, is_admin FROM users WHERE user_id = $1 LIMIT 1', [requesterId]);
  if (!r.rows[0]) { res.status(403).json({ error: 'Requester not found.' }); return null; }
  const row = r.rows[0];
  if (!userHasRole(row, role) && !row.is_admin) {
    res.status(403).json({ error: `This action requires the ${role} role.` }); return null;
  }
  return row;
}

// HR: get pending Manager & Account Manager registrations
app.get('/api/v1/hr/pending-registrations', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  try {
    const result = await db.query(
      `SELECT user_id, full_name, email, user_role, user_roles, account_status, created_at
       FROM users
       WHERE account_status = 'pending'
       ORDER BY created_at ASC`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch pending registrations.', detail: err.message });
  }
});

// HR: approve or reject any pending registration (Manager, Account Manager, or Staff)
app.patch('/api/v1/hr/approve-registration', async (req, res) => {
  const { requesterId, userId, action } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  if (!userId || !['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: 'userId and action (approve|reject) are required.' });
  }
  try {
    const target = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (!target.rows[0]) return res.status(404).json({ error: 'User not found.' });
    const newStatus = action === 'approve' ? 'active' : 'rejected';
    await db.query('UPDATE users SET account_status = $1 WHERE user_id = $2', [newStatus, userId]);
    return res.status(200).json({ success: true, message: `Account ${newStatus}.` });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update registration status.', detail: err.message });
  }
});

// Account Manager: get pending Staff registrations
app.get('/api/v1/account-manager/pending-staff-registrations', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'account_manager', res)) return;
  try {
    const result = await db.query(
      `SELECT user_id, full_name, email, user_role, user_roles, account_status, created_at
       FROM users
       WHERE account_status = 'pending'
         AND (LOWER(user_role::text) = 'staff'
              OR (user_roles @> ARRAY['staff'] AND NOT (user_roles && ARRAY['manager','account_manager','hr'])))
       ORDER BY created_at ASC`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch pending staff registrations.', detail: err.message });
  }
});

// Account Manager: approve or reject a Staff registration
app.patch('/api/v1/account-manager/approve-staff-registration', async (req, res) => {
  const { requesterId, userId, action } = req.body;
  if (!await requireRoleCheck(requesterId, 'account_manager', res)) return;
  if (!userId || !['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: 'userId and action (approve|reject) are required.' });
  }
  try {
    const target = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (!target.rows[0]) return res.status(404).json({ error: 'User not found.' });
    const targetRow = target.rows[0];
    if (!userHasRole(targetRow, 'staff')) {
      return res.status(403).json({ error: 'Account Managers can only approve Staff registrations.' });
    }
    const newStatus = action === 'approve' ? 'active' : 'rejected';
    await db.query('UPDATE users SET account_status = $1 WHERE user_id = $2', [newStatus, userId]);
    return res.status(200).json({ success: true, message: `Staff account ${newStatus}.` });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update staff registration status.', detail: err.message });
  }
});

// Account Manager: history of staff registrations already decided (active/rejected)
app.get('/api/v1/account-manager/staff-registration-history', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'account_manager', res)) return;
  try {
    const result = await db.query(
      `SELECT user_id, full_name, email, account_status, created_at
       FROM users
       WHERE account_status IN ('active', 'rejected')
         AND (LOWER(user_role::text) = 'staff'
              OR (user_roles @> ARRAY['staff'] AND NOT (user_roles && ARRAY['manager','account_manager','hr'])))
       ORDER BY created_at DESC
       LIMIT 200`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch staff registration history.', detail: err.message });
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
    const mgrCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (!mgrCheck.rows[0] || !userIsManagerial(mgrCheck.rows[0])) {
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
    const reviewer = await db.query('SELECT user_role, user_roles, full_name FROM users WHERE user_id = $1 LIMIT 1', [reviewerId]);
    if (!reviewer.rows[0]) {
      return res.status(404).json({ error: 'Reviewer not found.' });
    }

    if (!userHasRole(reviewer.rows[0], 'account_manager') && !userHasRole(reviewer.rows[0], 'hr')) {
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

// Sum of each staff member's approved weekly hour allocations, for workload-aware allocation UIs
app.get('/api/v1/staff/workload-summary', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT user_id, COALESCE(SUM(hours_per_week), 0) AS total_hours
       FROM hour_allocations
       WHERE manager_status = 'APPROVED' AND account_manager_status = 'APPROVED'
       GROUP BY user_id`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch workload summary.', detail: error.message });
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
      `SELECT user_id, full_name, user_role, user_roles, account_status${columns.has('email') ? ', email' : ''}${columns.has('phone') ? ', phone' : ''}
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

// Lightweight session validation: returns current roles + account_status for a user
// Used by portals to detect role revocations without a full re-login
app.get('/api/v1/auth/verify-session', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: 'userId is required.' });
  try {
    const result = await db.query(
      'SELECT user_id, user_role, user_roles, account_status FROM users WHERE user_id = $1 LIMIT 1',
      [userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found.' });
    const row = result.rows[0];
    const roles = Array.isArray(row.user_roles) && row.user_roles.length > 0
      ? row.user_roles : [row.user_role].filter(Boolean);
    return res.status(200).json({
      success: true,
      data: {
        user_id: row.user_id,
        user_role: row.user_role,
        user_roles: roles,
        account_status: row.account_status,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: 'Session verification failed.', detail: error.message });
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
           br.created_at AS created_at,
           NULL::UUID AS notification_id
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
           CONCAT(la.category::TEXT, ' leave \u2022 ', TO_CHAR(la.start_date, 'DD Mon YYYY'), ' \u2192 ', TO_CHAR(la.end_date, 'DD Mon YYYY'), ' \u2022 ', CASE la.workflow_status::TEXT WHEN 'PENDING' THEN 'Pending manager approval' WHEN 'APPROVED' THEN 'Approved' WHEN 'REJECTED' THEN 'Rejected' ELSE la.workflow_status::TEXT END) AS subtitle,
           la.workflow_status::TEXT AS status,
           la.created_at AS created_at,
           NULL::UUID AS notification_id
         FROM leave_applications la
         WHERE la.user_id = $1
         ${budgetUnion}
         UNION ALL
         SELECT
           'NOTIFICATION' AS category,
           n.title AS title,
           n.body AS subtitle,
           CASE WHEN n.is_read THEN 'READ' ELSE 'UNREAD' END AS status,
           n.created_at AS created_at,
           n.notification_id AS notification_id
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
      `SELECT leave_id, category, start_date, end_date, workflow_status, reviewer_remarks, mc_file_url, created_at
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

    const current = countryCode.toUpperCase();
    const isDomestic = current === 'SG';

    const travelMode = isDomestic ? 'DOMESTIC_ATTENDANCE' : 'OVERSEAS_ATTENDANCE';

    return { locationName, countryCode, travelMode };
  } catch (error) {
    console.error('Spatial Geocoding Live Engine Warning:', error.message);
    return {
      locationName: 'Location unavailable',
      countryCode: homeCountry,
      travelMode: String(homeCountry || '').toUpperCase() === 'SG' ? 'DOMESTIC_ATTENDANCE' : 'OVERSEAS_ATTENDANCE'
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

// Clients (web/mobile) use the sentinel string 'GENERAL' to represent non-project work in
// their project pickers — normalize it (and any blank value) to null before it ever reaches
// a project_code FK column, otherwise it fails as an unrecognised project code.
function normalizeProjectCode(code) {
  if (!code) return null;
  return String(code).trim().toUpperCase() === 'GENERAL' ? null : code;
}

// ========================================================================
// ROUTE: CLOCK-IN ENDPOINT
// ========================================================================
app.post('/api/v1/attendance/clock-in', async (req, res) => {
  const { userId, projectCode, latitude, longitude, isManualLocation, manualLocationText, remark, clockInTime, allocations } = req.body;
  // `allocations`, if provided, is [{ projectCode: string|null, allocatedHours: number }, ...] —
  // lets staff split this session's planned hours across several projects/General up front.
  // `projectCode` stays as the single-project fallback for older clients (mobile app, etc.).
  const requestedProjects = Array.isArray(allocations) && allocations.length > 0
    ? allocations.map((a) => ({ ...a, projectCode: normalizeProjectCode(a.projectCode) }))
    : [{ projectCode: normalizeProjectCode(projectCode), allocatedHours: null }];
  const primaryProjectCode = requestedProjects[0].projectCode || null;
  const entryType = primaryProjectCode ? 'PROJECT' : 'GENERAL';
  const isManualEntry = Boolean(clockInTime);

  try {
    const userProfile = await db.query('SELECT home_office_country, user_role, user_roles FROM users WHERE user_id = $1', [userId]);
    if (userProfile.rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    // Non-managerial staff must be assigned to every requested project to clock in (General is exempt)
    const userRow = userProfile.rows[0];
    if (!userIsManagerial(userRow)) {
      for (const alloc of requestedProjects) {
        if (!alloc.projectCode) continue;
        const assignCheck = await db.query(
          'SELECT assignment_id FROM project_assignments WHERE user_id = $1 AND project_code = $2 LIMIT 1',
          [userId, alloc.projectCode]
        );
        if (assignCheck.rows.length === 0) {
          return res.status(403).json({ error: `You are not assigned to project ${alloc.projectCode}. Please ask your manager to assign you first.` });
        }
      }
    }

    const homeCountry = userProfile.rows[0].home_office_country;
    let locationName = manualLocationText || 'Location unavailable';
    let countryCode = homeCountry;
    let travelMode = String(homeCountry || '').toUpperCase() === 'SG' ? 'DOMESTIC_ATTENDANCE' : 'OVERSEAS_ATTENDANCE';

    if (!isManualLocation && latitude && longitude) {
      const geoData = await resolveGeospatialMetrics(latitude, longitude, homeCountry);
      locationName = geoData.locationName;
      countryCode = geoData.countryCode;
      travelMode = geoData.travelMode;
    }

    const insertQuery = `
      INSERT INTO attendance_logs (
        attendance_id, user_id, project_code, clock_in_time, raw_coordinates,
        location_name, country_code, is_manual_location, travel_mode, status, entry_type, remark, is_manual_entry, created_at
      ) VALUES (
        $1, $2, $3, COALESCE($12::timestamptz, CURRENT_TIMESTAMP),
        CASE WHEN $4::numeric IS NOT NULL AND $5::numeric IS NOT NULL
             THEN ST_SetSRID(ST_MakePoint($5::numeric, $4::numeric), 4326) ELSE NULL END,
        $6, $7, $8, $9, 'ACTIVE', $10, $11, $13, CURRENT_TIMESTAMP
      ) RETURNING *;
    `;

    const result = await db.query(insertQuery, [
      randomUUID(), userId, primaryProjectCode, latitude, longitude, locationName, countryCode, isManualLocation || false, travelMode, entryType, remark || null, clockInTime || null, isManualEntry
    ]);

    const attendanceRow = result.rows[0];

    // Split the planned session hours across the requested projects/General, even by default,
    // editable afterward. First block starts ACTIVE, the rest wait as PENDING.
    const blockCount = requestedProjects.length;
    const defaultHoursEach = blockCount > 1
      ? STANDARD_WORKDAY_HOURS / blockCount
      : DEFAULT_SINGLE_BLOCK_HOURS;

    const allocationRows = [];
    for (let i = 0; i < requestedProjects.length; i++) {
      const alloc = requestedProjects[i];
      const hours = typeof alloc.allocatedHours === 'number' && alloc.allocatedHours > 0
        ? alloc.allocatedHours
        : defaultHoursEach;
      const inserted = await db.query(
        `INSERT INTO attendance_allocations (attendance_id, project_code, allocated_hours, status, seq, started_at)
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $4 = 'ACTIVE' THEN CURRENT_TIMESTAMP ELSE NULL END)
         RETURNING *`,
        [attendanceRow.attendance_id, alloc.projectCode || null, Math.round(hours * 100) / 100, i === 0 ? 'ACTIVE' : 'PENDING', i]
      );
      allocationRows.push(inserted.rows[0]);
    }

    res.status(201).json({ success: true, data: { ...attendanceRow, allocations: allocationRows } });
  } catch (error) {
    console.error("Database Insert Failure Error Detail:", error.message);
    res.status(500).json({ error: 'Clock-In transaction failure', detail: error.message });
  }
});

// ========================================================================
// ROUTE: CLOCK-OUT ENDPOINT 
// ========================================================================
app.post('/api/v1/attendance/clock-out', async (req, res) => {
  const { userId, attendanceId, remark, clockOutTime } = req.body;

  try {
    const logCheck = await db.query(
      "SELECT clock_in_time FROM attendance_logs WHERE attendance_id = $1 AND user_id = $2",
      [attendanceId, userId]
    );

    if (logCheck.rows.length === 0) {
      return res.status(404).json({ error: 'No active clock-in entry found matching your device session state.' });
    }

    if (clockOutTime) {
      const clockIn = new Date(logCheck.rows[0].clock_in_time);
      const clockOut = new Date(clockOutTime);
      if (Number.isNaN(clockOut.getTime()) || clockOut <= clockIn) {
        return res.status(400).json({ error: 'Clock-out time must be after the clock-in time.' });
      }
    }

    const updateQuery = `
      WITH TimeCalculations AS (
        SELECT
          attendance_id,
          clock_in_time,
          COALESCE($3::timestamptz, CURRENT_TIMESTAMP) AS current_out,
          EXTRACT(EPOCH FROM (COALESCE($3::timestamptz, CURRENT_TIMESTAMP) - clock_in_time)) / 3600 AS raw_hours,
          EXTRACT(HOUR FROM COALESCE($3::timestamptz, CURRENT_TIMESTAMP)) AS out_hour
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
        END,
        remark = COALESCE($2, attendance_logs.remark)
      FROM TimeCalculations TC
      WHERE attendance_logs.attendance_id = $1
      RETURNING attendance_logs.attendance_id, attendance_logs.daily_worktime_hours, attendance_logs.ot_hours_accrued;
    `;

    const result = await db.query(updateQuery, [attendanceId, remark || null, clockOutTime || null]);
    const attendanceRow = result.rows[0];

    // Close out whichever allocation was still running, and let the leftover ones stand as planned.
    // Bank whatever time the ACTIVE block had tracked so it isn't lost on clock-out.
    await db.query(
      `UPDATE attendance_allocations
       SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP,
           accumulated_hours = accumulated_hours + CASE WHEN status = 'ACTIVE' AND started_at IS NOT NULL
             THEN EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at)) / 3600 ELSE 0 END
       WHERE attendance_id = $1 AND status IN ('ACTIVE', 'PENDING')`,
      [attendanceId]
    );

    const allocResult = await db.query(
      `SELECT allocation_id, project_code, allocated_hours, status FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [attendanceId]
    );
    const totalAllocated = allocResult.rows.reduce((sum, r) => sum + Number(r.allocated_hours || 0), 0);
    const actualHours = Number(attendanceRow.daily_worktime_hours || 0);
    const reconciliation = {
      totalAllocatedHours: Math.round(totalAllocated * 100) / 100,
      actualWorkedHours: actualHours,
      mismatch: Math.round(Math.abs(totalAllocated - actualHours) * 100) / 100 > 0.1,
    };

    res.status(200).json({ success: true, data: { ...attendanceRow, allocations: allocResult.rows, reconciliation } });

  } catch (error) {
    res.status(500).json({ error: 'Clock-Out transaction failure', detail: error.message });
  }
});

// ========================================================================
// ROUTE: MANUAL TIME ENTRY (Log Time — enter actual start/end times directly)
// ========================================================================
app.post('/api/v1/attendance/manual-entry', async (req, res) => {
  const { userId, startTime, endTime, remark } = req.body;
  const projectCode = normalizeProjectCode(req.body.projectCode);
  const entryType = projectCode ? 'PROJECT' : 'GENERAL';

  if (!userId || !startTime || !endTime) {
    return res.status(400).json({ error: 'userId, startTime, and endTime are required.' });
  }
  const start = new Date(startTime);
  const end = new Date(endTime);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
    return res.status(400).json({ error: 'endTime must be a valid time after startTime.' });
  }

  try {
    const userProfile = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [userId]);
    if (userProfile.rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    if (entryType === 'PROJECT' && !userIsManagerial(userProfile.rows[0])) {
      const assignCheck = await db.query(
        'SELECT assignment_id FROM project_assignments WHERE user_id = $1 AND project_code = $2 LIMIT 1',
        [userId, projectCode]
      );
      if (assignCheck.rows.length === 0) {
        return res.status(403).json({ error: `You are not assigned to project ${projectCode}. Please ask your manager to assign you first.` });
      }
    }

    const rawHours = (end.getTime() - start.getTime()) / (1000 * 60 * 60);
    const outHour = end.getHours();
    const dailyWorktimeHours = Math.round((rawHours > 1 ? rawHours - 1 : rawHours) * 100) / 100;
    const otHoursAccrued = rawHours > 9.5 && outHour >= 18 ? Math.round((rawHours - 9.5) * 100) / 100 : 0;

    const insertQuery = `
      INSERT INTO attendance_logs (
        attendance_id, user_id, project_code, clock_in_time, clock_out_time,
        daily_worktime_hours, ot_hours_accrued, status, entry_type, is_manual_entry, remark, created_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, 'ACTIVE', $8, TRUE, $9, CURRENT_TIMESTAMP
      ) RETURNING *;
    `;
    const result = await db.query(insertQuery, [
      randomUUID(), userId, projectCode || null, start.toISOString(), end.toISOString(),
      dailyWorktimeHours, otHoursAccrued, entryType, remark || null
    ]);

    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Manual time entry failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: ACTIVE ATTENDANCE SESSION CHECK
// ========================================================================
app.get('/api/v1/attendance/active-session/:userId', async (req, res) => {
  const { userId } = req.params;
  if (!userId) {
    return res.status(400).json({ error: 'Missing userId parameter.' });
  }

  try {
    const result = await db.query(
      `SELECT
         attendance_id,
         user_id,
         project_code,
         clock_in_time,
         ST_Y(raw_coordinates::geometry) AS latitude,
         ST_X(raw_coordinates::geometry) AS longitude,
         location_name,
         country_code,
         is_manual_location,
         travel_mode,
         status,
         created_at
       FROM attendance_logs
       WHERE user_id = $1 AND status = 'ACTIVE' AND clock_out_time IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [userId]
    );

    const session = result.rows[0] || null;
    if (session) {
      const allocResult = await db.query(
        `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion
         FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
        [session.attendance_id]
      );
      session.allocations = allocResult.rows;
    }

    return res.status(200).json({ success: true, data: session });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch active attendance session.', detail: error.message });
  }
});

// Per-day, per-project worked hours for a date range — powers the staff dashboard's weekly
// project log. Handles both multi-project sessions (via attendance_allocations) and legacy
// single-project sessions (attendance_logs rows with no allocations at all).
app.get('/api/v1/attendance/project-log/:userId', async (req, res) => {
  const { userId } = req.params;
  const { start, end } = req.query;
  if (!start || !end) {
    return res.status(400).json({ error: 'start and end date query params are required (YYYY-MM-DD).' });
  }
  try {
    const result = await db.query(
      `WITH sessions AS (
         SELECT attendance_id, clock_in_time::date AS day, project_code, daily_worktime_hours,
                EXISTS (SELECT 1 FROM attendance_allocations aa WHERE aa.attendance_id = al.attendance_id) AS has_allocations
         FROM attendance_logs al
         WHERE al.user_id = $1 AND al.clock_in_time::date BETWEEN $2::date AND $3::date
       ),
       legacy AS (
         SELECT day, COALESCE(project_code, 'General') AS project_code, COALESCE(daily_worktime_hours, 0) AS hours
         FROM sessions WHERE NOT has_allocations
       ),
       allocated AS (
         SELECT s.day, COALESCE(aa.project_code, 'General') AS project_code, COALESCE(aa.accumulated_hours, 0) AS hours
         FROM sessions s
         JOIN attendance_allocations aa ON aa.attendance_id = s.attendance_id
         WHERE s.has_allocations
       )
       SELECT to_char(day, 'YYYY-MM-DD') AS day, project_code, SUM(hours) AS hours
       FROM (SELECT * FROM legacy UNION ALL SELECT * FROM allocated) combined
       GROUP BY day, project_code
       ORDER BY day`,
      [userId, start, end]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch project log.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: MULTI-PROJECT TIME ALLOCATION MANAGEMENT
// ========================================================================

// Add a project mid-session: splits the *remaining, unallocated* time (standard workday minus
// hours already used up by COMPLETED blocks) evenly across the not-yet-completed blocks + the new one.
app.post('/api/v1/attendance/allocations', async (req, res) => {
  const { userId, attendanceId } = req.body;
  const projectCode = normalizeProjectCode(req.body.projectCode);
  if (!userId || !attendanceId) {
    return res.status(400).json({ error: 'userId and attendanceId are required.' });
  }

  try {
    const sessionCheck = await db.query(
      'SELECT attendance_id FROM attendance_logs WHERE attendance_id = $1 AND user_id = $2 AND clock_out_time IS NULL',
      [attendanceId, userId]
    );
    if (sessionCheck.rows.length === 0) {
      return res.status(404).json({ error: 'No active clock-in session found.' });
    }

    if (projectCode) {
      const userProfile = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [userId]);
      if (!userIsManagerial(userProfile.rows[0])) {
        const assignCheck = await db.query(
          'SELECT assignment_id FROM project_assignments WHERE user_id = $1 AND project_code = $2 LIMIT 1',
          [userId, projectCode]
        );
        if (assignCheck.rows.length === 0) {
          return res.status(403).json({ error: `You are not assigned to project ${projectCode}. Please ask your manager to assign you first.` });
        }
      }
    }

    const existing = await db.query(
      `SELECT allocation_id, allocated_hours, status, seq FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [attendanceId]
    );
    const completedHours = existing.rows
      .filter((r) => r.status === 'COMPLETED')
      .reduce((sum, r) => sum + Number(r.allocated_hours || 0), 0);
    const openRows = existing.rows.filter((r) => r.status !== 'COMPLETED');
    const remainingHours = Math.max(STANDARD_WORKDAY_HOURS - completedHours, 0);
    const splitCount = openRows.length + 1;
    const evenShare = Math.round((remainingHours / splitCount) * 100) / 100;
    const nextSeq = existing.rows.length > 0 ? Math.max(...existing.rows.map((r) => r.seq)) + 1 : 0;
    const hasActive = existing.rows.some((r) => r.status === 'ACTIVE');

    for (const row of openRows) {
      await db.query('UPDATE attendance_allocations SET allocated_hours = $1 WHERE allocation_id = $2', [evenShare, row.allocation_id]);
    }

    const newStatus = hasActive ? 'PENDING' : 'ACTIVE';
    const inserted = await db.query(
      `INSERT INTO attendance_allocations (attendance_id, project_code, allocated_hours, status, seq, started_at)
       VALUES ($1, $2, $3, $4, $5, CASE WHEN $4 = 'ACTIVE' THEN CURRENT_TIMESTAMP ELSE NULL END)
       RETURNING *`,
      [attendanceId, projectCode || null, evenShare, newStatus, nextSeq]
    );

    const all = await db.query(
      `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion
       FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [attendanceId]
    );

    res.status(201).json({ success: true, data: { newAllocation: inserted.rows[0], allocations: all.rows } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add project allocation.', detail: error.message });
  }
});

// Direct manual edit — "editable at every stage" — overwrite one allocation's planned hours.
app.patch('/api/v1/attendance/allocations/:allocationId', async (req, res) => {
  const { allocationId } = req.params;
  const { userId, allocatedHours } = req.body;
  if (!userId || typeof allocatedHours !== 'number' || allocatedHours <= 0) {
    return res.status(400).json({ error: 'userId and a positive allocatedHours are required.' });
  }
  try {
    const result = await db.query(
      `UPDATE attendance_allocations aa
       SET allocated_hours = $1,
           notified_at = CASE WHEN $1 > aa.allocated_hours THEN NULL ELSE aa.notified_at END,
           last_edited_at = CURRENT_TIMESTAMP,
           edited_after_completion = aa.edited_after_completion OR aa.status = 'COMPLETED'
       FROM attendance_logs al
       WHERE aa.allocation_id = $2 AND aa.attendance_id = al.attendance_id AND al.user_id = $3
       RETURNING aa.*`,
      [Math.round(allocatedHours * 100) / 100, allocationId, userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Allocation not found.' });
    }
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update allocation.', detail: error.message });
  }
});

// Staff marked this complete too early and wants to keep working on it — resume tracking
// instead of only being able to adjust the hour number after the fact. Demotes whichever
// block is currently ACTIVE back to PENDING, since only one block runs at a time.
app.post('/api/v1/attendance/allocations/:allocationId/reopen', async (req, res) => {
  const { allocationId } = req.params;
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId is required.' });

  try {
    const current = await db.query(
      `SELECT aa.* FROM attendance_allocations aa
       JOIN attendance_logs al ON al.attendance_id = aa.attendance_id
       WHERE aa.allocation_id = $1 AND al.user_id = $2`,
      [allocationId, userId]
    );
    if (current.rows.length === 0) return res.status(404).json({ error: 'Allocation not found.' });
    const row = current.rows[0];
    if (row.status !== 'COMPLETED') return res.status(400).json({ error: 'Only a completed block can be reopened.' });

    // Pause whichever block is currently ACTIVE — bank the time it already tracked into
    // accumulated_hours rather than discarding it, so resuming it later doesn't restart at zero.
    await db.query(
      `UPDATE attendance_allocations
       SET status = 'PENDING',
           accumulated_hours = accumulated_hours + CASE WHEN started_at IS NOT NULL
             THEN EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at)) / 3600 ELSE 0 END,
           started_at = NULL
       WHERE attendance_id = $1 AND status = 'ACTIVE'`,
      [row.attendance_id]
    );
    await db.query(
      `UPDATE attendance_allocations
       SET status = 'ACTIVE', started_at = CURRENT_TIMESTAMP, completed_at = NULL, notified_at = NULL,
           last_edited_at = CURRENT_TIMESTAMP, edited_after_completion = TRUE
       WHERE allocation_id = $1`,
      [allocationId]
    );

    const all = await db.query(
      `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion
       FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [row.attendance_id]
    );
    res.status(200).json({ success: true, data: { allocations: all.rows } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reopen allocation.', detail: error.message });
  }
});

// Work finished before the time budget ran out — close this block now and hand off to the next one.
app.post('/api/v1/attendance/allocations/:allocationId/complete', async (req, res) => {
  const { allocationId } = req.params;
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId is required.' });

  try {
    const current = await db.query(
      `SELECT aa.* FROM attendance_allocations aa
       JOIN attendance_logs al ON al.attendance_id = aa.attendance_id
       WHERE aa.allocation_id = $1 AND al.user_id = $2`,
      [allocationId, userId]
    );
    if (current.rows.length === 0) return res.status(404).json({ error: 'Allocation not found.' });
    const row = current.rows[0];

    await db.query(
      `UPDATE attendance_allocations
       SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP,
           accumulated_hours = accumulated_hours + CASE WHEN status = 'ACTIVE' AND started_at IS NOT NULL
             THEN EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - started_at)) / 3600 ELSE 0 END
       WHERE allocation_id = $1`,
      [allocationId]
    );

    if (row.status === 'ACTIVE') {
      const next = await db.query(
        `SELECT allocation_id FROM attendance_allocations WHERE attendance_id = $1 AND status = 'PENDING' ORDER BY seq ASC LIMIT 1`,
        [row.attendance_id]
      );
      if (next.rows.length > 0) {
        await db.query(
          `UPDATE attendance_allocations SET status = 'ACTIVE', started_at = CURRENT_TIMESTAMP WHERE allocation_id = $1`,
          [next.rows[0].allocation_id]
        );
      }
    }

    const all = await db.query(
      `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion
       FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [row.attendance_id]
    );
    res.status(200).json({ success: true, data: { allocations: all.rows } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to complete allocation.', detail: error.message });
  }
});

// Time ran out but staff wants more time on this project — extends the budget and re-arms the reminder.
app.post('/api/v1/attendance/allocations/:allocationId/extend', async (req, res) => {
  const { allocationId } = req.params;
  const { userId, extraHours } = req.body;
  if (!userId || typeof extraHours !== 'number' || extraHours <= 0) {
    return res.status(400).json({ error: 'userId and a positive extraHours are required.' });
  }
  try {
    const result = await db.query(
      `UPDATE attendance_allocations aa SET allocated_hours = aa.allocated_hours + $1, notified_at = NULL
       FROM attendance_logs al
       WHERE aa.allocation_id = $2 AND aa.attendance_id = al.attendance_id AND al.user_id = $3
       RETURNING aa.*`,
      [Math.round(extraHours * 100) / 100, allocationId, userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Allocation not found.' });
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to extend allocation.', detail: error.message });
  }
});

// Mark an allocation as "reminder shown" so the frontend doesn't re-notify every poll.
app.post('/api/v1/attendance/allocations/:allocationId/mark-notified', async (req, res) => {
  const { allocationId } = req.params;
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId is required.' });
  try {
    await db.query(
      `UPDATE attendance_allocations aa SET notified_at = CURRENT_TIMESTAMP
       FROM attendance_logs al
       WHERE aa.allocation_id = $1 AND aa.attendance_id = al.attendance_id AND al.user_id = $2`,
      [allocationId, userId]
    );
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark allocation as notified.', detail: error.message });
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
    const hrCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [hrUserId]);
    if (hrCheck.rows.length === 0 || !userHasRole(hrCheck.rows[0], 'hr')) {
      return res.status(403).json({ error: "Access Denied: Only HR personnel can issue new project configurations." });
    }

    // Verify assigned Account Manager exists in database before establishing link
    const amCheck = await db.query("SELECT user_role, user_roles FROM users WHERE user_id = $1", [accountManagerId]);
    if (amCheck.rows.length === 0 || !userHasRole(amCheck.rows[0], 'account_manager')) {
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
    const projectCheck = await db.query('SELECT account_manager_id, account_manager_ids FROM projects WHERE project_code = $1', [projectCode]);
    if (projectCheck.rows.length === 0) {
      return res.status(404).json({ error: `Project reference lookup failed for code: ${projectCode}` });
    }

    const amIds = projectCheck.rows[0].account_manager_ids || [];
    if (!amIds.includes(accountManagerId) && projectCheck.rows[0].account_manager_id !== accountManagerId) {
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

    // Staff must be assigned to the project to make a budget request
    const requesterRow = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (requesterRow.rows[0] && !userIsManagerial(requesterRow.rows[0])) {
      const assignCheck = await db.query(
        'SELECT assignment_id FROM project_assignments WHERE user_id = $1 AND project_code = $2 LIMIT 1',
        [userId, projectCode]
      );
      if (assignCheck.rows.length === 0) {
        return res.status(403).json({ error: `You are not assigned to project ${projectCode}. Budget requests can only be made for projects you are assigned to.` });
      }
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
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [supervisorId]);
    if (managerCheck.rows.length === 0 || normalizeRole(managerCheck.rows[0].user_role) === 'staff') {
      return res.status(403).json({ error: 'Unauthorized.' });
    }
    const result = await db.query(
      `SELECT la.leave_id, la.user_id, u.full_name, la.category, la.start_date, la.end_date,
              la.workflow_status, la.reviewer_remarks, la.is_late_submission, la.updated_at, la.mc_file_url,
              r.full_name AS reviewer_name
       FROM leave_applications la
       JOIN users u ON la.user_id = u.user_id
       LEFT JOIN users r ON r.user_id = la.reviewed_by
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
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [supervisorId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
      return res.status(403).json({ error: "Unauthorized access path." });
    }

    const fetchPendingQuery = `
      SELECT la.leave_id, la.user_id, u.full_name, la.category, la.start_date, la.end_date, la.is_late_submission, la.workflow_status, la.mc_file_url
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

    // Check for overlapping dates (exclude REJECTED leaves)
    const overlapCheck = await db.query(
      `SELECT leave_id FROM leave_applications
       WHERE user_id = $1
         AND workflow_status::TEXT NOT IN ('REJECTED', 'CANCELLED')
         AND start_date <= $3::date
         AND end_date >= $2::date`,
      [userId, startDate, endDate]
    );
    if (overlapCheck.rows.length > 0) {
      return res.status(409).json({ error: 'You already have a leave application that overlaps with these dates. Please check your existing requests.' });
    }

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
      const notifBody = `You have just submitted a ${category.toLowerCase()} leave request from ${formatDateDMY(startDate)} to ${formatDateDMY(endDate)}. It is pending manager review.`;
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
// ROUTE: EDIT PENDING LEAVE APPLICATION
// ========================================================================
app.patch('/api/v1/leave/:leaveId', async (req, res) => {
  const { leaveId } = req.params;
  const { userId, requesterId, category, startDate, endDate, reason, mcFileUrl } = req.body;
  if (!userId || !category || !startDate || !endDate) {
    return res.status(400).json({ error: 'userId, category, startDate, and endDate are required.' });
  }
  try {
    const check = await db.query(
      'SELECT * FROM leave_applications WHERE leave_id = $1 AND user_id = $2',
      [leaveId, userId]
    );
    if (!check.rows[0]) return res.status(404).json({ error: 'Leave not found.' });

    // Editing on someone else's behalf requires HR; the staff owner can only edit their own
    // still-pending request. requesterId defaults to userId for the existing self-edit path.
    const actingId = requesterId || userId;
    const isHrEditor = actingId !== userId;
    if (isHrEditor) {
      if (!await requireRoleCheck(actingId, 'hr', res)) return;
    } else if (check.rows[0].workflow_status !== 'PENDING') {
      return res.status(400).json({ error: 'Only pending leave requests can be edited.' });
    }
    // Check for overlapping dates (excluding this leave itself)
    const overlapCheck = await db.query(
      `SELECT leave_id FROM leave_applications
       WHERE user_id = $1 AND leave_id != $2
         AND workflow_status::TEXT NOT IN ('REJECTED', 'CANCELLED')
         AND start_date <= $4::date AND end_date >= $3::date`,
      [userId, leaveId, startDate, endDate]
    );
    if (overlapCheck.rows.length > 0) {
      return res.status(409).json({ error: 'These dates overlap with another existing leave application.' });
    }
    const categoryUpper = category.toUpperCase();
    await db.query(
      `UPDATE leave_applications SET category = $1, start_date = $2, end_date = $3, reason = $4,
       mc_file_url = CASE WHEN $6::text = 'SICK' THEN COALESCE($7, mc_file_url) ELSE NULL END,
       updated_at = CURRENT_TIMESTAMP WHERE leave_id = $5`,
      [categoryUpper, startDate, endDate, reason || null, leaveId, categoryUpper, mcFileUrl || null]
    );
    return res.status(200).json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to update leave application.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: UPLOAD MC DOCUMENT FOR A SICK LEAVE (allowed regardless of status —
// staff can attach the MC any time after applying, not just while pending)
// ========================================================================
app.post('/api/v1/leave/:leaveId/mc-upload', async (req, res) => {
  const { leaveId } = req.params;
  const { userId, mcFileUrl } = req.body;
  if (!userId || !mcFileUrl) {
    return res.status(400).json({ error: 'userId and mcFileUrl are required.' });
  }
  try {
    const check = await db.query(
      'SELECT leave_id, category FROM leave_applications WHERE leave_id = $1 AND user_id = $2',
      [leaveId, userId]
    );
    if (!check.rows[0]) return res.status(404).json({ error: 'Leave not found.' });
    if (check.rows[0].category !== 'SICK') {
      return res.status(400).json({ error: 'MC upload only applies to sick leave requests.' });
    }
    const result = await db.query(
      'UPDATE leave_applications SET mc_file_url = $1, updated_at = CURRENT_TIMESTAMP WHERE leave_id = $2 RETURNING leave_id, mc_file_url',
      [mcFileUrl, leaveId]
    );
    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to upload MC document.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: CANCEL PENDING LEAVE APPLICATION
// ========================================================================
app.delete('/api/v1/leave/:leaveId', async (req, res) => {
  const { leaveId } = req.params;
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ error: 'userId is required to cancel a leave request.' });
  }

  try {
    const result = await db.query(
      `DELETE FROM leave_applications
       WHERE leave_id = $1 AND user_id = $2 AND workflow_status = 'PENDING'
       RETURNING leave_id, user_id, category, start_date, end_date`,
      [leaveId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Leave request not found or it is not eligible for cancellation.' });
    }

    try {
      const cancelled = result.rows[0];
      const message = `Your leave request from ${formatDateDMY(cancelled.start_date)} to ${formatDateDMY(cancelled.end_date)} has been deleted.`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [userId, 'Leave Request Deleted', message]);
    } catch (_) {}

    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to delete leave application.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: LEAVE BALANCE FOR A USER
// ========================================================================
app.get('/api/v1/leave/balance/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const [usageResult, entitlementResult] = await Promise.all([
      db.query(
        `SELECT COALESCE(SUM(end_date::date - start_date::date + 1), 0) AS used_days
         FROM leave_applications
         WHERE user_id = $1
           AND category::TEXT IN ('ANNUAL', 'EMERGENCY')
           AND workflow_status::TEXT = 'APPROVED'`,
        [userId]
      ),
      db.query('SELECT leave_entitlement_days FROM users WHERE user_id = $1', [userId]),
    ]);
    const usedDays = parseInt(usageResult.rows[0]?.used_days || 0);
    const totalDays = entitlementResult.rows[0]?.leave_entitlement_days ?? 12;
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
    const reviewerProfile = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
    const role = normalizeRole(reviewerProfile.rows[0].user_role);
    if (role === 'staff') return res.status(403).json({ error: 'Staff users cannot review leave.' });
    const result = await db.query(
      `UPDATE leave_applications SET workflow_status = $1, reviewer_remarks = $2, reviewed_by = $3, updated_at = CURRENT_TIMESTAMP WHERE leave_id = $4 RETURNING *`,
      [action.toUpperCase(), reviewerRemarks || '', reviewerId, leaveId]
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
    const reviewerProfile = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) {
      return res.status(404).json({ error: 'Reviewer profile not found in system directory.' });
    }

    // Block staff from approving leave; HR staff may not approve direct leave either
    if (!userIsManagerial(reviewerProfile.rows[0])) {
      return res.status(403).json({ error: `Access Denied: Only manager-level users can process workflow leave decisions.` });
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
      SET workflow_status = $1, reviewer_remarks = $2, reviewed_by = $3, updated_at = CURRENT_TIMESTAMP
      WHERE leave_id = $4 AND workflow_status = 'PENDING'
      RETURNING *;
    `;

    const result = await db.query(reviewQuery, [action.toUpperCase(), reviewerRemarks || 'Processed via Manager Dashboard.', reviewerId, leaveId]);
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

    // Non-managerial staff must be assigned to log progress
    const reporterRow = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [reporterId]);
    if (reporterRow.rows[0] && !userIsManagerial(reporterRow.rows[0])) {
      const assignCheck = await db.query(
        'SELECT assignment_id FROM project_assignments WHERE user_id = $1 AND project_code = $2 LIMIT 1',
        [reporterId, projectCode]
      );
      if (assignCheck.rows.length === 0) {
        return res.status(403).json({ error: `You are not assigned to project ${projectCode}. You cannot log progress for a project you are not assigned to.` });
      }
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
      `SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1`,
      [userId]
    );

    if (userRoleResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const userRow = userRoleResult.rows[0];
    if (userIsManagerial(userRow)) {
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
         WHERE COALESCE(p.status, 'ACTIVE') != 'INACTIVE'
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
              AND COALESCE(p.status, 'ACTIVE') != 'INACTIVE'
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
       WHERE COALESCE(status, 'ACTIVE') != 'INACTIVE'
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
      SELECT p.project_code, p.project_name, p.account_manager_id, p.account_manager_ids, p.manager_ids,
             p.budget_hours, p.total_tracked_hours, p.status, p.start_date, p.end_date, p.created_at,
             u.full_name AS account_manager_name,
             (SELECT array_agg(full_name ORDER BY full_name) FROM users WHERE user_id = ANY(p.account_manager_ids::uuid[])) AS account_manager_names,
             (SELECT array_agg(full_name ORDER BY full_name) FROM users WHERE user_id = ANY(p.manager_ids::uuid[])) AS manager_names
      FROM projects p
      LEFT JOIN users u ON u.user_id = p.account_manager_id
      ORDER BY p.created_at DESC
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
      'SELECT project_code, project_name FROM projects WHERE (project_code ILIKE $1 OR project_name ILIKE $1) AND COALESCE(status, \'ACTIVE\') != \'INACTIVE\' ORDER BY project_code ASC LIMIT 20',
      [query]
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch project suggestions.', detail: error.message });
  }
});

// Replaces a project's account_manager/manager project_assignments rows with the given sets
// (staff assignments are left untouched). This is the write-path for keeping the
// per-project role roster (used by the Org Tree, Team pages, etc.) in sync with
// whatever HR picks on the Project Codes form or the Users page "Project Roles" modal.
async function syncProjectRoleAssignments(projectCode, { accountManagerIds = [], managerIds = [] }, assignedBy) {
  const code = projectCode.toUpperCase().trim();
  await db.query(
    `DELETE FROM project_assignments WHERE project_code = $1 AND project_role IN ('account_manager', 'manager')`,
    [code]
  );
  const rows = [
    ...accountManagerIds.map((id) => ({ id, role: 'account_manager' })),
    ...managerIds.map((id) => ({ id, role: 'manager' })),
  ];
  for (const r of rows) {
    await db.query(
      `INSERT INTO project_assignments (assignment_id, user_id, project_code, project_role, assigned_by)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, project_code) DO UPDATE SET project_role = EXCLUDED.project_role, assigned_by = EXCLUDED.assigned_by`,
      [randomUUID(), r.id, code, r.role, assignedBy]
    );
  }
}

// Recomputes projects.account_manager_ids / manager_ids / account_manager_id from
// project_assignments — the reverse direction of syncProjectRoleAssignments, so edits
// made via the Users page "Project Roles" modal also show up on the Projects page.
async function syncProjectManagerFields(projectCodes) {
  for (const code of new Set(projectCodes.filter(Boolean).map((c) => c.toUpperCase().trim()))) {
    await db.query(
      `UPDATE projects p SET
         account_manager_ids = COALESCE((SELECT array_agg(pa.user_id) FROM project_assignments pa WHERE pa.project_code = p.project_code AND pa.project_role = 'account_manager'), '{}'),
         manager_ids = COALESCE((SELECT array_agg(pa.user_id) FROM project_assignments pa WHERE pa.project_code = p.project_code AND pa.project_role = 'manager'), '{}'),
         account_manager_id = (SELECT pa.user_id FROM project_assignments pa WHERE pa.project_code = p.project_code AND pa.project_role = 'account_manager' ORDER BY pa.created_at ASC LIMIT 1)
       WHERE p.project_code = $1`,
      [code]
    );
  }
}

app.post('/api/v1/projects/create', async (req, res) => {
  const { creatorId, projectCode, projectName, accountManagerIds, managerIds, budgetHours, startDate, endDate } = req.body;

  if (!creatorId || !projectCode || !projectName) {
    return res.status(400).json({ error: 'creatorId, projectCode and projectName are required.' });
  }

  try {
    const creatorCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [creatorId]);
    if (creatorCheck.rows.length === 0 || !userIsManagerial(creatorCheck.rows[0])) {
      return res.status(403).json({ error: 'Access Denied: Only authorized HR or manager users may issue new project codes.' });
    }

    const code = projectCode.toUpperCase().trim();
    const amIds = Array.isArray(accountManagerIds) ? accountManagerIds : [];
    const mgrIds = Array.isArray(managerIds) ? managerIds : [];

    const insertResult = await db.query(
      `INSERT INTO projects (project_code, project_name, budget_hours, total_tracked_hours, start_date, end_date, created_at)
       VALUES ($1, $2, $3, 0.00, $4, $5, CURRENT_TIMESTAMP)
       RETURNING *;`,
      [code, projectName.trim(), parseFloat(budgetHours) || 0, startDate || null, endDate || null]
    );

    await syncProjectRoleAssignments(code, { accountManagerIds: amIds, managerIds: mgrIds }, creatorId);
    await syncProjectManagerFields([code]);

    const finalProject = await db.query('SELECT * FROM projects WHERE project_code = $1', [code]);
    res.status(201).json({ success: true, data: finalProject.rows[0] || insertResult.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create project code.', detail: error.message });
  }
});

// PATCH /api/v1/projects/:projectCode - edit an existing project
app.patch('/api/v1/projects/:projectCode', async (req, res) => {
  const { projectCode } = req.params;
  const { projectName, accountManagerIds, managerIds, budgetHours, startDate, endDate, editorId } = req.body;
  if (!editorId) return res.status(400).json({ error: 'editorId is required.' });
  try {
    const editorCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || !userIsManagerial(editorCheck.rows[0])) {
      return res.status(403).json({ error: 'Access Denied.' });
    }
    const code = projectCode.toUpperCase().trim();
    const updates = [];
    const values = [];
    let idx = 1;
    if (projectName !== undefined) { updates.push(`project_name = $${idx++}`); values.push(projectName.trim()); }
    if (budgetHours !== undefined) { updates.push(`budget_hours = $${idx++}`); values.push(parseFloat(budgetHours) || 0); }
    if (startDate !== undefined) { updates.push(`start_date = $${idx++}`); values.push(startDate || null); }
    if (endDate !== undefined) { updates.push(`end_date = $${idx++}`); values.push(endDate || null); }
    const rolesProvided = Array.isArray(accountManagerIds) || Array.isArray(managerIds);
    if (updates.length === 0 && !rolesProvided) return res.status(400).json({ error: 'No fields to update.' });

    if (updates.length > 0) {
      values.push(code);
      await db.query(`UPDATE projects SET ${updates.join(', ')} WHERE project_code = $${idx}`, values);
    }

    if (rolesProvided) {
      await syncProjectRoleAssignments(code, {
        accountManagerIds: Array.isArray(accountManagerIds) ? accountManagerIds : [],
        managerIds: Array.isArray(managerIds) ? managerIds : [],
      }, editorId);
      await syncProjectManagerFields([code]);
    }

    const result = await db.query('SELECT * FROM projects WHERE project_code = $1', [code]);
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
    const editorCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || !userIsManagerial(editorCheck.rows[0])) {
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

// FETCH A STAFF MEMBER'S OWN BUDGET REQUESTS (full detail incl. justification/reviewer remarks)
app.get('/api/v1/projects/budget-requests/mine/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(200).json({ success: true, data: [] });
    }

    const result = await db.query(
      `SELECT br.*, p.project_name
       FROM budget_requests br
       LEFT JOIN projects p ON br.project_code = p.project_code
       WHERE br.user_id = $1
       ORDER BY br.created_at DESC`,
      [userId]
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch your budget requests.', detail: error.message });
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
      `SELECT br.*, p.project_name, u.full_name AS requester_name, u.email AS requester_email,
              r.full_name AS reviewer_name
       FROM budget_requests br
       JOIN projects p ON br.project_code = p.project_code
       LEFT JOIN users u ON u.user_id = br.user_id
       LEFT JOIN users r ON r.user_id = br.reviewed_by
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

// HR: update user roles (multi-role assignment)
app.patch('/api/v1/hr/update-user-roles', async (req, res) => {
  const { requesterId, userId, roles } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  if (!userId || !Array.isArray(roles) || roles.length === 0) {
    return res.status(400).json({ error: 'userId and a non-empty roles array are required.' });
  }
  const ALLOWED = ['hr', 'account_manager', 'manager', 'staff'];
  const cleaned = roles.map((r) => String(r).trim().toLowerCase()).filter((r) => ALLOWED.includes(r));
  if (cleaned.length === 0) {
    return res.status(400).json({ error: 'No valid roles provided. Allowed: hr, account_manager, manager, staff.' });
  }
  // Determine primary role by highest privilege: hr > account_manager > manager > staff
  const PRIORITY = ['hr', 'account_manager', 'manager', 'staff'];
  const primaryRole = PRIORITY.find((r) => cleaned.includes(r)) || cleaned[0];
  try {
    const resolvedPrimary = await getDefaultUserRole(primaryRole);
    await db.query(
      'UPDATE users SET user_role = $1, user_roles = $2 WHERE user_id = $3',
      [resolvedPrimary, cleaned, userId]
    );
    const updated = await db.query(
      'SELECT user_id, full_name, email, user_role, user_roles, account_status FROM users WHERE user_id = $1 LIMIT 1',
      [userId]
    );
    return res.status(200).json({ success: true, data: updated.rows[0] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update user roles.', detail: err.message });
  }
});

// HR: get all active users for role management
app.get('/api/v1/hr/active-users', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  try {
    const result = await db.query(
      `SELECT user_id, full_name, email, user_role, user_roles, account_status, created_at, leave_entitlement_days
       FROM users
       WHERE account_status = 'active' AND NOT is_hidden
       ORDER BY full_name ASC`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch active users.', detail: err.message });
  }
});

// HR: set a per-employee leave entitlement override
app.patch('/api/v1/hr/update-leave-entitlement', async (req, res) => {
  const { requesterId, userId, leaveEntitlementDays } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  const days = Number(leaveEntitlementDays);
  if (!userId || !Number.isInteger(days) || days < 0) {
    return res.status(400).json({ error: 'userId and a non-negative integer leaveEntitlementDays are required.' });
  }
  try {
    const updated = await db.query(
      'UPDATE users SET leave_entitlement_days = $1 WHERE user_id = $2 RETURNING user_id, full_name, leave_entitlement_days',
      [days, userId]
    );
    if (!updated.rows[0]) return res.status(404).json({ error: 'User not found.' });
    return res.status(200).json({ success: true, data: updated.rows[0] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update leave entitlement.', detail: err.message });
  }
});

// HR: list a user's current project-role assignments (for the "Project Roles" modal)
app.get('/api/v1/hr/user-project-roles/:userId', async (req, res) => {
  const { userId } = req.params;
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  try {
    const result = await db.query(
      `SELECT pa.assignment_id, pa.project_code, pa.project_role, p.project_name
       FROM project_assignments pa
       LEFT JOIN projects p ON p.project_code = pa.project_code
       WHERE pa.user_id = $1
       ORDER BY pa.project_code ASC`,
      [userId]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch project roles.', detail: err.message });
  }
});

// HR: replace a user's full set of project-role assignments in one call (the
// "Manage Project Roles" modal Save All action), then resync every affected
// project's account_manager_ids/manager_ids so the Projects page stays in sync.
app.post('/api/v1/hr/set-project-roles', async (req, res) => {
  const { requesterId, userId, assignments } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  const ALLOWED_ROLES = ['hr', 'account_manager', 'manager', 'staff'];
  if (!userId || !Array.isArray(assignments)) {
    return res.status(400).json({ error: 'userId and an assignments array are required.' });
  }
  const cleaned = assignments
    .map((a) => ({ projectCode: String(a.projectCode || '').toUpperCase().trim(), projectRole: a.projectRole }))
    .filter((a) => a.projectCode && ALLOWED_ROLES.includes(a.projectRole));

  try {
    const existing = await db.query('SELECT DISTINCT project_code FROM project_assignments WHERE user_id = $1', [userId]);
    const previousCodes = existing.rows.map((r) => r.project_code);

    await db.query('DELETE FROM project_assignments WHERE user_id = $1', [userId]);
    for (const a of cleaned) {
      await db.query(
        `INSERT INTO project_assignments (assignment_id, user_id, project_code, project_role, assigned_by)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, project_code) DO UPDATE SET project_role = EXCLUDED.project_role, assigned_by = EXCLUDED.assigned_by`,
        [randomUUID(), userId, a.projectCode, a.projectRole, requesterId]
      );
    }

    const affectedCodes = [...new Set([...previousCodes, ...cleaned.map((a) => a.projectCode)])];
    await syncProjectManagerFields(affectedCodes);

    return res.status(200).json({ success: true, data: cleaned });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update project roles.', detail: err.message });
  }
});

// GET /api/v1/account-manager/:userId/my-projects — projects managed by this AM with team members
app.get('/api/v1/account-manager/:userId/my-projects', async (req, res) => {
  const { userId } = req.params;
  try {
    // Verify the user is an account manager
    const userRow = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (!userRow.rows[0] || !userHasRole(userRow.rows[0], 'account_manager')) {
      return res.status(403).json({ error: 'Account Manager access required.' });
    }
    // Get projects where this user is account_manager
    const projectsRes = await db.query(
      `SELECT p.project_code, p.project_name, p.budget_hours, p.status, p.created_at
       FROM projects p
       WHERE p.account_manager_id = $1::uuid OR $1::uuid = ANY(p.account_manager_ids::uuid[])
       ORDER BY p.project_code ASC`,
      [userId]
    );
    // For each project, get the team members with their project roles
    const projectsWithTeam = await Promise.all(projectsRes.rows.map(async (p) => {
      const members = await db.query(
        `SELECT u.user_id, u.full_name, u.email, u.user_role, u.user_roles, u.supervisor_id,
                pa.project_role, pa.assignment_id
         FROM project_assignments pa
         JOIN users u ON u.user_id = pa.user_id
         WHERE pa.project_code = $1 AND u.account_status = 'active'
         ORDER BY pa.project_role ASC, u.full_name ASC`,
        [p.project_code]
      );
      return { ...p, members: members.rows };
    }));
    return res.status(200).json({ success: true, data: projectsWithTeam });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch account manager projects.', detail: error.message });
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
    const reviewerProfile = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
    if (!userHasRole(reviewerProfile.rows[0], 'account_manager')) return res.status(403).json({ error: 'Only Account Managers can perform final budget approval.' });

    const result = await db.query(
      "UPDATE budget_requests SET status = $1, reviewed_by = $2, reviewed_at = CURRENT_TIMESTAMP WHERE request_id = $3 AND status = 'MANAGER_APPROVED' RETURNING *",
      [action.toUpperCase(), reviewerId, requestId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Budget request not found or not awaiting AM approval.' });

    const budgetRow = result.rows[0];

    if (action.toUpperCase() === 'APPROVED') {
      // Increase the project's total budget hours
      await db.query('UPDATE projects SET budget_hours = budget_hours + $1 WHERE project_code = $2', [budgetRow.requested_hours, budgetRow.project_code]);
      // Also increase the specific staff member's individual hour allocation for this project
      // so their personal budget and the utilisation calculation both reflect the extra hours
      await db.query(
        `UPDATE hour_allocations
         SET hours_per_week = hours_per_week + $1
         WHERE user_id = $2 AND project_code = $3
           AND account_manager_status = 'APPROVED'`,
        [budgetRow.requested_hours, budgetRow.user_id, budgetRow.project_code]
      );
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
    const editorCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || !userIsManagerial(editorCheck.rows[0])) {
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

// REACTIVATE PROJECT (sets ACTIVE again — staff assignments must be re-added manually)
app.patch('/api/v1/projects/:projectCode/reactivate', async (req, res) => {
  const { projectCode } = req.params;
  const { editorId } = req.body;
  if (!editorId) return res.status(400).json({ error: 'editorId is required.' });
  try {
    const editorCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || !userIsManagerial(editorCheck.rows[0])) {
      return res.status(403).json({ error: 'Access Denied.' });
    }
    const code = projectCode.toUpperCase().trim();
    const result = await db.query(
      `UPDATE projects SET status = 'ACTIVE' WHERE project_code = $1 RETURNING *`,
      [code]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    res.status(200).json({ success: true, message: `Project ${code} reactivated.`, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reactivate project.', detail: error.message });
  }
});

app.get('/api/v1/users', async (req, res) => {
  const role = normalizeRole(req.query.role);

  try {
    if (role) {
      // Check both legacy user_role AND user_roles[] array for multi-role support
      const filtered = await db.query(
        `SELECT user_id, full_name, email, user_role::text AS user_role, user_roles, supervisor_id
         FROM users
         WHERE (LOWER(user_role::text) = $1 OR user_roles @> ARRAY[$1]::text[])
           AND account_status = 'active' AND NOT is_hidden
         ORDER BY full_name ASC`,
        [role]
      );
      return res.status(200).json({ success: true, data: filtered.rows });
    }

    const result = await db.query(
      `SELECT user_id, full_name, email, user_role, user_roles, supervisor_id
       FROM users
       WHERE account_status = 'active' AND NOT is_hidden
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
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
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

// PATCH /api/v1/users/unset-supervisor — remove a staff member from any team (HR action)
app.patch('/api/v1/users/unset-supervisor', async (req, res) => {
  const { staffId } = req.body;
  if (!staffId) return res.status(400).json({ error: 'staffId is required.' });
  try {
    await db.query('UPDATE users SET supervisor_id = NULL WHERE user_id = $1', [staffId]);
    res.status(200).json({ success: true, message: 'Staff member unassigned from team.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to unset supervisor.', detail: error.message });
  }
});

// PATCH /api/v1/users/remove-from-team — unlink a staff member from a manager's team
app.patch('/api/v1/users/remove-from-team', async (req, res) => {
  const { managerId, staffId } = req.body;
  if (!managerId || !staffId) {
    return res.status(400).json({ error: 'managerId and staffId are required.' });
  }
  try {
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
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

// HR: clear a staff member's supervisor regardless of who that supervisor currently is —
// used from the Hierarchy tree, where HR isn't necessarily that supervisor themselves.
app.patch('/api/v1/hr/remove-supervisor', async (req, res) => {
  const { requesterId, staffId } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  if (!staffId) return res.status(400).json({ error: 'staffId is required.' });
  try {
    await db.query('UPDATE users SET supervisor_id = NULL WHERE user_id = $1', [staffId]);
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove supervisor.', detail: error.message });
  }
});

// GET /api/v1/projects/utilisation-detail - weighted utilisation per project (for HR/manager portals)
app.get('/api/v1/projects/utilisation-detail', async (req, res) => {
  try {
    const result = await db.query(`
      WITH latest_progress AS (
        SELECT DISTINCT ON (reporter_id, project_code)
          reporter_id AS user_id, project_code, completion_percentage
        FROM project_progress_logs
        ORDER BY reporter_id, project_code, logged_at DESC
      ),
      latest_allocation AS (
        -- Latest approved allocation per user per project (fixes hours_requested bug)
        SELECT DISTINCT ON (user_id, project_code)
          user_id, project_code, hours_per_week
        FROM hour_allocations
        WHERE account_manager_status = 'APPROVED'
        ORDER BY user_id, project_code, created_at DESC
      ),
      staff_count AS (
        SELECT project_code, COUNT(*) AS cnt
        FROM project_assignments
        GROUP BY project_code
      ),
      user_hours AS (
        SELECT pa.project_code, pa.user_id,
               COALESCE(
                 -- Use approved allocation if it exists and is > 0
                 NULLIF((SELECT la.hours_per_week FROM latest_allocation la
                         WHERE la.user_id = pa.user_id AND la.project_code = pa.project_code LIMIT 1), 0),
                 -- Fallback: split project budget equally among all assigned staff
                 p.budget_hours / NULLIF(sc.cnt, 0)::numeric,
                 0
               ) AS allocated_hours
        FROM project_assignments pa
        JOIN projects p ON p.project_code = pa.project_code
        LEFT JOIN staff_count sc ON sc.project_code = pa.project_code
      )
      SELECT
        p.project_code,
        p.project_name,
        p.budget_hours,
        p.status,
        p.created_at,
        CASE WHEN SUM(uh.allocated_hours) > 0
          THEN ROUND(SUM(COALESCE(lp.completion_percentage, 0) * uh.allocated_hours / 100.0) / NULLIF(SUM(uh.allocated_hours), 0) * 100)
          ELSE 0
        END AS weighted_utilisation_pct,
        COUNT(DISTINCT uh.user_id) AS assigned_count,
        u.full_name AS account_manager_name
      FROM projects p
      LEFT JOIN user_hours uh ON uh.project_code = p.project_code
      LEFT JOIN latest_progress lp ON lp.user_id = uh.user_id AND lp.project_code = p.project_code
      LEFT JOIN users u ON u.user_id = p.account_manager_id
      GROUP BY p.project_code, p.project_name, p.budget_hours, p.status, p.created_at, u.full_name
      ORDER BY p.created_at DESC
    `);
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch utilisation detail.', detail: error.message });
  }
});

// GET /api/v1/manager/:managerId/my-projects - projects this manager/AM is in charge of (for the Team page banner)
app.get('/api/v1/manager/:managerId/my-projects', async (req, res) => {
  const { managerId } = req.params;
  try {
    const result = await db.query(
      `SELECT project_code, project_name, status,
              CASE WHEN account_manager_id = $1::uuid OR $1::uuid = ANY(account_manager_ids::uuid[]) THEN 'account_manager' ELSE 'manager' END AS my_role
       FROM projects
       WHERE account_manager_id = $1::uuid OR $1::uuid = ANY(account_manager_ids::uuid[]) OR $1::uuid = ANY(manager_ids::uuid[])
       ORDER BY project_code ASC`,
      [managerId]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch your projects.', detail: error.message });
  }
});

// GET /api/v1/manager/:managerId/team-assignments - staff + their project assignments for manager's team
app.get('/api/v1/manager/:managerId/team-assignments', async (req, res) => {
  const { managerId } = req.params;
  try {
    const result = await db.query(`
      SELECT
        u.user_id, u.full_name, u.email,
        pa.project_code,
        p.project_name,
        p.status AS project_status,
        (
          SELECT completion_percentage
          FROM project_progress_logs pl
          WHERE pl.reporter_id = u.user_id AND pl.project_code = pa.project_code
          ORDER BY pl.logged_at DESC LIMIT 1
        ) AS latest_progress
      FROM users u
      LEFT JOIN project_assignments pa ON pa.user_id = u.user_id
      LEFT JOIN projects p ON p.project_code = pa.project_code
      WHERE u.supervisor_id = $1
      ORDER BY u.full_name, pa.project_code
    `, [managerId]);
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch team assignments.', detail: error.message });
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

// GET /api/v1/projects/:projectCode/members — all users assigned to a project (for hierarchy view)
app.get('/api/v1/projects/:projectCode/members', async (req, res) => {
  const { projectCode } = req.params;
  try {
    const result = await db.query(
      `SELECT
         u.user_id, u.full_name, u.email, u.user_role, u.user_roles, u.supervisor_id,
         pa.project_role, pa.assignment_id
       FROM project_assignments pa
       JOIN users u ON u.user_id = pa.user_id
       WHERE pa.project_code = $1
         AND u.account_status = 'active'
       ORDER BY pa.project_role ASC, u.full_name ASC`,
      [projectCode.toUpperCase()]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch project members.', detail: error.message });
  }
});

// PATCH /api/v1/projects/assignments/role — update a user's project-specific role
app.patch('/api/v1/projects/assignments/role', async (req, res) => {
  const { managerId, userId, projectCode, projectRole } = req.body;
  const allowed = ['account_manager', 'manager', 'staff'];
  if (!managerId || !userId || !projectCode || !allowed.includes(projectRole)) {
    return res.status(400).json({ error: 'managerId, userId, projectCode and a valid projectRole (account_manager|manager|staff) are required.' });
  }
  try {
    const mgrCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (!mgrCheck.rows[0] || !userIsManagerial(mgrCheck.rows[0])) {
      return res.status(403).json({ error: 'Only manager-level users can update project roles.' });
    }
    const code = projectCode.toUpperCase();
    // A project has at most one Account Manager — demote any existing one when a new person takes the role.
    if (projectRole === 'account_manager') {
      await db.query(
        `UPDATE project_assignments SET project_role = 'manager'
         WHERE project_code = $1 AND project_role = 'account_manager' AND user_id != $2`,
        [code, userId]
      );
    }
    const result = await db.query(
      `UPDATE project_assignments SET project_role = $1
       WHERE user_id = $2 AND project_code = $3
       RETURNING *`,
      [projectRole, userId, code]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Assignment not found.' });
    await syncProjectManagerFields([code]);
    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to update project role.', detail: error.message });
  }
});

// POST /api/v1/projects/assign-bulk - assign multiple staff to a project at once
app.post('/api/v1/projects/assign-bulk', async (req, res) => {
  const { managerId, userIds, projectCode } = req.body;
  if (!managerId || !Array.isArray(userIds) || userIds.length === 0 || !projectCode) {
    return res.status(400).json({ error: 'managerId, userIds (array) and projectCode are required.' });
  }
  try {
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
      return res.status(403).json({ error: 'Only managers can assign projects.' });
    }
    const projectCheck = await db.query('SELECT project_code, budget_hours, project_name FROM projects WHERE project_code = $1 AND COALESCE(status, \'ACTIVE\') != \'INACTIVE\' LIMIT 1', [projectCode]);
    if (projectCheck.rows.length === 0) return res.status(404).json({ error: 'Project code not found or is inactive.' });

    const results = [];
    for (const userId of userIds) {
      // Determine project role for each user being assigned
      // HR/AM/Manager assigns => assign as 'staff' by default unless explicitly given
      const assigneeRow = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [userId]);
      const assigneeRoles = assigneeRow.rows[0]
        ? (Array.isArray(assigneeRow.rows[0].user_roles) && assigneeRow.rows[0].user_roles.length > 0
          ? assigneeRow.rows[0].user_roles : [assigneeRow.rows[0].user_role].filter(Boolean))
        : ['staff'];
      // Default project_role: use the user's highest-privilege role that makes sense for a project
      const PROJECT_ROLE_PRIORITY = ['account_manager', 'manager', 'staff'];
      const defaultProjectRole = PROJECT_ROLE_PRIORITY.find((r) => assigneeRoles.includes(r)) || 'staff';

      // A project has at most one Account Manager — demote any existing one when a new person takes the role.
      if (defaultProjectRole === 'account_manager') {
        await db.query(
          `UPDATE project_assignments SET project_role = 'manager'
           WHERE project_code = $1 AND project_role = 'account_manager' AND user_id != $2`,
          [projectCode, userId]
        );
      }

      const r = await db.query(
        `INSERT INTO project_assignments (assignment_id, user_id, project_code, assigned_by, project_role)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, project_code) DO UPDATE SET assigned_by = EXCLUDED.assigned_by
         RETURNING *`,
        [randomUUID(), userId, projectCode, managerId, defaultProjectRole]
      );
      results.push(r.rows[0]);
    }

    // Auto-distribute project budget hours equally among ALL currently assigned staff
    const budgetHours = Number(projectCheck.rows[0].budget_hours || 0);
    const projectName = projectCheck.rows[0].project_name || projectCode;
    if (budgetHours > 0) {
      const allAssigned = await db.query(
        'SELECT user_id FROM project_assignments WHERE project_code = $1',
        [projectCode]
      );
      const staffCount = allAssigned.rows.length;
      const perStaffHours = Math.round((budgetHours / staffCount) * 100) / 100;

      // Upsert allocation for each assigned staff member (delete old + insert new to avoid duplicates)
      for (const assignedUser of allAssigned.rows) {
        await db.query(
          `DELETE FROM hour_allocations WHERE user_id = $1 AND project_code = $2`,
          [assignedUser.user_id, projectCode]
        );
        await db.query(
          `INSERT INTO hour_allocations (user_id, project_code, hours_per_week, allocated_by, manager_status, account_manager_status)
           VALUES ($1, $2, $3, $4, 'APPROVED', 'APPROVED')`,
          [assignedUser.user_id, projectCode, perStaffHours, managerId]
        );
      }

      // Notify newly assigned staff
      for (const userId of userIds) {
        try {
          await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [
            userId, 'Project Assigned — Budget Allocated',
            `You have been assigned to ${projectCode} (${projectName}) with ${perStaffHours} hrs. Budget of ${budgetHours} hrs split equally among ${staffCount} team member${staffCount !== 1 ? 's' : ''}.`,
          ]);
        } catch (_) {}
      }

      // Notify manager
      try {
        await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [
          managerId, 'Staff Assigned to Project',
          `${userIds.length} staff added to ${projectCode}. Each member now has ${perStaffHours} hrs (${budgetHours} hrs ÷ ${staffCount} staff).`,
        ]);
      } catch (_) {}

      // Notify account manager
      try {
        const amRow = await db.query('SELECT account_manager_id FROM projects WHERE project_code = $1 LIMIT 1', [projectCode]);
        if (amRow.rows[0]?.account_manager_id) {
          await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [
            amRow.rows[0].account_manager_id, 'Project Team Updated',
            `${userIds.length} new staff added to ${projectCode}. Budget redistributed: ${perStaffHours} hrs/member (${staffCount} members).`,
          ]);
        }
      } catch (_) {}
    } else {
      // No budget set — just notify assignment
      for (const userId of userIds) {
        try {
          await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)',
            [userId, 'Project Assigned', `You have been assigned to project ${projectCode}.`]);
        } catch (_) {}
      }
    }

    await syncProjectManagerFields([projectCode]);

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
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
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

// REMOVE a project assignment from a staff member (manager only)
// Note: uses /assignments/ path to avoid conflict with DELETE /projects/:projectCode
app.delete('/api/v1/assignments/remove', async (req, res) => {
  const { managerId, userId, projectCode } = req.body;
  if (!managerId || !userId || !projectCode) {
    return res.status(400).json({ error: 'managerId, userId and projectCode are required.' });
  }
  try {
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
      return res.status(403).json({ error: 'Only manager-level users can remove project assignments.' });
    }
    const result = await db.query(
      'DELETE FROM project_assignments WHERE user_id = $1 AND project_code = $2 RETURNING *',
      [userId, projectCode.toUpperCase().trim()]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Assignment not found.' });
    }
    // Also clear any pending/approved allocations for this user+project
    await db.query(
      'DELETE FROM hour_allocations WHERE user_id = $1 AND project_code = $2',
      [userId, projectCode.toUpperCase().trim()]
    );
    await syncProjectManagerFields([projectCode]);
    return res.status(200).json({ success: true, message: `Assignment removed for ${projectCode}.` });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to remove assignment.', detail: error.message });
  }
});

app.get('/api/v1/manager/:managerId/attendance-logs', async (req, res) => {
  const { managerId } = req.params;

  try {
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
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
         al.entry_type,
         al.is_manual_entry,
         al.remark,
         al.created_at,
         COALESCE(
           (SELECT json_agg(json_build_object('project_code', aa.project_code, 'allocated_hours', aa.allocated_hours, 'accumulated_hours', aa.accumulated_hours, 'status', aa.status, 'edited_after_completion', aa.edited_after_completion, 'last_edited_at', aa.last_edited_at) ORDER BY aa.seq)
            FROM attendance_allocations aa WHERE aa.attendance_id = al.attendance_id),
           '[]'
         ) AS allocations
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

// HR: attendance logs across ALL employees (unlike the manager-scoped endpoint above,
// which is limited to direct reports)
app.get('/api/v1/hr/attendance-logs', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;

  try {
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
         al.entry_type,
         al.is_manual_entry,
         al.remark,
         al.created_at,
         COALESCE(
           (SELECT json_agg(json_build_object('project_code', aa.project_code, 'allocated_hours', aa.allocated_hours, 'accumulated_hours', aa.accumulated_hours, 'status', aa.status, 'edited_after_completion', aa.edited_after_completion, 'last_edited_at', aa.last_edited_at) ORDER BY aa.seq)
            FROM attendance_allocations aa WHERE aa.attendance_id = al.attendance_id),
           '[]'
         ) AS allocations
       FROM attendance_logs al
       JOIN users u ON u.user_id = al.user_id
       ORDER BY al.created_at DESC
       LIMIT 500`
    );

    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch attendance logs.', detail: error.message });
  }
});

// HR: leave requests across ALL employees, any status — the manager-scoped endpoints only
// surface a supervisor's own team. Gives HR the full picture needed to edit a request.
app.get('/api/v1/hr/leave-requests', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;

  try {
    const result = await db.query(
      `SELECT la.leave_id, la.user_id, u.full_name, u.email, la.category, la.start_date, la.end_date,
              la.reason, la.workflow_status, la.reviewer_remarks, la.is_late_submission, la.mc_file_url,
              la.created_at, la.updated_at, r.full_name AS reviewer_name
       FROM leave_applications la
       JOIN users u ON la.user_id = u.user_id
       LEFT JOIN users r ON r.user_id = la.reviewed_by
       ORDER BY la.created_at DESC
       LIMIT 500`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch leave requests.', detail: error.message });
  }
});

app.get('/api/v1/manager/:managerId/progress-logs', async (req, res) => {
  const { managerId } = req.params;

  try {
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
      return res.status(403).json({ error: 'Unauthorized manager access.' });
    }

    await applyDailyProgressBaselineForManagerTeam(managerId);

    const result = await db.query(
      `SELECT
         ppl.log_id,
         ppl.project_code,
         p.project_name,
         ppl.reporter_id,
         u.full_name AS reporter_name,
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
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
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