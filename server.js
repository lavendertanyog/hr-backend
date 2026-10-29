const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { randomUUID, randomBytes, createHash } = require('crypto');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const db = require('./db');

const isRenderEnvironment = Boolean(process.env.RENDER) || Boolean(process.env.RENDER_SERVICE_NAME);
if (!isRenderEnvironment) {
  dotenv.config();
}

const { Expo } = require('expo-server-sdk');
const expo = new Expo();

// Email sending, via AWS SES — falls back to logging when no AWS credentials are configured,
// so any flow that sends email stays fully testable locally without sending real mail. Sends
// from the verified mail.nextantech.com domain identity now that its DKIM records are in place.
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const { GoogleGenAI, MediaResolution, ThinkingLevel } = require('@google/genai');
const sesClient = process.env.AWS_ACCESS_KEY_ID
  ? new SESClient({ region: process.env.AWS_REGION || 'ap-southeast-1' })
  : null;
const SES_EMAIL_FROM = process.env.SES_EMAIL_FROM || 'noreply@mail.nextantech.com';
const SES_SENDER_NAME = process.env.SES_SENDER_NAME || 'Nextan Portal';
// A bare address shows as just "noreply" in most mail clients — the quoted display-name form
// (RFC 5322) makes it show as "Nextan Portal" instead, same address underneath.
const SES_SOURCE_HEADER = `"${SES_SENDER_NAME}" <${SES_EMAIL_FROM}>`;
// Routes every send through the "nextan-timesheet" configuration set (CloudWatch destination
// tracking Sends/Deliveries/Hard bounces/Complaints/Delivery delays) so bounce and complaint
// rates are actually visible instead of silently happening. The `email-type` message tag lets
// CloudWatch break metrics down per email kind instead of one lumped-together bucket.
const SES_CONFIGURATION_SET = process.env.SES_CONFIGURATION_SET || 'nextan-timesheet';

async function sendEmail(toEmail, subject, html, emailType = 'general') {
  if (!sesClient) {
    console.log(`[email] No AWS credentials configured — would have sent "${subject}" to ${toEmail}.`);
    return;
  }
  await sesClient.send(new SendEmailCommand({
    Source: SES_SOURCE_HEADER,
    Destination: { ToAddresses: [toEmail] },
    Message: {
      Subject: { Data: subject, Charset: 'UTF-8' },
      Body: { Html: { Data: html, Charset: 'UTF-8' } },
    },
    ConfigurationSetName: SES_CONFIGURATION_SET,
    Tags: [{ Name: 'email-type', Value: emailType }],
  }));
}

// Shared branded shell for transactional emails — logo, heading, body copy, then either a
// clickable button OR a plain-text code block (never both), then a footer note. `linkOrigin`
// picks the logo to match whichever portal triggered the email. The code-block variant exists
// specifically so emails like the temporary password below contain no link at all — Microsoft
// and other mail filters weigh links heavily when scoring a message as phishing, and a brand-new
// sending domain is already fighting an uphill reputation battle without one.
function brandedEmailHtml({ linkOrigin, heading, bodyHtml, buttonText, buttonUrl, codeBlock, footerText }) {
  const logoUrl = `${linkOrigin}/nextan-logo.png`;
  const actionHtml = codeBlock
    ? `<div style="background:#f1f5f9;border-radius:12px;padding:16px;text-align:center;">
         <span style="font-family:'Courier New',monospace;font-size:20px;font-weight:700;letter-spacing:2px;color:#0f172a;">${codeBlock}</span>
       </div>`
    : `<a href="${buttonUrl}" style="display:inline-block;background:#0c3b8f;color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;padding:12px 28px;border-radius:12px;">${buttonText}</a>`;
  return `<!doctype html>
<html><head><meta charset="utf-8" /></head>
<body style="margin:0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 16px;font-family:Arial,Helvetica,sans-serif;">
  <tr><td align="center">
    <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:16px;overflow:hidden;">
      <tr><td style="padding:32px 40px 0 40px;text-align:center;">
        <img src="${logoUrl}" alt="Nextan" height="32" style="height:32px;width:auto;" />
      </td></tr>
      <tr><td style="padding:28px 40px 0 40px;">
        ${heading ? `<h1 style="margin:0;font-size:20px;line-height:1.3;color:#0f172a;font-weight:700;">${heading}</h1>` : ''}
        <p style="margin:${heading ? '12px' : '0'} 0 0 0;font-size:14px;line-height:1.6;color:#475569;">
          ${bodyHtml}
        </p>
      </td></tr>
      <tr><td style="padding:24px 40px 0 40px;text-align:center;">
        ${actionHtml}
      </td></tr>
      <tr><td style="padding:28px 40px 32px 40px;">
        <hr style="border:none;border-top:1px solid #e2e8f0;margin:0 0 20px 0;" />
        <p style="margin:0;font-size:12px;line-height:1.6;color:#94a3b8;">
          ${footerText}
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>`;
}

async function sendTemporaryPasswordEmail(toEmail, tempPassword, portalOrigin) {
  // No link at all, by design — see brandedEmailHtml's comment. The temp password itself is the
  // whole "action"; the user logs in with it directly and changes it from their Profile page.
  const html = brandedEmailHtml({
    linkOrigin: portalOrigin,
    heading: 'Your temporary password',
    bodyHtml: "We received a request to reset the password for your Nextan Portal account. Use the temporary password below to log in, then set a new password from your Profile page.",
    codeBlock: tempPassword,
    footerText: "If you didn't request a password reset, please let your HR admin know - your password has already been changed to the one above.",
  });
  await sendEmail(toEmail, 'Your temporary Nextan Portal password', html, 'password-reset');
}

async function sendVerificationEmail(toEmail, verifyUrl) {
  const html = brandedEmailHtml({
    linkOrigin: new URL(verifyUrl).origin,
    heading: 'Verify your email',
    bodyHtml: `Confirm this is your email address (${toEmail}) to finish setting up your account - this link expires in 24 hours.`,
    buttonText: 'Verify email',
    buttonUrl: verifyUrl,
    footerText: "If you didn't create an account, you can safely ignore this email.",
  });
  await sendEmail(toEmail, 'Verify your Nextan Portal email', html, 'email-verification');
}

const STAFF_PORTAL_URL = process.env.STAFF_PORTAL_URL || 'https://staff.nextantech.com';

async function sendClockInReminderEmail(toEmail, fullName) {
  const html = brandedEmailHtml({
    linkOrigin: STAFF_PORTAL_URL,
    heading: 'Time to clock in',
    bodyHtml: "Hi, it's past 8:30am and you haven't clocked in today. Head to the Staff Portal to clock in.",
    buttonText: 'Clock in now',
    buttonUrl: `${STAFF_PORTAL_URL}/attendance`,
    footerText: 'Already clocked in? You can ignore this.',
  });
  await sendEmail(toEmail, "You haven't clocked in yet", html, 'clockin-reminder');
}

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

// Project lifecycle: ACTIVE -> DEPLOYED -> MAINTENANCE (-> DEPLOYED again). Only HR and
// Account Managers may move a project between these. Legacy INACTIVE rows (from the old
// Deactivate action) are treated as DEPLOYED everywhere.
function userCanManageProjectLifecycle(userRow) {
  return userHasRole(userRow, 'hr') || userHasRole(userRow, 'account_manager');
}

// Budget request reviewers: a manager may only review requests on projects they manage
// (projects.manager_ids), and an Account Manager only on projects they are the Account
// Manager of. HR / is_admin users skip the project check.
function userIsHrOrAdmin(userRow) {
  return Boolean(userRow?.is_admin) || userHasRole(userRow, 'hr');
}

async function isProjectManagerOf(userId, projectCode) {
  const r = await db.query(
    'SELECT 1 FROM projects WHERE project_code = $1 AND $2::uuid = ANY(manager_ids::uuid[])',
    [projectCode, userId]
  );
  return r.rows.length > 0;
}

async function isProjectAccountManagerOf(userId, projectCode) {
  const r = await db.query(
    `SELECT 1 FROM projects
     WHERE project_code = $1 AND (account_manager_id = $2::uuid OR $2::uuid = ANY(account_manager_ids::uuid[]))`,
    [projectCode, userId]
  );
  return r.rows.length > 0;
}

// Returns the first of the given project codes that is DEPLOYED (or legacy INACTIVE), or null.
// Deployed projects keep their assignments, so this — not the assignment check — is what stops
// time, progress and budget requests being logged against them.
async function findDeployedProjectCode(projectCodes) {
  const codes = [...new Set(projectCodes.filter(Boolean).map((c) => String(c).toUpperCase().trim()))];
  if (codes.length === 0) return null;
  const result = await db.query(
    `SELECT project_code FROM projects WHERE project_code = ANY($1) AND status IN ('DEPLOYED', 'INACTIVE') LIMIT 1`,
    [codes]
  );
  return result.rows[0]?.project_code || null;
}

function deployedProjectError(projectCode) {
  return `Project ${projectCode} has been deployed. Ask HR or an Account Manager to reactivate it for maintenance before logging work against it.`;
}

// Standard date format used across all notification/inbox text (matches the "DD Mon YYYY" TO_CHAR format used elsewhere)
// Hourly leave: 1 to 4 hours of one day, in half-hour steps, for Annual or Emergency leave (sick
// leave stays full-day, as it goes with an MC). Balances count it as hours / LEAVE_DAY_HOURS days.
const LEAVE_DAY_HOURS = 8;
const LEAVE_HOURS_MIN = 1;
const LEAVE_HOURS_MAX = 4;
const HOURLY_LEAVE_CATEGORIES = ['ANNUAL', 'EMERGENCY'];
// Days a leave counts for, in SQL: hours as a fraction of a day, otherwise every calendar day.
const LEAVE_DAYS_SQL = `(CASE WHEN leave_hours IS NOT NULL THEN leave_hours / ${LEAVE_DAY_HOURS}.0 ELSE (end_date::date - start_date::date + 1) END)`;

// Checks the hours on a leave request: null for a full-day request, or { hours } / { error }.
function parseLeaveHours(hours, category, startDate, endDate) {
  if (hours === undefined || hours === null || hours === '') return null;
  const h = Number(hours);
  if (!HOURLY_LEAVE_CATEGORIES.includes(String(category || '').toUpperCase())) {
    return { error: 'Leave by the hour is only for annual or emergency leave.' };
  }
  if (!Number.isFinite(h) || h < LEAVE_HOURS_MIN || h > LEAVE_HOURS_MAX || Math.round(h * 2) !== h * 2) {
    return { error: `Choose between ${LEAVE_HOURS_MIN} and ${LEAVE_HOURS_MAX} hours, in half hours.` };
  }
  if (startDate !== endDate) return { error: 'Leave by the hour is for a single day.' };
  return { hours: h };
}

const formatLeaveHours = (h) => `${Number(h)} h`;

// "on 12 Nov 2026 (2 h)" or "from 12 Nov 2026 to 14 Nov 2026", for notification text.
function leavePeriodText(start, end, hours) {
  if (hours !== null && hours !== undefined) return `on ${formatDateDMY(start)} (${formatLeaveHours(hours)})`;
  return `from ${formatDateDMY(start)} to ${formatDateDMY(end)}`;
}
// "12 Nov 2026 • 2 h" or "12 Nov 2026 → 14 Nov 2026", for the short notification lines.
function leaveRangeShort(start, end, hours) {
  if (hours !== null && hours !== undefined) return `${formatDateDMY(start)} • ${formatLeaveHours(hours)}`;
  return `${formatDateDMY(start)} → ${formatDateDMY(end)}`;
}

function formatDateDMY(dateLike) {
  if (!dateLike) return '';
  const d = dateLike instanceof Date ? dateLike : new Date(dateLike);
  if (Number.isNaN(d.getTime())) return String(dateLike);
  // timeZone pinned explicitly so notification text reads the same regardless of what timezone
  // the server process itself happens to be running under (local dev vs. Render in production).
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Singapore' });
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

  // Public holidays — editable by HR, read by every portal (attendance calendars, reports, and
  // the annual reminder job below). One list per office country (SG, MY, CN, LK); a Malaysian
  // holiday that only some states observe lists them in `states` (NULL = nationwide). Seeded once
  // with the known 2026 SG gazetted dates (only into an empty table, so a holiday HR renamed or
  // deleted never comes back); HR can add/edit/delete freely from here on.
  await db.query(`
    CREATE TABLE IF NOT EXISTS public_holidays (
      holiday_date DATE PRIMARY KEY,
      name TEXT NOT NULL,
      updated_by UUID REFERENCES users(user_id),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
  await db.query(`
    INSERT INTO public_holidays (holiday_date, name)
    SELECT v.holiday_date::date, v.name FROM (VALUES
        ('2026-01-01', 'New Year''s Day'),
        ('2026-02-17', 'Chinese New Year'),
        ('2026-02-18', 'Chinese New Year'),
        ('2026-03-21', 'Hari Raya Puasa'),
        ('2026-04-03', 'Good Friday'),
        ('2026-05-01', 'Labour Day'),
        ('2026-05-27', 'Hari Raya Haji'),
        ('2026-05-31', 'Vesak Day'),
        ('2026-06-01', 'Vesak Day (in lieu)'),
        ('2026-08-09', 'National Day'),
        ('2026-08-10', 'National Day (in lieu)'),
        ('2026-11-08', 'Deepavali'),
        ('2026-11-09', 'Deepavali (in lieu)'),
        ('2026-12-25', 'Christmas Day')
    ) AS v (holiday_date, name)
    WHERE NOT EXISTS (SELECT 1 FROM public_holidays);
  `);
  // Countries: the table used to hold Singapore only, keyed by date. Existing rows become SG, and
  // the key moves to an id so the same date can be a holiday in several countries (or carry two
  // Malaysian state holidays). Runs once: the old key is only dropped while it is still on the date.
  await db.query(`ALTER TABLE public_holidays ADD COLUMN IF NOT EXISTS country_code VARCHAR(2) NOT NULL DEFAULT 'SG';`);
  await db.query(`ALTER TABLE public_holidays ADD COLUMN IF NOT EXISTS states TEXT[];`);
  await db.query(`ALTER TABLE public_holidays ADD COLUMN IF NOT EXISTS holiday_id BIGSERIAL;`);
  await db.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
        WHERE c.conrelid = 'public_holidays'::regclass AND c.contype = 'p' AND a.attname = 'holiday_date'
      ) THEN
        ALTER TABLE public_holidays DROP CONSTRAINT public_holidays_pkey;
        ALTER TABLE public_holidays ADD PRIMARY KEY (holiday_id);
      END IF;
    END $$;
  `);
  await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS public_holidays_country_date_name ON public_holidays (country_code, holiday_date, name);`);

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
  await db.query(`ALTER TABLE hour_allocations ADD COLUMN IF NOT EXISTS account_manager_remarks TEXT;`);

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
  // ADD COLUMN IF NOT EXISTS above is a no-op on databases where mc_file_url already existed as
  // varchar(512) from an older migration — that cap silently rejects any real base64-encoded MC
  // image (thousands of chars), so widen it explicitly. TEXT->TEXT is a harmless no-op elsewhere.
  await db.query(`ALTER TABLE leave_applications ALTER COLUMN mc_file_url TYPE TEXT;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS is_late_submission BOOLEAN NOT NULL DEFAULT FALSE;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reviewer_remarks TEXT;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS workflow_status TEXT NOT NULL DEFAULT 'PENDING';`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reason TEXT;`);
  // Hourly leave: part of one day, in hours (start_date = end_date). Empty for full-day leave.
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS leave_hours NUMERIC(3,1);`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;`);
  await db.query(`ALTER TABLE leave_applications ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(user_id);`);
  // start_date/end_date were created as TIMESTAMPTZ instead of DATE. A leave request's dates
  // have no meaningful time-of-day or timezone component, but storing them as TIMESTAMPTZ meant
  // "2026-09-10" got stored as midnight in the server's LOCAL timezone (e.g. 2026-09-10 00:00+08),
  // which then displayed as the previous day everywhere the value got converted to UTC (JSON
  // responses, notification text, etc.) — a one-day-early date shown for every leave request.
  // Casting to DATE truncates the time/timezone component using the same session timezone that
  // created the row, so this preserves the intended calendar date for existing rows too.
  await db.query(`ALTER TABLE leave_applications ALTER COLUMN start_date TYPE DATE USING start_date::date;`);
  await db.query(`ALTER TABLE leave_applications ALTER COLUMN end_date TYPE DATE USING end_date::date;`);

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

  // First-login walkthrough: the portals ('staff', 'manager', 'account_manager', 'hr') whose tour
  // this person has finished or skipped, so each portal shows its tour once per account.
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS tours_completed TEXT[] NOT NULL DEFAULT '{}';`);

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
  // Justification is optional in the UI ("Justification (optional)") but was created NOT NULL —
  // submitting without one previously crashed with a 500. DROP NOT NULL is a no-op if already dropped.
  await db.query(`ALTER TABLE budget_requests ALTER COLUMN justification DROP NOT NULL;`);

  // Expense claims from a receipt photo. Status: PENDING (submitted) -> MANAGER_APPROVED
  // (claimant's supervisor) -> APPROVED (HR) -> PAID; REJECTED at either review. The receipt is
  // kept as a base64 data URL, like leave MCs. claim_scans logs every Gemini receipt scan and its
  // cost, which is what the monthly spend cap and the per-person daily limit are counted from.
  await db.query(`
    CREATE TABLE IF NOT EXISTS claims (
      claim_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'PENDING',
      purchase_date DATE NOT NULL,
      merchant TEXT NOT NULL,
      category TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'SGD',
      total_amount NUMERIC(10,2) NOT NULL,
      project_code TEXT REFERENCES projects(project_code) ON DELETE SET NULL,
      notes TEXT,
      receipt_image TEXT NOT NULL,
      ai_extraction JSONB,
      manager_reviewed_by UUID REFERENCES users(user_id),
      manager_reviewed_at TIMESTAMPTZ,
      manager_remarks TEXT,
      hr_reviewed_by UUID REFERENCES users(user_id),
      hr_reviewed_at TIMESTAMPTZ,
      hr_remarks TEXT,
      paid_at DATE,
      paid_reference TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ
    );
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS claim_items (
      item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      claim_id UUID NOT NULL REFERENCES claims(claim_id) ON DELETE CASCADE,
      description TEXT NOT NULL,
      quantity NUMERIC(10,2),
      amount NUMERIC(10,2),
      sort_order INTEGER NOT NULL DEFAULT 0
    );
  `);
  // Lines between a receipt's items and its total: service charge, each tax (a receipt can have
  // more than one, e.g. SST at 6% and 8%, or SST on labour only), rounding, discounts. Amounts are
  // in the claim's own currency; a DISCOUNT is stored positive and subtracted.
  await db.query(`
    CREATE TABLE IF NOT EXISTS claim_charges (
      charge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      claim_id UUID NOT NULL REFERENCES claims(claim_id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('SERVICE_CHARGE', 'TAX', 'ROUNDING', 'DISCOUNT', 'OTHER')),
      label TEXT,
      rate NUMERIC(5,2),
      amount NUMERIC(10,2) NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0
    );
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS claim_charges_claim_idx ON claim_charges (claim_id);`);
  // true when the item prices already include the tax (e.g. "prices include GST"), so tax lines
  // are recorded but not added on top of the items.
  await db.query(`ALTER TABLE claims ADD COLUMN IF NOT EXISTS tax_inclusive BOOLEAN NOT NULL DEFAULT false;`);
  // true when the claimant was warned that this looked like one of their earlier claims and
  // submitted it anyway; approvers see it next to the duplicate flag.
  await db.query(`ALTER TABLE claims ADD COLUMN IF NOT EXISTS duplicate_acknowledged BOOLEAN NOT NULL DEFAULT false;`);
  // Claims are paid in the company currency (SGD). A claim in another currency keeps its
  // original amount and also stores the exchange rate for the purchase date, the date that rate
  // was published (the last business day on or before the purchase), where it came from, and
  // the amount in the company currency.
  await db.query(`ALTER TABLE claims ADD COLUMN IF NOT EXISTS fx_rate NUMERIC(14,6);`);
  await db.query(`ALTER TABLE claims ADD COLUMN IF NOT EXISTS fx_rate_date DATE;`);
  await db.query(`ALTER TABLE claims ADD COLUMN IF NOT EXISTS fx_source TEXT;`);
  await db.query(`ALTER TABLE claims ADD COLUMN IF NOT EXISTS amount_base NUMERIC(10,2);`);
  await db.query(`
    CREATE TABLE IF NOT EXISTS fx_rates (
      currency TEXT NOT NULL,
      base TEXT NOT NULL,
      for_date DATE NOT NULL,
      rate NUMERIC(14,6) NOT NULL,
      rate_date DATE NOT NULL,
      source TEXT NOT NULL,
      fetched_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (currency, base, for_date)
    );
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS claim_scans (
      scan_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      cost_usd NUMERIC(12,6) NOT NULL DEFAULT 0,
      outcome TEXT NOT NULL,
      extraction JSONB
    );
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS claims_user_idx ON claims (user_id, created_at DESC);`);
  await db.query(`CREATE INDEX IF NOT EXISTS claims_status_idx ON claims (status);`);
  await db.query(`CREATE INDEX IF NOT EXISTS claim_items_claim_idx ON claim_items (claim_id);`);
  await db.query(`CREATE INDEX IF NOT EXISTS claim_scans_created_idx ON claim_scans (created_at);`);

  // Generic audit trail — every edit to user-facing data (attendance times, allocation
  // project/hours, progress %, leave requests, budget/project approvals, ...) is recorded here
  // as a before/after snapshot, via auditInterceptor(). One shared table rather than a
  // per-feature original_* column, so new editable fields don't need their own schema change.
  await db.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      audit_id SERIAL PRIMARY KEY,
      table_name TEXT NOT NULL,
      record_id TEXT NOT NULL,
      altered_by UUID REFERENCES users(user_id),
      pre_value JSONB,
      post_value JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
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

  // Self-service "forgot password" via emailed link — separate from password_reset_requests
  // (which is the manual, HR-approved flow used when someone can't prove email ownership).
  // A token here proves the requester controls the inbox, so it applies immediately with no
  // HR approval step.
  await db.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      token TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Self-service email verification, proving the signup email is real and owned by the
  // signer-upper — replaces admin approval as the login gate for new accounts. HR can still
  // revoke access afterward via the existing approve-account (reject) endpoint.
  await db.query(`
    CREATE TABLE IF NOT EXISTS email_verification_tokens (
      token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      token TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // HR-configurable per-employee leave entitlement (replaces hardcoded 12-day balance)
  await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS leave_entitlement_days INTEGER NOT NULL DEFAULT 12;`);

  // Log Time: remarks + general (non-project) vs project entries + manual entry flag
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS remark TEXT;`);
  // Mandatory description for General (non-project) work — separate from the optional remark.
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS description TEXT;`);
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS entry_type TEXT NOT NULL DEFAULT 'PROJECT';`);
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS is_manual_entry BOOLEAN NOT NULL DEFAULT FALSE;`);
  await db.query(`ALTER TABLE attendance_logs ALTER COLUMN project_code DROP NOT NULL;`);

  // "Still working?" liveness check for long-running sessions — resets each time the staff
  // member presses Continue. Used to prompt at 4h since last confirmation and auto-clock-out
  // at 6h, so a forgotten clock-out can't silently run overnight.
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS last_activity_confirmed_at TIMESTAMPTZ;`);

  // Real wall-clock moment a Manual Entry was actually submitted — kept separate from the
  // staff-entered clock_in_time (which can be hours/days in the past) and never shown to
  // staff themselves, only available for HR/manager reporting on when a backdated entry was
  // really made.
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS manual_entry_actual_submitted_at TIMESTAMPTZ;`);

  // Preserves a log's clock-in/out times exactly as first recorded, the moment staff first
  // edits them — clock_in_time/clock_out_time always hold the current (possibly edited) value
  // shown to staff, while these two are the untouched audit trail, never shown in the UI.
  // COALESCE'd on every edit so only the very first original is ever captured.
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS original_clock_in_time TIMESTAMPTZ;`);
  await db.query(`ALTER TABLE attendance_logs ADD COLUMN IF NOT EXISTS original_clock_out_time TIMESTAMPTZ;`);

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

  // A staff-entered correction to a completed block's actual worked hours — kept separate from
  // accumulated_hours (the original system-recorded value) so reports can show both the system
  // record and the correction, rather than overwriting history.
  await db.query(`ALTER TABLE attendance_allocations ADD COLUMN IF NOT EXISTS corrected_hours NUMERIC(6,2);`);
  // What staff actually worked on for this project block — required for General (no project
  // name to explain it), optional for a named project. Lives per-allocation rather than per
  // session, since one session can hold several project blocks each with their own note.
  await db.query(`ALTER TABLE attendance_allocations ADD COLUMN IF NOT EXISTS description TEXT;`);

  // Login sessions. Every login gets one; "Remember me" makes it a trusted-device session that
  // the login page can resume without a password until it expires. Only a SHA-256 hash of the
  // token is stored, so a copy of this table can't be used to sign in.
  await db.query(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      session_id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      portal TEXT,
      device_label TEXT,
      trusted BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_used_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ
    );
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions (user_id);`);
  // One-time codes for "Switch portal": a signed-in user gets one for another portal they have the
  // role for, and that portal's login page trades it for its own session. Only the hash is kept.
  await db.query(`
    CREATE TABLE IF NOT EXISTS portal_handoffs (
      code_hash TEXT PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      portal TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ
    );
  `);
}

const STANDARD_WORKDAY_HOURS = 8;
const DEFAULT_SINGLE_BLOCK_HOURS = 4;

async function tableExists(tableName) {
  const result = await db.query('SELECT to_regclass($1) AS regclass', [tableName]);
  return !!result.rows?.[0]?.regclass;
}

function isAutoProgressEntry(progressSummary) {
  return String(progressSummary || '').startsWith('Auto-progress baseline');
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

// ── Sign-up from any email address ──
// Anyone can sign up with any email. A Nextan email (@nextan.com.sg) is active once verified; any
// other email (e.g. Gmail) then waits for HR approval (account_status 'pending', approved under
// HR Approvals > Pending Accounts), since sign-up lets people pick their own roles. HR hears about
// every sign-up: an Inbox notification to each HR user and an email to HR_NOTIFY_EMAIL.
const COMPANY_EMAIL_DOMAIN = '@nextan.com.sg';
const HR_NOTIFY_EMAIL = process.env.HR_NOTIFY_EMAIL || 'hr.admin@nextan.com.sg';
const HR_PORTAL_URL = process.env.HR_PORTAL_URL || 'https://hr.nextantech.com';
const SIGNUP_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isCompanyEmail = (email) => String(email || '').toLowerCase().endsWith(COMPANY_EMAIL_DOMAIN);
const escapeHtml = (v) => String(v ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

// Tells HR about an account: `stage` is 'signed_up' (just created) or 'awaiting_approval' (a
// non-Nextan email has been verified and needs approving). Never blocks the sign-up itself.
async function notifyHrOfSignup({ email, roles, stage }) {
  const roleText = (roles || []).map((r) => String(r).replace('_', ' ')).join(', ') || 'staff';
  const company = isCompanyEmail(email);
  const title = stage === 'awaiting_approval' ? 'Account waiting for approval' : 'New sign-up';
  const body = stage === 'awaiting_approval'
    ? `${email} (${roleText}) has verified their email and is waiting for approval. Approve or reject it under Approvals > Pending Accounts.`
    : company
      ? `${email} signed up as ${roleText}. It becomes active once they verify their email.`
      : `${email} signed up as ${roleText} with a non-Nextan email. Once they verify it, the account waits for your approval under Approvals > Pending Accounts.`;
  try {
    const hrUsers = await db.query(
      `SELECT user_id FROM users WHERE account_status = 'active' AND (user_role = 'hr' OR 'hr' = ANY(user_roles))`
    );
    for (const hr of hrUsers.rows) {
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [hr.user_id, title, body]);
    }
  } catch (err) {
    console.error('[signup] HR notification failed:', err.message);
  }
  try {
    const html = brandedEmailHtml({
      linkOrigin: HR_PORTAL_URL,
      heading: title,
      bodyHtml: escapeHtml(body),
      buttonText: 'Open HR portal',
      buttonUrl: `${HR_PORTAL_URL}/admin`,
    });
    await sendEmail(HR_NOTIFY_EMAIL, `${title}: ${email}`, html, 'hr-signup-notice');
  } catch (err) {
    console.error('[signup] HR email failed:', err.message);
  }
}

// ========================================================================
// ROUTE: EMAIL/PASSWORD SIGNUP
// ========================================================================
app.post('/api/v1/auth/signup', async (req, res) => {
  const { email, password, portalUrl } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const normalized = email.trim().toLowerCase();
  if (!SIGNUP_EMAIL_RE.test(normalized) || normalized.length > 254) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
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

    // 'unverified' replaces 'pending' as the default for new signups — the login gate is now
    // self-service email verification (see /auth/verify-email) rather than admin approval.
    // 'pending' stays supported for any accounts already sitting in that state, and admins can
    // still revoke a verified account by rejecting it via /admin/approve-account.
    const insertCols = ['user_id', 'full_name', 'user_role', 'user_roles', 'email', 'password_hash', 'account_status'];
    const insertVals = [userId, fullName, resolvedRole, allRoles, normalized, passwordHash, 'unverified'];
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

    const verifyToken = randomUUID() + randomUUID();
    await db.query(
      `INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '24 hours')`,
      [userId, verifyToken]
    );
    const PORTAL_URL_BY_ROLE = {
      staff: STAFF_PORTAL_URL,
      hr: 'https://hr.nextantech.com',
      manager: 'https://manager.nextantech.com',
      account_manager: 'https://accountmanager.nextantech.com',
    };
    const origin = (portalUrl || PORTAL_URL_BY_ROLE[signupRole] || STAFF_PORTAL_URL).replace(/\/$/, '');
    const verifyUrl = `${origin}/verify-email?token=${verifyToken}`;
    try {
      await sendVerificationEmail(normalized, verifyUrl);
    } catch (emailError) {
      console.error('[signup] verification email failed for', normalized, emailError);
    }
    await notifyHrOfSignup({ email: normalized, roles: allRoles, stage: 'signed_up' });

    const needsApproval = !isCompanyEmail(normalized);
    return res.status(201).json({
      success: true,
      unverified: true,
      needsApproval,
      message: needsApproval
        ? 'Account created. Check your email for a link to verify it. As this isn\'t a Nextan email, HR will then approve your account before you can sign in.'
        : 'Account created. Check your email for a link to verify your account before signing in.',
      data: result.rows[0],
    });
  } catch (error) {
    return res.status(500).json({ error: 'Signup failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: VERIFY EMAIL (activates the account — no admin approval needed)
// ========================================================================
app.post('/api/v1/auth/verify-email', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token is required.' });

  try {
    const tokenRes = await db.query(
      `SELECT token_id, user_id FROM email_verification_tokens
       WHERE token = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP`,
      [token]
    );
    const row = tokenRes.rows[0];
    if (!row) {
      return res.status(400).json({ error: 'This verification link is invalid or has expired. Request a new one.' });
    }

    const account = (await db.query('SELECT email, user_role, user_roles, account_status FROM users WHERE user_id = $1', [row.user_id])).rows[0];
    const needsApproval = account && !isCompanyEmail(account.email);
    const updated = await db.query(
      `UPDATE users SET account_status = $2 WHERE user_id = $1 AND account_status = 'unverified' RETURNING user_id`,
      [row.user_id, needsApproval ? 'pending' : 'active']
    );
    await db.query('UPDATE email_verification_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_id = $1', [row.token_id]);
    if (needsApproval) {
      if (updated.rows.length > 0) {
        const roles = Array.isArray(account.user_roles) && account.user_roles.length ? account.user_roles : [account.user_role];
        await notifyHrOfSignup({ email: account.email, roles, stage: 'awaiting_approval' });
      }
      return res.status(200).json({
        success: true,
        pendingApproval: true,
        message: 'Email verified. HR will now approve your account, and you\'ll get an email when you can sign in.',
      });
    }
    return res.status(200).json({ success: true, message: 'Email verified. You can now log in.' });
  } catch (error) {
    console.error('[verify-email] failed', error);
    return res.status(500).json({ error: 'Failed to verify email.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: RESEND VERIFICATION EMAIL
// ========================================================================
app.post('/api/v1/auth/resend-verification', async (req, res) => {
  const { email, portalUrl } = req.body;
  if (!email || !portalUrl) return res.status(400).json({ error: 'Email and portalUrl are required.' });
  const normalized = email.trim().toLowerCase();

  try {
    const userRes = await db.query(`SELECT user_id FROM users WHERE LOWER(email) = $1 AND account_status = 'unverified' LIMIT 1`, [normalized]);
    const user = userRes.rows[0];
    // Same generic response regardless of match, so this can't be used to probe accounts.
    if (user) {
      const verifyToken = randomUUID() + randomUUID();
      await db.query(
        `INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '24 hours')`,
        [user.user_id, verifyToken]
      );
      const origin = portalUrl.replace(/\/$/, '');
      const verifyUrl = `${origin}/verify-email?token=${verifyToken}`;
      await sendVerificationEmail(normalized, verifyUrl);
      console.log('[resend-verification] sent to', normalized);
    } else {
      console.log('[resend-verification] no unverified account for', normalized);
    }
    return res.status(200).json({ success: true, message: 'If an unverified account exists for that email, a new verification link has been sent.' });
  } catch (error) {
    console.error('[resend-verification] failed for', normalized, error);
    return res.status(500).json({ error: 'Failed to resend verification email.', detail: error.message });
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

// Random temp password, avoiding visually ambiguous characters (0/O, 1/l/I) since someone has to
// read and retype this from an email — 12 chars from a ~54-character set is well over the
// account's own 6-char minimum, so it's not the weak link.
function generateTempPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let out = '';
  for (let i = 0; i < 12; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

// ========================================================================
// ROUTE: FORGOT PASSWORD (self-service, via a temporary password — no link)
// ========================================================================
// Deliberately no link in this flow: mail filters (Microsoft's especially) weigh links heavily
// when scoring phishing risk, and a newly-verified sending domain is already fighting an uphill
// reputation battle without one. Instead, the account's password is changed immediately to a
// random temporary one, emailed as plain text; the user logs in with it directly and sets a new
// password from their Profile page (see /auth/change-password). `portalUrl` only picks which
// portal's logo appears in the email — there's no link to build a return URL for anymore.
app.post('/api/v1/auth/forgot-password', async (req, res) => {
  const { email, portalUrl } = req.body;
  if (!email || !portalUrl) {
    return res.status(400).json({ error: 'Email and portalUrl are required.' });
  }
  const normalized = email.trim().toLowerCase();

  try {
    const userRes = await db.query('SELECT user_id FROM users WHERE LOWER(email) = $1 LIMIT 1', [normalized]);
    const user = userRes.rows[0];
    // Always respond success even if the email isn't found, so this endpoint can't be used
    // to check which emails have accounts.
    if (user) {
      const tempPassword = generateTempPassword();
      const hash = await bcrypt.hash(tempPassword, 10);
      await db.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [hash, user.user_id]);
      await revokeUserSessions(user.user_id);
      const portalOrigin = portalUrl.replace(/\/$/, '');
      await sendTemporaryPasswordEmail(normalized, tempPassword, portalOrigin);
      console.log('[forgot-password] sent temporary password to', normalized);
    } else {
      console.log('[forgot-password] no account found for', normalized);
    }
    return res.status(200).json({ success: true, message: 'If an account exists for that email, a temporary password has been sent.' });
  } catch (error) {
    console.error('[forgot-password] failed for', normalized, error);
    return res.status(500).json({ error: 'Failed to process reset request.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: CHANGE PASSWORD (logged-in self-service, from the Profile page)
// ========================================================================
app.post('/api/v1/auth/change-password', async (req, res) => {
  const { userId, currentPassword, newPassword } = req.body;
  if (!userId || !currentPassword || !newPassword) {
    return res.status(400).json({ error: 'userId, currentPassword, and newPassword are required.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  try {
    const userRes = await db.query('SELECT password_hash FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    const user = userRes.rows[0];
    if (!user) return res.status(404).json({ error: 'Account not found.' });

    const valid = user.password_hash ? await bcrypt.compare(currentPassword, user.password_hash) : false;
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect.' });

    const hash = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [hash, userId]);
    await revokeUserSessions(userId, bearerToken(req));
    return res.status(200).json({ success: true, message: 'Password updated.' });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to change password.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: RESET PASSWORD WITH TOKEN (applies immediately — email ownership already proven)
// ========================================================================
app.post('/api/v1/auth/reset-password-token', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and newPassword are required.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }

  try {
    const tokenRes = await db.query(
      `SELECT token_id, user_id FROM password_reset_tokens
       WHERE token = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP`,
      [token]
    );
    const row = tokenRes.rows[0];
    if (!row) {
      return res.status(400).json({ error: 'This reset link is invalid or has expired. Request a new one.' });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [hash, row.user_id]);
    await revokeUserSessions(row.user_id);
    await db.query('UPDATE password_reset_tokens SET used_at = CURRENT_TIMESTAMP WHERE token_id = $1', [row.token_id]);
    return res.status(200).json({ success: true, message: 'Password updated. You can now log in.' });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to reset password.', detail: error.message });
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
      'SELECT user_id, full_name, user_role, user_roles, email, password_hash, account_status, is_admin, tours_completed, home_office_country FROM users WHERE LOWER(email) = $1 LIMIT 1',
      [normalized]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'No account found for this email. Please sign up first.' });
    // Check approval status (allow null/missing = legacy active users). Deny-by-default rather
    // than checking specific statuses: previously only 'pending'/'rejected' were blocked, so a
    // deactivated account (any other non-active status, e.g. 'inactive') could still log in —
    // only the separate, slower verify-session poll would eventually catch it after the fact.
    const status = String(user.account_status || 'active').toLowerCase();
    if (status === 'unverified') {
      return res.status(403).json({ error: 'Please verify your email first. Check your inbox for the verification link, or request a new one.', unverified: true });
    }
    if (status === 'pending') {
      return res.status(403).json({ error: 'Your account is pending admin approval. Please wait for Rebecca Lau or hr.admin@nextan.com.sg to approve your account.' });
    }
    if (status === 'rejected') {
      return res.status(403).json({ error: 'Your account registration was not approved. Please contact hr.admin@nextan.com.sg.' });
    }
    if (status !== 'active') {
      return res.status(403).json({ error: 'This account is not active. Please contact hr.admin@nextan.com.sg.' });
    }
    if (!user.password_hash) {
      const hash = await bcrypt.hash(password, 10);
      await db.query('UPDATE users SET password_hash = $1 WHERE user_id = $2', [hash, user.user_id]);
    } else {
      const valid = await bcrypt.compare(password, user.password_hash);
      if (!valid) return res.status(401).json({ error: 'Incorrect password.' });
    }
    const session = await createAuthSession(user, {
      trusted: req.body.trustDevice === true,
      portal: req.body.portal,
      deviceLabel: deviceLabelFrom(req),
    });
    return res.status(200).json({ success: true, data: sessionUserPayload(user), session });
  } catch (error) {
    return res.status(500).json({ error: 'Login failed.', detail: error.message });
  }
});

// ========================================================================
// LOGIN SESSIONS ("Remember me on this device")
// ========================================================================
// A login returns a session token. With "Remember me" ticked the portal keeps it in
// localStorage and the login page trades it for a fresh one via /auth/resume, so the user skips
// the password until the session expires: 30 days, or 1 day for HR and admin accounts because of
// what they can change. Sessions keep the expiry set at password login (resuming doesn't extend
// it), and each resume replaces the token so a copied one stops working once the device is used.
// Tokens are sent as `Authorization: Bearer <token>`, ready for the rest of the API to use.
const SESSION_DAY_MS = 24 * 60 * 60 * 1000;
const TRUSTED_SESSION_DAYS = 30;
const PRIVILEGED_TRUSTED_SESSION_DAYS = 1;
const UNTRUSTED_SESSION_DAYS = 1;
const SESSION_PORTALS = ['staff', 'manager', 'account_manager', 'hr'];

function hashSessionToken(token) {
  return createHash('sha256').update(String(token)).digest('hex');
}

function isPrivilegedAccount(user) {
  return Boolean(user.is_admin) || userHasRole(user, 'hr');
}

function sessionDaysFor(user, trusted) {
  if (!trusted) return UNTRUSTED_SESSION_DAYS;
  return isPrivilegedAccount(user) ? PRIVILEGED_TRUSTED_SESSION_DAYS : TRUSTED_SESSION_DAYS;
}

// "Chrome on Windows" etc., so people can recognise their devices on the Profile page.
function deviceLabelFrom(req) {
  const ua = String(req.headers['user-agent'] || '');
  const browser = /Edg\//.test(ua) ? 'Edge'
    : /OPR\//.test(ua) ? 'Opera'
    : /Chrome\//.test(ua) ? 'Chrome'
    : /Firefox\//.test(ua) ? 'Firefox'
    : /Safari\//.test(ua) ? 'Safari'
    : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows'
    : /iPhone|iPad/.test(ua) ? 'iOS'
    : /Android/.test(ua) ? 'Android'
    : /Mac OS X/.test(ua) ? 'macOS'
    : /Linux/.test(ua) ? 'Linux'
    : 'unknown device';
  return `${browser} on ${os}`;
}

function bearerToken(req) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ''));
  return match ? match[1].trim() : null;
}

// The user object the portals keep in sessionStorage — same shape /auth/login has always returned.
function sessionUserPayload(user) {
  const { password_hash, account_status, is_admin, ...safeUser } = user;
  safeUser.full_name = deriveNameFromEmail(user.email);
  safeUser.user_roles = Array.isArray(safeUser.user_roles) && safeUser.user_roles.length > 0
    ? safeUser.user_roles
    : [safeUser.user_role].filter(Boolean);
  return safeUser;
}

async function createAuthSession(user, { trusted, portal, deviceLabel, expiresAt }) {
  const token = randomBytes(32).toString('base64url');
  let expires = new Date(Date.now() + sessionDaysFor(user, trusted) * SESSION_DAY_MS);
  // A resumed session keeps its original expiry, unless the account has since become HR/admin.
  if (expiresAt && new Date(expiresAt) < expires) expires = new Date(expiresAt);
  await db.query(
    `INSERT INTO auth_sessions (session_id, user_id, token_hash, portal, device_label, trusted, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [randomUUID(), user.user_id, hashSessionToken(token),
      SESSION_PORTALS.includes(portal) ? portal : null, deviceLabel || null, Boolean(trusted), expires]
  );
  return { token, trusted: Boolean(trusted), expiresAt: expires.toISOString() };
}

// The live session for a token, joined with its user, or null if it's unknown, revoked or expired.
async function findAuthSession(token) {
  if (!token) return null;
  const result = await db.query(
    `SELECT s.session_id, s.portal, s.device_label, s.trusted, s.expires_at,
            u.user_id, u.full_name, u.user_role, u.user_roles, u.email, u.account_status, u.is_admin, u.tours_completed, u.home_office_country
     FROM auth_sessions s JOIN users u ON u.user_id = s.user_id
     WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > CURRENT_TIMESTAMP
     LIMIT 1`,
    [hashSessionToken(token)]
  );
  return result.rows[0] || null;
}

// For routes that need to know who is calling: the live session from the Bearer token, or null
// after responding 401. Use this rather than trusting a userId sent in the request.
async function requireSession(req, res) {
  const session = await findAuthSession(bearerToken(req));
  if (!session || String(session.account_status || 'active').toLowerCase() !== 'active') {
    res.status(401).json({ error: 'Your sign-in has ended. Please log in again.', signedOut: true });
    return null;
  }
  return session;
}

// Signs a user out everywhere: after a password change or reset, or a change to their roles.
// `exceptToken` keeps the session that made the change (changing your own password).
async function revokeUserSessions(userId, exceptToken = null) {
  await db.query(
    `UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
     WHERE user_id = $1 AND revoked_at IS NULL AND token_hash IS DISTINCT FROM $2`,
    [userId, exceptToken ? hashSessionToken(exceptToken) : null]
  );
}

app.post('/api/v1/auth/resume', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'token is required.' });
  try {
    const session = await findAuthSession(token);
    if (!session || !session.trusted || String(session.account_status || 'active').toLowerCase() !== 'active') {
      return res.status(401).json({ error: 'Your saved sign-in has expired. Please log in again.' });
    }
    await db.query('UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE session_id = $1', [session.session_id]);
    const next = await createAuthSession(session, {
      trusted: true,
      portal: session.portal,
      deviceLabel: deviceLabelFrom(req),
      expiresAt: session.expires_at,
    });
    return res.status(200).json({ success: true, data: sessionUserPayload(session), session: next });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to resume sign-in.', detail: error.message });
  }
});

// ── Switch portal ──
// The four portals are separate sites, so a session can't be shared. A signed-in user asks for a
// one-time code for another portal they have the role for (the Staff portal is open to every
// role, as its login page is); the code works once, for that portal only, within a minute.
const PORTAL_HANDOFF_SECONDS = 60;

function canUsePortal(user, portal) {
  if (portal === 'staff') return ['staff', 'manager', 'account_manager', 'hr'].some((r) => userHasRole(user, r));
  return userHasRole(user, portal);
}

app.post('/api/v1/auth/handoff', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const portal = String(req.body.portal || '');
  if (!SESSION_PORTALS.includes(portal)) return res.status(400).json({ error: 'Choose a portal to switch to.' });
  if (!canUsePortal(session, portal)) return res.status(403).json({ error: "Your account doesn't have access to that portal." });
  try {
    const code = randomBytes(32).toString('base64url');
    await db.query(
      `INSERT INTO portal_handoffs (code_hash, user_id, portal, expires_at)
       VALUES ($1, $2, $3, CURRENT_TIMESTAMP + make_interval(secs => $4))`,
      [hashSessionToken(code), session.user_id, portal, PORTAL_HANDOFF_SECONDS]
    );
    await db.query('DELETE FROM portal_handoffs WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL \'1 day\'');
    return res.status(200).json({ success: true, code, expiresInSeconds: PORTAL_HANDOFF_SECONDS });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to switch portal.', detail: error.message });
  }
});

// The target portal's login page trades the code for a session there (same response as login).
app.post('/api/v1/auth/handoff/exchange', async (req, res) => {
  const { code, portal } = req.body;
  if (!code || !SESSION_PORTALS.includes(String(portal || ''))) return res.status(400).json({ error: 'code and portal are required.' });
  const expired = () => res.status(401).json({ error: 'That link has expired. Please sign in.' });
  try {
    // Marking it used in the same statement means a code can only ever be spent once.
    const used = await db.query(
      `UPDATE portal_handoffs SET used_at = CURRENT_TIMESTAMP
       WHERE code_hash = $1 AND portal = $2 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP
       RETURNING user_id`,
      [hashSessionToken(code), portal]
    );
    if (used.rows.length === 0) return expired();
    const userRes = await db.query(
      'SELECT user_id, full_name, user_role, user_roles, email, password_hash, account_status, is_admin, tours_completed, home_office_country FROM users WHERE user_id = $1',
      [used.rows[0].user_id]
    );
    const user = userRes.rows[0];
    if (!user || String(user.account_status || 'active').toLowerCase() !== 'active' || !canUsePortal(user, portal)) return expired();
    const session = await createAuthSession(user, { trusted: false, portal, deviceLabel: deviceLabelFrom(req) });
    return res.status(200).json({ success: true, data: sessionUserPayload(user), session });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to switch portal.', detail: error.message });
  }
});

// Log out: ends this device's session. Always succeeds, so logging out never gets stuck.
app.post('/api/v1/auth/logout', async (req, res) => {
  const token = bearerToken(req);
  try {
    if (token) {
      await db.query(
        'UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE token_hash = $1 AND revoked_at IS NULL',
        [hashSessionToken(token)]
      );
    }
    return res.status(200).json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to log out.', detail: error.message });
  }
});

// First-login walkthrough: marks this portal's tour as seen for the signed-in user, whether they
// finished it or skipped it. Login and resume return `tours_completed` so the portal knows.
app.post('/api/v1/auth/tours/complete', async (req, res) => {
  const { portal } = req.body || {};
  if (!SESSION_PORTALS.includes(portal)) return res.status(400).json({ error: 'portal is not valid.' });
  try {
    const session = await requireSession(req, res);
    if (!session) return;
    const result = await db.query(
      `UPDATE users SET tours_completed = array_append(COALESCE(tours_completed, '{}'), $2::text)
       WHERE user_id = $1 AND NOT ($2::text = ANY(COALESCE(tours_completed, '{}')))
       RETURNING tours_completed`,
      [session.user_id, portal]
    );
    const toursCompleted = result.rows[0]?.tours_completed
      || [...new Set([...(session.tours_completed || []), portal])];
    return res.status(200).json({ success: true, data: { tours_completed: toursCompleted } });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save the walkthrough.', detail: error.message });
  }
});

// The signed-in user's own remembered devices, for the Profile page.
app.get('/api/v1/auth/sessions', async (req, res) => {
  try {
    const current = await findAuthSession(bearerToken(req));
    if (!current) return res.status(401).json({ error: 'Please log in again to see your devices.' });
    const result = await db.query(
      `SELECT session_id, portal, device_label, created_at, last_used_at, expires_at
       FROM auth_sessions
       WHERE user_id = $1 AND trusted AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
       ORDER BY created_at DESC`,
      [current.user_id]
    );
    const data = result.rows.map((row) => ({ ...row, is_current: row.session_id === current.session_id }));
    return res.status(200).json({ success: true, data });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load your devices.', detail: error.message });
  }
});

// Forget one remembered device (`sessionId`), or every one except this device (`allOthers: true`).
app.post('/api/v1/auth/sessions/revoke', async (req, res) => {
  const { sessionId, allOthers } = req.body;
  if (!sessionId && allOthers !== true) return res.status(400).json({ error: 'sessionId or allOthers is required.' });
  if (sessionId && !UUID_RE.test(sessionId)) return res.status(400).json({ error: 'sessionId is not valid.' });
  try {
    const current = await findAuthSession(bearerToken(req));
    if (!current) return res.status(401).json({ error: 'Please log in again to manage your devices.' });
    const result = allOthers === true
      ? await db.query(
        `UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
         WHERE user_id = $1 AND session_id <> $2 AND revoked_at IS NULL`,
        [current.user_id, current.session_id])
      : await db.query(
        `UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP
         WHERE user_id = $1 AND session_id = $2 AND revoked_at IS NULL`,
        [current.user_id, sessionId]);
    return res.status(200).json({ success: true, data: { revoked: result.rowCount } });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to sign out the device.', detail: error.message });
  }
});

// ========================================================================
// ADMIN ROUTES (is_admin = true required)
// ========================================================================

// Helper: verify requester is admin. Any user holding the 'hr' role gets full admin access —
// HR is a single tier, not split between a designated admin and everyone else — with is_admin
// as an additional (not exclusive) way in for anyone specifically flagged that way.
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
      await revokeUserSessions(row.user_id);
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

// HR Admin only: get pending Manager & Account Manager registrations
app.get('/api/v1/hr/pending-registrations', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireAdmin(requesterId, res)) return;
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

// HR Admin only: approve or reject any pending registration (Manager, Account Manager, or Staff)
// Tells someone their account is now active: a new sign-up approved, or a rejected or revoked
// account reactivated. Sent by both the HR and the Account Manager registration routes.
async function sendAccountActiveEmail(toEmail) {
  const html = brandedEmailHtml({
    linkOrigin: STAFF_PORTAL_URL,
    heading: 'Your Nextan Portal account is active',
    bodyHtml: 'Your account has been approved. You can now log in with the email and password you signed up with.',
    buttonText: 'Log in',
    buttonUrl: STAFF_PORTAL_URL,
    footerText: "You're receiving this because an account was requested with this email address.",
  });
  await sendEmail(toEmail, 'Your Nextan Portal account is active', html, 'account-active');
}

app.patch('/api/v1/hr/approve-registration', async (req, res) => {
  const { requesterId, userId, action } = req.body;
  if (!await requireAdmin(requesterId, res)) return;
  if (!userId || !['approve', 'reject'].includes(action)) {
    return res.status(400).json({ error: 'userId and action (approve|reject) are required.' });
  }
  try {
    const target = await db.query('SELECT user_role, user_roles, email, account_status FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (!target.rows[0]) return res.status(404).json({ error: 'User not found.' });
    const newStatus = action === 'approve' ? 'active' : 'rejected';
    await db.query('UPDATE users SET account_status = $1 WHERE user_id = $2', [newStatus, userId]);
    if (target.rows[0].account_status !== 'active' && newStatus === 'active' && target.rows[0].email) {
      sendAccountActiveEmail(target.rows[0].email)
        .catch((e) => console.error('[email] Account active email failed:', e.message));
    }
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
    const target = await db.query('SELECT user_role, user_roles, email, account_status FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (!target.rows[0]) return res.status(404).json({ error: 'User not found.' });
    const targetRow = target.rows[0];
    if (!userHasRole(targetRow, 'staff')) {
      return res.status(403).json({ error: 'Account Managers can only approve Staff registrations.' });
    }
    const newStatus = action === 'approve' ? 'active' : 'rejected';
    await db.query('UPDATE users SET account_status = $1 WHERE user_id = $2', [newStatus, userId]);
    if (targetRow.account_status !== 'active' && newStatus === 'active' && targetRow.email) {
      sendAccountActiveEmail(targetRow.email)
        .catch((e) => console.error('[email] Account active email failed:', e.message));
    }
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
// Notifications are private: reading or marking them read needs the owner's session token.
// Creating one by API is HR/admin only (the server inserts its own notifications directly).
app.get('/api/v1/notifications/:userId', async (req, res) => {
  try {
    const session = await requireSession(req, res);
    if (!session) return;
    if (session.user_id !== req.params.userId) {
      return res.status(403).json({ error: 'You can only see your own notifications.' });
    }
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
    const session = await requireSession(req, res);
    if (!session) return;
    if (!isPrivilegedAccount(session)) {
      return res.status(403).json({ error: 'Only HR can send notifications.' });
    }
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
  if (!UUID_RE.test(req.params.notifId)) return res.status(400).json({ error: 'Notification id is not valid.' });
  try {
    const session = await requireSession(req, res);
    if (!session) return;
    const result = await db.query(
      'UPDATE notifications SET is_read = TRUE WHERE notification_id = $1 AND user_id = $2',
      [req.params.notifId, session.user_id]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'Notification not found.' });
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
    const projectRow = await db.query('SELECT 1 FROM projects WHERE project_code = $1', [projectCode]);
    if (projectRow.rows.length === 0) return res.status(404).json({ error: 'Project code not found.' });

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
  const { reviewerId, action, reviewerRemarks } = req.body;
  const normalizedAction = String(action || '').toUpperCase();
  const remarks = String(reviewerRemarks || '').trim() || null;

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

    // Only a PENDING allocation can be reviewed; an approved or rejected one used to be
    // flippable here with no record of the change.
    const updated = await db.query(
      `UPDATE hour_allocations
       SET account_manager_status = $1,
           account_manager_reviewer_id = $2,
           account_manager_reviewed_at = CURRENT_TIMESTAMP,
           account_manager_remarks = $4
       WHERE allocation_id = $3 AND account_manager_status = 'PENDING'
       RETURNING *`,
      [normalizedAction, reviewerId, allocationId, remarks]
    );

    if (!updated.rows[0]) {
      const exists = await db.query('SELECT 1 FROM hour_allocations WHERE allocation_id = $1', [allocationId]);
      if (exists.rows.length > 0) {
        return res.status(409).json({ error: 'This allocation has already been reviewed.' });
      }
      return res.status(404).json({ error: 'Allocation request not found.' });
    }

    const row = updated.rows[0];
    const reviewerName = reviewer.rows[0].full_name || 'Account Manager';
    const statusWord = normalizedAction === 'APPROVED' ? 'approved' : 'rejected';

    await db.query(
      'INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)',
      [row.user_id, `Allocation ${normalizedAction}`, `${reviewerName} ${statusWord} your allocation for ${row.project_code} (${row.hours_per_week} hrs/week).${remarks ? ` Remark: ${remarks}` : ''}`]
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
    return res.status(403).json({ error: 'Please enter a valid email address.' });
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
      'SELECT user_id, user_role, user_roles, account_status, home_office_country FROM users WHERE user_id = $1 LIMIT 1',
      [userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found.' });
    // A tab that sends its session token is signed out once that session is revoked (log out
    // elsewhere, password change, Sign out on the Profile device list) or has expired. Tabs from
    // before login sessions existed send no token and keep the old behaviour.
    const token = bearerToken(req);
    if (token) {
      const session = await findAuthSession(token);
      if (!session || session.user_id !== userId) {
        return res.status(401).json({ error: 'Your sign-in has ended. Please log in again.', signedOut: true });
      }
    }
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
        home_office_country: row.home_office_country,
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
    const session = await requireSession(req, res);
    if (!session) return;
    if (session.user_id !== userId) {
      return res.status(403).json({ error: 'You can only see your own inbox.' });
    }
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
           CONCAT(la.category::TEXT, ' leave \u2022 ', TO_CHAR(la.start_date, 'DD Mon YYYY'),
             CASE WHEN la.leave_hours IS NOT NULL THEN CONCAT(' \u2022 ', RTRIM(TO_CHAR(la.leave_hours, 'FM90.9'), '.'), ' h') ELSE CONCAT(' \u2192 ', TO_CHAR(la.end_date, 'DD Mon YYYY')) END, ' \u2022 ', CASE la.workflow_status::TEXT WHEN 'PENDING' THEN 'Pending manager approval' WHEN 'APPROVED' THEN 'Approved' WHEN 'REJECTED' THEN 'Rejected' ELSE la.workflow_status::TEXT END) AS subtitle,
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
      `SELECT leave_id, category, start_date, end_date, leave_hours, workflow_status, reviewer_remarks, reason, mc_file_url, created_at
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
// CORE UTILITY: AUDIT INTERCEPTOR
// ========================================================================
// Records a before/after snapshot of an edit. preValue MUST be read by the caller BEFORE
// running its UPDATE — reading it here (after the fact) would just capture the new row twice,
// which is exactly the bug this used to have (pre_value and post_value were always identical).
async function auditInterceptor(tableName, recordId, userId, preValue, postValue) {
    try {
        await db.query(
            'INSERT INTO audit_logs (table_name, record_id, altered_by, pre_value, post_value, created_at) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)',
            [tableName, String(recordId), userId, JSON.stringify(preValue ?? null), JSON.stringify(postValue ?? null)]
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
    const isDomestic = current === String(homeCountry || 'SG').toUpperCase();

    const travelMode = isDomestic ? 'DOMESTIC_ATTENDANCE' : 'OVERSEAS_ATTENDANCE';

    return { locationName, countryCode, travelMode };
  } catch (error) {
    console.error('Spatial Geocoding Live Engine Warning:', error.message);
    return {
      locationName: 'Location unavailable',
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

// Clients (web/mobile) use the sentinel string 'GENERAL' to represent non-project work in
// their project pickers — normalize it (and any blank value) to null before it ever reaches
// a project_code FK column, otherwise it fails as an unrecognised project code.
function normalizeProjectCode(code) {
  if (!code) return null;
  return String(code).trim().toUpperCase() === 'GENERAL' ? null : code;
}

// A user can log more than one session on the same day (e.g. catching up on a different
// project's hours retroactively) — that's legitimate. But two same-category (same project,
// or both General) sessions whose time ranges overlap are almost always duplicate/redundant
// reporting of the same wall-clock time. Rather than rejecting the newer entry outright, clip
// its counted hours down to only the portion that isn't already covered by an existing
// same-category session, so the same minute never gets counted twice in daily/weekly totals.
// The clock-in/out timestamps themselves are left untouched (they're the record of what the
// user actually entered) — only the derived hour totals are adjusted.
// Finds a staff member's existing attendance log whose time range genuinely overlaps
// [startIso, endIso) — used to block a new Manual Entry (or edit) from being logged on top of
// time already recorded, rather than silently allowing duplicates. An open (still-active) log
// has no clock_out_time yet, so it's treated as covering up to "now".
async function findOverlappingAttendanceLog(userId, startIso, endIso, excludeAttendanceId) {
  const result = await db.query(
    `SELECT attendance_id, clock_in_time, clock_out_time FROM attendance_logs
     WHERE user_id = $1 AND attendance_id != $2
       AND clock_in_time < $4::timestamptz
       AND COALESCE(clock_out_time, CURRENT_TIMESTAMP) > $3::timestamptz
     ORDER BY clock_in_time ASC
     LIMIT 1`,
    [userId, excludeAttendanceId || '00000000-0000-0000-0000-000000000000', startIso, endIso]
  );
  return result.rows[0] || null;
}

async function clipOverlappingHours(userId, projectCode, startIso, endIso, excludeAttendanceId) {
  const start = new Date(startIso);
  const end = new Date(endIso);
  const rawHours = Math.max((end - start) / 3600000, 0);

  const others = await db.query(
    `SELECT clock_in_time, clock_out_time FROM attendance_logs
     WHERE user_id = $1 AND attendance_id != $2 AND clock_out_time IS NOT NULL
       AND COALESCE(project_code, '') = COALESCE($3, '')
       AND clock_in_time < $5 AND clock_out_time > $4`,
    [userId, excludeAttendanceId || '00000000-0000-0000-0000-000000000000', projectCode || null, start.toISOString(), end.toISOString()]
  );

  const intervals = others.rows
    .map((r) => [
      new Date(Math.max(new Date(r.clock_in_time), start)),
      new Date(Math.min(new Date(r.clock_out_time), end)),
    ])
    .filter(([s, e]) => e > s)
    .sort((a, b) => a[0] - b[0]);

  const merged = [];
  for (const [s, e] of intervals) {
    if (merged.length > 0 && s <= merged[merged.length - 1][1]) {
      if (e > merged[merged.length - 1][1]) merged[merged.length - 1][1] = e;
    } else {
      merged.push([s, e]);
    }
  }
  const coveredMs = merged.reduce((sum, [s, e]) => sum + (e - s), 0);
  const clippedHours = Math.max(rawHours - coveredMs / 3600000, 0);
  return { rawHours, clippedHours, ratio: rawHours > 0 ? clippedHours / rawHours : 1 };
}

// ========================================================================
// ROUTE: CLOCK-IN ENDPOINT
// ========================================================================
app.post('/api/v1/attendance/clock-in', async (req, res) => {
  const { userId, projectCode, latitude, longitude, isManualLocation, manualLocationText, remark, description, clockInTime, allocations } = req.body;
  // `allocations`, if provided, is [{ projectCode: string|null, allocatedHours: number }, ...] —
  // lets staff split this session's planned hours across several projects/General up front.
  // `projectCode` stays as the single-project fallback for older clients (mobile app, etc.).
  const requestedProjects = Array.isArray(allocations) && allocations.length > 0
    ? allocations.map((a) => ({ ...a, projectCode: normalizeProjectCode(a.projectCode) }))
    : [{ projectCode: normalizeProjectCode(projectCode), allocatedHours: null }];
  const primaryProjectCode = requestedProjects[0].projectCode || null;
  const entryType = primaryProjectCode ? 'PROJECT' : 'GENERAL';
  const isManualEntry = Boolean(clockInTime);
  // A description is required for General (non-project) work, but only once the session is
  // closed out (see /clock-out) — the work isn't known yet at the moment of clocking in.

  try {
    const userProfile = await db.query('SELECT home_office_country, user_role, user_roles FROM users WHERE user_id = $1', [userId]);
    if (userProfile.rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    const deployedCode = await findDeployedProjectCode(requestedProjects.map((a) => a.projectCode));
    if (deployedCode) {
      return res.status(403).json({ error: deployedProjectError(deployedCode) });
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

    const newSessionStart = clockInTime ? new Date(clockInTime) : new Date();
    // Staff can log a past or present shift, never a future one — a 60s tolerance absorbs
    // ordinary clock skew between the staff member's device and the server.
    if (clockInTime && newSessionStart.getTime() > Date.now() + 60000) {
      return res.status(400).json({ error: 'You can only log attendance for today or a past date, not the future.' });
    }

    // A backdated clock-in (clockInTime provided) can land inside time already recorded
    // elsewhere — block it the same way Manual Entry is blocked, rather than allowing a
    // duplicate, open-ended session on top of an existing entry.
    const overlap = await findOverlappingAttendanceLog(userId, newSessionStart.toISOString(), 'infinity');
    if (overlap) {
      return res.status(409).json({
        error: 'This time overlaps an entry you\'ve already logged. Edit that entry instead of creating a new one.',
        overlap: { attendance_id: overlap.attendance_id, clock_in_time: overlap.clock_in_time, clock_out_time: overlap.clock_out_time },
      });
    }

    const homeCountry = userProfile.rows[0].home_office_country;
    let locationName = manualLocationText || 'Location unavailable';
    let countryCode = homeCountry;
    // Without a GPS fix the session is recorded at the staff member's own office.
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
        location_name, country_code, is_manual_location, travel_mode, status, entry_type, remark, is_manual_entry, description, created_at, last_activity_confirmed_at
      ) VALUES (
        $1, $2, $3, COALESCE($12::timestamptz, CURRENT_TIMESTAMP),
        CASE WHEN $4::numeric IS NOT NULL AND $5::numeric IS NOT NULL
             THEN ST_SetSRID(ST_MakePoint($5::numeric, $4::numeric), 4326) ELSE NULL END,
        $6, $7, $8, $9, 'ACTIVE', $10, $11, $13, $14, CURRENT_TIMESTAMP, COALESCE($12::timestamptz, CURRENT_TIMESTAMP)
      ) RETURNING *;
    `;

    const result = await db.query(insertQuery, [
      randomUUID(), userId, primaryProjectCode, latitude, longitude, locationName, countryCode, isManualLocation || false, travelMode, entryType, remark || null, clockInTime || null, isManualEntry, description || null
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
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $4 = 'ACTIVE' THEN $6::timestamptz ELSE NULL END)
         RETURNING *`,
        [attendanceRow.attendance_id, alloc.projectCode || null, Math.round(hours * 100) / 100, i === 0 ? 'ACTIVE' : 'PENDING', i, attendanceRow.clock_in_time]
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
  const { userId, attendanceId, remark, description, clockOutTime, isAutoClockOut } = req.body;

  try {
    const logCheck = await db.query(
      `SELECT al.clock_in_time, al.project_code, al.description, u.home_office_country
       FROM attendance_logs al JOIN users u ON u.user_id = al.user_id
       WHERE al.attendance_id = $1 AND al.user_id = $2`,
      [attendanceId, userId]
    );

    if (logCheck.rows.length === 0) {
      return res.status(404).json({ error: 'No active clock-in entry found matching your device session state.' });
    }

    // General (non-project) work has no project name to explain what was done, so its own
    // allocation-level description (typed live on that card, saved via PATCH /allocations/:id)
    // is required before closing out — every other project's description stays optional. Asked
    // for here rather than at clock-in, since the work is only known once it's actually underway.
    // The system's own 4-hour stale-session backstop is exempt: nobody's present to type one, and
    // a session that can never auto-close because it's missing a description is worse than one
    // that closes with the description left blank.
    if (!isAutoClockOut) {
      const generalCheck = await db.query(
        'SELECT description FROM attendance_allocations WHERE attendance_id = $1 AND project_code IS NULL LIMIT 1',
        [attendanceId]
      );
      if (generalCheck.rows.length > 0 && !(generalCheck.rows[0].description || '').trim()) {
        return res.status(400).json({ error: 'A description is required when logging General (non-project) work.' });
      }
    }

    const clockIn = new Date(logCheck.rows[0].clock_in_time);

    if (clockOutTime) {
      const clockOut = new Date(clockOutTime);
      // Manual Entry's time picker only has minute precision, so a clock-out submitted in the
      // same minute as a second-precise clock-in can look "earlier" by a few seconds — compare
      // against the start of the clock-in's minute instead of the exact instant.
      const clockInFloored = new Date(clockIn);
      clockInFloored.setSeconds(0, 0);
      if (Number.isNaN(clockOut.getTime()) || clockOut < clockInFloored) {
        return res.status(400).json({ error: 'Clock-out time must be after the clock-in time.' });
      }
    }

    const currentOut = clockOutTime ? new Date(clockOutTime) : new Date();
    const { clippedHours, ratio } = await clipOverlappingHours(
      userId, logCheck.rows[0].project_code, clockIn.toISOString(), currentOut.toISOString(), attendanceId
    );
    const timeZone = timeZoneForCountry(logCheck.rows[0].home_office_country);
    const outHour = localHourOf(currentOut, timeZone);
    const crossesLunch = sessionOverlapsLunch(clockIn, currentOut, timeZone);
    const dailyWorktimeHours = Math.round((crossesLunch ? Math.max(clippedHours - 1, 0) : Math.max(clippedHours, 0)) * 100) / 100;
    const otHoursAccrued = clippedHours > 9.5 && outHour >= 18 ? Math.round((clippedHours - 9.5) * 100) / 100 : 0;

    const updateQuery = `
      UPDATE attendance_logs
      SET
        clock_out_time = $2::timestamptz,
        daily_worktime_hours = $3,
        ot_hours_accrued = $4,
        remark = COALESCE($5, remark),
        description = COALESCE($6, description)
      WHERE attendance_id = $1
      RETURNING attendance_id, daily_worktime_hours, ot_hours_accrued;
    `;

    const result = await db.query(updateQuery, [attendanceId, currentOut.toISOString(), dailyWorktimeHours, otHoursAccrued, remark || null, description || null]);
    const attendanceRow = result.rows[0];

    // Close out whichever allocation was still running, and let the leftover ones stand as planned.
    // Bank whatever time the ACTIVE block had tracked so it isn't lost on clock-out, scaled down
    // by the same overlap ratio so double-booked time doesn't get double-counted here either.
    await db.query(
      `UPDATE attendance_allocations
       SET status = 'COMPLETED', completed_at = $2::timestamptz,
           accumulated_hours = accumulated_hours + CASE WHEN status = 'ACTIVE' AND started_at IS NOT NULL
             THEN EXTRACT(EPOCH FROM ($2::timestamptz - started_at)) / 3600 * $3::numeric ELSE 0 END
       WHERE attendance_id = $1 AND status IN ('ACTIVE', 'PENDING')`,
      [attendanceId, currentOut.toISOString(), ratio]
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
// ROUTE: MANUAL TIME ENTRY (Log Time — records an already-finished block of work directly)
// ========================================================================
// Unlike Clock In/Out, this never creates a live/open session — the moment it's submitted,
// the entry is done: clock_out_time is derived as clockInTime + the sum of the requested
// allocations' hours, and every allocation is inserted already COMPLETED with its full
// planned hours as its accumulated (actual) hours. There is no ticking, no "active" block,
// and nothing left to later clock out of.
app.post('/api/v1/attendance/manual-entry', async (req, res) => {
  const { userId, clockInTime, clockOutTime, remark, description } = req.body;
  const allocationsInput = Array.isArray(req.body.allocations) && req.body.allocations.length > 0
    ? req.body.allocations.map((a) => ({ ...a, projectCode: normalizeProjectCode(a.projectCode) }))
    : null;

  if (!userId || !clockInTime || !allocationsInput) {
    return res.status(400).json({ error: 'userId, clockInTime, and at least one allocation are required.' });
  }
  // General (non-project) work has no project name to explain what was done, so a description
  // is mandatory whenever any allocation is General — separate from the optional remark.
  if (allocationsInput.some((a) => !a.projectCode) && !(description || '').trim()) {
    return res.status(400).json({ error: 'A description is required when logging General (non-project) work.' });
  }
  const start = new Date(clockInTime);
  if (Number.isNaN(start.getTime())) {
    return res.status(400).json({ error: 'clockInTime is not a valid date/time.' });
  }
  // Staff can log a past or present shift, never a future one — a 60s tolerance absorbs
  // ordinary clock skew between the staff member's device and the server.
  if (start.getTime() > Date.now() + 60000) {
    return res.status(400).json({ error: 'You can only log attendance for today or a past date, not the future.' });
  }
  if (allocationsInput.some((a) => !(Number(a.allocatedHours) > 0))) {
    return res.status(400).json({ error: 'Every project needs a positive number of hours.' });
  }
  const totalHours = allocationsInput.reduce((sum, a) => sum + Number(a.allocatedHours), 0);
  // The overall attendance period defaults to start + the projects' total hours, but staff can
  // override the actual end time directly — e.g. clocked in 8:30am, project only took 8 hours,
  // but didn't actually clock off until 6pm. That extra time isn't attributed to any project,
  // it just extends how long the day is recorded as, for daily hours/OT purposes.
  let end;
  if (clockOutTime) {
    end = new Date(clockOutTime);
    if (Number.isNaN(end.getTime()) || end <= start) {
      return res.status(400).json({ error: 'End time must be a valid time after the start time.' });
    }
  } else {
    end = new Date(start.getTime() + totalHours * 3600000);
  }
  const actualDurationHours = (end.getTime() - start.getTime()) / 3600000;

  try {
    const userProfile = await db.query('SELECT user_role, user_roles, home_office_country FROM users WHERE user_id = $1', [userId]);
    if (userProfile.rows.length === 0) {
      return res.status(404).json({ error: 'User profile not found' });
    }
    const deployedCode = await findDeployedProjectCode(allocationsInput.map((a) => a.projectCode));
    if (deployedCode) {
      return res.status(403).json({ error: deployedProjectError(deployedCode) });
    }
    if (!userIsManagerial(userProfile.rows[0])) {
      for (const alloc of allocationsInput) {
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

    // Block logging a new entry on top of time already recorded — staff should edit the
    // existing entry instead of creating an overlapping duplicate.
    const overlap = await findOverlappingAttendanceLog(userId, start.toISOString(), end.toISOString());
    if (overlap) {
      return res.status(409).json({
        error: 'This time range overlaps an entry you\'ve already logged. Edit that entry instead of creating a new one.',
        overlap: { attendance_id: overlap.attendance_id, clock_in_time: overlap.clock_in_time, clock_out_time: overlap.clock_out_time },
      });
    }

    const primaryProjectCode = allocationsInput[0].projectCode || null;
    const entryType = primaryProjectCode ? 'PROJECT' : 'GENERAL';
    // Unlike live clock-out, a Manual Entry always credits exactly what was entered — no
    // overlap-deduplication against other sessions. It's a deliberate, precise record the staff
    // member is entering by hand, not a live timer that could double-count a forgotten clock-out.
    const timeZone = timeZoneForCountry(userProfile.rows[0].home_office_country);
    const outHour = localHourOf(end, timeZone);
    const crossesLunch = sessionOverlapsLunch(start, end, timeZone);
    const dailyWorktimeHours = Math.round((crossesLunch ? Math.max(actualDurationHours - 1, 0) : Math.max(actualDurationHours, 0)) * 100) / 100;
    const otHoursAccrued = actualDurationHours > 9.5 && outHour >= 18 ? Math.round((actualDurationHours - 9.5) * 100) / 100 : 0;

    const insertQuery = `
      INSERT INTO attendance_logs (
        attendance_id, user_id, project_code, clock_in_time, clock_out_time,
        daily_worktime_hours, ot_hours_accrued, status, entry_type, is_manual_entry,
        manual_entry_actual_submitted_at, remark, description, created_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, 'ACTIVE', $8, TRUE, CURRENT_TIMESTAMP, $9, $10, CURRENT_TIMESTAMP
      ) RETURNING *;
    `;
    const result = await db.query(insertQuery, [
      randomUUID(), userId, primaryProjectCode, start.toISOString(), end.toISOString(),
      dailyWorktimeHours, otHoursAccrued, entryType, remark || null, description || null
    ]);
    const attendanceRow = result.rows[0];

    const allocationRows = [];
    for (let i = 0; i < allocationsInput.length; i++) {
      const alloc = allocationsInput[i];
      // Credited in full — allocated_hours (the plan) and accumulated_hours (the actual) start
      // out identical, since a Manual Entry records the hours exactly as entered.
      const plannedHours = Math.round(Number(alloc.allocatedHours) * 100) / 100;
      const actualHours = plannedHours;
      const inserted = await db.query(
        `INSERT INTO attendance_allocations (attendance_id, project_code, allocated_hours, accumulated_hours, status, seq, started_at, completed_at)
         VALUES ($1, $2, $3, $4, 'COMPLETED', $5, $6::timestamptz, $7::timestamptz)
         RETURNING *`,
        [attendanceRow.attendance_id, alloc.projectCode || null, plannedHours, actualHours, i, start.toISOString(), end.toISOString()]
      );
      allocationRows.push(inserted.rows[0]);
    }

    res.status(201).json({ success: true, data: { ...attendanceRow, allocations: allocationRows } });
  } catch (error) {
    res.status(500).json({ error: 'Manual time entry failed.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: EDIT AN ALREADY-LOGGED ENTRY'S CLOCK-IN/OUT TIMES
// ========================================================================
// Lets staff correct a finished attendance log's times instead of logging a second, overlapping
// entry. The pre-edit values are preserved in original_clock_in_time/original_clock_out_time
// (captured once, on the first edit only) purely for record-keeping — staff themselves only ever
// see clock_in_time/clock_out_time, which always hold the current, edited version.
app.patch('/api/v1/attendance/:attendanceId/edit-times', async (req, res) => {
  const { attendanceId } = req.params;
  const { userId, clockInTime, clockOutTime } = req.body;
  if (!userId || !clockInTime || !clockOutTime) {
    return res.status(400).json({ error: 'userId, clockInTime and clockOutTime are required.' });
  }
  const start = new Date(clockInTime);
  const end = new Date(clockOutTime);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
    return res.status(400).json({ error: 'End time must be a valid time after the start time.' });
  }
  // Editing can't move an entry into the future either — same rule as creating one.
  if (start.getTime() > Date.now() + 60000) {
    return res.status(400).json({ error: 'You can only log attendance for today or a past date, not the future.' });
  }

  try {
    const existing = await db.query(
      'SELECT * FROM attendance_logs WHERE attendance_id = $1 AND user_id = $2',
      [attendanceId, userId]
    );
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Attendance entry not found.' });
    }
    if (!existing.rows[0].clock_out_time) {
      return res.status(400).json({ error: 'This session is still active — clock it out before editing its times.' });
    }

    const overlap = await findOverlappingAttendanceLog(userId, start.toISOString(), end.toISOString(), attendanceId);
    if (overlap) {
      return res.status(409).json({
        error: 'This time range overlaps another entry you\'ve already logged.',
        overlap: { attendance_id: overlap.attendance_id, clock_in_time: overlap.clock_in_time, clock_out_time: overlap.clock_out_time },
      });
    }

    const actualDurationHours = (end.getTime() - start.getTime()) / 3600000;
    const timeZone = await userTimeZone(userId);
    const outHour = localHourOf(end, timeZone);
    const crossesLunch = sessionOverlapsLunch(start, end, timeZone);
    const dailyWorktimeHours = Math.round((crossesLunch ? Math.max(actualDurationHours - 1, 0) : Math.max(actualDurationHours, 0)) * 100) / 100;
    const otHoursAccrued = actualDurationHours > 9.5 && outHour >= 18 ? Math.round((actualDurationHours - 9.5) * 100) / 100 : 0;

    // Optional: replace the entry's project list in the same save. Each block is re-created
    // COMPLETED with the hours entered, carrying over any description a kept project already had.
    let newAllocations = null;
    if (Array.isArray(req.body.allocations) && req.body.allocations.length > 0) {
      newAllocations = req.body.allocations.map((a) => ({
        projectCode: normalizeProjectCode(a.projectCode),
        hours: Math.round(Number(a.hours ?? a.allocatedHours) * 100) / 100,
      }));
      if (newAllocations.some((a) => !(a.hours > 0))) {
        return res.status(400).json({ error: 'Every project needs a positive number of hours.' });
      }
      const codes = newAllocations.map((a) => a.projectCode || '');
      if (new Set(codes).size !== codes.length) {
        return res.status(400).json({ error: 'The same project is listed twice. Combine its hours into one row.' });
      }
      const totalAllocated = newAllocations.reduce((sum, a) => sum + a.hours, 0);
      if (totalAllocated > actualDurationHours + 0.02) {
        return res.status(400).json({
          error: `Project hours (${totalAllocated.toFixed(2)}h) can't be more than the time between start and end (${actualDurationHours.toFixed(2)}h).`,
        });
      }
      const profile = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [userId]);
      if (profile.rows.length > 0 && !userIsManagerial(profile.rows[0])) {
        for (const alloc of newAllocations) {
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
    }

    const client = await db.pool.connect();
    let result;
    try {
      await client.query('BEGIN');
      result = await client.query(
        `UPDATE attendance_logs
         SET original_clock_in_time = COALESCE(original_clock_in_time, clock_in_time),
             original_clock_out_time = COALESCE(original_clock_out_time, clock_out_time),
             clock_in_time = $2::timestamptz,
             clock_out_time = $3::timestamptz,
             daily_worktime_hours = $4,
             ot_hours_accrued = $5
         WHERE attendance_id = $1
         RETURNING attendance_id, clock_in_time, clock_out_time, daily_worktime_hours, ot_hours_accrued`,
        [attendanceId, start.toISOString(), end.toISOString(), dailyWorktimeHours, otHoursAccrued]
      );
      if (newAllocations) {
        const old = await client.query('SELECT project_code, description FROM attendance_allocations WHERE attendance_id = $1', [attendanceId]);
        const oldDescriptions = new Map(old.rows.map((r) => [r.project_code || '', r.description]));
        await client.query('DELETE FROM attendance_allocations WHERE attendance_id = $1', [attendanceId]);
        for (let i = 0; i < newAllocations.length; i++) {
          const alloc = newAllocations[i];
          await client.query(
            `INSERT INTO attendance_allocations
               (attendance_id, project_code, allocated_hours, accumulated_hours, status, seq, started_at, completed_at, description, last_edited_at, edited_after_completion)
             VALUES ($1, $2, $3, $3, 'COMPLETED', $4, $5::timestamptz, $6::timestamptz, $7, CURRENT_TIMESTAMP, TRUE)`,
            [attendanceId, alloc.projectCode || null, alloc.hours, i, start.toISOString(), end.toISOString(), oldDescriptions.get(alloc.projectCode || '') || null]
          );
        }
        const primaryProjectCode = newAllocations[0].projectCode || null;
        await client.query(
          'UPDATE attendance_logs SET project_code = $2, entry_type = $3 WHERE attendance_id = $1',
          [attendanceId, primaryProjectCode, primaryProjectCode ? 'PROJECT' : 'GENERAL']
        );
      }
      await client.query('COMMIT');
    } catch (txError) {
      await client.query('ROLLBACK');
      throw txError;
    } finally {
      client.release();
    }

    await auditInterceptor('attendance_logs', attendanceId, userId, existing.rows[0], { ...result.rows[0], ...(newAllocations ? { allocations: newAllocations } : {}) });

    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to edit attendance entry.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: DELETE ATTENDANCE ENTRY
// ========================================================================
app.delete('/api/v1/attendance/:attendanceId', async (req, res) => {
  const { attendanceId } = req.params;
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ error: 'userId is required.' });
  }
  try {
    const existing = await db.query(
      'SELECT * FROM attendance_logs WHERE attendance_id = $1 AND user_id = $2',
      [attendanceId, userId]
    );
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Attendance entry not found.' });
    }
    if (!existing.rows[0].clock_out_time) {
      return res.status(400).json({ error: 'This session is still active — clock it out before deleting it.' });
    }
    // The delete cascades to the entry's project blocks, so keep them in the audit snapshot too.
    const blocks = await db.query('SELECT * FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC', [attendanceId]);
    await db.query('DELETE FROM attendance_logs WHERE attendance_id = $1', [attendanceId]);
    await auditInterceptor('attendance_logs', attendanceId, userId, { ...existing.rows[0], allocations: blocks.rows }, null);
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete attendance entry.', detail: error.message });
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
         created_at,
         last_activity_confirmed_at
       FROM attendance_logs
       WHERE user_id = $1 AND status = 'ACTIVE' AND clock_out_time IS NULL
       ORDER BY created_at DESC
       LIMIT 1`,
      [userId]
    );

    const session = result.rows[0] || null;
    if (session) {
      const allocResult = await db.query(
        `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, corrected_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion, description
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

// Staff presses "Continue" on the "Still working?" prompt — resets the 4h/6h liveness clock.
app.post('/api/v1/attendance/:attendanceId/confirm-continue', async (req, res) => {
  const { attendanceId } = req.params;
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId is required.' });
  try {
    const result = await db.query(
      `UPDATE attendance_logs SET last_activity_confirmed_at = CURRENT_TIMESTAMP
       WHERE attendance_id = $1 AND user_id = $2 AND status = 'ACTIVE' AND clock_out_time IS NULL
       RETURNING attendance_id, last_activity_confirmed_at`,
      [attendanceId, userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'No active session found matching this id.' });
    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to confirm activity.', detail: error.message });
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
         SELECT attendance_id, (clock_in_time AT TIME ZONE $4::text)::date AS day, project_code, daily_worktime_hours,
                EXISTS (SELECT 1 FROM attendance_allocations aa WHERE aa.attendance_id = al.attendance_id) AS has_allocations
         FROM attendance_logs al
         WHERE al.user_id = $1 AND (al.clock_in_time AT TIME ZONE $4::text)::date BETWEEN $2::date AND $3::date
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
      [userId, start, end, await userTimeZone(userId)]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch project log.', detail: error.message });
  }
});

// Per-session clock-in/out times (plus each session's project-hour breakdown) for the Weekly
// Project Log's timeline chart — one row per attendance log, so the chart can position a bar at
// its real start/end time instead of a plain accumulated-hours total. Includes a session that's
// still clocked in (clock_out_time NULL) so a just-started session shows up immediately instead
// of waiting for clock-out — the frontend already renders a null clock_out_time as "still active".
app.get('/api/v1/attendance/sessions/:userId', async (req, res) => {
  const { userId } = req.params;
  const { start, end } = req.query;
  if (!start || !end) {
    return res.status(400).json({ error: 'start and end date query params are required (YYYY-MM-DD).' });
  }
  try {
    const result = await db.query(
      `SELECT
         al.attendance_id,
         to_char((al.clock_in_time AT TIME ZONE $4::text)::date, 'YYYY-MM-DD') AS day,
         al.clock_in_time,
         al.clock_out_time,
         COALESCE(
           (SELECT json_agg(json_build_object('project_code', COALESCE(aa.project_code, 'General'), 'hours', aa.accumulated_hours) ORDER BY aa.seq)
            FROM attendance_allocations aa WHERE aa.attendance_id = al.attendance_id),
           json_build_array(json_build_object('project_code', COALESCE(al.project_code, 'General'), 'hours', al.daily_worktime_hours))
         ) AS allocations
       FROM attendance_logs al
       WHERE al.user_id = $1
         AND (al.clock_in_time AT TIME ZONE $4::text)::date BETWEEN $2::date AND $3::date
       ORDER BY al.clock_in_time ASC`,
      [userId, start, end, await userTimeZone(userId)]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch attendance sessions.', detail: error.message });
  }
});

// Raw clock-in/out time ranges already logged for one calendar day in the user's own time zone — used by Manual Entry
// to warn "you've already logged time today" with the actual period, before creating a
// possibly-duplicate entry.
app.get('/api/v1/attendance/day-entries/:userId', async (req, res) => {
  const { userId } = req.params;
  const { date } = req.query;
  if (!date) {
    return res.status(400).json({ error: 'date query param is required (YYYY-MM-DD).' });
  }
  try {
    const result = await db.query(
      `SELECT attendance_id, clock_in_time, clock_out_time
       FROM attendance_logs
       WHERE user_id = $1 AND (clock_in_time AT TIME ZONE $3::text)::date = $2::date
       ORDER BY clock_in_time ASC`,
      [userId, date, await userTimeZone(userId)]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch day entries.', detail: error.message });
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
      if (await findDeployedProjectCode([projectCode])) {
        return res.status(403).json({ error: deployedProjectError(projectCode) });
      }
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
      `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, corrected_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion, description
       FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [attendanceId]
    );

    res.status(201).json({ success: true, data: { newAllocation: inserted.rows[0], allocations: all.rows } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add project allocation.', detail: error.message });
  }
});

// Direct manual edit — "editable at every stage" — overwrite one allocation's planned hours,
// or (only once it's COMPLETED) record a correction to what was actually worked. The correction
// is kept in its own column rather than overwriting accumulated_hours, so a report can always
// show both what the system originally recorded and what the staff member says really happened.
app.patch('/api/v1/attendance/allocations/:allocationId', async (req, res) => {
  const { allocationId } = req.params;
  const { userId, allocatedHours, correctedHours, description } = req.body;
  const projectCodeProvided = req.body.projectCode !== undefined;
  const projectCode = projectCodeProvided ? normalizeProjectCode(req.body.projectCode) : undefined;
  if (!userId) {
    return res.status(400).json({ error: 'userId is required.' });
  }
  if (allocatedHours == null && correctedHours == null && description === undefined && !projectCodeProvided) {
    return res.status(400).json({ error: 'Provide allocatedHours, correctedHours, description, or projectCode to update.' });
  }

  const beforeAllocation = await db.query('SELECT * FROM attendance_allocations WHERE allocation_id = $1', [allocationId]);

  if (projectCodeProvided) {
    try {
      const target = await db.query(
        `SELECT aa.attendance_id FROM attendance_allocations aa
         JOIN attendance_logs al ON al.attendance_id = aa.attendance_id
         WHERE aa.allocation_id = $1 AND al.user_id = $2`,
        [allocationId, userId]
      );
      if (target.rows.length === 0) {
        return res.status(404).json({ error: 'Allocation not found.' });
      }
      const { attendance_id: attendanceId } = target.rows[0];

      if (projectCode) {
        if (await findDeployedProjectCode([projectCode])) {
          return res.status(403).json({ error: deployedProjectError(projectCode) });
        }
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

      const sibling = await db.query(
        `SELECT allocation_id FROM attendance_allocations
         WHERE attendance_id = $1 AND allocation_id != $2
           AND project_code IS NOT DISTINCT FROM $3`,
        [attendanceId, allocationId, projectCode]
      );
      if (sibling.rows.length > 0) {
        return res.status(409).json({ error: `${projectCode || 'General'} is already on this entry — delete the other block first, or edit that one instead.` });
      }

      const result = await db.query(
        `UPDATE attendance_allocations SET project_code = $1, last_edited_at = CURRENT_TIMESTAMP
         WHERE allocation_id = $2 RETURNING *`,
        [projectCode, allocationId]
      );
      await auditInterceptor('attendance_allocations', allocationId, userId, beforeAllocation.rows[0], result.rows[0]);
      return res.status(200).json({ success: true, data: result.rows[0] });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to update project code.', detail: error.message });
    }
  }

  if (description !== undefined) {
    try {
      const result = await db.query(
        `UPDATE attendance_allocations aa SET description = $1
         FROM attendance_logs al
         WHERE aa.allocation_id = $2 AND aa.attendance_id = al.attendance_id AND al.user_id = $3
         RETURNING aa.*`,
        [(description || '').trim() || null, allocationId, userId]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Allocation not found.' });
      }
      await auditInterceptor('attendance_allocations', allocationId, userId, beforeAllocation.rows[0], result.rows[0]);
      return res.status(200).json({ success: true, data: result.rows[0] });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to update description.', detail: error.message });
    }
  }

  try {
    if (correctedHours != null) {
      if (typeof correctedHours !== 'number' || correctedHours <= 0) {
        return res.status(400).json({ error: 'correctedHours must be a positive number.' });
      }
      const result = await db.query(
        `UPDATE attendance_allocations aa
         SET corrected_hours = $1, last_edited_at = CURRENT_TIMESTAMP
         FROM attendance_logs al
         WHERE aa.allocation_id = $2 AND aa.attendance_id = al.attendance_id AND al.user_id = $3
           AND aa.status = 'COMPLETED'
         RETURNING aa.*`,
        [Math.round(correctedHours * 100) / 100, allocationId, userId]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Completed allocation not found — only completed projects can have their actual hours corrected.' });
      }
      await auditInterceptor('attendance_allocations', allocationId, userId, beforeAllocation.rows[0], result.rows[0]);
      return res.status(200).json({ success: true, data: result.rows[0] });
    }

    if (typeof allocatedHours !== 'number' || allocatedHours <= 0) {
      return res.status(400).json({ error: 'allocatedHours must be a positive number.' });
    }
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
    await auditInterceptor('attendance_allocations', allocationId, userId, beforeAllocation.rows[0], result.rows[0]);
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update allocation.', detail: error.message });
  }
});

// Delete a project allocation entirely — e.g. staff added it by mistake, or wants to redo it
// from scratch. Its hours are folded back in and re-split evenly across whatever open
// (not-yet-completed) allocations remain, the same way adding a project re-splits the
// remaining budget. If the deleted block was the one actively running, the earliest still-
// pending block is promoted to ACTIVE so the session always has something running (unless
// everything left is already COMPLETED, in which case nothing needs to be active).
app.delete('/api/v1/attendance/allocations/:allocationId', async (req, res) => {
  const { allocationId } = req.params;
  const { userId } = req.body;
  if (!userId) {
    return res.status(400).json({ error: 'userId is required.' });
  }

  try {
    const target = await db.query(
      `SELECT aa.attendance_id, aa.status
       FROM attendance_allocations aa
       JOIN attendance_logs al ON al.attendance_id = aa.attendance_id
       WHERE aa.allocation_id = $1 AND al.user_id = $2`,
      [allocationId, userId]
    );
    if (target.rows.length === 0) {
      return res.status(404).json({ error: 'Allocation not found.' });
    }
    const { attendance_id: attendanceId, status: deletedStatus } = target.rows[0];

    const siblingCount = await db.query(
      'SELECT COUNT(*)::int AS n FROM attendance_allocations WHERE attendance_id = $1',
      [attendanceId]
    );
    if (siblingCount.rows[0].n <= 1) {
      return res.status(400).json({ error: 'Can\'t delete the only project on this entry.' });
    }

    const deletedBlock = await db.query('SELECT * FROM attendance_allocations WHERE allocation_id = $1', [allocationId]);
    await db.query('DELETE FROM attendance_allocations WHERE allocation_id = $1', [allocationId]);
    await auditInterceptor('attendance_allocations', allocationId, userId, deletedBlock.rows[0], null);

    const remaining = await db.query(
      `SELECT allocation_id, allocated_hours, status FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [attendanceId]
    );
    const completedHours = remaining.rows
      .filter((r) => r.status === 'COMPLETED')
      .reduce((sum, r) => sum + Number(r.allocated_hours || 0), 0);
    const openRows = remaining.rows.filter((r) => r.status !== 'COMPLETED');
    if (openRows.length > 0) {
      const remainingHours = Math.max(STANDARD_WORKDAY_HOURS - completedHours, 0);
      const evenShare = Math.round((remainingHours / openRows.length) * 100) / 100;
      for (const row of openRows) {
        await db.query('UPDATE attendance_allocations SET allocated_hours = $1 WHERE allocation_id = $2', [evenShare, row.allocation_id]);
      }
    }

    if (deletedStatus === 'ACTIVE') {
      const stillHasActive = remaining.rows.some((r) => r.status === 'ACTIVE');
      if (!stillHasActive) {
        const nextPending = remaining.rows.find((r) => r.status === 'PENDING');
        if (nextPending) {
          await db.query(
            `UPDATE attendance_allocations SET status = 'ACTIVE', started_at = CURRENT_TIMESTAMP WHERE allocation_id = $1`,
            [nextPending.allocation_id]
          );
        }
      }
    }

    const all = await db.query(
      `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, corrected_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion, description
       FROM attendance_allocations WHERE attendance_id = $1 ORDER BY seq ASC`,
      [attendanceId]
    );
    res.status(200).json({ success: true, data: { allocations: all.rows } });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete allocation.', detail: error.message });
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
      `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, corrected_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion, description
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
      `SELECT allocation_id, attendance_id, project_code, allocated_hours, accumulated_hours, corrected_hours, status, seq, started_at, completed_at, notified_at, last_edited_at, edited_after_completion, description
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
    const projectCheck = await db.query('SELECT * FROM projects WHERE project_code = $1', [projectCode]);
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

    await auditInterceptor('projects', projectCode, accountManagerId, projectCheck.rows[0], updatedProject);

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
    if (await findDeployedProjectCode([projectCode])) {
      return res.status(403).json({ error: deployedProjectError(projectCode) });
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
// ROUTE: EDIT / DELETE A BUDGET REQUEST (the requester's own, while still PENDING —
// once a manager or account manager has acted on it, it's no longer editable)
// ========================================================================
app.patch('/api/v1/projects/budget-request/:requestId', async (req, res, next) => {
  const { requestId } = req.params;
  if (requestId === 'review' || requestId === 'am-review' || requestId === 'undo-review') return next();
  const { userId, requestedHours, justification } = req.body;
  const requestedNumber = parseFloat(requestedHours);

  if (isNaN(requestedNumber) || requestedNumber <= 0) {
    return res.status(400).json({ error: 'requestedHours must be a positive number.' });
  }

  try {
    const existing = await db.query('SELECT user_id, status FROM budget_requests WHERE request_id = $1', [requestId]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Budget request not found.' });
    }
    if (existing.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'You can only edit your own budget requests.' });
    }
    if (existing.rows[0].status !== 'PENDING') {
      return res.status(400).json({ error: 'This request has already been reviewed and can no longer be edited.' });
    }

    const result = await db.query(
      `UPDATE budget_requests SET requested_hours = $2, justification = $3 WHERE request_id = $1 RETURNING *`,
      [requestId, requestedNumber, justification?.trim() || null]
    );
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update budget request.', detail: error.message });
  }
});

app.delete('/api/v1/projects/budget-request/:requestId', async (req, res, next) => {
  const { requestId } = req.params;
  if (requestId === 'review' || requestId === 'am-review' || requestId === 'undo-review') return next();
  const { userId } = req.body;

  try {
    const existing = await db.query('SELECT user_id, status FROM budget_requests WHERE request_id = $1', [requestId]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Budget request not found.' });
    }
    if (existing.rows[0].user_id !== userId) {
      return res.status(403).json({ error: 'You can only delete your own budget requests.' });
    }
    if (existing.rows[0].status !== 'PENDING') {
      return res.status(400).json({ error: 'This request has already been reviewed and can no longer be deleted.' });
    }

    await db.query('DELETE FROM budget_requests WHERE request_id = $1', [requestId]);
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete budget request.', detail: error.message });
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
      `SELECT la.leave_id, la.user_id, u.full_name, la.category, la.start_date, la.end_date, la.leave_hours,
              la.workflow_status, la.reviewer_remarks, la.is_late_submission, la.updated_at, la.mc_file_url,
              r.full_name AS reviewer_name
       FROM leave_applications la
       JOIN users u ON la.user_id = u.user_id
       LEFT JOIN users r ON r.user_id = la.reviewed_by
       WHERE u.supervisor_id = $1
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
      SELECT la.leave_id, la.user_id, u.full_name, la.category, la.start_date, la.end_date, la.leave_hours, la.is_late_submission, la.workflow_status, la.mc_file_url
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
  const { userId, category, startDate, endDate, mcFileUrl, reason, hours } = req.body;

  const validCategories = ['ANNUAL', 'EMERGENCY', 'SICK'];
  if (!validCategories.includes(category?.toUpperCase())) {
    return res.status(400).json({ error: "Invalid category. Must be 'ANNUAL', 'EMERGENCY', or 'SICK'." });
  }
  // Required fields: without these the request used to save a leave with no owner, or crash
  // with a 500 on an empty date.
  if (!userId || !UUID_RE.test(String(userId))) {
    return res.status(400).json({ error: 'userId is required.' });
  }
  const isRealDate = (d) => /^\d{4}-\d{2}-\d{2}$/.test(String(d || '')) && !Number.isNaN(new Date(`${d}T00:00:00Z`).getTime())
    && new Date(`${d}T00:00:00Z`).toISOString().slice(0, 10) === d;
  if (!isRealDate(startDate) || !isRealDate(endDate)) {
    return res.status(400).json({ error: 'Please select a start and end date.' });
  }
  if (endDate < startDate) {
    return res.status(400).json({ error: 'The end date cannot be before the start date.' });
  }
  const hourly = parseLeaveHours(hours, category, startDate, endDate);
  if (hourly?.error) return res.status(400).json({ error: hourly.error });
  const leaveHours = hourly ? hourly.hours : null;

  try {
    const applicant = await db.query('SELECT 1 FROM users WHERE user_id = $1', [userId]);
    if (applicant.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

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
        leave_id, user_id, category, start_date, end_date, mc_file_url, is_late_submission, workflow_status, reviewer_remarks, reason, leave_hours, created_at
      ) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'PENDING', NULL, $7, $8, CURRENT_TIMESTAMP)
      RETURNING leave_id, user_id, category, start_date, end_date, is_late_submission, workflow_status, leave_hours;
    `;

    const result = await db.query(leaveInsertQuery, [
      userId, category.toUpperCase(), startDate, endDate,
      category.toUpperCase() === 'SICK' ? mcFileUrl : null,
      isLateSubmission, reason || null, leaveHours
    ]);

    // Notify the requester
    try {
      const notifTitle = 'Leave Request Submitted';
      const notifBody = `You have just submitted a ${category.toLowerCase()} leave request ${leavePeriodText(startDate, endDate, leaveHours)}. It is pending manager review.`;
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
// ROUTE: UNIFIED LEAVE WORKFLOW REVIEW (Manager Restrictions Enforced)
// ========================================================================
// NOTE: these MUST be registered before the generic PATCH /leave/:leaveId route below —
// Express matches routes in registration order, and ":leaveId" is a wildcard that would
// otherwise swallow "review" and "re-review" as if they were literal leave IDs, making
// these handlers permanently unreachable.
// PATCH /api/v1/leave/re-review - re-review an already-reviewed leave request
app.patch('/api/v1/leave/re-review', async (req, res) => {
  const { leaveId, reviewerId, action, reviewerRemarks } = req.body;
  const validActions = ['APPROVED', 'REJECTED'];
  if (!validActions.includes(action?.toUpperCase())) {
    return res.status(400).json({ error: 'Invalid action. Must be APPROVED or REJECTED.' });
  }
  try {
    const reviewerProfile = await db.query('SELECT user_role, user_roles, is_admin FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
    const role = normalizeRole(reviewerProfile.rows[0].user_role);
    if (role === 'staff') return res.status(403).json({ error: 'Staff users cannot review leave.' });
    // Only the applicant's own manager (or HR/admin) may change a past decision — previously any
    // non-staff user could override any team's leave from their History tab.
    const isHrReviewer = Boolean(reviewerProfile.rows[0].is_admin) || userHasRole(reviewerProfile.rows[0], 'hr');
    if (!isHrReviewer) {
      const ownership = await db.query(
        `SELECT 1 FROM leave_applications la JOIN users u ON u.user_id = la.user_id
         WHERE la.leave_id = $1 AND u.supervisor_id = $2`,
        [leaveId, reviewerId]
      );
      if (ownership.rows.length === 0) {
        return res.status(403).json({ error: 'This leave request does not belong to a member of your team.' });
      }
    }
    const beforeLeave = await db.query('SELECT * FROM leave_applications WHERE leave_id = $1', [leaveId]);
    const result = await db.query(
      `UPDATE leave_applications SET workflow_status = $1, reviewer_remarks = $2, reviewed_by = $3, updated_at = CURRENT_TIMESTAMP WHERE leave_id = $4 RETURNING *`,
      [action.toUpperCase(), reviewerRemarks || '', reviewerId, leaveId]
    );
    const updated = result.rows[0];
    if (!updated) return res.status(404).json({ error: 'Leave request not found.' });
    await auditInterceptor('leave_applications', leaveId, reviewerId, beforeLeave.rows[0], updated);
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

// PATCH /api/v1/leave/undo-review - the Undo on the manager's toast. Puts a decision the same
// manager made in the last 10 minutes back to PENDING, so it can be decided again. (Undo used to
// call /leave/review with the opposite action, which only works on PENDING requests, so it failed.)
const UNDO_REVIEW_WINDOW_MINUTES = 10;
app.patch('/api/v1/leave/undo-review', async (req, res) => {
  const { leaveId, reviewerId } = req.body;
  if (!leaveId || !reviewerId) return res.status(400).json({ error: 'leaveId and reviewerId are required.' });
  try {
    const before = await db.query(
      `SELECT la.* FROM leave_applications la JOIN users u ON u.user_id = la.user_id
       WHERE la.leave_id = $1 AND u.supervisor_id = $2`,
      [leaveId, reviewerId]
    );
    if (!before.rows[0]) return res.status(403).json({ error: 'This leave request does not belong to a member of your team.' });
    const result = await db.query(
      `UPDATE leave_applications
       SET workflow_status = 'PENDING', reviewer_remarks = NULL, reviewed_by = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE leave_id = $1 AND reviewed_by = $2 AND workflow_status IN ('APPROVED', 'REJECTED')
         AND updated_at > CURRENT_TIMESTAMP - make_interval(mins => $3)
       RETURNING *`,
      [leaveId, reviewerId, UNDO_REVIEW_WINDOW_MINUTES]
    );
    const updated = result.rows[0];
    if (!updated) {
      return res.status(409).json({ error: 'This decision can no longer be undone. Use History to change it instead.' });
    }
    await auditInterceptor('leave_applications', leaveId, reviewerId, before.rows[0], updated);
    try {
      const notifTitle = 'Leave Decision Withdrawn';
      const notifBody = `${updated.category} • ${leaveRangeShort(updated.start_date, updated.end_date, updated.leave_hours)} • Back to pending manager review.`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [updated.user_id, notifTitle, notifBody]);
      await sendPushToUser(updated.user_id, notifTitle, notifBody);
    } catch (_) {}
    return res.status(200).json({ success: true, data: updated });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to undo the decision.', detail: error.message });
  }
});

app.patch('/api/v1/leave/review', async (req, res) => {
  const { leaveId, reviewerId, action, reviewerRemarks } = req.body;

  // FORWARD_TO_ACCOUNT_MANAGER used to be accepted here, but the leave status type in the database
  // has no such value, so it crashed with a 500. No portal sends it; leave goes manager-only.
  const approvedActions = ['APPROVED', 'REJECTED'];
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

    const beforeLeave = await db.query('SELECT * FROM leave_applications WHERE leave_id = $1', [leaveId]);

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

    await auditInterceptor('leave_applications', leaveId, reviewerId, beforeLeave.rows[0], updatedLeave);

    // Notify the leave applicant
    try {
      const startStr = updatedLeave.start_date
        ? new Date(updatedLeave.start_date).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Singapore' })
        : '';
      const endStr = updatedLeave.end_date
        ? new Date(updatedLeave.end_date).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'Asia/Singapore' })
        : '';
      const category = updatedLeave.category || 'ANNUAL';
      const period = updatedLeave.leave_hours != null ? `${startStr} • ${formatLeaveHours(updatedLeave.leave_hours)}` : `${startStr} → ${endStr}`;
      const hasCustomRemark = reviewerRemarks && reviewerRemarks !== 'Processed via Manager Dashboard.';
      const notifTitle = action.toUpperCase() === 'APPROVED' ? 'Leave Application Approved' : 'Leave Application Rejected';
      const notifBody = action.toUpperCase() === 'APPROVED'
        ? `${category} • ${period} • Approved${hasCustomRemark ? '\nNote: ' + reviewerRemarks : ''}`
        : `${category} • ${period} • Rejected${hasCustomRemark ? '\nReason: ' + reviewerRemarks : ''}`;
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
// ROUTE: EDIT PENDING LEAVE APPLICATION
// ========================================================================
app.patch('/api/v1/leave/:leaveId', async (req, res) => {
  const { leaveId } = req.params;
  const { userId, requesterId, category, startDate, endDate, reason, mcFileUrl, hours } = req.body;
  if (!userId || !category || !startDate || !endDate) {
    return res.status(400).json({ error: 'userId, category, startDate, and endDate are required.' });
  }
  const hourly = parseLeaveHours(hours, category, startDate, endDate);
  if (hourly?.error) return res.status(400).json({ error: hourly.error });
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
    const updated = await db.query(
      `UPDATE leave_applications SET category = $1, start_date = $2, end_date = $3, reason = $4,
       mc_file_url = CASE WHEN $6::text = 'SICK' THEN COALESCE($7, mc_file_url) ELSE NULL END,
       leave_hours = $8, updated_at = CURRENT_TIMESTAMP WHERE leave_id = $5
       RETURNING *`,
      [categoryUpper, startDate, endDate, reason || null, leaveId, categoryUpper, mcFileUrl || null, hourly ? hourly.hours : null]
    );
    await auditInterceptor('leave_applications', leaveId, actingId, check.rows[0], updated.rows[0]);
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
    console.error('[mc-upload] failed for leaveId', leaveId, error);
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
       RETURNING *`,
      [leaveId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Leave request not found or it is not eligible for cancellation.' });
    }
    await auditInterceptor('leave_applications', leaveId, userId, result.rows[0], null);

    try {
      const cancelled = result.rows[0];
      const message = `Your leave request ${leavePeriodText(cancelled.start_date, cancelled.end_date, cancelled.leave_hours)} has been deleted.`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [userId, 'Leave Request Deleted', message]);
    } catch (_) {}

    const { leave_id, user_id, category, start_date, end_date } = result.rows[0];
    return res.status(200).json({ success: true, data: { leave_id, user_id, category, start_date, end_date } });
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
        `SELECT COALESCE(SUM(${LEAVE_DAYS_SQL}), 0) AS used_days
         FROM leave_applications
         WHERE user_id = $1
           AND category::TEXT IN ('ANNUAL', 'EMERGENCY')
           AND workflow_status::TEXT = 'APPROVED'`,
        [userId]
      ),
      db.query('SELECT leave_entitlement_days FROM users WHERE user_id = $1', [userId]),
    ]);
    // Hourly leave makes this a fraction of a day (2 h = 0.25 days at 8 h a day).
    const usedDays = Math.round(Number(usageResult.rows[0]?.used_days || 0) * 100) / 100;
    const totalDays = entitlementResult.rows[0]?.leave_entitlement_days ?? 12;
    const remainingDays = Math.max(0, Math.round((totalDays - usedDays) * 100) / 100);
    return res.status(200).json({ success: true, data: { totalDays, usedDays, remainingDays } });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to calculate leave balance.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: PROJECT PROGRESS UPDATE ENDPOINT 
// ========================================================================
app.post('/api/v1/projects/progress-log', async (req, res) => {
  const { projectCode, reporterId, completionPercentage, progressSummary } = req.body;

  // completionPercentage is the progress MADE this update (e.g. "10" for +10%), not the new
  // running total — staff shouldn't have to remember and re-type where they already were.
  const increment = parseFloat(completionPercentage);
  if (isNaN(increment) || increment <= 0 || increment > 100) {
    return res.status(400).json({ error: "Validation Exception: progress added must be greater than 0% and at most 100%." });
  }

  try {
    const projectCheck = await db.query('SELECT project_code FROM projects WHERE project_code = $1', [projectCode]);
    if (projectCheck.rows.length === 0) {
      return res.status(404).json({ error: `Routing Error: Project with code '${projectCode}' does not exist.` });
    }
    if (await findDeployedProjectCode([projectCode])) {
      return res.status(403).json({ error: deployedProjectError(projectCode) });
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
    if (baseline >= 100) {
      return res.status(400).json({ error: 'This project is already at 100% completion.' });
    }
    const effectivePercentage = Math.min(100, baseline + increment);

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

// ========================================================================
// ROUTE: EDIT / DELETE A PROGRESS LOG ENTRY (the reporter's own manual entries only —
// system-generated "Auto-progress baseline" rows can't be edited or deleted)
// ========================================================================
app.patch('/api/v1/projects/progress-log/:logId', async (req, res) => {
  const { logId } = req.params;
  const { userId, completionPercentage, progressSummary } = req.body;

  const percentage = parseFloat(completionPercentage);
  if (isNaN(percentage) || percentage < 0 || percentage > 100) {
    return res.status(400).json({ error: 'Completion % must be between 0 and 100.' });
  }

  try {
    const existing = await db.query('SELECT * FROM project_progress_logs WHERE log_id = $1', [logId]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Progress log entry not found.' });
    }
    if (existing.rows[0].reporter_id !== userId) {
      return res.status(403).json({ error: 'You can only edit your own progress entries.' });
    }
    if (isAutoProgressEntry(existing.rows[0].progress_summary)) {
      return res.status(400).json({ error: 'System-generated progress entries cannot be edited.' });
    }

    const result = await db.query(
      `UPDATE project_progress_logs SET completion_percentage = $2, progress_summary = $3 WHERE log_id = $1
       RETURNING log_id, project_code, completion_percentage, progress_summary, logged_at`,
      [logId, percentage, progressSummary?.trim() || `Progress update: ${percentage}%`]
    );
    await auditInterceptor('project_progress_logs', logId, userId, existing.rows[0], result.rows[0]);
    res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update progress entry.', detail: error.message });
  }
});

app.delete('/api/v1/projects/progress-log/:logId', async (req, res) => {
  const { logId } = req.params;
  const { userId } = req.body;

  try {
    const existing = await db.query('SELECT * FROM project_progress_logs WHERE log_id = $1', [logId]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Progress log entry not found.' });
    }
    if (existing.rows[0].reporter_id !== userId) {
      return res.status(403).json({ error: 'You can only delete your own progress entries.' });
    }
    if (isAutoProgressEntry(existing.rows[0].progress_summary)) {
      return res.status(400).json({ error: 'System-generated progress entries cannot be deleted.' });
    }

    await db.query('DELETE FROM project_progress_logs WHERE log_id = $1', [logId]);
    await auditInterceptor('project_progress_logs', logId, userId, existing.rows[0], null);
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete progress entry.', detail: error.message });
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
         WHERE COALESCE(p.status, 'ACTIVE') NOT IN ('INACTIVE', 'DEPLOYED')
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
              AND COALESCE(p.status, 'ACTIVE') NOT IN ('INACTIVE', 'DEPLOYED')
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
       WHERE COALESCE(status, 'ACTIVE') NOT IN ('INACTIVE', 'DEPLOYED')
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
      'SELECT project_code, project_name FROM projects WHERE (project_code ILIKE $1 OR project_name ILIKE $1) AND COALESCE(status, \'ACTIVE\') NOT IN (\'INACTIVE\', \'DEPLOYED\') ORDER BY project_code ASC LIMIT 20',
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

    const existing = await db.query('SELECT 1 FROM projects WHERE project_code = $1', [code]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: `Project code ${code} already exists.` });
    }

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
    const code = projectCode.toUpperCase().trim();
    const before = await db.query('SELECT * FROM projects WHERE project_code = $1', [code]);
    if (before.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    await db.query('DELETE FROM projects WHERE project_code = $1', [code]);
    await auditInterceptor('projects', code, editorId, before.rows[0], null);
    res.status(200).json({ success: true, message: `Project ${code} deleted.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete project.', detail: error.message });
  }
});

// FETCH ALL PENDING BUDGET REQUESTS. With ?reviewerId=, only the projects that manager manages
// (HR / admin still see all), so the Manager portal lists only requests it is allowed to review.
app.get('/api/v1/projects/budget-requests', async (req, res) => {
  const { reviewerId } = req.query;
  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(200).json({ success: true, data: [] });
    }

    let scopeToManager = false;
    if (reviewerId) {
      const reviewer = await db.query('SELECT user_role, user_roles, is_admin FROM users WHERE user_id = $1', [reviewerId]);
      if (reviewer.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
      scopeToManager = !userIsHrOrAdmin(reviewer.rows[0]);
    }

    const result = await db.query(
      `SELECT br.*, p.project_name, u.full_name AS requester_name, u.email AS requester_email
       FROM budget_requests br
       JOIN projects p ON br.project_code = p.project_code
       LEFT JOIN users u ON u.user_id = br.user_id
       WHERE br.status = 'PENDING'
         ${scopeToManager ? 'AND $1::uuid = ANY(p.manager_ids::uuid[])' : ''}
       ORDER BY br.created_at ASC`,
      scopeToManager ? [reviewerId] : []
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

  // REFER_TO_AM used to be accepted here, but nothing listed or acted on a referred request,
  // so it went nowhere. A manager who approves already hands the request to the Account Manager.
  const validActions = ['MANAGER_APPROVED', 'REJECTED'];
  if (!validActions.includes(action?.toUpperCase())) {
    return res.status(400).json({ error: "Invalid action. Must be MANAGER_APPROVED or REJECTED." });
  }
  if (!requestId || !reviewerId) {
    return res.status(400).json({ error: 'requestId and reviewerId are required.' });
  }

  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(503).json({ error: 'budget_requests table is not initialized in this environment.' });
    }

    const reviewer = await db.query('SELECT user_role, user_roles, is_admin FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewer.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
    const requestRow = await db.query('SELECT project_code FROM budget_requests WHERE request_id = $1', [requestId]);
    if (requestRow.rows.length === 0) return res.status(404).json({ error: "Request not found or already processed." });
    const requestProject = requestRow.rows[0].project_code;
    if (!userIsHrOrAdmin(reviewer.rows[0]) && !(await isProjectManagerOf(reviewerId, requestProject))) {
      return res.status(403).json({ error: `Only a manager of project ${requestProject} can review this budget request.` });
    }

    // A project without an Account Manager has no one to hand the second approval step to —
    // in that case the manager's approval is final, same effect as the AM review endpoint
    // (bump project budget_hours + the requester's own hour_allocations, status straight to
    // APPROVED) rather than leaving the request stuck at MANAGER_APPROVED forever.
    let finalAction = action.toUpperCase();
    let projectHasAM = true;
    if (finalAction === 'MANAGER_APPROVED') {
      const proj = await db.query(
        'SELECT account_manager_id, account_manager_ids FROM projects WHERE project_code = $1',
        [requestProject]
      );
      const amIds = proj.rows[0]?.account_manager_ids || [];
      projectHasAM = Boolean(proj.rows[0]?.account_manager_id) || amIds.length > 0;
      if (!projectHasAM) finalAction = 'APPROVED';
    }

    const beforeBudgetRequest = await db.query('SELECT * FROM budget_requests WHERE request_id = $1', [requestId]);

    const result = await db.query(
      "UPDATE budget_requests SET status = $1, reviewed_by = $2, reviewed_at = CURRENT_TIMESTAMP WHERE request_id = $3 AND status = 'PENDING' RETURNING *",
      [finalAction, reviewerId, requestId]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "Request not found or already processed." });

    const budgetRow = result.rows[0];

    if (finalAction === 'APPROVED') {
      await db.query('UPDATE projects SET budget_hours = budget_hours + $1 WHERE project_code = $2', [budgetRow.requested_hours, budgetRow.project_code]);
      await db.query(
        `UPDATE hour_allocations
         SET hours_per_week = hours_per_week + $1
         WHERE user_id = $2 AND project_code = $3
           AND account_manager_status = 'APPROVED'`,
        [budgetRow.requested_hours, budgetRow.user_id, budgetRow.project_code]
      );
    }

    await auditInterceptor('budget_requests', requestId, reviewerId, beforeBudgetRequest.rows[0], budgetRow);

    try {
      if (budgetRow.user_id) {
        let notifTitle, notifBody;
        if (finalAction === 'APPROVED') {
          notifTitle = 'Request for Additional Hours — Fully Approved!';
          notifBody = `Your request for additional hours of ${budgetRow.requested_hours}hrs for project ${budgetRow.project_code} has been fully approved by your manager (no Account Manager is assigned to this project).`;
        } else if (finalAction === 'MANAGER_APPROVED') {
          notifTitle = 'Request for Additional Hours — Manager Approved';
          notifBody = `Your request for additional hours of ${budgetRow.requested_hours}hrs for project ${budgetRow.project_code} has been approved by your manager, and is pending Account Manager approval.`;
        } else {
          notifTitle = 'Request for Additional Hours Rejected';
          notifBody = `Your request for additional hours for project ${budgetRow.project_code} has been rejected by the manager.`;
        }
        await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [budgetRow.user_id, notifTitle, notifBody]);
        await sendPushToUser(budgetRow.user_id, notifTitle, notifBody);
      }
    } catch (_) {}

    res.status(200).json({ success: true, data: budgetRow });
  } catch (error) {
    res.status(500).json({ error: 'Review process failed', detail: error.message });
  }
});

// PATCH /api/v1/projects/budget-request/undo-review - the Undo on the manager's toast. Puts a
// decision the same manager made in the last 10 minutes back to PENDING. (Undo used to call
// /review with the opposite action, which only works on PENDING requests, so it failed.) A
// MANAGER_APPROVED request can't be undone once the Account Manager has decided it, because its
// status has moved on. A manager approval that was final (project with no Account Manager) also
// takes the added hours back off the project budget and the requester's allocation.
app.patch('/api/v1/projects/budget-request/undo-review', async (req, res) => {
  const { requestId, reviewerId } = req.body;
  if (!requestId || !reviewerId) return res.status(400).json({ error: 'requestId and reviewerId are required.' });
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const before = await client.query(
      `SELECT * FROM budget_requests
       WHERE request_id = $1 AND reviewed_by = $2 AND status IN ('MANAGER_APPROVED', 'APPROVED', 'REJECTED')
         AND reviewed_at > CURRENT_TIMESTAMP - make_interval(mins => $3)
       FOR UPDATE`,
      [requestId, reviewerId, UNDO_REVIEW_WINDOW_MINUTES]
    );
    const row = before.rows[0];
    if (!row) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This decision can no longer be undone.' });
    }
    if (row.status === 'APPROVED') {
      await client.query('UPDATE projects SET budget_hours = budget_hours - $1 WHERE project_code = $2', [row.requested_hours, row.project_code]);
      await client.query(
        `UPDATE hour_allocations SET hours_per_week = hours_per_week - $1
         WHERE user_id = $2 AND project_code = $3 AND account_manager_status = 'APPROVED'`,
        [row.requested_hours, row.user_id, row.project_code]
      );
    }
    const result = await client.query(
      `UPDATE budget_requests SET status = 'PENDING', reviewed_by = NULL, reviewed_at = NULL, reviewer_remarks = NULL
       WHERE request_id = $1 RETURNING *`,
      [requestId]
    );
    await client.query('COMMIT');
    const updated = result.rows[0];
    await auditInterceptor('budget_requests', requestId, reviewerId, row, updated);
    try {
      const notifTitle = 'Budget Decision Withdrawn';
      const notifBody = `Your request for additional hours of ${updated.requested_hours}hrs for project ${updated.project_code} is back to pending manager review.`;
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [updated.user_id, notifTitle, notifBody]);
      await sendPushToUser(updated.user_id, notifTitle, notifBody);
    } catch (_) {}
    return res.status(200).json({ success: true, data: updated });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return res.status(500).json({ error: 'Failed to undo the decision.', detail: error.message });
  } finally {
    client.release();
  }
});

// GET budget requests pending Account Manager final approval — normally status = MANAGER_APPROVED
// (the manager already reviewed it), but also includes a still-PENDING request on a project that
// has no manager to review it, mirroring the "only one approver exists" logic in am-review.
// REFER_TO_AM rows (an action the manager review no longer accepts) are listed with
// MANAGER_APPROVED so any left from before can still be finished. With ?reviewerId=, only that
// Account Manager's projects (HR / admin still see all).
app.get('/api/v1/projects/budget-requests/pending-am', async (req, res) => {
  const { reviewerId } = req.query;
  try {
    const hasBudgetRequestsTable = await tableExists('public.budget_requests');
    if (!hasBudgetRequestsTable) {
      return res.status(200).json({ success: true, data: [] });
    }

    let scopeToAm = false;
    if (reviewerId) {
      const reviewer = await db.query('SELECT user_role, user_roles, is_admin FROM users WHERE user_id = $1', [reviewerId]);
      if (reviewer.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
      scopeToAm = !userIsHrOrAdmin(reviewer.rows[0]);
    }

    const result = await db.query(
      `SELECT br.*, p.project_name, u.full_name AS requester_name, u.email AS requester_email
       FROM budget_requests br
       JOIN projects p ON br.project_code = p.project_code
       LEFT JOIN users u ON u.user_id = br.user_id
       WHERE (br.status IN ('MANAGER_APPROVED', 'REFER_TO_AM')
          OR (br.status = 'PENDING' AND (p.manager_ids IS NULL OR array_length(p.manager_ids, 1) IS NULL)))
         ${scopeToAm ? 'AND (p.account_manager_id = $1::uuid OR $1::uuid = ANY(p.account_manager_ids::uuid[]))' : ''}
       ORDER BY br.created_at ASC`,
      scopeToAm ? [reviewerId] : []
    );
    res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending AM budget requests.', detail: error.message });
  }
});

// ========================================================================
// ROUTE: EXPENSE CLAIMS (receipt scan with Gemini; manager -> HR approval -> paid)
// ========================================================================
// Every claim route works from the signed-in session (requireSession), never a userId in the
// request. Receipt scanning is capped twice: the Gemini API's prepaid credit balance (AI Studio
// billing is prepay; with auto-reload off, scans stop when it runs out) and our own
// CLAIM_SCAN_MONTHLY_CAP_USD, counted from claim_scans. When a
// scan can't run (not set up, a cap reached, or Gemini failing) the portal falls back to manual
// entry, so claims never depend on the scan.
const CLAIM_CATEGORIES = [
  { code: 'MEALS', label: 'Meals & entertainment' },
  { code: 'LOCAL_TRANSPORT', label: 'Local transport' },
  { code: 'TRAVEL', label: 'Travel (flights, hotel)' },
  { code: 'PARKING_TOLLS', label: 'Parking & tolls' },
  { code: 'OFFICE_SUPPLIES', label: 'Office supplies' },
  { code: 'PHONE_INTERNET', label: 'Phone & internet' },
  { code: 'MEDICAL', label: 'Medical' },
  { code: 'TRAINING', label: 'Training' },
  { code: 'OTHERS', label: 'Others' },
];
const CLAIM_CATEGORY_CODES = CLAIM_CATEGORIES.map((c) => c.code);
const CLAIM_CHARGE_KINDS = ['SERVICE_CHARGE', 'TAX', 'ROUNDING', 'DISCOUNT', 'OTHER'];
const CLAIM_CHARGE_LABELS = { SERVICE_CHARGE: 'Service charge', TAX: 'Tax', ROUNDING: 'Rounding', DISCOUNT: 'Discount', OTHER: 'Other' };
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.1-flash-lite';
const GEMINI_PRICE_IN_PER_M = Number(process.env.GEMINI_PRICE_IN_PER_M || 0.25);
const GEMINI_PRICE_OUT_PER_M = Number(process.env.GEMINI_PRICE_OUT_PER_M || 1.5);
const CLAIM_SCAN_MONTHLY_CAP_USD = Number(process.env.CLAIM_SCAN_MONTHLY_CAP_USD || 19);
const CLAIM_SCAN_DAILY_LIMIT = Number(process.env.CLAIM_SCAN_DAILY_LIMIT_PER_USER || 20);
const CLAIM_SCAN_TIMEOUT_MS = 45_000;
const RECEIPT_MAX_CHARS = 4_000_000; // a base64 image of about 3 MB; the portal sends ~300 KB
const RECEIPT_DATA_URL_RE = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/;
const SGT_MONTH_START_SQL = `(date_trunc('month', now() AT TIME ZONE 'Asia/Singapore') AT TIME ZONE 'Asia/Singapore')`;
const SGT_DAY_START_SQL = `(date_trunc('day', now() AT TIME ZONE 'Asia/Singapore') AT TIME ZONE 'Asia/Singapore')`;

let geminiClient = null;
function getGeminiClient() {
  if (!process.env.GEMINI_API_KEY) return null;
  if (!geminiClient) geminiClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  return geminiClient;
}

function parseReceiptImage(value) {
  const match = RECEIPT_DATA_URL_RE.exec(String(value || ''));
  if (!match) return { error: 'Please attach a photo of the receipt (JPEG, PNG or WebP).' };
  if (value.length > RECEIPT_MAX_CHARS) return { error: 'The receipt photo is too large. Please use a smaller photo.' };
  return { mimeType: match[1], data: match[2] };
}

function sgtTodayYmd() {
  return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Singapore' });
}

function isRealYmd(d) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(d || ''))
    && new Date(`${d}T00:00:00Z`).toISOString().slice(0, 10) === d;
}

function roundMoney(n) {
  return Math.round(Number(n) * 100) / 100;
}

// Cleans what the staff member submits (or edits). Returns { error } or { value }.
function validateClaimInput(body) {
  const purchaseDate = String(body.purchaseDate || '');
  if (!isRealYmd(purchaseDate)) return { error: 'Please enter the date of purchase.' };
  if (purchaseDate > sgtTodayYmd()) return { error: 'The date of purchase cannot be in the future.' };
  const merchant = String(body.merchant || '').trim();
  if (!merchant) return { error: 'Please enter the shop, restaurant or company name.' };
  if (merchant.length > 200) return { error: 'The merchant name is too long (200 characters at most).' };
  const category = String(body.category || '').toUpperCase();
  if (!CLAIM_CATEGORY_CODES.includes(category)) return { error: 'Please choose a category.' };
  const currency = String(body.currency || 'SGD').trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(currency)) return { error: 'Currency must be a 3-letter code, for example SGD.' };
  const total = Number(body.totalAmount);
  if (!Number.isFinite(total) || total <= 0) return { error: 'Please enter the amount paid (more than 0).' };
  if (total > 100000) return { error: 'The amount is too large. Please check it.' };
  const rawItems = Array.isArray(body.items) ? body.items : [];
  if (rawItems.length > 50) return { error: 'A claim can list at most 50 items.' };
  const items = [];
  for (const it of rawItems) {
    const description = String(it?.description || '').trim();
    if (!description) continue;
    const quantity = it.quantity === null || it.quantity === undefined || it.quantity === '' ? null : Number(it.quantity);
    const amount = it.amount === null || it.amount === undefined || it.amount === '' ? null : Number(it.amount);
    if (quantity !== null && (!Number.isFinite(quantity) || quantity <= 0)) return { error: `Check the quantity for "${description}".` };
    if (amount !== null && !Number.isFinite(amount)) return { error: `Check the amount for "${description}".` };
    items.push({ description: description.slice(0, 200), quantity, amount: amount === null ? null : roundMoney(amount) });
  }
  const rawCharges = Array.isArray(body.charges) ? body.charges : [];
  if (rawCharges.length > 10) return { error: 'A claim can list at most 10 charges and taxes.' };
  const charges = [];
  for (const ch of rawCharges) {
    if (ch?.amount === null || ch?.amount === undefined || ch?.amount === '') continue;
    const kind = String(ch.kind || '').toUpperCase();
    if (!CLAIM_CHARGE_KINDS.includes(kind)) return { error: 'Choose a type for each charge or tax line.' };
    const label = String(ch.label || '').trim().slice(0, 60) || CLAIM_CHARGE_LABELS[kind];
    const amount = Number(ch.amount);
    // Rounding can go either way; every other line is entered as the positive amount printed.
    if (!Number.isFinite(amount) || (kind !== 'ROUNDING' && amount < 0)) return { error: `Check the amount for "${label}".` };
    const rate = ch.rate === null || ch.rate === undefined || ch.rate === '' ? null : Number(ch.rate);
    if (rate !== null && (!Number.isFinite(rate) || rate < 0 || rate > 100)) return { error: `Check the rate for "${label}" (0 to 100%).` };
    charges.push({ kind, label, rate, amount: roundMoney(amount) });
  }
  const taxInclusive = body.taxInclusive === true;
  const notes = String(body.notes || '').trim();
  if (notes.length > 1000) return { error: 'Notes are too long (1,000 characters at most).' };
  const projectCode = body.projectCode ? String(body.projectCode).toUpperCase().trim() : null;
  return { value: { purchaseDate, merchant, category, currency, total: roundMoney(total), items, charges, taxInclusive, notes: notes || null, projectCode } };
}

// A project on a claim must exist, not be deployed, and (for staff) be one they are assigned to.
async function checkClaimProject(session, projectCode) {
  if (!projectCode) return null;
  const project = await db.query('SELECT project_code FROM projects WHERE project_code = $1', [projectCode]);
  if (project.rows.length === 0) return `Project ${projectCode} was not found.`;
  if (await findDeployedProjectCode([projectCode])) return deployedProjectError(projectCode);
  if (!userIsManagerial(session)) {
    const assigned = await db.query('SELECT 1 FROM project_assignments WHERE user_id = $1 AND project_code = $2 LIMIT 1', [session.user_id, projectCode]);
    if (assigned.rows.length === 0) return `You are not assigned to project ${projectCode}.`;
  }
  return null;
}

// ── Exchange rates ──
// Rates are the European Central Bank's daily reference rates, read through Frankfurter (free, no
// key). MAS has no public API; to use MAS rates later, replace fetchFxRate and keep the rest.
// The rate is for the purchase date; for a weekend or holiday it is the last rate published
// before it, and rate_date records which day that was.
const COMPANY_CURRENCY = (process.env.COMPANY_CURRENCY || 'SGD').toUpperCase();
const FX_SOURCE = 'ECB reference rate';
const FX_TIMEOUT_MS = 8_000;

async function fetchFxRate(currency, date) {
  const url = `https://api.frankfurter.dev/v1/${date}?base=${encodeURIComponent(currency)}&symbols=${encodeURIComponent(COMPANY_CURRENCY)}`;
  const response = await fetch(url, { signal: AbortSignal.timeout(FX_TIMEOUT_MS) });
  if (!response.ok) return null;
  const body = await response.json();
  const rate = Number(body?.rates?.[COMPANY_CURRENCY]);
  if (!Number.isFinite(rate) || rate <= 0 || !isRealYmd(body?.date)) return null;
  return { rate, rateDate: body.date };
}

// { rate, rateDate, source } for converting `currency` on `date` into the company currency, or
// null when no rate can be found (an unknown currency, or the rate service is down).
async function getFxRate(currency, date) {
  if (currency === COMPANY_CURRENCY) return { rate: 1, rateDate: date, source: null };
  const cached = await db.query(
    'SELECT rate, rate_date::text AS rate_date, source FROM fx_rates WHERE currency = $1 AND base = $2 AND for_date = $3',
    [currency, COMPANY_CURRENCY, date]
  );
  if (cached.rows[0]) return { rate: Number(cached.rows[0].rate), rateDate: cached.rows[0].rate_date, source: cached.rows[0].source };
  let fetched = null;
  try { fetched = await fetchFxRate(currency, date); } catch (err) { console.error('[claims] Exchange rate lookup failed:', err.message); }
  if (!fetched) return null;
  await db.query(
    `INSERT INTO fx_rates (currency, base, for_date, rate, rate_date, source) VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (currency, base, for_date) DO NOTHING`,
    [currency, COMPANY_CURRENCY, date, fetched.rate, fetched.rateDate, FX_SOURCE]
  );
  return { rate: fetched.rate, rateDate: fetched.rateDate, source: FX_SOURCE };
}

// The exchange-rate columns for a validated claim. A claim is never blocked by a missing rate;
// the fields stay empty and HR sees that no rate was found.
async function claimFxFields(v) {
  const fx = await getFxRate(v.currency, v.purchaseDate);
  if (!fx) return { fxRate: null, fxRateDate: null, fxSource: null, amountBase: null };
  return { fxRate: fx.rate, fxRateDate: fx.rateDate, fxSource: fx.source, amountBase: roundMoney(v.total * fx.rate) };
}

// Fills in the exchange rate for unpaid claims that don't have one yet: claims made before rates
// were added, or while the rate service was down. Runs at startup and hourly. Paid and rejected
// claims are left as they are.
async function backfillClaimFxRates() {
  try {
    const r = await db.query(
      `SELECT claim_id, purchase_date::text AS purchase_date, currency, total_amount FROM claims
       WHERE fx_rate IS NULL AND status NOT IN ('PAID', 'REJECTED') ORDER BY created_at ASC LIMIT 200`
    );
    let filled = 0;
    for (const c of r.rows) {
      const fx = await claimFxFields({ currency: c.currency, purchaseDate: c.purchase_date, total: Number(c.total_amount) });
      if (fx.fxRate === null) continue;
      await db.query(
        `UPDATE claims SET fx_rate = $2, fx_rate_date = $3, fx_source = $4, amount_base = $5 WHERE claim_id = $1 AND fx_rate IS NULL`,
        [c.claim_id, fx.fxRate, fx.fxRateDate, fx.fxSource, fx.amountBase]
      );
      filled += 1;
    }
    if (filled) console.log(`[claims] Filled in the exchange rate for ${filled} claim(s).`);
  } catch (err) {
    console.error('[claims] Exchange rate backfill failed:', err.message);
  }
}

async function notifyClaimUser(userId, title, body) {
  if (!userId) return;
  try {
    await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [userId, title, body]);
    await sendPushToUser(userId, title, body);
  } catch (_) {}
}

function claimSummary(c) {
  return `${c.merchant}, ${c.currency} ${Number(c.total_amount).toFixed(2)} on ${formatDateDMY(c.purchase_date)}`;
}

// Two claims look like the same receipt when they have the same purchase date, amount, currency
// and merchant (compared without case, spaces or punctuation, so "Sdn. Bhd." matches "Sdn Bhd").
// Rejected claims are ignored.
const CLAIM_MERCHANT_KEY_SQL = (col) => `regexp_replace(lower(${col}), '[^a-z0-9]', '', 'g')`;
const CLAIM_SAME_RECEIPT_SQL = (a, b) => `${b}.purchase_date = ${a}.purchase_date AND ${b}.total_amount = ${a}.total_amount
  AND ${b}.currency = ${a}.currency AND ${CLAIM_MERCHANT_KEY_SQL(`${b}.merchant`)} = ${CLAIM_MERCHANT_KEY_SQL(`${a}.merchant`)}
  AND ${b}.status <> 'REJECTED'`;

// Adds possible_duplicates to each claim for managers and HR: other claims, by anyone, that look
// like the same receipt. HR sees every name; a manager sees names only for their own team (and
// the claimant themselves), otherwise "another employee".
async function attachClaimDuplicates(rows, viewer) {
  if (rows.length === 0) return rows;
  const r = await db.query(
    `SELECT c.claim_id, d.claim_id AS dup_id, d.user_id AS dup_user_id, d.status AS dup_status,
            d.created_at AS dup_created_at, u.full_name AS dup_name, u.supervisor_id AS dup_supervisor_id
     FROM claims c
     JOIN claims d ON d.claim_id <> c.claim_id AND ${CLAIM_SAME_RECEIPT_SQL('c', 'd')}
     JOIN users u ON u.user_id = d.user_id
     WHERE c.claim_id = ANY($1::uuid[])
     ORDER BY d.created_at ASC`,
    [rows.map((row) => row.claim_id)]
  );
  const byClaim = new Map();
  for (const d of r.rows) {
    const claim = rows.find((row) => row.claim_id === d.claim_id);
    const samePerson = claim && d.dup_user_id === claim.user_id;
    const showName = viewer.isHr || samePerson || d.dup_supervisor_id === viewer.userId;
    if (!byClaim.has(d.claim_id)) byClaim.set(d.claim_id, []);
    byClaim.get(d.claim_id).push({
      claim_id: d.dup_id,
      same_person: Boolean(samePerson),
      claimant_name: showName ? d.dup_name : null,
      status: d.dup_status,
      submitted_at: d.dup_created_at,
    });
  }
  return rows.map((row) => ({ ...row, possible_duplicates: byClaim.get(row.claim_id) || [] }));
}

// Lists never include the receipt photo (it can be hundreds of KB); it is fetched on its own.
// Dates are cast to text so a DATE isn't shifted a day by the JSON timestamp conversion.
const CLAIM_LIST_SELECT = `
  SELECT c.claim_id, c.user_id, c.status, c.purchase_date::text AS purchase_date, c.merchant, c.category,
         c.currency, c.total_amount, c.project_code, p.project_name, c.notes,
         c.manager_reviewed_by, c.manager_reviewed_at, c.manager_remarks,
         c.hr_reviewed_by, c.hr_reviewed_at, c.hr_remarks, c.paid_at::text AS paid_at, c.paid_reference,
         c.created_at, c.updated_at, c.tax_inclusive, c.duplicate_acknowledged,
         c.fx_rate, c.fx_rate_date::text AS fx_rate_date, c.fx_source, c.amount_base,
         u.full_name AS claimant_name, u.email AS claimant_email,
         mr.full_name AS manager_reviewer_name, hrr.full_name AS hr_reviewer_name,
         COALESCE((SELECT json_agg(json_build_object('description', i.description, 'quantity', i.quantity, 'amount', i.amount) ORDER BY i.sort_order)
                   FROM claim_items i WHERE i.claim_id = c.claim_id), '[]'::json) AS items,
         COALESCE((SELECT json_agg(json_build_object('kind', ch.kind, 'label', ch.label, 'rate', ch.rate, 'amount', ch.amount) ORDER BY ch.sort_order)
                   FROM claim_charges ch WHERE ch.claim_id = c.claim_id), '[]'::json) AS charges
  FROM claims c
  JOIN users u ON u.user_id = c.user_id
  LEFT JOIN projects p ON p.project_code = c.project_code
  LEFT JOIN users mr ON mr.user_id = c.manager_reviewed_by
  LEFT JOIN users hrr ON hrr.user_id = c.hr_reviewed_by`;

async function fetchClaimForUpdate(claimId) {
  const r = await db.query(
    `SELECT c.*, c.purchase_date::text AS purchase_date, u.supervisor_id
     FROM claims c JOIN users u ON u.user_id = c.user_id WHERE c.claim_id = $1`,
    [claimId]
  );
  return r.rows[0] || null;
}

// Audit rows leave out the receipt photo itself; it never changes after submission except by an
// edit, which the audit records as a flag.
function claimAuditSnapshot(row, items) {
  if (!row) return null;
  const { receipt_image, ai_extraction, ...rest } = row;
  return { ...rest, has_receipt: Boolean(receipt_image), items: items || undefined };
}

async function saveClaimItems(client, claimId, items) {
  await client.query('DELETE FROM claim_items WHERE claim_id = $1', [claimId]);
  for (let i = 0; i < items.length; i += 1) {
    const it = items[i];
    await client.query(
      'INSERT INTO claim_items (claim_id, description, quantity, amount, sort_order) VALUES ($1, $2, $3, $4, $5)',
      [claimId, it.description, it.quantity, it.amount, i]
    );
  }
}

async function saveClaimCharges(client, claimId, charges) {
  await client.query('DELETE FROM claim_charges WHERE claim_id = $1', [claimId]);
  for (let i = 0; i < charges.length; i += 1) {
    const ch = charges[i];
    await client.query(
      'INSERT INTO claim_charges (claim_id, kind, label, rate, amount, sort_order) VALUES ($1, $2, $3, $4, $5, $6)',
      [claimId, ch.kind, ch.label, ch.rate, ch.amount, i]
    );
  }
}

const RECEIPT_SCAN_PROMPT = [
  'You read a photo of a receipt for a staff expense claim in Singapore or Malaysia.',
  'Extract only what is printed on the receipt. Never guess an amount; use null for anything you cannot read.',
  '- document_type: RECEIPT for a receipt, tax invoice or invoice; QUOTATION for a quotation, estimate or proforma; OTHER if it is not a bill.',
  '- purchase_date: the date on the receipt as YYYY-MM-DD.',
  '- merchant: the shop, restaurant or company name.',
  '- currency: ISO 4217 code. "RM" means MYR. Use SGD when the receipt shows only "$" with no other currency.',
  '- items: each line purchased, with its quantity and line amount. Leave out subtotal, tax, service charge, rounding, discount, change, payment and tax-summary lines.',
  '- charges: every line between the items and the total that changes the amount, once each:',
  '  SERVICE_CHARGE for a service charge; TAX for GST, SST, service tax, sales tax or government tax (one line per tax rate);',
  '  ROUNDING for a rounding adjustment (negative if it lowers the total); DISCOUNT for a discount or voucher (as a positive amount); OTHER for anything else.',
  '  Give the label as printed and the rate as a percentage when printed. Skip tax summary tables that repeat a tax line already listed.',
  '- tax_inclusive: true when the item prices already include the tax (for example "prices include GST"), so the tax was not added on top.',
  '- total: the final amount paid.',
  `- category: the best fit from ${CLAIM_CATEGORY_CODES.join(', ')}.`,
  '- readable: false if the photo is not a receipt or the total cannot be read.',
].join('\n');

const nullable = (type) => ({ anyOf: [{ type }, { type: 'null' }] });
const RECEIPT_SCAN_SCHEMA = {
  type: 'object',
  properties: {
    readable: { type: 'boolean' },
    document_type: { type: 'string', enum: ['RECEIPT', 'QUOTATION', 'OTHER'] },
    purchase_date: { ...nullable('string'), description: 'YYYY-MM-DD' },
    merchant: nullable('string'),
    currency: nullable('string'),
    category: { type: 'string', enum: CLAIM_CATEGORY_CODES },
    items: {
      type: 'array',
      items: {
        type: 'object',
        properties: { description: { type: 'string' }, quantity: nullable('number'), amount: nullable('number') },
        required: ['description', 'quantity', 'amount'],
      },
    },
    charges: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          kind: { type: 'string', enum: CLAIM_CHARGE_KINDS },
          label: { type: 'string' },
          rate: nullable('number'),
          amount: nullable('number'),
        },
        required: ['kind', 'label', 'rate', 'amount'],
      },
    },
    tax_inclusive: { type: 'boolean' },
    total: nullable('number'),
  },
  required: ['readable', 'document_type', 'purchase_date', 'merchant', 'currency', 'category', 'items', 'charges', 'tax_inclusive', 'total'],
};

// Turns Gemini's JSON into the form fields the portal fills in, dropping anything malformed.
function normalizeReceiptScan(raw) {
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? roundMoney(v) : null);
  const date = isRealYmd(raw?.purchase_date) && raw.purchase_date <= sgtTodayYmd() ? raw.purchase_date : null;
  const currency = /^[A-Z]{3}$/.test(String(raw?.currency || '').toUpperCase()) ? String(raw.currency).toUpperCase() : 'SGD';
  const items = (Array.isArray(raw?.items) ? raw.items : []).slice(0, 50)
    .map((it) => ({ description: String(it?.description || '').trim().slice(0, 200), quantity: num(it?.quantity), amount: num(it?.amount) }))
    .filter((it) => it.description);
  return {
    readable: raw?.readable !== false,
    purchaseDate: date,
    merchant: String(raw?.merchant || '').trim().slice(0, 200) || null,
    currency,
    category: CLAIM_CATEGORY_CODES.includes(raw?.category) ? raw.category : 'OTHERS',
    items,
    charges: (Array.isArray(raw?.charges) ? raw.charges : []).slice(0, 10)
      .filter((ch) => CLAIM_CHARGE_KINDS.includes(ch?.kind) && num(ch?.amount) !== null)
      .map((ch) => {
        const rate = num(ch.rate);
        return {
          kind: ch.kind,
          label: String(ch.label || '').trim().slice(0, 60) || CLAIM_CHARGE_LABELS[ch.kind],
          rate: rate !== null && rate >= 0 && rate <= 100 ? rate : null,
          // Discounts are kept positive (they're subtracted); only rounding may be negative.
          amount: ch.kind === 'ROUNDING' ? num(ch.amount) : Math.abs(num(ch.amount)),
        };
      }),
    taxInclusive: raw?.tax_inclusive === true,
    documentType: ['RECEIPT', 'QUOTATION', 'OTHER'].includes(raw?.document_type) ? raw.document_type : 'RECEIPT',
    totalAmount: num(raw?.total) !== null && num(raw?.total) > 0 ? num(raw.total) : null,
  };
}

async function logClaimScan(userId, outcome, { inputTokens = 0, outputTokens = 0, cost = 0, extraction = null } = {}) {
  const r = await db.query(
    `INSERT INTO claim_scans (user_id, input_tokens, output_tokens, cost_usd, outcome, extraction)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING scan_id`,
    [userId, inputTokens, outputTokens, cost, outcome, extraction ? JSON.stringify(extraction) : null]
  );
  return r.rows[0].scan_id;
}

app.get('/api/v1/claims/categories', (req, res) => {
  res.status(200).json({ success: true, data: CLAIM_CATEGORIES });
});

// Exchange rate into the company currency for a purchase date, so the form can show the
// converted amount. The same rate is looked up again on submit; this one is only for display.
app.get('/api/v1/claims/fx-rate', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const currency = String(req.query.currency || '').toUpperCase();
  const date = String(req.query.date || '');
  if (!/^[A-Z]{3}$/.test(currency)) return res.status(400).json({ error: 'currency must be a 3-letter code.' });
  if (!isRealYmd(date) || date > sgtTodayYmd()) return res.status(400).json({ error: 'date must be a past YYYY-MM-DD date.' });
  try {
    const fx = await getFxRate(currency, date);
    if (!fx) return res.status(200).json({ success: true, data: null, base: COMPANY_CURRENCY, message: `No exchange rate found for ${currency}.` });
    return res.status(200).json({ success: true, base: COMPANY_CURRENCY, data: fx });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to look up the exchange rate.', detail: error.message });
  }
});

// Reads a receipt photo with Gemini and returns the fields for the staff member to check.
// Nothing is saved except the scan log. Expected "can't scan" cases answer 200 with
// available:false and a message, so the portal simply switches to manual entry.
app.post('/api/v1/claims/scan', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const image = parseReceiptImage(req.body.receiptImage);
  if (image.error) return res.status(400).json({ error: image.error });
  const manual = (message) => res.status(200).json({ success: true, available: false, message });
  try {
    const client = getGeminiClient();
    if (!client) return manual('Receipt scanning is not set up yet. Please fill in the details yourself.');

    const month = await db.query(`SELECT COALESCE(SUM(cost_usd), 0) AS cost FROM claim_scans WHERE created_at >= ${SGT_MONTH_START_SQL}`);
    if (Number(month.rows[0].cost) >= CLAIM_SCAN_MONTHLY_CAP_USD) {
      await logClaimScan(session.user_id, 'blocked');
      return manual("Receipt scanning has reached this month's limit. Please fill in the details yourself.");
    }
    const today = await db.query(
      `SELECT COUNT(*)::int AS n FROM claim_scans WHERE user_id = $1 AND outcome <> 'blocked' AND created_at >= ${SGT_DAY_START_SQL}`,
      [session.user_id]
    );
    if (today.rows[0].n >= CLAIM_SCAN_DAILY_LIMIT) {
      await logClaimScan(session.user_id, 'blocked');
      return manual(`You've used today's ${CLAIM_SCAN_DAILY_LIMIT} receipt scans. Please fill in the details yourself.`);
    }

    let response;
    try {
      response = await Promise.race([
        client.models.generateContent({
          model: GEMINI_MODEL,
          contents: [{ role: 'user', parts: [{ inlineData: { mimeType: image.mimeType, data: image.data } }, { text: RECEIPT_SCAN_PROMPT }] }],
          config: {
            responseMimeType: 'application/json',
            responseJsonSchema: RECEIPT_SCAN_SCHEMA,
            mediaResolution: MediaResolution.MEDIA_RESOLUTION_HIGH,
            thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
          },
        }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Receipt scan timed out.')), CLAIM_SCAN_TIMEOUT_MS)),
      ]);
    } catch (err) {
      console.error('[claims] Receipt scan failed:', err.message);
      await logClaimScan(session.user_id, 'error');
      return manual("We couldn't read the receipt right now. Please fill in the details yourself.");
    }

    const usage = response.usageMetadata || {};
    const inputTokens = usage.promptTokenCount || 0;
    const outputTokens = (usage.candidatesTokenCount || 0) + (usage.thoughtsTokenCount || 0);
    const cost = (inputTokens * GEMINI_PRICE_IN_PER_M + outputTokens * GEMINI_PRICE_OUT_PER_M) / 1e6;
    let raw = null;
    try { raw = JSON.parse(response.text || ''); } catch (_) {}
    const scanId = await logClaimScan(session.user_id, raw ? 'ok' : 'error', { inputTokens, outputTokens, cost, extraction: raw });
    if (!raw) return manual("We couldn't read the receipt. Please fill in the details yourself.");
    const fields = normalizeReceiptScan(raw);
    if (!fields.readable) {
      return res.status(200).json({ success: true, available: true, scanId, data: fields, message: "This photo doesn't look like a readable receipt. Check the details or retake the photo." });
    }
    // A quotation or estimate isn't proof of payment; the details are still filled in.
    if (fields.documentType === 'QUOTATION') {
      return res.status(200).json({ success: true, available: true, scanId, data: fields, message: 'This looks like a quotation or estimate, not a receipt. Claims need the final receipt or tax invoice, so upload that instead if you have it.' });
    }
    return res.status(200).json({ success: true, available: true, scanId, data: fields });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to scan the receipt.', detail: error.message });
  }
});

// Submit a claim. A claimant with no supervisor goes straight to HR.
app.post('/api/v1/claims', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const input = validateClaimInput(req.body);
  if (input.error) return res.status(400).json({ error: input.error });
  const image = parseReceiptImage(req.body.receiptImage);
  if (image.error) return res.status(400).json({ error: image.error });
  const v = input.value;
  const client = await db.pool.connect();
  try {
    const projectError = await checkClaimProject(session, v.projectCode);
    if (projectError) return res.status(400).json({ error: projectError });

    // The claimant is only ever warned about their own earlier claims; matches with other
    // people's claims are shown to the manager and HR instead.
    const ownDup = await db.query(
      `SELECT 1 FROM (SELECT $2::date AS purchase_date, $3::numeric AS total_amount, $4::text AS currency, $5::text AS merchant) n
       JOIN claims d ON d.user_id = $1 AND ${CLAIM_SAME_RECEIPT_SQL('n', 'd')} LIMIT 1`,
      [session.user_id, v.purchaseDate, v.total, v.currency, v.merchant]
    );
    const duplicateAcknowledged = ownDup.rows.length > 0;
    if (duplicateAcknowledged && req.body.confirmDuplicate !== true) {
      return res.status(409).json({ error: `You already have a claim for ${v.merchant}, ${v.currency} ${v.total.toFixed(2)} on ${formatDateDMY(v.purchaseDate)}. Submit it again only if this is a different receipt.`, duplicate: true });
    }

    let aiExtraction = null;
    if (req.body.scanId && UUID_RE.test(String(req.body.scanId))) {
      const scan = await db.query('SELECT extraction FROM claim_scans WHERE scan_id = $1 AND user_id = $2', [req.body.scanId, session.user_id]);
      aiExtraction = scan.rows[0]?.extraction || null;
    }

    const fx = await claimFxFields(v);
    const me = await db.query('SELECT supervisor_id FROM users WHERE user_id = $1', [session.user_id]);
    const supervisorId = me.rows[0]?.supervisor_id && me.rows[0].supervisor_id !== session.user_id ? me.rows[0].supervisor_id : null;
    const status = supervisorId ? 'PENDING' : 'MANAGER_APPROVED';

    await client.query('BEGIN');
    const inserted = await client.query(
      `INSERT INTO claims (user_id, status, purchase_date, merchant, category, currency, total_amount, project_code,
                           notes, receipt_image, ai_extraction, manager_remarks, tax_inclusive, duplicate_acknowledged,
                           fx_rate, fx_rate_date, fx_source, amount_base)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
       RETURNING claim_id, status, purchase_date::text AS purchase_date, merchant, currency, total_amount`,
      [session.user_id, status, v.purchaseDate, v.merchant, v.category, v.currency, v.total, v.projectCode,
        v.notes, req.body.receiptImage, aiExtraction ? JSON.stringify(aiExtraction) : null,
        supervisorId ? null : 'No manager assigned; sent straight to HR.', v.taxInclusive, duplicateAcknowledged,
        fx.fxRate, fx.fxRateDate, fx.fxSource, fx.amountBase]
    );
    const claim = inserted.rows[0];
    await saveClaimItems(client, claim.claim_id, v.items);
    await saveClaimCharges(client, claim.claim_id, v.charges);
    await client.query('COMMIT');

    await notifyClaimUser(session.user_id, 'Claim Submitted',
      `Your claim for ${claimSummary(claim)} is ${supervisorId ? 'waiting for your manager' : 'waiting for HR'}.`);
    if (supervisorId) {
      await notifyClaimUser(supervisorId, 'Claim to Review', `${session.full_name} submitted a claim: ${claimSummary(claim)}.`);
    }
    return res.status(201).json({ success: true, data: claim });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return res.status(500).json({ error: 'Failed to submit the claim.', detail: error.message });
  } finally {
    client.release();
  }
});

app.get('/api/v1/claims/mine', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  try {
    const r = await db.query(`${CLAIM_LIST_SELECT} WHERE c.user_id = $1 ORDER BY c.created_at DESC LIMIT 200`, [session.user_id]);
    return res.status(200).json({ success: true, data: r.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load your claims.', detail: error.message });
  }
});

app.get('/api/v1/claims/manager-pending', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  try {
    const r = await db.query(
      `${CLAIM_LIST_SELECT} WHERE c.status = 'PENDING' AND u.supervisor_id = $1 AND c.user_id <> $1 ORDER BY c.created_at ASC`,
      [session.user_id]
    );
    return res.status(200).json({ success: true, data: await attachClaimDuplicates(r.rows, { isHr: false, userId: session.user_id }) });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load claims to review.', detail: error.message });
  }
});

app.get('/api/v1/claims/manager-history', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  try {
    const r = await db.query(
      `${CLAIM_LIST_SELECT} WHERE c.manager_reviewed_by = $1 ORDER BY c.manager_reviewed_at DESC LIMIT 200`,
      [session.user_id]
    );
    return res.status(200).json({ success: true, data: await attachClaimDuplicates(r.rows, { isHr: false, userId: session.user_id }) });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load your claim decisions.', detail: error.message });
  }
});

function requireClaimsHr(session, res) {
  if (!isPrivilegedAccount(session)) {
    res.status(403).json({ error: 'Only HR can do this.' });
    return false;
  }
  return true;
}

app.get('/api/v1/claims/hr-pending', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session || !requireClaimsHr(session, res)) return;
  try {
    const r = await db.query(`${CLAIM_LIST_SELECT} WHERE c.status = 'MANAGER_APPROVED' ORDER BY c.created_at ASC`);
    return res.status(200).json({ success: true, data: await attachClaimDuplicates(r.rows, { isHr: true, userId: session.user_id }) });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load claims to approve.', detail: error.message });
  }
});

// HR list with optional ?status= and ?month=YYYY-MM (month the claim was submitted, SGT).
app.get('/api/v1/claims/hr-list', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session || !requireClaimsHr(session, res)) return;
  const { status, month } = req.query;
  const where = [];
  const params = [];
  if (status) {
    params.push(String(status).toUpperCase());
    where.push(`c.status = $${params.length}`);
  }
  if (month) {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(String(month))) return res.status(400).json({ error: 'month must be YYYY-MM.' });
    params.push(`${month}-01`);
    where.push(`(c.created_at AT TIME ZONE 'Asia/Singapore')::date >= $${params.length}::date
                AND (c.created_at AT TIME ZONE 'Asia/Singapore')::date < ($${params.length}::date + INTERVAL '1 month')`);
  }
  try {
    const r = await db.query(
      `${CLAIM_LIST_SELECT} ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY c.created_at DESC LIMIT 500`,
      params
    );
    return res.status(200).json({ success: true, data: await attachClaimDuplicates(r.rows, { isHr: true, userId: session.user_id }) });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load claims.', detail: error.message });
  }
});

// Claims HR approved in a month (SGT), for payroll. The portal turns this into the CSV.
app.get('/api/v1/claims/export', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session || !requireClaimsHr(session, res)) return;
  const { month } = req.query;
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(String(month || ''))) return res.status(400).json({ error: 'month must be YYYY-MM.' });
  try {
    const r = await db.query(
      `${CLAIM_LIST_SELECT}
       WHERE c.status IN ('APPROVED', 'PAID')
         AND (c.hr_reviewed_at AT TIME ZONE 'Asia/Singapore')::date >= $1::date
         AND (c.hr_reviewed_at AT TIME ZONE 'Asia/Singapore')::date < ($1::date + INTERVAL '1 month')
       ORDER BY u.full_name ASC, c.purchase_date ASC`,
      [`${month}-01`]
    );
    return res.status(200).json({ success: true, data: await attachClaimDuplicates(r.rows, { isHr: true, userId: session.user_id }) });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to export claims.', detail: error.message });
  }
});

app.get('/api/v1/claims/scan-usage', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session || !requireClaimsHr(session, res)) return;
  try {
    const r = await db.query(
      `SELECT COALESCE(SUM(cost_usd), 0) AS cost,
              COUNT(*) FILTER (WHERE outcome = 'ok')::int AS scans,
              COUNT(*) FILTER (WHERE outcome = 'error')::int AS errors,
              COUNT(*) FILTER (WHERE outcome = 'blocked')::int AS blocked
       FROM claim_scans WHERE created_at >= ${SGT_MONTH_START_SQL}`
    );
    const row = r.rows[0];
    return res.status(200).json({
      success: true,
      data: {
        costUsd: Number(row.cost), scans: row.scans, errors: row.errors, blocked: row.blocked,
        monthlyCapUsd: CLAIM_SCAN_MONTHLY_CAP_USD, dailyLimitPerUser: CLAIM_SCAN_DAILY_LIMIT,
        configured: Boolean(process.env.GEMINI_API_KEY), model: GEMINI_MODEL,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load scan usage.', detail: error.message });
  }
});

// HR marks approved claims paid (bulk), with the payment date and reference.
app.patch('/api/v1/claims/mark-paid', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session || !requireClaimsHr(session, res)) return;
  const { claimIds, paidDate, paidReference } = req.body;
  const ids = Array.isArray(claimIds) ? claimIds.filter((id) => UUID_RE.test(String(id))) : [];
  if (ids.length === 0) return res.status(400).json({ error: 'Select at least one claim.' });
  if (!isRealYmd(paidDate)) return res.status(400).json({ error: 'Please enter the payment date.' });
  const reference = String(paidReference || '').trim().slice(0, 200) || null;
  try {
    const r = await db.query(
      `UPDATE claims SET status = 'PAID', paid_at = $2, paid_reference = $3, updated_at = CURRENT_TIMESTAMP
       WHERE claim_id = ANY($1::uuid[]) AND status = 'APPROVED'
       RETURNING claim_id, user_id, merchant, currency, total_amount, purchase_date::text AS purchase_date`,
      [ids, paidDate, reference]
    );
    for (const c of r.rows) {
      await auditInterceptor('claims', c.claim_id, session.user_id, { status: 'APPROVED' }, { status: 'PAID', paid_at: paidDate, paid_reference: reference });
      await notifyClaimUser(c.user_id, 'Claim Paid', `Your claim for ${claimSummary(c)} was paid on ${formatDateDMY(paidDate)}.`);
    }
    return res.status(200).json({ success: true, data: { updated: r.rows.length, skipped: ids.length - r.rows.length } });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to mark claims paid.', detail: error.message });
  }
});

// Edit your own claim while it is still waiting for your manager. A new receipt photo is optional.
app.patch('/api/v1/claims/:claimId', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const { claimId } = req.params;
  if (!UUID_RE.test(claimId)) return res.status(400).json({ error: 'Claim id is not valid.' });
  const input = validateClaimInput(req.body);
  if (input.error) return res.status(400).json({ error: input.error });
  let newImage = null;
  if (req.body.receiptImage) {
    const image = parseReceiptImage(req.body.receiptImage);
    if (image.error) return res.status(400).json({ error: image.error });
    newImage = req.body.receiptImage;
  }
  const v = input.value;
  const client = await db.pool.connect();
  try {
    const before = await fetchClaimForUpdate(claimId);
    if (!before) return res.status(404).json({ error: 'Claim not found.' });
    if (before.user_id !== session.user_id) return res.status(403).json({ error: 'You can only edit your own claims.' });
    if (before.status !== 'PENDING') return res.status(400).json({ error: 'This claim has already been reviewed and can no longer be edited.' });
    const projectError = await checkClaimProject(session, v.projectCode);
    if (projectError) return res.status(400).json({ error: projectError });
    const beforeItems = (await db.query('SELECT description, quantity, amount FROM claim_items WHERE claim_id = $1 ORDER BY sort_order', [claimId])).rows;
    const beforeCharges = (await db.query('SELECT kind, label, rate, amount FROM claim_charges WHERE claim_id = $1 ORDER BY sort_order', [claimId])).rows;
    const fx = await claimFxFields(v);

    await client.query('BEGIN');
    const updated = await client.query(
      `UPDATE claims SET purchase_date = $2, merchant = $3, category = $4, currency = $5, total_amount = $6,
              project_code = $7, notes = $8, receipt_image = COALESCE($9, receipt_image), tax_inclusive = $10,
              fx_rate = $11, fx_rate_date = $12, fx_source = $13, amount_base = $14, updated_at = CURRENT_TIMESTAMP
       WHERE claim_id = $1 AND status = 'PENDING' RETURNING *`,
      [claimId, v.purchaseDate, v.merchant, v.category, v.currency, v.total, v.projectCode, v.notes, newImage, v.taxInclusive,
        fx.fxRate, fx.fxRateDate, fx.fxSource, fx.amountBase]
    );
    if (updated.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This claim has already been reviewed and can no longer be edited.' });
    }
    await saveClaimItems(client, claimId, v.items);
    await saveClaimCharges(client, claimId, v.charges);
    await client.query('COMMIT');
    await auditInterceptor('claims', claimId, session.user_id,
      { ...claimAuditSnapshot(before, beforeItems), charges: beforeCharges },
      { ...claimAuditSnapshot(updated.rows[0], v.items), charges: v.charges, receipt_replaced: Boolean(newImage) });
    return res.status(200).json({ success: true, data: { claim_id: claimId } });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return res.status(500).json({ error: 'Failed to update the claim.', detail: error.message });
  } finally {
    client.release();
  }
});

app.delete('/api/v1/claims/:claimId', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const { claimId } = req.params;
  if (!UUID_RE.test(claimId)) return res.status(400).json({ error: 'Claim id is not valid.' });
  try {
    const before = await fetchClaimForUpdate(claimId);
    if (!before) return res.status(404).json({ error: 'Claim not found.' });
    if (before.user_id !== session.user_id) return res.status(403).json({ error: 'You can only delete your own claims.' });
    if (before.status !== 'PENDING') return res.status(400).json({ error: 'This claim has already been reviewed and can no longer be deleted.' });
    const items = (await db.query('SELECT description, quantity, amount FROM claim_items WHERE claim_id = $1 ORDER BY sort_order', [claimId])).rows;
    const charges = (await db.query('SELECT kind, label, rate, amount FROM claim_charges WHERE claim_id = $1 ORDER BY sort_order', [claimId])).rows;
    const r = await db.query(`DELETE FROM claims WHERE claim_id = $1 AND status = 'PENDING'`, [claimId]);
    if (r.rowCount === 0) return res.status(400).json({ error: 'This claim has already been reviewed and can no longer be deleted.' });
    await auditInterceptor('claims', claimId, session.user_id, { ...claimAuditSnapshot(before, items), charges }, null);
    return res.status(200).json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to delete the claim.', detail: error.message });
  }
});

// The receipt photo: only the claimant, their manager, or HR.
app.get('/api/v1/claims/:claimId/receipt', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const { claimId } = req.params;
  if (!UUID_RE.test(claimId)) return res.status(400).json({ error: 'Claim id is not valid.' });
  try {
    const claim = await fetchClaimForUpdate(claimId);
    if (!claim) return res.status(404).json({ error: 'Claim not found.' });
    const allowed = claim.user_id === session.user_id || claim.supervisor_id === session.user_id || isPrivilegedAccount(session);
    if (!allowed) return res.status(403).json({ error: 'You cannot view this receipt.' });
    return res.status(200).json({ success: true, data: { receiptImage: claim.receipt_image } });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load the receipt.', detail: error.message });
  }
});

function readClaimDecision(body) {
  const action = String(body.action || '').toUpperCase();
  if (!['APPROVED', 'REJECTED'].includes(action)) return { error: 'Invalid action. Must be APPROVED or REJECTED.' };
  const remarks = String(body.remarks || '').trim().slice(0, 1000);
  if (action === 'REJECTED' && !remarks) return { error: 'Please give a reason for rejecting this claim.' };
  return { action, remarks: remarks || null };
}

app.patch('/api/v1/claims/:claimId/manager-review', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session) return;
  const { claimId } = req.params;
  if (!UUID_RE.test(claimId)) return res.status(400).json({ error: 'Claim id is not valid.' });
  const decision = readClaimDecision(req.body);
  if (decision.error) return res.status(400).json({ error: decision.error });
  try {
    const before = await fetchClaimForUpdate(claimId);
    if (!before) return res.status(404).json({ error: 'Claim not found.' });
    if (before.user_id === session.user_id) return res.status(403).json({ error: "You can't review your own claim." });
    if (before.supervisor_id !== session.user_id) return res.status(403).json({ error: 'This claim is not from a member of your team.' });
    const newStatus = decision.action === 'APPROVED' ? 'MANAGER_APPROVED' : 'REJECTED';
    const r = await db.query(
      `UPDATE claims SET status = $2, manager_reviewed_by = $3, manager_reviewed_at = CURRENT_TIMESTAMP,
              manager_remarks = $4, updated_at = CURRENT_TIMESTAMP
       WHERE claim_id = $1 AND status = 'PENDING'
       RETURNING claim_id, status, merchant, currency, total_amount, purchase_date::text AS purchase_date`,
      [claimId, newStatus, session.user_id, decision.remarks]
    );
    if (r.rows.length === 0) return res.status(409).json({ error: 'This claim has already been reviewed.' });
    await auditInterceptor('claims', claimId, session.user_id, { status: before.status }, { status: newStatus, manager_remarks: decision.remarks });
    const c = r.rows[0];
    await notifyClaimUser(before.user_id,
      newStatus === 'REJECTED' ? 'Claim Rejected' : 'Claim Approved by Manager',
      newStatus === 'REJECTED'
        ? `Your claim for ${claimSummary(c)} was rejected by your manager. Reason: ${decision.remarks}`
        : `Your claim for ${claimSummary(c)} was approved by your manager and is waiting for HR.`);
    return res.status(200).json({ success: true, data: c });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to review the claim.', detail: error.message });
  }
});

app.patch('/api/v1/claims/:claimId/hr-review', async (req, res) => {
  const session = await requireSession(req, res);
  if (!session || !requireClaimsHr(session, res)) return;
  const { claimId } = req.params;
  if (!UUID_RE.test(claimId)) return res.status(400).json({ error: 'Claim id is not valid.' });
  const decision = readClaimDecision(req.body);
  if (decision.error) return res.status(400).json({ error: decision.error });
  try {
    const before = await fetchClaimForUpdate(claimId);
    if (!before) return res.status(404).json({ error: 'Claim not found.' });
    if (before.user_id === session.user_id) return res.status(403).json({ error: "You can't approve your own claim. Another HR user must review it." });
    const r = await db.query(
      `UPDATE claims SET status = $2, hr_reviewed_by = $3, hr_reviewed_at = CURRENT_TIMESTAMP,
              hr_remarks = $4, updated_at = CURRENT_TIMESTAMP
       WHERE claim_id = $1 AND status = 'MANAGER_APPROVED'
       RETURNING claim_id, status, merchant, currency, total_amount, purchase_date::text AS purchase_date`,
      [claimId, decision.action, session.user_id, decision.remarks]
    );
    if (r.rows.length === 0) return res.status(409).json({ error: 'This claim is not waiting for HR approval.' });
    await auditInterceptor('claims', claimId, session.user_id, { status: before.status }, { status: decision.action, hr_remarks: decision.remarks });
    const c = r.rows[0];
    await notifyClaimUser(before.user_id,
      decision.action === 'REJECTED' ? 'Claim Rejected' : 'Claim Approved',
      decision.action === 'REJECTED'
        ? `Your claim for ${claimSummary(c)} was rejected by HR. Reason: ${decision.remarks}`
        : `Your claim for ${claimSummary(c)} was approved by HR and will be paid with your salary.`);
    return res.status(200).json({ success: true, data: c });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to review the claim.', detail: error.message });
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
    const changed = await db.query(
      'UPDATE users SET user_role = $1, user_roles = $2 WHERE user_id = $3',
      [resolvedPrimary, cleaned, userId]
    );
    if (changed.rowCount === 0) return res.status(404).json({ error: 'User not found.' });
    await revokeUserSessions(userId);
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
      `SELECT user_id, full_name, email, user_role, user_roles, account_status, created_at, leave_entitlement_days, home_office_country
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
  const { requesterId, userId, leaveEntitlementDays, reason } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  const days = Number(leaveEntitlementDays);
  if (!userId || !Number.isInteger(days) || days < 0) {
    return res.status(400).json({ error: 'userId and a non-negative integer leaveEntitlementDays are required.' });
  }
  try {
    const before = await db.query('SELECT leave_entitlement_days FROM users WHERE user_id = $1', [userId]);
    const updated = await db.query(
      'UPDATE users SET leave_entitlement_days = $1 WHERE user_id = $2 RETURNING user_id, full_name, leave_entitlement_days',
      [days, userId]
    );
    if (!updated.rows[0]) return res.status(404).json({ error: 'User not found.' });
    await auditInterceptor('users', userId, requesterId,
      { leave_entitlement_days: before.rows[0]?.leave_entitlement_days ?? 12 },
      { leave_entitlement_days: days, reason: String(reason || '').trim() || null });
    return res.status(200).json({ success: true, data: updated.rows[0] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update leave entitlement.', detail: err.message });
  }
});

// HR: set the same leave entitlement for several employees at once (e.g. a new grade or year).
app.patch('/api/v1/hr/update-leave-entitlement-bulk', async (req, res) => {
  const { requesterId, userIds, leaveEntitlementDays, reason } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  const days = Number(leaveEntitlementDays);
  if (!Array.isArray(userIds) || userIds.length === 0 || !Number.isInteger(days) || days < 0) {
    return res.status(400).json({ error: 'userIds (non-empty array) and a non-negative integer leaveEntitlementDays are required.' });
  }
  try {
    const before = await db.query('SELECT user_id, leave_entitlement_days FROM users WHERE user_id = ANY($1::uuid[])', [userIds]);
    const updated = await db.query(
      'UPDATE users SET leave_entitlement_days = $1 WHERE user_id = ANY($2::uuid[]) RETURNING user_id, leave_entitlement_days',
      [days, userIds]
    );
    const cleanReason = String(reason || '').trim() || null;
    for (const row of before.rows) {
      await auditInterceptor('users', row.user_id, requesterId,
        { leave_entitlement_days: row.leave_entitlement_days ?? 12 },
        { leave_entitlement_days: days, reason: cleanReason });
    }
    return res.status(200).json({ success: true, updated: updated.rows.length, data: updated.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update leave entitlements.', detail: err.message });
  }
});

// HR: approved Annual + Emergency days used per employee (same rule as /leave/balance/:userId),
// so the People page can show used/remaining beside each entitlement in one request.
app.get('/api/v1/hr/leave-balances', async (req, res) => {
  const { requesterId } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  try {
    const result = await db.query(
      `SELECT user_id, ROUND(COALESCE(SUM(${LEAVE_DAYS_SQL}), 0), 2)::float AS used_days
       FROM leave_applications
       WHERE category::TEXT IN ('ANNUAL', 'EMERGENCY') AND workflow_status::TEXT = 'APPROVED'
       GROUP BY user_id`
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch leave balances.', detail: err.message });
  }
});

// Public holidays — read is open to every portal (attendance calendars, reports); writes are
// HR-only. Optional ?year=2027 filters to just that calendar year.
// Malaysia's states and federal territories, the names a state-only holiday is tagged with.
const MALAYSIA_STATES = [
  'Johor', 'Kedah', 'Kelantan', 'Malacca', 'Negeri Sembilan', 'Pahang', 'Penang', 'Perak', 'Perlis',
  'Sabah', 'Sarawak', 'Selangor', 'Terengganu', 'Kuala Lumpur', 'Labuan', 'Putrajaya',
];
// The holiday country asked for (SG, MY, CN or LK), Singapore when none is given; null if unknown.
function holidayCountryParam(value) {
  const code = String(value || 'SG').toUpperCase();
  return OFFICE_TIME_ZONES[code] ? code : null;
}
// A holiday's states, validated: only Malaysia has state holidays, and only known state names.
// Returns null for nationwide, or { error } for a name that isn't a Malaysian state.
function holidayStatesParam(country, states) {
  if (country !== 'MY' || !Array.isArray(states) || states.length === 0) return null;
  const unknown = states.filter((st) => !MALAYSIA_STATES.includes(st));
  if (unknown.length > 0) return { error: `Unknown Malaysian state: ${unknown.join(', ')}.` };
  return MALAYSIA_STATES.filter((st) => states.includes(st)); // de-duplicated, in a fixed order
}
const HOLIDAY_COLUMNS = 'holiday_id, holiday_date, name, country_code, states';

// ?country= picks the list (SG, MY, CN or LK; Singapore when left out, for older portals).
app.get('/api/v1/public-holidays', async (req, res) => {
  const { year } = req.query;
  const country = holidayCountryParam(req.query.country);
  if (!country) return res.status(400).json({ error: 'country must be SG, MY, CN or LK.' });
  try {
    const result = year
      ? await db.query(`SELECT ${HOLIDAY_COLUMNS} FROM public_holidays WHERE country_code = $1 AND EXTRACT(YEAR FROM holiday_date) = $2 ORDER BY holiday_date ASC, name ASC`, [country, year])
      : await db.query(`SELECT ${HOLIDAY_COLUMNS} FROM public_holidays WHERE country_code = $1 ORDER BY holiday_date ASC, name ASC`, [country]);
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch public holidays.', detail: error.message });
  }
});

// Company-wide leave calendar — who is on approved leave between ?from and ?to (YYYY-MM-DD,
// inclusive). Open to any active user in every portal, so it deliberately returns only the
// person's name and dates: no leave type (sick leave is medical), reason or MC.
app.get('/api/v1/calendar/leave', async (req, res) => {
  const { requesterId, from, to } = req.query;
  const isoDate = /^\d{4}-\d{2}-\d{2}$/;
  if (!requesterId) return res.status(400).json({ error: 'requesterId is required.' });
  if (!isoDate.test(String(from || '')) || !isoDate.test(String(to || '')) || from > to) {
    return res.status(400).json({ error: 'from and to must be YYYY-MM-DD dates, with from on or before to.' });
  }
  try {
    const requester = await db.query('SELECT account_status FROM users WHERE user_id = $1', [requesterId]);
    if (requester.rows.length === 0 || String(requester.rows[0].account_status || 'active').toLowerCase() !== 'active') {
      return res.status(403).json({ error: 'Access Denied.' });
    }
    const result = await db.query(
      `SELECT la.leave_id, la.user_id, u.full_name, la.start_date, la.end_date, la.leave_hours
       FROM leave_applications la
       JOIN users u ON u.user_id = la.user_id
       WHERE la.workflow_status = 'APPROVED'
         AND la.start_date <= $2 AND la.end_date >= $1
         AND COALESCE(u.account_status, 'active') = 'active' AND NOT COALESCE(u.is_hidden, false)
       ORDER BY la.start_date ASC, u.full_name ASC`,
      [from, to]
    );
    return res.status(200).json({ success: true, data: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch leave calendar.', detail: error.message });
  }
});

// Add or edit one holiday. With holidayId it edits that holiday; without, it adds one (re-adding
// the same country, date and name just updates its states). Portals from before countries
// existed send no country: that is Singapore, and saving a date that already has one Singapore
// holiday renames it, as it used to.
app.post('/api/v1/hr/public-holidays', async (req, res) => {
  const { requesterId, holidayId, holidayDate, name } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  const country = holidayCountryParam(req.body.country);
  if (!country) return res.status(400).json({ error: 'Choose a country: Singapore, Malaysia, China or Sri Lanka.' });
  if (!holidayDate || !/^\d{4}-\d{2}-\d{2}$/.test(String(holidayDate)) || !name || !String(name).trim()) {
    return res.status(400).json({ error: 'Enter a date and a name for the holiday.' });
  }
  const states = holidayStatesParam(country, req.body.states);
  if (states?.error) return res.status(400).json({ error: states.error });
  const cleanName = String(name).trim();
  try {
    let targetId = holidayId || null;
    if (!targetId && req.body.country === undefined) {
      const legacy = await db.query(`SELECT holiday_id FROM public_holidays WHERE country_code = 'SG' AND holiday_date = $1`, [holidayDate]);
      if (legacy.rows.length === 1) targetId = legacy.rows[0].holiday_id;
    }
    let result;
    if (targetId) {
      const before = await db.query('SELECT holiday_id FROM public_holidays WHERE holiday_id = $1', [targetId]);
      if (before.rows.length === 0) return res.status(404).json({ error: 'That holiday no longer exists. Refresh the page.' });
      result = await db.query(
        `UPDATE public_holidays SET holiday_date = $2, name = $3, country_code = $4, states = $5, updated_by = $6, updated_at = CURRENT_TIMESTAMP
         WHERE holiday_id = $1 RETURNING ${HOLIDAY_COLUMNS}`,
        [targetId, holidayDate, cleanName, country, states, requesterId]
      );
    } else {
      result = await db.query(
        `INSERT INTO public_holidays (holiday_date, name, country_code, states, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
         ON CONFLICT (country_code, holiday_date, name) DO UPDATE SET states = $4, updated_by = $5, updated_at = CURRENT_TIMESTAMP
         RETURNING ${HOLIDAY_COLUMNS}`,
        [holidayDate, cleanName, country, states, requesterId]
      );
    }
    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({ error: 'This country already has a holiday with that name on that date.' });
    }
    return res.status(500).json({ error: 'Failed to save public holiday.', detail: error.message });
  }
});

// Deletes one holiday by id. A YYYY-MM-DD in place of the id is the older portals' delete-by-date,
// which only ever meant Singapore.
app.delete('/api/v1/hr/public-holidays/:holidayId', async (req, res) => {
  const { holidayId } = req.params;
  const { requesterId } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  const isLegacyDate = /^\d{4}-\d{2}-\d{2}$/.test(holidayId);
  if (!isLegacyDate && !/^\d+$/.test(holidayId)) return res.status(400).json({ error: 'Unknown holiday.' });
  try {
    if (isLegacyDate) {
      await db.query(`DELETE FROM public_holidays WHERE country_code = 'SG' AND holiday_date = $1`, [holidayId]);
    } else {
      await db.query('DELETE FROM public_holidays WHERE holiday_id = $1', [holidayId]);
    }
    return res.status(200).json({ success: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to delete public holiday.', detail: error.message });
  }
});

// Google's public holiday calendars, used to fetch Malaysia, China and Sri Lanka holidays (there
// is no open government dataset for them like data.gov.sg). HR sees a preview and confirms
// before anything is saved, and can fix or add any holiday by hand.
const GOOGLE_HOLIDAY_CALENDARS = { MY: 'en.malaysia', CN: 'en.china', LK: 'en.lk' };

// Parses Google's holiday .ics into { holiday_date, name, states } for one year. Observances
// (Valentine's Day and the like) are left out, and Malaysia's "(regional holiday)" entries get
// the states named in their description ("Public holiday in Sabah, Labuan").
function parseHolidayIcs(text, year, country) {
  const unfolded = String(text).replace(/\r?\n[ \t]/g, '');
  const unescape = (v) => String(v || '').replace(/\\n/g, '\n').replace(/\\([,;\\])/g, '$1').trim();
  const out = [];
  for (const block of unfolded.split('BEGIN:VEVENT').slice(1)) {
    const date = block.match(/\nDTSTART;VALUE=DATE:(\d{4})(\d{2})(\d{2})/) || [];
    const summary = unescape((block.match(/\nSUMMARY:([^\r\n]*)/) || [])[1]);
    const description = unescape((block.match(/\nDESCRIPTION:([^\r\n]*)/) || [])[1]);
    if (date[1] !== String(year) || !summary || !/^Public holiday/i.test(description)) continue;
    let states = null;
    const inStates = description.match(/^Public holiday in ([^\n]+)/i);
    if (country === 'MY' && inStates) {
      const named = inStates[1].split(',').map((x) => x.trim());
      states = MALAYSIA_STATES.filter((st) => named.includes(st));
      if (states.length === 0) states = null;
    }
    out.push({
      holiday_date: `${date[1]}-${date[2]}-${date[3]}`,
      name: summary.replace(/\s*\(regional holiday\)\s*$/i, '').trim(),
      states,
    });
  }
  return out.sort((a, b) => (a.holiday_date === b.holiday_date ? a.name.localeCompare(b.name) : a.holiday_date < b.holiday_date ? -1 : 1));
}

// Fetches a country's public holidays for a year — Singapore from data.gov.sg's consolidated
// dataset (refreshed annually by MOM), the others from Google's holiday calendars — and flags
// which are already in our own table, so the frontend can preview before writing anything.
app.get('/api/v1/hr/public-holidays/fetch-official', async (req, res) => {
  const { requesterId, year } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  if (!/^\d{4}$/.test(String(year || ''))) return res.status(400).json({ error: 'year is required.' });
  const country = holidayCountryParam(req.query.country);
  if (!country) return res.status(400).json({ error: 'country must be SG, MY, CN or LK.' });
  const sourceLabel = country === 'SG' ? 'data.gov.sg' : 'the Google public holiday calendar';
  try {
    let forYear;
    let source;
    if (country === 'SG') {
      const officialRes = await axios.get('https://data.gov.sg/api/action/datastore_search', {
        params: { resource_id: 'd_8ef23381f9417e4d4254ee8b4dcdb176', limit: 1000 },
      });
      const records = officialRes.data?.result?.records || [];
      forYear = records
        .filter((r) => String(r.date || '').startsWith(String(year)))
        .map((r) => ({ holiday_date: r.date, name: r.holiday, states: null }));
      source = 'data.gov.sg — Ministry of Manpower';
    } else {
      const calendarId = encodeURIComponent(`${GOOGLE_HOLIDAY_CALENDARS[country]}#holiday@group.v.calendar.google.com`);
      const icsRes = await axios.get(`https://calendar.google.com/calendar/ical/${calendarId}/public/basic.ics`, {
        responseType: 'text', timeout: 15000,
      });
      forYear = parseHolidayIcs(icsRes.data, year, country);
      source = 'Google public holiday calendar';
    }

    const existingRes = await db.query(
      `SELECT holiday_date, name FROM public_holidays WHERE country_code = $1 AND EXTRACT(YEAR FROM holiday_date) = $2`,
      [country, year]
    );
    // Malaysia can have several holidays on one date (different states), so a fetched one only
    // counts as saved when its name matches too. Elsewhere any holiday already on that date
    // counts, as before, so a slightly different name ("Vesak Day (in lieu)") isn't duplicated.
    const existing = new Set(existingRes.rows.map((h) => `${h.holiday_date}|${h.name.toLowerCase()}`));
    const existingDates = new Set(existingRes.rows.map((h) => h.holiday_date));

    const data = forYear.map((h) => ({
      ...h,
      alreadyExists: country === 'MY'
        ? existing.has(`${h.holiday_date}|${h.name.toLowerCase()}`)
        : existingDates.has(h.holiday_date),
    }));

    return res.status(200).json({ success: true, data, source });
  } catch (error) {
    return res.status(502).json({ error: `Failed to fetch holidays from ${sourceLabel}. Try again, or add them by hand.`, detail: error.message });
  }
});

// Bulk-adds holidays for one country in one request — used after the "fetch official holidays"
// preview is confirmed, so N holidays don't need N separate round trips.
app.post('/api/v1/hr/public-holidays/bulk', async (req, res) => {
  const { requesterId, holidays } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  if (!Array.isArray(holidays) || holidays.length === 0) {
    return res.status(400).json({ error: 'holidays must be a non-empty array.' });
  }
  const country = holidayCountryParam(req.body.country);
  if (!country) return res.status(400).json({ error: 'country must be SG, MY, CN or LK.' });
  try {
    // Rows without a date or a name, or with an unknown state, are skipped and counted, so the
    // portal can say how many.
    const saved = [];
    let skipped = 0;
    for (const h of holidays) {
      const states = holidayStatesParam(country, h.states);
      if (!h.holiday_date || !h.name || !String(h.name).trim() || states?.error) { skipped++; continue; }
      const result = await db.query(
        `INSERT INTO public_holidays (holiday_date, name, country_code, states, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
         ON CONFLICT (country_code, holiday_date, name) DO UPDATE SET states = $4, updated_by = $5, updated_at = CURRENT_TIMESTAMP
         RETURNING ${HOLIDAY_COLUMNS}`,
        [h.holiday_date, String(h.name).trim(), country, states, requesterId]
      );
      saved.push(result.rows[0]);
    }
    return res.status(200).json({ success: true, data: saved, skipped });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save public holidays.', detail: error.message });
  }
});

// HR: permanently delete a user and every record tied to them. Irreversible — the frontend
// gates this behind a confirmation modal.
// HR: edit a user's basic info (name/email/office country) — for correcting data entry mistakes
// (e.g. an email that doesn't actually belong to the listed staff member). The office country
// sets the time zone the staff member's attendance is recorded and shown in.
app.patch('/api/v1/hr/users/:userId', async (req, res) => {
  const { userId } = req.params;
  const { requesterId, fullName, email, homeOfficeCountry } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  if (!fullName || !fullName.trim()) return res.status(400).json({ error: 'Full name is required.' });
  if (!email || !email.trim()) return res.status(400).json({ error: 'Email is required.' });
  const normalizedEmail = email.trim().toLowerCase();
  if (!SIGNUP_EMAIL_RE.test(normalizedEmail)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  const country = homeOfficeCountry === undefined ? null : String(homeOfficeCountry).toUpperCase();
  if (country !== null && !OFFICE_TIME_ZONES[country]) {
    return res.status(400).json({ error: 'Choose an office country: Singapore, Malaysia, China or Sri Lanka.' });
  }

  try {
    const dupe = await db.query('SELECT user_id FROM users WHERE LOWER(email) = $1 AND user_id != $2', [normalizedEmail, userId]);
    if (dupe.rows.length > 0) return res.status(409).json({ error: 'Another user already has this email.' });

    const before = await db.query('SELECT user_id, full_name, email, home_office_country FROM users WHERE user_id = $1', [userId]);
    if (before.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
    const result = await db.query(
      `UPDATE users SET full_name = $1, email = $2, home_office_country = COALESCE($4, home_office_country)
       WHERE user_id = $3 RETURNING user_id, full_name, email, home_office_country`,
      [fullName.trim(), normalizedEmail, userId, country]
    );
    await auditInterceptor('users', userId, requesterId, before.rows[0], result.rows[0]);
    return res.status(200).json({ success: true, data: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update user.', detail: err.message });
  }
});

app.delete('/api/v1/hr/users/:userId', async (req, res) => {
  const { userId } = req.params;
  const { requesterId } = req.body;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  if (requesterId === userId) return res.status(400).json({ error: "You can't delete your own account." });

  try {
    const target = await db.query('SELECT user_id, full_name FROM users WHERE user_id = $1', [userId]);
    if (target.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

    // Clear references that aren't ON DELETE CASCADE so the final delete doesn't hit an FK violation.
    await db.query('UPDATE users SET supervisor_id = NULL WHERE supervisor_id = $1', [userId]);
    await db.query('UPDATE project_assignments SET assigned_by = NULL WHERE assigned_by = $1', [userId]);
    await db.query('UPDATE hour_allocations SET allocated_by = NULL WHERE allocated_by = $1', [userId]);
    await db.query('UPDATE hour_allocations SET account_manager_reviewer_id = NULL WHERE account_manager_reviewer_id = $1', [userId]);
    await db.query('UPDATE leave_applications SET reviewed_by = NULL WHERE reviewed_by = $1', [userId]);
    await db.query('UPDATE budget_requests SET reviewed_by = NULL WHERE reviewed_by = $1', [userId]);
    await db.query('UPDATE password_reset_requests SET reviewed_by = NULL WHERE reviewed_by = $1', [userId]);

    // Explicitly clear attendance data too, since attendance_logs/attendance_allocations predate
    // ensureOperationalTables and their FK cascade behavior isn't guaranteed here.
    await db.query(
      'DELETE FROM attendance_allocations WHERE attendance_id IN (SELECT attendance_id FROM attendance_logs WHERE user_id = $1)',
      [userId]
    );
    await db.query('DELETE FROM attendance_logs WHERE user_id = $1', [userId]);

    await db.query('DELETE FROM users WHERE user_id = $1', [userId]);
    return res.status(200).json({ success: true, data: { user_id: userId, full_name: target.rows[0].full_name } });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete user.', detail: err.message });
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

// Per-staff budget usage report, for every project this Account Manager manages: hours
// allocated vs. tracked, over-budget flag, and any approved budget extensions for that
// staff member on that project.
app.get('/api/v1/account-manager/:userId/staff-usage-report', async (req, res) => {
  const { userId } = req.params;
  try {
    const userRow = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [userId]);
    if (!userRow.rows[0] || !userHasRole(userRow.rows[0], 'account_manager')) {
      return res.status(403).json({ error: 'Account Manager access required.' });
    }
    const result = await db.query(`
      WITH latest_allocation AS (
        SELECT DISTINCT ON (user_id, project_code) user_id, project_code, hours_per_week
        FROM hour_allocations
        WHERE account_manager_status = 'APPROVED'
        ORDER BY user_id, project_code, created_at DESC
      ),
      tracked AS (
        SELECT al.user_id, aa.project_code,
               SUM(COALESCE(aa.corrected_hours, aa.accumulated_hours, 0)) AS used_hours
        FROM attendance_allocations aa
        JOIN attendance_logs al ON al.attendance_id = aa.attendance_id
        WHERE aa.project_code IS NOT NULL
        GROUP BY al.user_id, aa.project_code
      ),
      extensions AS (
        SELECT user_id, project_code, SUM(requested_hours) AS extension_hours
        FROM budget_requests
        WHERE status = 'APPROVED'
        GROUP BY user_id, project_code
      )
      SELECT
        p.project_code, p.project_name, p.budget_hours AS project_budget_hours,
        u.user_id, u.full_name,
        COALESCE(la.hours_per_week, 0) AS allocated_hours,
        COALESCE(t.used_hours, 0) AS used_hours,
        COALESCE(ext.extension_hours, 0) AS extension_hours
      FROM project_assignments pa
      JOIN projects p ON p.project_code = pa.project_code
      JOIN users u ON u.user_id = pa.user_id
      LEFT JOIN latest_allocation la ON la.user_id = pa.user_id AND la.project_code = pa.project_code
      LEFT JOIN tracked t ON t.user_id = pa.user_id AND t.project_code = pa.project_code
      LEFT JOIN extensions ext ON ext.user_id = pa.user_id AND ext.project_code = pa.project_code
      WHERE p.account_manager_id = $1::uuid OR $1::uuid = ANY(p.account_manager_ids::uuid[])
      ORDER BY p.project_name ASC, u.full_name ASC
    `, [userId]);

    const rows = result.rows.map((r) => {
      const allocated = Number(r.allocated_hours || 0);
      const used = Number(r.used_hours || 0);
      return {
        ...r,
        allocated_hours: allocated,
        used_hours: used,
        extension_hours: Number(r.extension_hours || 0),
        percent_used: allocated > 0 ? Math.round((used / allocated) * 1000) / 10 : 0,
        over_budget: allocated > 0 && used > allocated,
      };
    });
    return res.status(200).json({ success: true, data: rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to build staff usage report.', detail: error.message });
  }
});

// Per-employee budget/project usage report, across ALL of that employee's assigned projects
// (not scoped to any single Account Manager's ownership) — used by report generators (HR/AM PDF).
app.get('/api/v1/reports/budget-usage/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await db.query(`
      WITH latest_allocation AS (
        SELECT DISTINCT ON (user_id, project_code) user_id, project_code, hours_per_week
        FROM hour_allocations
        WHERE account_manager_status = 'APPROVED'
        ORDER BY user_id, project_code, created_at DESC
      ),
      tracked AS (
        SELECT al.user_id, aa.project_code,
               SUM(COALESCE(aa.corrected_hours, aa.accumulated_hours, 0)) AS used_hours
        FROM attendance_allocations aa
        JOIN attendance_logs al ON al.attendance_id = aa.attendance_id
        WHERE aa.project_code IS NOT NULL
        GROUP BY al.user_id, aa.project_code
      ),
      extensions AS (
        SELECT user_id, project_code, SUM(requested_hours) AS extension_hours
        FROM budget_requests
        WHERE status = 'APPROVED'
        GROUP BY user_id, project_code
      )
      SELECT
        p.project_code, p.project_name,
        COALESCE(la.hours_per_week, 0) AS allocated_hours,
        COALESCE(t.used_hours, 0) AS used_hours,
        COALESCE(ext.extension_hours, 0) AS extension_hours
      FROM project_assignments pa
      JOIN projects p ON p.project_code = pa.project_code
      LEFT JOIN latest_allocation la ON la.user_id = pa.user_id AND la.project_code = pa.project_code
      LEFT JOIN tracked t ON t.user_id = pa.user_id AND t.project_code = pa.project_code
      LEFT JOIN extensions ext ON ext.user_id = pa.user_id AND ext.project_code = pa.project_code
      WHERE pa.user_id = $1::uuid
      ORDER BY p.project_name ASC
    `, [userId]);

    const rows = result.rows.map((r) => {
      const allocated = Number(r.allocated_hours || 0);
      const used = Number(r.used_hours || 0);
      return {
        ...r,
        allocated_hours: allocated,
        used_hours: used,
        extension_hours: Number(r.extension_hours || 0),
        percent_used: allocated > 0 ? Math.round((used / allocated) * 1000) / 10 : 0,
        over_budget: allocated > 0 && used > allocated,
      };
    });
    return res.status(200).json({ success: true, data: rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to build budget usage report.', detail: error.message });
  }
});

// Account Manager final approval of budget requests. Normally MANAGER_APPROVED → APPROVED/
// REJECTED (the manager reviews first, AM gives final sign-off). But a project can have an AM
// and no manager — the mirror image of a project with a manager and no AM, which manager-review
// already handles by finalizing on its own. Here, if the project has no manager, there's no one
// to produce a MANAGER_APPROVED state, so the AM is also allowed to act directly on a PENDING
// request — same "only one approver exists, so their approval is final" principle either way.
app.patch('/api/v1/projects/budget-request/am-review', async (req, res) => {
  const { requestId, reviewerId, action } = req.body;
  const validActions = ['APPROVED', 'REJECTED'];
  if (!validActions.includes(action?.toUpperCase())) {
    return res.status(400).json({ error: "Invalid action. Must be APPROVED or REJECTED." });
  }
  try {
    const reviewerProfile = await db.query('SELECT user_role, user_roles, is_admin FROM users WHERE user_id = $1', [reviewerId]);
    if (reviewerProfile.rows.length === 0) return res.status(404).json({ error: 'Reviewer not found.' });
    if (!userHasRole(reviewerProfile.rows[0], 'account_manager')) return res.status(403).json({ error: 'Only Account Managers can perform final budget approval.' });

    const beforeBudgetRequest = await db.query('SELECT * FROM budget_requests WHERE request_id = $1', [requestId]);
    if (beforeBudgetRequest.rows.length === 0) return res.status(404).json({ error: 'Budget request not found.' });
    const requestProject = beforeBudgetRequest.rows[0].project_code;

    if (!userIsHrOrAdmin(reviewerProfile.rows[0]) && !(await isProjectAccountManagerOf(reviewerId, requestProject))) {
      return res.status(403).json({ error: `Only the Account Manager of project ${requestProject} can give final approval.` });
    }

    const proj = await db.query('SELECT manager_ids FROM projects WHERE project_code = $1', [requestProject]);
    const projectHasManager = (proj.rows[0]?.manager_ids || []).length > 0;
    const acceptedSourceStatuses = projectHasManager ? ['MANAGER_APPROVED', 'REFER_TO_AM'] : ['PENDING'];

    const result = await db.query(
      `UPDATE budget_requests SET status = $1, reviewed_by = $2, reviewed_at = CURRENT_TIMESTAMP
       WHERE request_id = $3 AND status = ANY($4) RETURNING *`,
      [action.toUpperCase(), reviewerId, requestId, acceptedSourceStatuses]
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

    await auditInterceptor('budget_requests', requestId, reviewerId, beforeBudgetRequest.rows[0], budgetRow);

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

// MARK PROJECT DEPLOYED (ACTIVE or MAINTENANCE -> DEPLOYED). Staff assignments are kept so the
// same team comes back when it is reactivated; time logging is blocked while it is DEPLOYED.
// HR and Account Managers only. /deactivate is kept as an alias for portal builds that still
// call it.
async function markProjectDeployed(req, res) {
  const { projectCode } = req.params;
  const { editorId } = req.body;
  if (!editorId) return res.status(400).json({ error: 'editorId is required.' });
  try {
    const editorCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || !userCanManageProjectLifecycle(editorCheck.rows[0])) {
      return res.status(403).json({ error: 'Access Denied: Only HR or Account Manager users can mark a project as deployed.' });
    }
    const code = projectCode.toUpperCase().trim();
    const existing = await db.query('SELECT status FROM projects WHERE project_code = $1', [code]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    const before = String(existing.rows[0].status || 'ACTIVE').toUpperCase();
    if (before === 'DEPLOYED' || before === 'INACTIVE') {
      return res.status(400).json({ error: `Project ${code} is already deployed.` });
    }
    const result = await db.query(
      `UPDATE projects SET status = 'DEPLOYED' WHERE project_code = $1 RETURNING *`,
      [code]
    );
    await auditInterceptor('projects', code, editorId, { status: before }, { status: 'DEPLOYED' });
    res.status(200).json({ success: true, message: `Project ${code} marked as deployed.`, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark project as deployed.', detail: error.message });
  }
}
app.patch('/api/v1/projects/:projectCode/deploy', markProjectDeployed);
app.patch('/api/v1/projects/:projectCode/deactivate', markProjectDeployed);

// REACTIVATE PROJECT FOR MAINTENANCE (DEPLOYED -> MAINTENANCE). Staff can log time against a
// MAINTENANCE project like an ACTIVE one. HR and Account Managers only.
app.patch('/api/v1/projects/:projectCode/reactivate', async (req, res) => {
  const { projectCode } = req.params;
  const { editorId } = req.body;
  if (!editorId) return res.status(400).json({ error: 'editorId is required.' });
  try {
    const editorCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [editorId]);
    if (editorCheck.rows.length === 0 || !userCanManageProjectLifecycle(editorCheck.rows[0])) {
      return res.status(403).json({ error: 'Access Denied: Only HR or Account Manager users can reactivate a project.' });
    }
    const code = projectCode.toUpperCase().trim();
    const existing = await db.query('SELECT status FROM projects WHERE project_code = $1', [code]);
    if (existing.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    const before = String(existing.rows[0].status || 'ACTIVE').toUpperCase();
    if (before !== 'DEPLOYED' && before !== 'INACTIVE') {
      return res.status(400).json({ error: `Only a deployed project can be reactivated. ${code} is ${before}.` });
    }
    const result = await db.query(
      `UPDATE projects SET status = 'MAINTENANCE' WHERE project_code = $1 RETURNING *`,
      [code]
    );
    await auditInterceptor('projects', code, editorId, { status: before }, { status: 'MAINTENANCE' });
    res.status(200).json({ success: true, message: `Project ${code} reactivated for maintenance.`, data: result.rows[0] });
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
    if (managerCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Only manager-role users can set supervisor assignments.' });
    }
    // A project's org tree lets HR assign someone as that project's Manager/Account Manager
    // regardless of their global account role (intentionally — project role is independent of
    // account role). So eligibility here also accepts anyone holding a manager/account_manager
    // project_role on at least one project, not just users whose global role is managerial.
    let isEligible = userIsManagerial(managerCheck.rows[0]);
    if (!isEligible) {
      const projectRoleCheck = await db.query(
        `SELECT 1 FROM project_assignments WHERE user_id = $1 AND project_role IN ('manager', 'account_manager') LIMIT 1`,
        [managerId]
      );
      isEligible = projectRoleCheck.rows.length > 0;
    }
    if (!isEligible) {
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
  const { managerId, userIds, projectCode, projectRole: forcedProjectRole } = req.body;
  const VALID_PROJECT_ROLES = ['account_manager', 'manager', 'staff'];
  if (!managerId || !Array.isArray(userIds) || userIds.length === 0 || !projectCode) {
    return res.status(400).json({ error: 'managerId, userIds (array) and projectCode are required.' });
  }
  if (forcedProjectRole && !VALID_PROJECT_ROLES.includes(forcedProjectRole)) {
    return res.status(400).json({ error: 'projectRole, if given, must be account_manager, manager, or staff.' });
  }
  try {
    const managerCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [managerId]);
    if (managerCheck.rows.length === 0 || !userIsManagerial(managerCheck.rows[0])) {
      return res.status(403).json({ error: 'Only managers can assign projects.' });
    }
    const projectCheck = await db.query('SELECT project_code, budget_hours, project_name FROM projects WHERE project_code = $1 AND COALESCE(status, \'ACTIVE\') NOT IN (\'INACTIVE\', \'DEPLOYED\') LIMIT 1', [projectCode]);
    if (projectCheck.rows.length === 0) return res.status(404).json({ error: 'Project code not found or has been deployed.' });

    const results = [];
    for (const userId of userIds) {
      let defaultProjectRole = forcedProjectRole;
      if (!defaultProjectRole) {
        // No explicit role given — fall back to guessing from the user's own account role.
        // (Callers that already know the intended project role, like the Hierarchy tree's
        // "+ Add Manager/Staff" controls, should pass projectRole directly instead of relying
        // on this guess — using this default and correcting it with a second call let the AM
        // demotion below fire against the guessed role instead of the real intended one.)
        const assigneeRow = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1 LIMIT 1', [userId]);
        const assigneeRoles = assigneeRow.rows[0]
          ? (Array.isArray(assigneeRow.rows[0].user_roles) && assigneeRow.rows[0].user_roles.length > 0
            ? assigneeRow.rows[0].user_roles : [assigneeRow.rows[0].user_role].filter(Boolean))
          : ['staff'];
        const PROJECT_ROLE_PRIORITY = ['account_manager', 'manager', 'staff'];
        defaultProjectRole = PROJECT_ROLE_PRIORITY.find((r) => assigneeRoles.includes(r)) || 'staff';
      }

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
         u.home_office_country,
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
           (SELECT json_agg(json_build_object('project_code', aa.project_code, 'allocated_hours', aa.allocated_hours, 'accumulated_hours', aa.accumulated_hours, 'status', aa.status, 'edited_after_completion', aa.edited_after_completion, 'last_edited_at', aa.last_edited_at, 'description', aa.description) ORDER BY aa.seq)
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

// Account Manager: attendance logs for staff on projects this AM manages — powers the AM
// Portal's report generator (same shape as the manager/HR variants above, scoped by project
// ownership instead of supervisor_id).
app.get('/api/v1/account-manager/:userId/attendance-logs', async (req, res) => {
  const { userId } = req.params;

  try {
    const amCheck = await db.query('SELECT user_role, user_roles FROM users WHERE user_id = $1', [userId]);
    if (amCheck.rows.length === 0 || !userHasRole(amCheck.rows[0], 'account_manager')) {
      return res.status(403).json({ error: 'Account Manager access required.' });
    }

    const result = await db.query(
      `SELECT
         al.attendance_id,
         al.user_id,
         u.full_name,
         u.home_office_country,
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
           (SELECT json_agg(json_build_object('project_code', aa.project_code, 'allocated_hours', aa.allocated_hours, 'accumulated_hours', aa.accumulated_hours, 'status', aa.status, 'edited_after_completion', aa.edited_after_completion, 'last_edited_at', aa.last_edited_at, 'description', aa.description) ORDER BY aa.seq)
            FROM attendance_allocations aa WHERE aa.attendance_id = al.attendance_id),
           '[]'
         ) AS allocations
       FROM attendance_logs al
       JOIN users u ON u.user_id = al.user_id
       WHERE EXISTS (
         SELECT 1 FROM project_assignments pa
         JOIN projects p ON p.project_code = pa.project_code
         WHERE pa.user_id = al.user_id
           AND (p.account_manager_id = $1::uuid OR $1::uuid = ANY(p.account_manager_ids::uuid[]))
       )
       ORDER BY al.created_at DESC
       LIMIT 500`,
      [userId]
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
         u.home_office_country,
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
           (SELECT json_agg(json_build_object('project_code', aa.project_code, 'allocated_hours', aa.allocated_hours, 'accumulated_hours', aa.accumulated_hours, 'status', aa.status, 'edited_after_completion', aa.edited_after_completion, 'last_edited_at', aa.last_edited_at, 'description', aa.description) ORDER BY aa.seq)
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
      `SELECT la.leave_id, la.user_id, u.full_name, u.email, la.category, la.start_date, la.end_date, la.leave_hours,
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

// HR Portal > Audit Log: read-only, filterable, paginated view of audit_logs. Each row is
// resolved to the person who made the change ("changed by") and, where the record belongs to
// someone, the person it belongs to ("affected"). Allocation snapshots carry no user_id, so
// those are traced through their attendance entry; project changes have no affected person.
const AUDIT_TABLES = ['attendance_logs', 'attendance_allocations', 'leave_applications', 'project_progress_logs', 'budget_requests', 'projects', 'users'];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
app.get('/api/v1/hr/audit-logs', async (req, res) => {
  const { requesterId, from, to, tableName, alteredBy, subjectUserId } = req.query;
  if (!await requireRoleCheck(requesterId, 'hr', res)) return;
  const isoDate = /^\d{4}-\d{2}-\d{2}$/;
  if ((from && !isoDate.test(from)) || (to && !isoDate.test(to)) || (from && to && from > to)) {
    return res.status(400).json({ error: 'from and to must be YYYY-MM-DD dates, with from on or before to.' });
  }
  if (tableName && !AUDIT_TABLES.includes(tableName)) {
    return res.status(400).json({ error: 'Unknown record type.' });
  }
  if ((alteredBy && !UUID_RE.test(alteredBy)) || (subjectUserId && !UUID_RE.test(subjectUserId))) {
    return res.status(400).json({ error: 'Invalid user filter.' });
  }
  const pageSize = Math.min(Math.max(parseInt(req.query.pageSize, 10) || 20, 1), 100);
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  try {
    const result = await db.query(
      `WITH a AS (
         SELECT l.*,
           CASE l.table_name
             WHEN 'users' THEN l.record_id
             WHEN 'projects' THEN NULL
             WHEN 'project_progress_logs' THEN COALESCE(l.post_value->>'reporter_id', l.pre_value->>'reporter_id')
             -- Only the entry's owner can edit its blocks, so fall back to the editor once the
             -- entry itself has been deleted.
             WHEN 'attendance_allocations' THEN COALESCE((
               SELECT al.user_id::text FROM attendance_logs al
               WHERE al.attendance_id::text = COALESCE(l.post_value->>'attendance_id', l.pre_value->>'attendance_id')),
               l.altered_by::text)
             ELSE COALESCE(l.post_value->>'user_id', l.pre_value->>'user_id')
           END AS subject_user_id
         FROM audit_logs l
       )
       SELECT a.audit_id, a.table_name, a.record_id, a.altered_by, a.pre_value, a.post_value, a.created_at,
              a.subject_user_id, ab.full_name AS altered_by_name, su.full_name AS subject_name,
              COUNT(*) OVER() AS total_count
       FROM a
       LEFT JOIN users ab ON ab.user_id::text = a.altered_by::text
       LEFT JOIN users su ON su.user_id::text = a.subject_user_id
       WHERE ($1::date IS NULL OR (a.created_at AT TIME ZONE 'Asia/Singapore')::date >= $1::date)
         AND ($2::date IS NULL OR (a.created_at AT TIME ZONE 'Asia/Singapore')::date <= $2::date)
         AND ($3::text IS NULL OR a.table_name = $3)
         AND ($4::text IS NULL OR a.altered_by::text = $4)
         AND ($5::text IS NULL OR a.subject_user_id = $5)
       ORDER BY a.created_at DESC, a.audit_id DESC
       LIMIT $6 OFFSET $7`,
      [from || null, to || null, tableName || null, alteredBy ? alteredBy.toLowerCase() : null, subjectUserId ? subjectUserId.toLowerCase() : null, pageSize, (page - 1) * pageSize]
    );
    const total = result.rows.length ? Number(result.rows[0].total_count) : 0;
    return res.status(200).json({
      success: true,
      data: result.rows.map(({ total_count, ...row }) => row),
      pagination: { page, pageSize, total },
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to fetch audit logs.', detail: error.message });
  }
});

// ========================================================================
// SERVER-SIDE BACKSTOP: force clock-out any session that's gone 4+ hours since its last
// confirmation (Continue press, or clock-in if never confirmed) — independent of whether
// anyone still has the Staff Portal open in a browser. The client-side "still working?" cycle
// in AttendanceReminders.js only runs while a tab is open and polling; once that tab/browser
// closes, its checkpoints stop firing entirely and a session can sit ACTIVE indefinitely with
// nothing to catch it. This sweep is that catch, checked every minute regardless of any client.
// Mirrors the client's own exception: during lunch (12pm-2pm SGT), hold off the clock-out so
// someone back from lunch still gets a chance to press Continue before being cut off. Runs every
// day including weekends — staff aren't expected to clock in at 8:30am on a weekend (that
// reminder stays weekend-suppressed), but if someone does clock in, this backstop applies to
// them exactly as on a weekday.
// ========================================================================
function sgtNowServer() {
  // Singapore has no DST, so a fixed +8h offset from UTC is always correct — see the matching
  // comment in AttendanceReminders.js for why only the UTC getters on the result are valid.
  const now = new Date();
  return new Date(now.getTime() + 8 * 60 * 60 * 1000);
}
// Each office's time zone, keyed by users.home_office_country (set by HR). Rules that depend on
// the time of day — lunch, overtime, the 8:30am clock-in reminder and which calendar day a
// session belongs to — follow the staff member's own office, so a 9am clock-in in Colombo is
// 9am, not 11:30am SGT. Company-wide dates (claims, payroll, audit log) stay on SGT.
const OFFICE_TIME_ZONES = {
  SG: 'Asia/Singapore',
  MY: 'Asia/Kuala_Lumpur',
  CN: 'Asia/Shanghai',
  LK: 'Asia/Colombo',
};
const DEFAULT_TIME_ZONE = 'Asia/Singapore';
function timeZoneForCountry(country) {
  return OFFICE_TIME_ZONES[String(country || '').toUpperCase()] || DEFAULT_TIME_ZONE;
}
async function userTimeZone(userId) {
  const result = await db.query('SELECT home_office_country FROM users WHERE user_id = $1', [userId]);
  return timeZoneForCountry(result.rows[0]?.home_office_country);
}

// Minutes the time zone is ahead of UTC at a given instant (Colombo is +330, Singapore +480).
function tzOffsetMinutes(instant, timeZone) {
  const d = new Date(instant);
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-US', {
      timeZone, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    }).formatToParts(d).map((p) => [p.type, p.value])
  );
  const asUtc = Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour, +parts.minute, +parts.second);
  return Math.round((asUtc - Math.floor(d.getTime() / 1000) * 1000) / 60000);
}
// The wall-clock time in `timeZone` as a Date whose UTC getters read that local time, the same
// trick as sgtNowServer. Only the UTC getters on the result are meaningful.
function zonedWallClock(instant, timeZone) {
  const d = new Date(instant);
  return new Date(d.getTime() + tzOffsetMinutes(d, timeZone) * 60000);
}

// Hour of day (0-23) in the staff member's own time zone. Overtime used to read Date#getHours(),
// which is the server's own time zone — UTC on Render — so "clock-out at 18:00 or later" was
// really 2am SGT.
function localHourOf(instant, timeZone) {
  return zonedWallClock(instant, timeZone).getUTCHours();
}
function isLunchWindow(wallClock) {
  const hourDecimal = wallClock.getUTCHours() + wallClock.getUTCMinutes() / 60;
  return hourDecimal >= 12 && hourDecimal < 14;
}

// The automatic 1-hour lunch deduction should only apply to a session that actually ran through
// lunch — previously it fired on ANY session over 1 hour long regardless of when it happened,
// shorting attendance for people who simply worked a long evening or started late. This checks
// real overlap against 12pm-2pm in the staff member's own time zone on the day the session started.
function sessionOverlapsLunch(startInstant, endInstant, timeZone) {
  const start = new Date(startInstant);
  const end = new Date(endInstant);
  const offsetMs = tzOffsetMinutes(start, timeZone) * 60000;
  const startLocal = new Date(start.getTime() + offsetMs);
  const lunchStartLocal = new Date(startLocal);
  lunchStartLocal.setUTCHours(12, 0, 0, 0);
  const lunchEndLocal = new Date(startLocal);
  lunchEndLocal.setUTCHours(14, 0, 0, 0);
  const lunchStart = new Date(lunchStartLocal.getTime() - offsetMs);
  const lunchEnd = new Date(lunchEndLocal.getTime() - offsetMs);
  return start < lunchEnd && end > lunchStart;
}

// A budget request reaches MANAGER_APPROVED expecting an Account Manager to give the final
// sign-off — but if the project has no AM (removed after the manager's review, or the project
// never had one), nothing can ever move it past MANAGER_APPROVED: the AM-review endpoint only
// accepts requests already at that status, and there's no AM to call it. This sweep finds any
// such orphaned request and finalizes it exactly like a normal approval (bump budget_hours +
// the requester's hour_allocations, notify them) — the same effect as manager-review's own
// "no AM on this project" auto-finalize, just catching requests that got stuck before or after
// that check ran.
async function finalizeOrphanedBudgetApprovals() {
  try {
    const orphaned = await db.query(
      `SELECT br.* FROM budget_requests br
       JOIN projects p ON p.project_code = br.project_code
       WHERE br.status = 'MANAGER_APPROVED'
         AND p.account_manager_id IS NULL
         AND (p.account_manager_ids IS NULL OR array_length(p.account_manager_ids, 1) IS NULL)`
    );
    for (const budgetRow of orphaned.rows) {
      const before = { ...budgetRow };
      const result = await db.query(
        `UPDATE budget_requests SET status = 'APPROVED', reviewed_at = CURRENT_TIMESTAMP
         WHERE request_id = $1 AND status = 'MANAGER_APPROVED' RETURNING *`,
        [budgetRow.request_id]
      );
      if (result.rows.length === 0) continue; // already handled by a concurrent request
      const finalized = result.rows[0];

      await db.query('UPDATE projects SET budget_hours = budget_hours + $1 WHERE project_code = $2', [finalized.requested_hours, finalized.project_code]);
      await db.query(
        `UPDATE hour_allocations
         SET hours_per_week = hours_per_week + $1
         WHERE user_id = $2 AND project_code = $3
           AND account_manager_status = 'APPROVED'`,
        [finalized.requested_hours, finalized.user_id, finalized.project_code]
      );
      await auditInterceptor('budget_requests', finalized.request_id, finalized.reviewed_by, before, finalized);

      try {
        if (finalized.user_id) {
          const title = 'Request for Additional Hours — Fully Approved!';
          const body = `Your request for additional hours of ${finalized.requested_hours}hrs for project ${finalized.project_code} has been fully approved (no Account Manager is assigned to this project).`;
          await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [finalized.user_id, title, body]);
          await sendPushToUser(finalized.user_id, title, body);
        }
      } catch (_) {}

      console.log(`[budget-approval] Auto-finalized orphaned MANAGER_APPROVED request ${finalized.request_id} (project ${finalized.project_code} has no Account Manager).`);
    }
  } catch (error) {
    console.error('[budget-approval] Orphaned-request sweep failed:', error.message);
  }
}

async function autoClockOutStaleSessions() {
  try {
    const stale = await db.query(
      `SELECT al.attendance_id, al.user_id, u.home_office_country
       FROM attendance_logs al JOIN users u ON u.user_id = al.user_id
       WHERE al.status = 'ACTIVE' AND al.clock_out_time IS NULL
         AND COALESCE(al.last_activity_confirmed_at, al.clock_in_time) <= NOW() - INTERVAL '4 hours'`
    );
    for (const row of stale.rows) {
      // Lunch in the staff member's own time zone: hold off the forced clock-out, same as the client.
      if (isLunchWindow(zonedWallClock(new Date(), timeZoneForCountry(row.home_office_country)))) continue;
      try {
        await axios.post(`http://localhost:${process.env.PORT || 5000}/api/v1/attendance/clock-out`, {
          userId: row.user_id,
          attendanceId: row.attendance_id,
          isAutoClockOut: true,
        });
        console.log(`[auto-clockout] Force-clocked-out stale session ${row.attendance_id} (4+ hours since last confirmation).`);
      } catch (err) {
        console.error(`[auto-clockout] Failed to clock out ${row.attendance_id}:`, err.message);
      }
    }
  } catch (error) {
    console.error('[auto-clockout] Sweep failed:', error.message);
  }
}

// ANNUAL REMINDER: on 1 December (SGT) each year — one month before New Year — nudge every HR
// user to add next year's public holidays. Guarded against re-sending by checking whether a
// notification with that exact title already exists, so checking hourly (cheap insurance against
// a restart landing right on the day) never produces duplicates.
async function checkAnnualHolidayReminder() {
  const sgt = sgtNowServer();
  if (sgt.getUTCMonth() !== 11 || sgt.getUTCDate() !== 1) return; // December 1st only
  const nextYear = sgt.getUTCFullYear() + 1;
  const title = `Update public holidays for ${nextYear}`;
  try {
    const already = await db.query('SELECT 1 FROM notifications WHERE title = $1 LIMIT 1', [title]);
    if (already.rows.length > 0) return;

    const hrUsers = await db.query(
      `SELECT user_id FROM users WHERE account_status = 'active' AND (user_role = 'hr' OR 'hr' = ANY(user_roles))`
    );
    const body = `New Year is about a month away — add ${nextYear}'s public holidays in the Calendar page so attendance and reports reflect them correctly.`;
    for (const row of hrUsers.rows) {
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [row.user_id, title, body]);
      sendPushToUser(row.user_id, title, body).catch(() => {});
    }
    console.log(`[holiday-reminder] Sent ${hrUsers.rows.length} reminder(s) for ${nextYear} public holidays.`);
  } catch (error) {
    console.error('[holiday-reminder] Failed:', error.message);
  }
}

// CLOCK-IN EMAIL REMINDER: mirrors the in-app 8:30am-noon banner in AttendanceReminders.js, but
// as a server-side sweep so it reaches people even if they never open the portal that day — same
// reasoning as autoClockOutStaleSessions being a backstop for the client-side "still working?"
// cycle. Unlike the in-app banner (which re-nags every hour a tab is open), this sends at most
// ONE email per person per day — a repeated hourly email would read as spammy in a way an in-app
// banner doesn't. Checked every 15 minutes; each run only sends to someone once, guarded by a
// same-day notifications-table lookup (same dedup pattern as checkAnnualHolidayReminder).
async function checkClockInEmailReminders() {
  const reminderTitle = "You haven't clocked in yet";
  try {
    const staffUsers = await db.query(
      `SELECT user_id, full_name, email, home_office_country FROM users
       WHERE account_status = 'active' AND NOT is_hidden AND email IS NOT NULL
         AND (user_role = 'staff' OR 'staff' = ANY(user_roles))`
    );

    let sent = 0;
    for (const row of staffUsers.rows) {
      const timeZone = timeZoneForCountry(row.home_office_country);
      const local = zonedWallClock(new Date(), timeZone); // UTC getters hold the local wall-clock value
      const isWeekday = local.getUTCDay() !== 0 && local.getUTCDay() !== 6;
      const hourDecimal = local.getUTCHours() + local.getUTCMinutes() / 60;
      if (!isWeekday || hourDecimal < 8.5 || hourDecimal >= 12) continue; // same 8:30am-noon window as the in-app reminder

      const clockedInToday = await db.query(
        `SELECT 1 FROM attendance_logs
         WHERE user_id = $1 AND (clock_in_time AT TIME ZONE $2::text)::date = (NOW() AT TIME ZONE $2::text)::date
         LIMIT 1`,
        [row.user_id, timeZone]
      );
      if (clockedInToday.rows.length > 0) continue;

      const alreadyReminded = await db.query(
        `SELECT 1 FROM notifications
         WHERE user_id = $1 AND title = $2 AND (created_at AT TIME ZONE $3::text)::date = (NOW() AT TIME ZONE $3::text)::date
         LIMIT 1`,
        [row.user_id, reminderTitle, timeZone]
      );
      if (alreadyReminded.rows.length > 0) continue;

      const body = "It's past 8:30am and you haven't clocked in today. Head to the Staff Portal to clock in.";
      await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [row.user_id, reminderTitle, body]);
      try {
        await sendClockInReminderEmail(row.email, row.full_name);
        sent += 1;
      } catch (emailError) {
        console.error('[clockin-reminder] email failed for', row.email, emailError.message);
      }
    }
    if (sent > 0) console.log(`[clockin-reminder] Sent ${sent} clock-in reminder email(s).`);
  } catch (error) {
    console.error('[clockin-reminder] Sweep failed:', error.message);
  }
}

// In server.js
const PORT = process.env.PORT || 5000; // Changed from 3000
ensureOperationalTables()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Backend API Server running on port ${PORT}`);
      setInterval(autoClockOutStaleSessions, 60 * 1000);
      autoClockOutStaleSessions();
      setInterval(checkAnnualHolidayReminder, 60 * 60 * 1000);
      checkAnnualHolidayReminder();
      setInterval(finalizeOrphanedBudgetApprovals, 5 * 60 * 1000);
      finalizeOrphanedBudgetApprovals();
      setInterval(checkClockInEmailReminders, 15 * 60 * 1000);
      checkClockInEmailReminders();
      setInterval(backfillClaimFxRates, 60 * 60 * 1000);
      backfillClaimFxRates();
    });
  })
  .catch((error) => {
    console.error('Failed to initialize required database tables:', error?.message || error);
    if (error?.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  });