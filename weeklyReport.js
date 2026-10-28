// Weekly report: each person says what they achieved this week and something worth sharing with the
// group, due by the end of Friday. People who haven't submitted are reminded on Saturday 5:30pm,
// Sunday 5:30pm and Monday 8:30am (Singapore time), and each manager is told on Monday who did and
// didn't submit. Optional end-of-day notes can be added during the week.
//
// Kept in its own file (registered from server.js) so it stays apart from the claims code.
// A week runs Monday to Sunday and is identified by its Monday (week_start).

const MAX_TEXT = 3000;
const MAX_NOTE = 1000;

function ymdAddDays(ymd, n) {
  const d = new Date(`${ymd}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

// The Monday of the week that contains `ymd`.
function mondayOf(ymd) {
  const d = new Date(`${ymd}T00:00:00Z`);
  const sinceMonday = (d.getUTCDay() + 6) % 7;
  d.setUTCDate(d.getUTCDate() - sinceMonday);
  return d.toISOString().slice(0, 10);
}

function register(app, deps) {
  const { db, requireSession, userIsManagerial, isRealYmd, sgtTodayYmd, sgtNowServer, sendEmail, brandedEmailHtml, emailText, normalizeLanguage, staffPortalUrl, managerPortalUrl } = deps;

  const rolesOf = (session) => (Array.isArray(session.user_roles) && session.user_roles.length > 0 ? session.user_roles : [session.user_role]).map((r) => String(r || '').toLowerCase());
  const isHr = (session) => rolesOf(session).includes('hr');

  // A usable week: a real Monday that isn't in the future. Defaults to the current week.
  function readWeek(raw) {
    const today = sgtTodayYmd();
    const thisWeek = mondayOf(today);
    if (raw === undefined || raw === null || raw === '') return { weekStart: thisWeek };
    const weekStart = String(raw);
    if (!isRealYmd(weekStart)) return { error: 'Choose a valid week.' };
    if (mondayOf(weekStart) !== weekStart) return { error: 'A week starts on a Monday.' };
    if (weekStart > thisWeek) return { error: 'You can only report on this week or an earlier one.' };
    return { weekStart };
  }

  const shape = (week, row) => ({
    weekStart: week, weekEnd: ymdAddDays(week, 6), dueDate: ymdAddDays(week, 4),
    status: row ? row.status : 'MISSING',
    achievements: row?.achievements || '', highlight: row?.highlight || '',
    submittedAt: row?.submitted_at || null, updatedAt: row?.updated_at || null,
  });

  // ---- the signed-in person's own report for a week, with their end-of-day notes
  app.get('/api/v1/weekly-reports/me', async (req, res) => {
    const session = await requireSession(req, res);
    if (!session) return;
    const w = readWeek(req.query.weekStart);
    if (w.error) return res.status(400).json({ error: w.error });
    try {
      const report = await db.query(
        `SELECT status, achievements, highlight, submitted_at, updated_at FROM weekly_reports WHERE user_id = $1 AND week_start = $2`,
        [session.user_id, w.weekStart]
      );
      const notes = await db.query(
        `SELECT note_date::text AS note_date, note FROM daily_report_notes
         WHERE user_id = $1 AND note_date BETWEEN $2 AND $3 ORDER BY note_date`,
        [session.user_id, w.weekStart, ymdAddDays(w.weekStart, 6)]
      );
      return res.status(200).json({ success: true, data: { ...shape(w.weekStart, report.rows[0]), dailyNotes: notes.rows } });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to load your weekly report.', detail: error.message });
    }
  });

  // ---- save a draft, or submit
  app.put('/api/v1/weekly-reports/me', async (req, res) => {
    const session = await requireSession(req, res);
    if (!session) return;
    const w = readWeek(req.body.weekStart);
    if (w.error) return res.status(400).json({ error: w.error });
    const achievements = String(req.body.achievements || '').trim();
    const highlight = String(req.body.highlight || '').trim();
    if (achievements.length > MAX_TEXT || highlight.length > MAX_TEXT) return res.status(400).json({ error: `Each answer can be up to ${MAX_TEXT} characters.` });
    const submit = req.body.submit === true;
    if (submit && !achievements) return res.status(400).json({ error: 'Please say what you achieved this week before submitting.' });
    try {
      // submitted_at keeps the time of the first submission; later edits only change updated_at
      const r = await db.query(
        `INSERT INTO weekly_reports (user_id, week_start, achievements, highlight, status, submitted_at)
         VALUES ($1, $2, $3, $4, $5, CASE WHEN $5::text = 'SUBMITTED' THEN CURRENT_TIMESTAMP END)
         ON CONFLICT (user_id, week_start) DO UPDATE SET
           achievements = EXCLUDED.achievements, highlight = EXCLUDED.highlight, updated_at = CURRENT_TIMESTAMP,
           status = CASE WHEN weekly_reports.status = 'SUBMITTED' OR EXCLUDED.status = 'SUBMITTED' THEN 'SUBMITTED' ELSE 'DRAFT' END,
           submitted_at = COALESCE(weekly_reports.submitted_at, EXCLUDED.submitted_at)
         RETURNING status, achievements, highlight, submitted_at, updated_at`,
        [session.user_id, w.weekStart, achievements, highlight, submit ? 'SUBMITTED' : 'DRAFT']
      );
      return res.status(200).json({ success: true, data: shape(w.weekStart, r.rows[0]) });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to save your weekly report.', detail: error.message });
    }
  });

  // ---- optional end-of-day note
  app.put('/api/v1/weekly-reports/daily-note', async (req, res) => {
    const session = await requireSession(req, res);
    if (!session) return;
    const date = String(req.body.date || '');
    if (!isRealYmd(date) || date > sgtTodayYmd()) return res.status(400).json({ error: 'Choose a day that is today or earlier.' });
    const note = String(req.body.note || '').trim();
    if (note.length > MAX_NOTE) return res.status(400).json({ error: `A daily note can be up to ${MAX_NOTE} characters.` });
    try {
      if (!note) {
        await db.query('DELETE FROM daily_report_notes WHERE user_id = $1 AND note_date = $2', [session.user_id, date]);
        return res.status(200).json({ success: true, data: { date, note: '' } });
      }
      await db.query(
        `INSERT INTO daily_report_notes (user_id, note_date, note) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, note_date) DO UPDATE SET note = EXCLUDED.note, updated_at = CURRENT_TIMESTAMP`,
        [session.user_id, date, note]
      );
      return res.status(200).json({ success: true, data: { date, note } });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to save the note.', detail: error.message });
    }
  });

  // ---- who submitted and who didn't: a manager's direct reports, or everyone for HR
  app.get('/api/v1/weekly-reports/team', async (req, res) => {
    const session = await requireSession(req, res);
    if (!session) return;
    if (!userIsManagerial(session)) return res.status(403).json({ error: 'Only managers and HR can see the team report.' });
    const w = readWeek(req.query.weekStart);
    if (w.error) return res.status(400).json({ error: w.error });
    try {
      const members = await db.query(
        `SELECT u.user_id, u.full_name, u.email, r.status, r.achievements, r.highlight, r.submitted_at,
                (SELECT COUNT(*)::int FROM daily_report_notes n WHERE n.user_id = u.user_id AND n.note_date BETWEEN $2::date AND $2::date + 6) AS daily_notes
         FROM users u
         LEFT JOIN weekly_reports r ON r.user_id = u.user_id AND r.week_start = $2
         WHERE u.account_status = 'active' AND NOT u.is_hidden AND (u.user_role = 'staff' OR 'staff' = ANY(u.user_roles))
           AND u.user_id <> $1 AND ($3::boolean OR u.supervisor_id = $1)
         ORDER BY (r.status = 'SUBMITTED') NULLS FIRST, u.full_name`,
        [session.user_id, w.weekStart, isHr(session)]
      );
      const rows = members.rows.map((m) => ({
        userId: m.user_id, fullName: m.full_name, email: m.email,
        status: m.status === 'SUBMITTED' ? 'SUBMITTED' : m.status === 'DRAFT' ? 'DRAFT' : 'MISSING',
        achievements: m.status === 'SUBMITTED' ? m.achievements : '', highlight: m.status === 'SUBMITTED' ? m.highlight : '',
        submittedAt: m.submitted_at, dailyNotes: m.daily_notes,
      }));
      const submitted = rows.filter((m) => m.status === 'SUBMITTED').length;
      return res.status(200).json({ success: true, data: {
        weekStart: w.weekStart, weekEnd: ymdAddDays(w.weekStart, 6), dueDate: ymdAddDays(w.weekStart, 4),
        total: rows.length, submitted, notSubmitted: rows.length - submitted, members: rows,
      } });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to load the team report.', detail: error.message });
    }
  });

  // ---- reminders: Saturday 5:30pm, Sunday 5:30pm, Monday 8:30am for the week that just ended
  async function sendReminderEmail(row, which) {
    const text = emailText(row.preferred_language).weeklyReport;
    const html = brandedEmailHtml({
      lang: normalizeLanguage(row.preferred_language), linkOrigin: staffPortalUrl,
      heading: text.heading, bodyHtml: text.body(which), buttonText: text.button,
      buttonUrl: `${staffPortalUrl}/weekly-report`, footerText: text.footer,
    });
    await sendEmail(row.email, text.subject, html, 'weekly-report-reminder');
  }

  async function checkWeeklyReportReminders() {
    const now = sgtNowServer();
    const dow = now.getUTCDay(); // 0 Sunday ... 6 Saturday (the UTC getters hold the SGT wall clock)
    const hour = now.getUTCHours() + now.getUTCMinutes() / 60;
    let which = null;
    if (dow === 6 && hour >= 17.5) which = 'saturday';
    else if (dow === 0 && hour >= 17.5) which = 'sunday';
    else if (dow === 1 && hour >= 8.5 && hour < 12) which = 'monday';
    if (!which) return;
    const weekStart = mondayOf(ymdAddDays(sgtTodayYmd(), which === 'monday' ? -3 : dow === 6 ? 0 : -1));
    const title = `Weekly report reminder (${which})`;
    const marker = `[week ${weekStart}]`;
    try {
      const pending = await db.query(
        `SELECT u.user_id, u.full_name, u.email, u.preferred_language FROM users u
         WHERE u.account_status = 'active' AND NOT u.is_hidden AND u.email IS NOT NULL
           AND (u.user_role = 'staff' OR 'staff' = ANY(u.user_roles))
           AND NOT EXISTS (SELECT 1 FROM weekly_reports r WHERE r.user_id = u.user_id AND r.week_start = $1 AND r.status = 'SUBMITTED')
           AND NOT EXISTS (SELECT 1 FROM notifications n WHERE n.user_id = u.user_id AND n.title = $2 AND n.body LIKE '%' || $3 || '%')`,
        [weekStart, title, marker]
      );
      let sent = 0;
      for (const row of pending.rows) {
        const body = `Your weekly report for ${weekStart} to ${ymdAddDays(weekStart, 6)} is still waiting. It was due on Friday. ${marker}`;
        await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [row.user_id, title, body]);
        try { await sendReminderEmail(row, which); sent += 1; } catch (e) { console.error('[weekly-report] reminder email failed for', row.email, e.message); }
      }
      if (sent > 0) console.log(`[weekly-report] Sent ${sent} ${which} reminder(s) for the week of ${weekStart}.`);
    } catch (error) {
      console.error('[weekly-report] Reminder sweep failed:', error.message);
    }
  }

  // ---- Monday 9am: tell each manager who submitted and who didn't, for the week just ended
  async function checkManagerWeeklySummary() {
    const now = sgtNowServer();
    const hour = now.getUTCHours() + now.getUTCMinutes() / 60;
    if (now.getUTCDay() !== 1 || hour < 9 || hour >= 13) return;
    const weekStart = mondayOf(ymdAddDays(sgtTodayYmd(), -3));
    const title = 'Weekly report summary';
    const marker = `[week ${weekStart}]`;
    try {
      const managers = await db.query(
        `SELECT DISTINCT m.user_id FROM users m JOIN users s ON s.supervisor_id = m.user_id
         WHERE m.account_status = 'active' AND NOT m.is_hidden AND s.account_status = 'active' AND NOT s.is_hidden
           AND (s.user_role = 'staff' OR 'staff' = ANY(s.user_roles))`
      );
      for (const m of managers.rows) {
        const done = await db.query(`SELECT 1 FROM notifications WHERE user_id = $1 AND title = $2 AND body LIKE '%' || $3 || '%' LIMIT 1`, [m.user_id, title, marker]);
        if (done.rows.length > 0) continue;
        const team = await db.query(
          `SELECT s.full_name, (r.status = 'SUBMITTED') AS submitted FROM users s
           LEFT JOIN weekly_reports r ON r.user_id = s.user_id AND r.week_start = $2
           WHERE s.supervisor_id = $1 AND s.account_status = 'active' AND NOT s.is_hidden AND (s.user_role = 'staff' OR 'staff' = ANY(s.user_roles))
           ORDER BY s.full_name`,
          [m.user_id, weekStart]
        );
        const missing = team.rows.filter((t) => !t.submitted).map((t) => t.full_name);
        const body = `Week of ${weekStart} to ${ymdAddDays(weekStart, 6)}: ${team.rows.length - missing.length} of ${team.rows.length} submitted. `
          + (missing.length ? `Not submitted: ${missing.join(', ')}.` : 'Everyone submitted.') + ` ${marker}`;
        await db.query('INSERT INTO notifications (user_id, title, body) VALUES ($1, $2, $3)', [m.user_id, title, body]);
      }
    } catch (error) {
      console.error('[weekly-report] Manager summary failed:', error.message);
    }
  }

  return { checkWeeklyReportReminders, checkManagerWeeklySummary };
}

async function ensureTables(db) {
  await db.query(`
    CREATE TABLE IF NOT EXISTS weekly_reports (
      report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      week_start DATE NOT NULL,
      achievements TEXT NOT NULL DEFAULT '',
      highlight TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'DRAFT',
      submitted_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (user_id, week_start)
    );
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS daily_report_notes (
      note_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
      note_date DATE NOT NULL,
      note TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
      UNIQUE (user_id, note_date)
    );
  `);
}

module.exports = { register, ensureTables, mondayOf, ymdAddDays };
