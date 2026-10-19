# hr-backend

The REST API for the Nextan Timesheet System: Node 20, Express 5, PostgreSQL (`pg`), bcryptjs, AWS SES for email. Nearly all routes, helpers and scheduled jobs are in `server.js`; `db.js` exports the database pool. Runs locally on port 5000 (`npm run dev`).

Shared workspace notes, skills and agents live one folder up, in `../CLAUDE.md` and `../.claude/`. If the `nextan-*` skills are not loaded, read them directly from `../.claude/skills/<name>/SKILL.md`.

- Before adding or changing a route, column or job, follow `nextan-backend-endpoint`.
- `main` auto-deploys the live backend on Render. Never push to it. Work on your own branch (see the Team table in `../CLAUDE.md`).
- All business rules use Singapore time (SGT, UTC+8).
- Before reporting a task as done, run `nextan-release-check`.
