// Sets each person's line manager (users.supervisor_id), position and department from the company list, so claims go
// to the right approver and the department line shows who is who. People are matched by name (full name, or the part of their email before the @
// with dots as spaces, or the full email address). It only prints what it would do unless you pass --apply.
//
//   node scripts/import-hierarchy.js            (dry run)
//   node scripts/import-hierarchy.js --apply    (writes supervisor_id, job_position and department)
//
// Run it against the database you mean to change: it uses the same DATABASE_URL as the server.
const db = require('../db');

const APPLY = process.argv.includes('--apply');

// Name | Position | Department | Reports to  (from the list sent by the company, 20 Oct 2026)
// People whose live account is spelt differently from the company list are matched by email.
const LIST = [
  ['Sean Tan', 'Director', '', ''],
  ['Rebecca Lau', 'Biz Admin Manager', 'Fin, HR & Admin', 'Sean Tan'],
  ['Justin Low', 'Sales Manager', 'Sales', 'Sean Tan'],
  ['John Tan', 'Project Manager', 'Project', 'Justin Low'],
  ['junan.yong@nextan.com.sg', 'Technician', 'Project', 'Justin Low'],
  ['Jerry', '', '', 'Justin Low'],
  ['dongliang.lin@nextan.com.sg', 'R&D Manager', 'R&D', 'Justin Low'],
  ['jiangwei.chen@nextan.com.sg', 'Senior Engineer', 'R&D', 'dongliang.lin@nextan.com.sg'],
  ['jianfeng.huang@nextan.com.sg', 'Software Engineer', 'R&D', 'dongliang.lin@nextan.com.sg'],
  ['sihao.lu@nextan.com.sg', 'Senior Software Engineer', 'R&D', 'dongliang.lin@nextan.com.sg'],
  ['Charlene Tan', 'Software Engineer', '', 'Justin Low'],
  ['Jerome Snehan', 'System Architect', '', 'Sean Tan'],
  ['Kushani', 'Technical Consultant', '', 'Jerome Snehan'],
  ['anton.christon@nextan.com.sg', 'Business Analyst', '', 'Sean Tan'],
  ['Gary Cheng', 'Technical Consultant', '', 'Sean Tan'],
  ['aliamahran@nextan.com.sg', 'Project Assistant', '', 'Sean Tan'],
  ['farah.julia@nextan.com.sg', 'Junior App Developer', '', 'Sean Tan'],
  ['eunice.tan@nextan.com.sg', '', '', 'Sean Tan'],
  ['Zulaiha', 'Senior Business Dev Manager', 'Sales', 'Sean Tan'],
];

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();

(async () => {
  const users = (await db.query('SELECT user_id, full_name, email, supervisor_id, job_position, department FROM users')).rows;
  const keyOf = (u) => [norm(u.full_name), norm(String(u.email || '').split('@')[0]), norm(u.email)];
  const find = (name) => {
    const n = norm(name);
    const hits = users.filter((u) => keyOf(u).includes(n));
    return hits.length === 1 ? hits[0] : hits.length > 1 ? 'many' : null;
  };

  let changes = 0; const problems = [];
  for (const [name, position, department, managerName] of LIST) {
    const person = find(name);
    if (!person) { problems.push(`No account found for ${name}`); continue; }
    if (person === 'many') { problems.push(`More than one account matches ${name}`); continue; }

    // Position and department: only filled in or corrected when the list has a value for them.
    const newPosition = position || person.job_position || null;
    const newDepartment = department || person.department || null;
    if (newPosition !== (person.job_position || null) || newDepartment !== (person.department || null)) {
      console.log(`${person.full_name}: ${APPLY ? 'now has' : 'would get'} position "${newPosition || ''}" and department "${newDepartment || ''}"`);
      if (APPLY) await db.query('UPDATE users SET job_position = $1, department = $2 WHERE user_id = $3', [newPosition, newDepartment, person.user_id]);
      changes++;
    }
    if (!managerName) {
      if (person.supervisor_id) { console.log(`${name} (${position}): would clear the line manager (no one above)`); if (APPLY) await db.query('UPDATE users SET supervisor_id = NULL WHERE user_id = $1', [person.user_id]); changes++; }
      else console.log(`${name} (${position}): no line manager, claims go straight to HR`);
      continue;
    }
    const manager = find(managerName);
    if (!manager || manager === 'many') { problems.push(`Cannot set ${name}'s manager: ${managerName} ${manager === 'many' ? 'matches several accounts' : 'has no account'}`); continue; }
    if (person.supervisor_id === manager.user_id) { console.log(`${name}: already reports to ${managerName}`); continue; }
    console.log(`${name} (${position}): ${APPLY ? 'now reports' : 'would report'} to ${managerName}`);
    if (APPLY) await db.query('UPDATE users SET supervisor_id = $1 WHERE user_id = $2', [manager.user_id, person.user_id]);
    changes++;
  }
  console.log(`\n${APPLY ? 'Updated' : 'Would update'} ${changes} person(s).`);
  if (problems.length) { console.log('\nNeeds a look:'); problems.forEach((p) => console.log('  - ' + p)); }
  if (!APPLY) console.log('\nDry run only. Run with --apply to write the changes.');
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
