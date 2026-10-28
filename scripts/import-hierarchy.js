// Sets each person's line manager (users.supervisor_id), title, department and the departments they head from
// the company's department list, so claims go to the right approver and the Department Chart shows who is who.
// People are matched by name (full name, or the part of their email before the @ with dots as spaces, or the
// full email address). It only prints what it would do unless you pass --apply.
//
//   node scripts/import-hierarchy.js            (dry run)
//   node scripts/import-hierarchy.js --apply    (writes supervisor_id, job_position, department, is_department_head, also_head_of)
//
// Run it against the database you mean to change: it uses the same DATABASE_URL as the server.
// The backend that adds the department columns must be deployed first.
const db = require('../db');

const APPLY = process.argv.includes('--apply');

// Department names, as on the company's department list.
const OPS = 'Operation & Project Sales Department';
const CHINA = 'Nextan China Department';
const HR_FIN = 'HR & Finance Department';
const CEO_OFFICE = 'CEO Office';
const SRI_LANKA = 'Nextan Sri Lanka';
const HEALTHCARE = 'Healthcare Business Department';
const IT_MY = 'Accelerated IT Department MY';

// Name | Title | Department | Reports to | Departments they head
// People whose live account is spelt differently from the company list are matched by email. A person heads
// one or more departments; their own department is the first one. Jerry is the Junan Yong account.
const LIST = [
  ['Sean Tan', 'Director', CEO_OFFICE, '', [CEO_OFFICE, IT_MY]],
  ['Rebecca Lau', 'Biz Admin Manager', HR_FIN, 'Sean Tan', [HR_FIN]],
  ['Justin Low', 'Sales Manager', OPS, 'Sean Tan', [OPS, CHINA]],
  ['Charlene Tan', 'Software Engineer', OPS, 'Justin Low', []],
  ['John Tan', 'Project Manager', OPS, 'Justin Low', []],
  ['junan.yong@nextan.com.sg', 'Technician', OPS, 'John Tan', []],
  ['dongliang.lin@nextan.com.sg', 'R&D Manager', CHINA, 'Justin Low', []],
  ['jianfeng.huang@nextan.com.sg', 'Software Engineer', CHINA, 'dongliang.lin@nextan.com.sg', []],
  ['jiangwei.chen@nextan.com.sg', 'Senior Engineer', CHINA, 'dongliang.lin@nextan.com.sg', []],
  ['sihao.lu@nextan.com.sg', 'Senior Software Engineer', CHINA, 'dongliang.lin@nextan.com.sg', []],
  ['anton.christon@nextan.com.sg', 'Business Analyst', CEO_OFFICE, 'Sean Tan', []],
  ['Gary Cheng', 'Technical Consultant', CEO_OFFICE, 'Sean Tan', []],
  ['Hudson', '', CEO_OFFICE, 'Sean Tan', []],
  ['Jerome Snehan', 'System Architect', SRI_LANKA, 'Sean Tan', [SRI_LANKA]],
  ['Kushani', 'Technical Consultant', SRI_LANKA, 'Jerome Snehan', []],
  ['Zulaiha', 'Senior Business Dev Manager', HEALTHCARE, 'Sean Tan', [HEALTHCARE]],
  ['eunice.tan@nextan.com.sg', '', IT_MY, 'Sean Tan', []],
  ['farah.julia@nextan.com.sg', 'Junior App Developer', IT_MY, 'Sean Tan', []],
  ['aliamahran@nextan.com.sg', 'Project Assistant', IT_MY, 'Sean Tan', []],
];

const norm = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
const same = (a, b) => JSON.stringify([...(a || [])].sort()) === JSON.stringify([...(b || [])].sort());

(async () => {
  const users = (await db.query(
    'SELECT user_id, full_name, email, supervisor_id, job_position, department, is_department_head, also_head_of FROM users'
  )).rows;
  const keyOf = (u) => [norm(u.full_name), norm(String(u.email || '').split('@')[0]), norm(u.email)];
  const find = (name) => {
    const n = norm(name);
    const hits = users.filter((u) => keyOf(u).includes(n));
    return hits.length === 1 ? hits[0] : hits.length > 1 ? 'many' : null;
  };

  let changes = 0; const problems = [];
  for (const [name, title, department, managerName, heads] of LIST) {
    const person = find(name);
    if (!person) { problems.push(`No account found for ${name}`); continue; }
    if (person === 'many') { problems.push(`More than one account matches ${name}`); continue; }

    // Title, department and the departments they head. Someone who heads a department and has no title
    // gets "Head of {department}". Nothing else about their account changes.
    const headsOwn = heads.some((h) => h.toLowerCase() === department.toLowerCase());
    const others = heads.filter((h) => h.toLowerCase() !== department.toLowerCase());
    const newTitle = title || person.job_position || (headsOwn ? `Head of ${department}` : null);
    const wants = { title: newTitle, department, head: headsOwn, also: others };
    const has = { title: person.job_position || null, department: person.department || null, head: Boolean(person.is_department_head), also: person.also_head_of || [] };
    if (wants.title !== has.title || wants.department !== has.department || wants.head !== has.head || !same(wants.also, has.also)) {
      const headText = headsOwn ? `head of ${department}` : 'not a head';
      const alsoText = others.length ? `, also head of ${others.join(' and ')}` : '';
      console.log(`${person.full_name}: ${APPLY ? 'now' : 'would be'} "${wants.title || ''}" in ${department}, ${headText}${alsoText}`);
      if (APPLY) {
        await db.query('UPDATE users SET job_position = $1, department = $2, is_department_head = $3, also_head_of = $4 WHERE user_id = $5',
          [wants.title, wants.department, wants.head, wants.also, person.user_id]);
      }
      changes++;
    }

    if (!managerName) {
      if (person.supervisor_id) { console.log(`${person.full_name}: ${APPLY ? 'now has' : 'would have'} no line manager (no one above)`); if (APPLY) await db.query('UPDATE users SET supervisor_id = NULL WHERE user_id = $1', [person.user_id]); changes++; }
      else console.log(`${person.full_name}: no line manager, claims go straight to HR`);
      continue;
    }
    const manager = find(managerName);
    if (!manager || manager === 'many') { problems.push(`Cannot set ${person.full_name}'s manager: ${managerName} ${manager === 'many' ? 'matches several accounts' : 'has no account'}`); continue; }
    if (person.supervisor_id === manager.user_id) { console.log(`${person.full_name}: already reports to ${manager.full_name}`); continue; }
    console.log(`${person.full_name}: ${APPLY ? 'now reports' : 'would report'} to ${manager.full_name}`);
    if (APPLY) await db.query('UPDATE users SET supervisor_id = $1 WHERE user_id = $2', [manager.user_id, person.user_id]);
    changes++;
  }
  console.log(`\n${APPLY ? 'Updated' : 'Would update'} ${changes} thing(s).`);
  if (problems.length) { console.log('\nNeeds a look:'); problems.forEach((p) => console.log('  - ' + p)); }
  if (!APPLY) console.log('\nDry run only. Run with --apply to write the changes.');
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
