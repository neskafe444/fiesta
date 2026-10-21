// test.js
const fs = require('fs');
const path = require('path');
const { runAllChecks } = require('./audit.js');

const htmlPath = path.join(__dirname, 'auth-system.html');
if (!fs.existsSync(htmlPath)) {
  console.error('❌ auth-system.html не найден');
  process.exit(1);
}

const html = fs.readFileSync(htmlPath, 'utf8');
const results = runAllChecks(html);

let pass = 0, warn = 0, fail = 0;
const icon = { pass: '✅', warn: '⚠️ ', fail: '❌' };

console.log('\n=== ОТЧЁТ АУДИТА ===\n');
for (const r of results) {
  if (r.status === 'pass') pass++;
  if (r.status === 'warn') warn++;
  if (r.status === 'fail') fail++;
  console.log(`${icon[r.status]} #${r.id} ${r.title} [${r.severity}] — ${r.status.toUpperCase()}`);
  for (const f of r.findings) {
    console.log(`     • ${f.text}`);
    console.log(`       fix: ${f.fix}`);
  }
}
console.log(`\nИтого: ${pass} pass, ${warn} warn, ${fail} fail\n`);

// Валят сборку только критичные fail
if (fail > 0) {
  console.error(`❌ Сборка провалена: ${fail} критичных проблем.`);
  process.exit(1);
}
console.log('✅ Сборка успешна (критичных проблем нет).');
