// extract-js.js
const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, 'auth-system.html');
const outPath = path.join(__dirname, 'extracted.js');

if (!fs.existsSync(htmlPath)) {
  console.error('❌ Не найден auth-system.html');
  process.exit(1);
}

const html = fs.readFileSync(htmlPath, 'utf8');
const match = html.match(/<script>([\s\S]*?)<\/script>/);
if (!match) {
  console.error('❌ В HTML не найден блок <script>');
  process.exit(1);
}

fs.writeFileSync(outPath, match[1], 'utf8');
console.log('✅ JavaScript извлечён в extracted.js (' + match[1].length + ' символов)');
