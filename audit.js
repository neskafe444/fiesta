// audit.js
// 10 проверок кода. Каждая возвращает {status, findings[]}
// status: 'pass' | 'warn' | 'fail'

function runAllChecks(htmlSource) {
  const results = [];

  // ---- 1. Хранение паролей ----
  {
    const f = [];
    if (/const\s+salt\s*=\s*['"][^'"]+['"]/.test(htmlSource))
      f.push({ text: 'Соль захардкожена в клиентском коде.', fix: 'Уникальная соль на сервере.' });
    if (/Math\.abs\(hash\)/.test(htmlSource))
      f.push({ text: 'Math.abs() теряет знак хеша → коллизии.', fix: 'Криптографический хеш.' });
    if (!/crypto\.subtle|bcrypt|argon2|scrypt|pbkdf2/i.test(htmlSource))
      f.push({ text: 'Нет криптографического хеширования (32-битная свёртка).', fix: 'PBKDF2/bcrypt/argon2.' });
    if (/passwordHash/.test(htmlSource) && /localStorage/.test(htmlSource))
      f.push({ text: 'passwordHash хранится в localStorage.', fix: 'Только на сервере.' });
    results.push({ id: 1, title: 'Хранение паролей', severity: 'critical',
      status: f.length ? 'fail' : 'pass', findings: f });
  }

  // ---- 2. Хранение сессии ----
  {
    const f = [];
    if (/localStorage\.setItem\(\s*this\.SESSION_KEY/.test(htmlSource))
      f.push({ text: 'Сессия в localStorage — уязвимо к XSS.', fix: 'httpOnly cookie.' });
    if (!/expires|ttl|maxAge/.test(htmlSource))
      f.push({ text: 'Нет TTL сессии.', fix: 'Проверять срок жизни.' });
    if (!/addEventListener\(\s*['"]storage/.test(htmlSource))
      f.push({ text: 'Нет синхронизации вкладок (storage event).', fix: 'window.addEventListener("storage").' });
    results.push({ id: 2, title: 'Хранение сессии', severity: 'critical',
      status: f.length ? 'fail' : 'pass', findings: f });
  }

  // ---- 3. XSS ----
  {
    const f = [];
    const danger = htmlSource.match(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/g);
    if (danger)
      f.push({ text: 'Опасные DOM-вставки: ' + [...new Set(danger)].join(', '), fix: 'textContent/DOMPurify.' });
    if (!/Content-Security-Policy/.test(htmlSource))
      f.push({ text: 'Нет CSP.', fix: 'Добавить CSP-заголовок.' });
    results.push({ id: 3, title: 'XSS через DOM', severity: 'high',
      status: f.length ? 'warn' : 'pass', findings: f });
  }

  // ---- 4. Валидация логина ----
  {
    const f = [];
    if (!/normalize\(/.test(htmlSource))
      f.push({ text: 'Нет Unicode-нормализации (NFKC).', fix: 'username.normalize("NFKC").trim().' });
    if (!/admin|root|system|blacklist|reserved/i.test(htmlSource))
      f.push({ text: 'Нет чёрного списка имён.', fix: 'Запретить admin/root/system.' });
    results.push({ id: 4, title: 'Валидация логина', severity: 'medium',
      status: f.length ? 'warn' : 'pass', findings: f });
  }

  // ---- 5. Политика паролей ----
  {
    const f = [];
    const m = htmlSource.match(/password\.length\s*<\s*(\d+)/);
    const min = m ? parseInt(m[1], 10) : null;
    if (min === null || min < 8)
      f.push({ text: 'Минимальная длина пароля: ' + (min ?? 'не найдена'), fix: '≥ 12 символов.' });
    if (!/zxcvbn|pwned|common|weak/i.test(htmlSource))
      f.push({ text: 'Нет проверки по словарю паролей.', fix: 'zxcvbn/HaveIBeenPwned.' });
    results.push({ id: 5, title: 'Политика паролей', severity: 'medium',
      status: f.length ? 'warn' : 'pass', findings: f });
  }

  // ---- 6. Rate limiting ----
  {
    const f = [];
    if (!/attempt|rate|limit|throttle|lockout|cooldown/i.test(htmlSource))
      f.push({ text: 'Нет rate limiting.', fix: 'Блокировка после N попыток.' });
    if (!/captcha/i.test(htmlSource))
      f.push({ text: 'Нет CAPTCHA.', fix: 'Добавить CAPTCHA.' });
    results.push({ id: 6, title: 'Rate limiting', severity: 'high',
      status: f.length ? 'fail' : 'pass', findings: f });
  }

  // ---- 7. Логика сессии ----
  {
    const f = [];
    if (/findUser\(\s*session\.username\s*\)/.test(htmlSource))
      f.push({ text: 'Сессия восстанавливается по username.', fix: 'Искать по userId.' });
    if (!/expiresAt|ttl/.test(htmlSource))
      f.push({ text: 'Нет проверки срока сессии.', fix: 'Сравнивать loginAt с now().' });
    results.push({ id: 7, title: 'Логика сессии', severity: 'low',
      status: f.length ? 'warn' : 'pass', findings: f });
  }

  // ---- 8. Гонка регистрации ----
  {
    const f = [];
    if (/userExists\([\s\S]*?getUsers\(\)[\s\S]*?saveUsers\(/.test(htmlSource))
      f.push({ text: 'TOCTOU: проверка → запись не атомарна.', fix: 'navigator.locks или сервер.' });
    results.push({ id: 8, title: 'Гонка при регистрации', severity: 'medium',
      status: f.length ? 'warn' : 'pass', findings: f });
  }

  // ---- 9. Утечка ошибок ----
  {
    const f = [];
    if (/e\.message/.test(htmlSource))
      f.push({ text: 'e.message выводится в UI.', fix: 'Общее сообщение пользователю.' });
    if (/уже существует|already exists/i.test(htmlSource))
      f.push({ text: 'Сообщение раскрывает существование логина.', fix: 'Общий текст.' });
    results.push({ id: 9, title: 'Утечка через ошибки', severity: 'medium',
      status: f.length ? 'warn' : 'pass', findings: f });
  }

  // ---- 10. Качество кода ----
  {
    const f = [];
    if (/Math\.random\(\)\.toString\(36\)\.substr/.test(htmlSource))
      f.push({ text: 'Math.random() + substr для ID.', fix: 'crypto.randomUUID().' });
    if (/console\.error/.test(htmlSource))
      f.push({ text: 'console.error в проде.', fix: 'Убрать/лог-сервер.' });
    if (!/crypto\.randomUUID/.test(htmlSource))
      f.push({ text: 'Нет crypto.randomUUID.', fix: 'Использовать crypto.randomUUID().' });
    results.push({ id: 10, title: 'Качество кода', severity: 'low',
      status: f.length ? 'warn' : 'pass', findings: f });
  }

  return results;
}

module.exports = { runAllChecks };
