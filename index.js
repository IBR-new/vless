#!/usr/bin/env node
'use strict';

const { Client } = require('ssh2');
const readline = require('readline');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync } = require('child_process');

const C = {
  dim: s => `\x1b[2m${s}\x1b[0m`,
  b: s => `\x1b[1m${s}\x1b[0m`,
  ok: s => `\x1b[32m${s}\x1b[0m`,
  err: s => `\x1b[31m${s}\x1b[0m`,
  warn: s => `\x1b[33m${s}\x1b[0m`,
  acc: s => `\x1b[35m${s}\x1b[0m`
};

// значения можно передать флагами — тогда вопрос не задаётся
const argv = process.argv.slice(2);
function flag(name) {
  const i = argv.indexOf('--' + name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : null;
}

let rl = null;
function ask(q, def, preset) {
  if (preset) return Promise.resolve(preset);
  if (!rl) rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(res => {
    rl.question(`  ${q}${def ? C.dim(` [${def}]`) : ''}: `, a => res((a || '').trim() || def || ''));
  });
}
function closeRl() { if (rl) { rl.close(); rl = null; } }

// Повторяет вопрос, пока не получит осмысленный ответ.
// Пустая строка — не повод завершаться: её мог оставить случайный Enter,
// нажатый пока npx скачивал пакет.
async function askRequired(q, def, preset, validate) {
  for (;;) {
    const v = (await ask(q, def, preset)).trim();
    preset = null;
    if (!v) { console.log('  ' + C.warn('Ничего не введено — повторите.')); continue; }
    const err = validate ? validate(v) : null;
    if (err) { console.log('  ' + C.warn(err)); continue; }
    return v;
  }
}

function fail(msg, hint) {
  console.log('\n  ' + C.err('✗ ' + msg));
  if (hint) hint.split('\n').forEach(l => console.log('    ' + C.dim(l)));
  console.log('');
  closeRl();
  process.exit(1);
}

// --- рабочий стол: на Windows он может быть перенесён в OneDrive ---
function desktopDir() {
  const home = os.homedir();
  if (process.platform === 'win32') {
    try {
      const out = execSync(
        'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" /v Desktop',
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      const m = out.match(/Desktop\s+REG_(?:EXPAND_)?SZ\s+(.+)/);
      if (m) {
        const p = m[1].trim().replace(/%([^%]+)%/g, (_, v) => process.env[v] || '');
        if (fs.existsSync(p)) return p;
      }
    } catch (e) { /* падать из-за реестра не будем */ }
  }
  const d = path.join(home, 'Desktop');
  return fs.existsSync(d) ? d : home;
}

// --- быстрая проверка: доезжает ли адрес вообще ---
// Различаем причины: опечатка и блокировка требуют разных советов.
function probe(host, port, timeout) {
  return new Promise(res => {
    const s = new net.Socket();
    const done = r => { s.destroy(); res(r); };
    s.setTimeout(timeout);
    s.once('connect', () => done('ok'));
    s.once('timeout', () => done('timeout'));
    s.once('error', e => {
      const c = e.code || '';
      if (c === 'ENOTFOUND' || c === 'EAI_AGAIN') return done('dns');
      if (c === 'ECONNREFUSED') return done('refused');
      done('timeout');
    });
    s.connect(port, host);
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

const looksLikeIp = h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) && h.split('.').every(o => +o <= 255);

function buildYaml(v) {
  return `# Профиль Clash — VLESS + Reality
# Сервер: ${v.host}  ·  создан ${new Date().toISOString().slice(0, 10)}
# Порт и режим задаёт сам Clash Verge, поэтому в профиле их нет.

mode: rule
log-level: info
ipv6: false
unified-delay: true
tcp-concurrent: true

profile:
  store-selected: true
  store-fake-ip: true

dns:
  enable: true
  listen: 127.0.0.1:1053
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'
    - '*.local'
  default-nameserver: [1.1.1.1, 8.8.8.8]
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  proxy-server-nameserver:
    - https://1.1.1.1/dns-query

proxies:
  - name: VLESS-443
    type: vless
    server: ${v.host}
    port: 443
    uuid: ${v.uuid}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${v.dest}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${v.pub}
      short-id: ${v.sid}

  - name: VLESS-8443
    type: vless
    server: ${v.host}
    port: 8443
    uuid: ${v.uuid}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: ${v.dest}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${v.pub}
      short-id: ${v.sid}

proxy-groups:
  - name: PROXY
    type: select
    proxies: [AUTO, VLESS-443, VLESS-8443, DIRECT]
  - name: AUTO
    type: url-test
    proxies: [VLESS-443, VLESS-8443]
    url: https://cp.cloudflare.com/generate_204
    interval: 300
    tolerance: 50

rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,169.254.0.0/16,DIRECT,no-resolve
  - DOMAIN-SUFFIX,lan,DIRECT
  - DOMAIN-SUFFIX,local,DIRECT
  - IP-CIDR,${v.host}/32,DIRECT,no-resolve
  - MATCH,PROXY
`;
}

async function main() {
  console.log('');
  console.log('  ' + C.b('VLESS + Reality') + C.dim(' — установка прокси на ваш сервер'));
  console.log('  ' + C.dim('Данные возьмите из письма хостера. Выйти — Ctrl+C.'));
  console.log('');

  const validHost = v => (looksLikeIp(v) || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v))
    ? null : `«${v}» не похоже на адрес. Нужен IP вида 203.0.113.10`;

  // У части хостеров SSH висит не на 22.
  const port = parseInt(flag('port') || process.env.VLESS_PORT || '22', 10) || 22;

  // Адрес спрашиваем, пока не получим тот, до которого реально есть маршрут.
  let host;
  for (;;) {
    host = await askRequired('IP сервера', null, flag('host') || process.env.VLESS_HOST, validHost);
    process.stdout.write('  ' + C.dim('проверяю доступность адреса… '));
    const r = await probe(host, port, 10000);
    if (r === 'ok') { console.log(C.ok('доступен')); break; }
    console.log('');
    if (r === 'dns') {
      console.log('  ' + C.warn(`Адрес ${host} не найден — похоже на опечатку.`));
    } else if (r === 'refused') {
      console.log('  ' + C.warn(`Сервер ${host} отклонил подключение по SSH.`));
      console.log('    ' + C.dim('Адрес доступен, но порт 22 закрыт. Проверьте, запущен ли сервер.'));
    } else {
      console.log('  ' + C.warn(`Адрес ${host} недоступен с вашего интернета.`));
      console.log('    ' + C.dim('Сервер может быть исправен, но маршрута до него нет.'));
      console.log('    ' + C.dim('Чаще всего это блокировка IP у провайдера — попросите хостера заменить адрес.'));
    }
    if (flag('host') || process.env.VLESS_HOST) fail('Адрес недоступен.');
    console.log('  ' + C.dim('Введите другой адрес или нажмите Ctrl+C.'));
    console.log('');
  }

  const script = fs.readFileSync(path.join(__dirname, 'setup.sh'), 'utf8');
  let user = null, pass = null;

  // Логин и пароль спрашиваем, пока сервер их не примет.
  for (let attempt = 1; ; attempt++) {
    user = await askRequired('Логин', 'root', attempt === 1 ? (flag('user') || process.env.VLESS_USER) : null);
    pass = await askRequired('Пароль', null, attempt === 1 ? (flag('pass') || process.env.VLESS_PASS) : null);
    console.log('');

    // Обрыв соединения обычно временный: сервер ещё разворачивается либо
    // сработала защита от перебора. Пробуем несколько раз с паузой.
    let res = null, authFailed = false;
    for (let t = 1; t <= 3; t++) {
      try {
        res = await runSetup(host, port, user, pass, script);
        break;
      } catch (e) {
        if (e.kind === 'auth') { authFailed = true; break; }

        if (e.kind === 'reset' || e.kind === 'timeout') {
          if (t < 3) {
            console.log('  ' + C.warn('Сервер разорвал соединение.') +
              C.dim(` Повторю через 10 секунд — попытка ${t + 1} из 3.`));
            await sleep(10000);
            continue;
          }
          fail('Сервер трижды разорвал соединение.',
            'Обычно причина одна из трёх:\n' +
            '· сервер ещё разворачивается — подождите 5 минут после письма хостера;\n' +
            '· сработала защита от перебора паролей — подождите 15 минут;\n' +
            '· SSH закрыт firewall — проверьте панель управления у хостера.\n' +
            'Проверить вручную: ssh ' + user + '@' + host + (port !== 22 ? ' -p ' + port : ''));
        }
        fail('Не удалось подключиться: ' + e.message);
      }
    }

    if (authFailed) {
      console.log('  ' + C.warn('Сервер отклонил логин или пароль.'));
      console.log('    ' + C.dim('Сверьтесь с письмом хостера: пароль вводится без пробелов по краям.'));
      if (flag('pass') || process.env.VLESS_PASS) fail('Неверные учётные данные.');
      console.log('  ' + C.dim('Попробуйте ещё раз или нажмите Ctrl+C.'));
      console.log('');
      await sleep(1500);   // не упираемся в ограничение sshd на частые попытки
      continue;
    }

    finish(res.code, res.raw, host);
    return;
  }
}

// Одно SSH-подключение: ставит и запускает серверную часть.
function runSetup(host, port, user, pass, script) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let raw = '', settled = false;
    const done = fn => { if (!settled) { settled = true; fn(); } };

    conn.on('ready', () => {
      console.log('  ' + C.ok('✓') + ' подключился к серверу\n');
      conn.exec('bash -s', (err, stream) => {
        if (err) return done(() => reject(Object.assign(new Error(err.message), { kind: 'exec' })));
        stream.on('data', d => {
          raw += d.toString();
          d.toString().split('\n').filter(Boolean).forEach(line => {
            if (/^\[\d\d:\d\d:\d\d\]/.test(line)) console.log('  ' + C.dim(line.replace(/^\[.*?\]\s*/, '→ ')));
            else if (/ПРОКСИ РАБОТАЕТ/.test(line)) console.log('  ' + C.ok('✓ проверка связи пройдена'));
          });
        });
        stream.stderr.on('data', d => { raw += d.toString(); });
        stream.on('close', code => { conn.end(); done(() => resolve({ code, raw })); });
        stream.end(script);
      });
    }).on('error', e => {
      const sig = (e.code || '') + ' ' + (e.message || '');
      const kind = e.level === 'client-authentication' ? 'auth'
        : e.level === 'client-timeout' ? 'timeout'
        : /ECONNRESET|ECONNABORTED|EPIPE|ETIMEDOUT/.test(sig) ? 'reset'
        : 'other';
      done(() => reject(Object.assign(new Error(e.message), { kind })));
    }).connect({ host, port, username: user, password: pass, readyTimeout: 25000 });
  });
}

function finish(code, raw, host) {
  const get = k => { const m = raw.match(new RegExp('^' + k + '=(.+)$', 'm')); return m ? m[1].trim() : null; };
  const v = { host, uuid: get('UUID'), pub: get('PUBLIC_KEY'), sid: get('SHORT_ID'), dest: get('DEST') };

  if (code !== 0 || !v.uuid || !v.pub || !v.sid || !v.dest) {
    fail('Установка не завершилась.',
      'Сервер вернул код ' + code + '. Последние строки вывода:\n' +
      raw.trim().split('\n').slice(-6).join('\n'));
  }

  const file = path.join(desktopDir(), 'vless.yaml');
  fs.writeFileSync(file, buildYaml(v), 'utf8');

  console.log('');
  console.log('  ' + C.ok(C.b('Готово.')));
  console.log('  ' + 'Профиль сохранён: ' + C.acc(file));
  console.log('');
  console.log('  ' + C.dim('Осталось два шага:'));
  console.log('  ' + C.dim('  1. Перетащите этот файл в Clash Verge — вкладка «Профили».'));
  console.log('  ' + C.dim('  2. Включите «Режим TUN», системный прокси при этом выключите.'));
  console.log('');
  closeRl();
}

process.on('SIGINT', () => {
  console.log('\n  ' + C.dim('Отменено. Ничего не изменено.') + '\n');
  closeRl();
  process.exit(130);
});

main().catch(e => fail('Непредвиденная ошибка: ' + e.message));
