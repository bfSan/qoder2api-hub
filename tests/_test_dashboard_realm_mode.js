/* #26 自动路由：三态开关（自动/锁国内/锁国际）+ 本次实际出口（有头=换过，无头=没换）+ 换区原因。
 *
 * 为什么测：自动换区是**后台替用户做的决定**——隐式行为比显式操作更需要可见。
 * 界面最容易出的两类错：① 把「没换区」渲染成「当前区」（假指示）；② 用户锁了国内却发现走了国际，
 * 界面上看不出为什么（缺原因）→ 被当成 bug。这条套件把三态、有头/无头、两类原因都钉住。
 */
const fs = require('fs');
const path = require('path');
const ROOT = process.env.QD_DASH_ROOT || path.join(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'dashboard.html'), 'utf8');
let PASS = 0, FAIL = 0;
function check(name, cond){ if(cond){ PASS++; console.log('  ok   ' + name); } else { FAIL++; console.log('  FAIL ' + name); } }
function slice(from, to){
  const a = html.indexOf(from), b = html.indexOf(to);
  return (a >= 0 && b > a) ? html.slice(a, b) : '';
}
const FN = slice('function realmModeOf(state){', 'function updateUI(){');
check('锚点：realmModeOf / realmActualNote / 渲染与切换函数都抽到', FN.length > 1500);
check('标记：三个档位按钮与「实际出口」行都在 DOM 里（自动 / 锁定国内 / 锁定国际）',
  /id="realmModeAuto"[^>]*>自动</.test(html) && /id="realmModeCn"[^>]*>锁定国内</.test(html)
  && /id="realmModeIntl"[^>]*>锁定国际</.test(html) && /id="realmActual"/.test(html));

const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const els = {};
function mk(id){
  const el = { id: id, _cls: new Set(), title: '', innerHTML: '', textContent: '', style: {},
    classList: { add(c){ el._cls.add(c); }, remove(c){ el._cls.delete(c); }, contains(c){ return el._cls.has(c); },
                 toggle(c, on){ if(on === undefined) on = !el._cls.has(c); if(on) el._cls.add(c); else el._cls.delete(c); } } };
  return el;
}
const posted = []; const toasts = [];
function load(state, seen, accounts, win){
  Object.keys(els).forEach(k => delete els[k]);
  const W = win || {};
  W.REALM_STATE = state; W.LAST_REALM_SEEN = seen; W.ACCOUNTS = accounts || [];
  W.ACTIVE_GATEWAY_REALM = (state || {}).current || 'intl';
  W.updateUI = () => {}; W.VIEW_REALM = W.ACTIVE_GATEWAY_REALM;
  const doc = { getElementById: (id) => (els[id] = els[id] || mk(id)) };
  const api = new Function('document', 'esc', 'window', 'toast', 'postJSON', 'loadAccounts', 'loadModels', 'refresh',
    FN + '; return {realmModeOf:realmModeOf, realmActualNote:realmActualNote, renderRealmMode:renderRealmMode,' +
    ' renderRealmActual:renderRealmActual, setRealmMode:setRealmMode};')(
    doc, esc, W,
    (m, k) => toasts.push(k + ':' + m),
    async (url, body) => { posted.push({ url: url, body: body }); return { current: (body || {}).realm }; },
    async () => {}, async () => {}, async () => {});
  return { api: api, els: els, W: W };
}

// —— 三态判定 ——
let env = load({ current: 'intl', auto_enabled: true, auto_env: 'QD_AUTO_REALM' });
check('auto_enabled=true → 当前档位是「自动」', env.api.realmModeOf(env.W.REALM_STATE) === 'auto');
env = load({ current: 'cn', auto_enabled: false });
check('锁定国内 → 「锁定国内」', env.api.realmModeOf(env.W.REALM_STATE) === 'cn');
env = load({ current: 'intl', auto_enabled: false });
check('锁定国际 → 「锁定国际」', env.api.realmModeOf(env.W.REALM_STATE) === 'intl');
env.api.renderRealmMode();
const actives = ['realmModeAuto', 'realmModeCn', 'realmModeIntl'].filter(id => env.els[id] && env.els[id].classList.contains('active'));
check('渲染：三档里**恰好一个**处于 active（不会出现两档同时亮）', actives.length === 1 && actives[0] === 'realmModeIntl');
check('渲染：悬停提示写明环境变量名（改它要重启，面板只展示）', /QD_AUTO_REALM/.test(env.els['realmModeBar'].title));

// —— 实际出口：有头 / 无头 ——
env = load({ current: 'intl', auto_enabled: false }, null);
let note = env.api.realmActualNote(env.W.LAST_REALM_SEEN, env.W.REALM_STATE, env.W.ACCOUNTS);
check('无头 → 「未观察到换区」+ 说明回落到默认出口（**不假造当前区指示**）',
  note.switched === false && /未观察到换区/.test(note.head) && /没有该头就是没换/.test(note.detail));
env = load({ current: 'intl', auto_enabled: true }, { realm: 'intl' });
note = env.api.realmActualNote(env.W.LAST_REALM_SEEN, env.W.REALM_STATE, env.W.ACCOUNTS);
check('有头但同为当前区 → 「与默认出口一致」，不算换区', note.switched === false && /一致/.test(note.head));
env = load({ current: 'cn', auto_enabled: true }, { realm: 'intl' }, [{ realm: 'cn', enabled: true }, { realm: 'intl', enabled: true }]);
note = env.api.realmActualNote(env.W.LAST_REALM_SEEN, env.W.REALM_STATE, env.W.ACCOUNTS);
check('换区 + 默认区有可用账号 → 提示「没有该模型」这一类原因',
  note.switched === true && /自动换区/.test(note.head) && /没有该模型/.test(note.detail));
env = load({ current: 'cn', auto_enabled: true }, { realm: 'intl' }, [{ realm: 'cn', enabled: false }, { realm: 'intl', enabled: true }]);
note = env.api.realmActualNote(env.W.LAST_REALM_SEEN, env.W.REALM_STATE, env.W.ACCOUNTS);
check('换区 + 默认区没有可用账号 → 提示「没有可用账号（启用 0 个）」',
  note.switched === true && /没有可用账号/.test(note.detail));
env = load({ current: 'cn', auto_enabled: true }, { realm: 'intl' }, []);
note = env.api.realmActualNote(env.W.LAST_REALM_SEEN, env.W.REALM_STATE, env.W.ACCOUNTS);
check('账号未加载时不瞎猜 → 「原因待定」', /原因待定/.test(note.detail));

// —— 渲染与开关行为 ——
env = load({ current: 'cn', auto_enabled: true, auto_env: 'QD_AUTO_REALM' }, { realm: 'intl' }, [{ realm: 'cn', enabled: true }]);
env.api.renderRealmActual();
check('换区时配色变 warn（一眼可见）且把「默认出口是…本次被自动改走」写全',
  env.els['realmActual'].style.color === 'var(--warn)' && /默认出口是 国内版/.test(env.els['realmActual'].innerHTML));
posted.length = 0; toasts.length = 0;
env.api.setRealmMode('auto');
check('点「自动」→ **不发请求**（环境变量只能重启改），只给提示', posted.length === 0 && /环境变量/.test(toasts[0] || ''));
posted.length = 0;
env.api.setRealmMode('cn');
check('点「锁定国内」→ POST /realm {realm:"cn"}', posted.length === 1 && posted[0].url === '/realm' && posted[0].body.realm === 'cn');

console.log('');
console.log('SUMMARY: TOTAL ' + (PASS + FAIL) + ' checks, ' + PASS + ' passed, ' + FAIL + ' failed');
console.log('RESULT: ' + (FAIL ? 'RED' : 'GREEN') + ' (exit ' + (FAIL ? 1 : 0) + ')');
process.exit(FAIL ? 1 : 0);
