/* ============================================================
   Admin panel — login, inline editing, media, lists, settings,
   sections, backup/restore, HTML export
   ============================================================ */
(function () {
'use strict';
const A = window.__SITE__;
const { S, icon, esc, escAttr, uid, toast } = A;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const D = () => A.D;

/* ---------- password ---------- */
/* ---------- password: salted + iterated SHA-256, never stored as plain text ---------- */
const SHA_K = [], SHA_H = [];
{ let n = 2, c = 0; while (c < 64) { let p = true; for (let i = 2; i * i <= n; i++) if (n % i === 0) { p = false; break; } if (p) { if (c < 8) SHA_H[c] = (Math.pow(n, 0.5) % 1) * 4294967296 | 0; SHA_K[c] = (Math.pow(n, 1 / 3) % 1) * 4294967296 | 0; c++; } n++; } }
function sha256js(msg) {
  const l = msg.length, n = ((l + 9 + 63) >> 6) << 6, buf = new Uint8Array(n); buf.set(msg); buf[l] = 0x80;
  const dv = new DataView(buf.buffer); dv.setUint32(n - 4, (l * 8) >>> 0); dv.setUint32(n - 8, Math.floor(l * 8 / 4294967296));
  const h = SHA_H.slice(), w = new Int32Array(64);
  for (let o = 0; o < n; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(o + i * 4);
    for (let i = 16; i < 64; i++) { const a = w[i - 15], c = w[i - 2]; w[i] = (w[i - 16] + ((a >>> 7 | a << 25) ^ (a >>> 18 | a << 14) ^ (a >>> 3)) + w[i - 7] + ((c >>> 17 | c << 15) ^ (c >>> 19 | c << 13) ^ (c >>> 10))) | 0; }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
      const t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    [a, b, c, d, e, f, g, hh].forEach((v, i) => { h[i] = (h[i] + v) | 0; });
  }
  const out = new Uint8Array(32), o2 = new DataView(out.buffer); h.forEach((v, i) => o2.setInt32(i * 4, v)); return out;
}
async function sha256b(bytes) { if (window.crypto && crypto.subtle) { try { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); } catch (e) { /* fall back */ } } return sha256js(bytes); }
const hexOf = (u) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');
async function hashPw(pw, salt, kdf) {
  if (kdf === 'pbkdf2') { /* slow, standard key derivation (210k iterations) */
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
    return hexOf(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(salt), iterations: 210000 }, key, 256)));
  }
  let h = await sha256b(new TextEncoder().encode(salt + ':' + pw)); for (let i = 0; i < 5000; i++) h = await sha256b(h); return hexOf(h); /* legacy records */
}
const hasSubtle = () => !!(window.crypto && crypto.subtle && crypto.subtle.deriveBits);
const sameStr = (a, b) => { a = String(a); b = String(b); if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };
async function setPw(pw) { const salt = hexOf(crypto.getRandomValues(new Uint8Array(16))), kdf = hasSubtle() ? 'pbkdf2' : ''; D().admin = { salt, hash: await hashPw(pw, salt, kdf), ...(kdf ? { kdf } : {}) }; A.persist(true); }
const hasPw = () => { const a = D().admin || {}; return !!(a.hash || a.password); };
async function checkPw(pw) {
  const a = D().admin || {};
  if (a.hash) {
    if (a.kdf === 'pbkdf2' && !hasSubtle()) return false; /* cannot verify without WebCrypto (open the site over https) */
    const ok = sameStr(await hashPw(pw, a.salt, a.kdf), a.hash);
    if (ok && a.kdf !== 'pbkdf2' && hasSubtle()) await setPw(pw); /* silently upgrade an old 5000-round SHA-256 record */
    return ok;
  }
  if (a.password && sameStr(pw, a.password)) { await setPw(pw); return true; } /* old plain-text password: upgrade once */
  return false;
}
let loginFails = 0;
function openSetPassword() {
  const m = modal(`${mh('تعیین رمز مدیر')}<p class="desc">رمز مدیر هنوز تعیین نشده است. یک رمز قوی (حداقل ۸ کاراکتر) انتخاب کنید. رمز به‌صورت رمزنگاری‌شده فقط در همین مرورگر نگه‌داری می‌شود.</p><label class="fld">رمز جدید<input type="password" dir="ltr" data-p="new" autocomplete="new-password"></label><label class="fld">تکرار رمز<input type="password" dir="ltr" data-p="new2" autocomplete="new-password"><span class="err hidden"></span></label><div class="mrow"><button type="button" class="btn btn-navy" data-ok>ذخیره و ورود</button><button type="button" class="btn btn-soft" data-act="modal-close">انصراف</button></div>`);
  m.querySelector('[data-ok]').onclick = async () => {
    const n = m.querySelector('[data-p="new"]').value, n2 = m.querySelector('[data-p="new2"]').value, err = m.querySelector('.err');
    const fail = (t) => { err.textContent = t; err.classList.remove('hidden'); };
    if (n.length < 8) return fail('رمز باید حداقل ۸ کاراکتر باشد.');
    if (n !== n2) return fail('تکرار رمز یکسان نیست.');
    await setPw(n); closeModal(); S.admin = true; S.edit = true; try { sessionStorage.setItem('company_site_edit', '1'); sessionStorage.setItem(A.SESSION_KEY, '1'); } catch (e) { /* ignore */ }
    A.render(true); toast('رمز ذخیره شد و وارد شدید.');
  };
}

/* ---------- modal ---------- */
function modal(html, o = {}) {
  closeModal();
  const bg = document.createElement('div'); bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal${o.wide ? ' wide' : ''}" role="dialog" aria-modal="true">${html}</div>`;
  bg.addEventListener('click', (e) => { if (e.target === bg) dismissModal(); });
  document.body.appendChild(bg);
  const first = bg.querySelector('input,textarea,select,button.btn'); if (first && first.type !== 'file') setTimeout(() => first.focus(), 30);
  return bg;
}
let modalCancel = null; /* callback of the open modal that must run when it is dismissed (Esc, backdrop, X) instead of saved */
function closeModal() { modalCancel = null; $$('.modal-bg').forEach((m) => m.remove()); }
function dismissModal() { const cb = modalCancel; closeModal(); if (cb) cb(); }
const mh = (title) => `<h3>${esc(title)}<button type="button" data-act="modal-close" aria-label="بستن">${icon('x')}</button></h3>`;
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { dismissModal(); closePops(); if ($('.lightbox')) $('.lightbox').remove(); } });

/* ---------- popovers (icon picker / link picker) ---------- */
function closePops() { $$('.ipick,.linkpick').forEach((p) => p.remove()); }
function placePop(el, anchor) {
  document.body.appendChild(el);
  const r = anchor.getBoundingClientRect(), w = el.offsetWidth, h = el.offsetHeight;
  let left = Math.min(Math.max(8, r.left + r.width / 2 - w / 2), innerWidth - w - 8);
  let top = r.bottom + 8; if (top + h > innerHeight - 8) top = Math.max(8, r.top - h - 8);
  el.style.left = left + 'px'; el.style.top = top + 'px';
}
document.addEventListener('mousedown', (e) => { if (!e.target.closest('.ipick,.linkpick,[data-act="icon-pick"],[data-act="link-pick"]')) closePops(); });

/* ---------- files ---------- */
function pickFiles(accept, multiple) {
  return new Promise((res) => {
    const inp = document.createElement('input'); inp.type = 'file'; inp.accept = accept; inp.multiple = !!multiple; inp.style.display = 'none';
    inp.onchange = () => { const f = Array.from(inp.files || []); inp.remove(); res(f); };
    document.body.appendChild(inp); inp.click();
  });
}
function readAsDataURL(file) { return new Promise((res) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = () => res(null); r.readAsDataURL(file); }); }
/* Real image type from the first bytes: on phones (content:// / cloud pickers) file.type is often empty, wrong or "application/octet-stream". */
function sniffImageType(file) {
  return new Promise((res) => {
    const r = new FileReader();
    r.onload = () => {
      const b = new Uint8Array(r.result), asc = (i, n) => String.fromCharCode.apply(null, Array.from(b.slice(i, i + n)));
      if (b[0] === 0xFF && b[1] === 0xD8) return res('image/jpeg');
      if (b[0] === 0x89 && asc(1, 3) === 'PNG') return res('image/png');
      if (asc(0, 3) === 'GIF') return res('image/gif');
      if (asc(0, 4) === 'RIFF' && asc(8, 4) === 'WEBP') return res('image/webp');
      if (asc(0, 2) === 'BM') return res('image/bmp');
      if (asc(4, 4) === 'ftyp') { const br = asc(8, 4); if (/^(avif|avis)$/.test(br)) return res('image/avif'); if (/^(heic|heix|hevc|hevx|heim|heis|mif1|msf1)$/.test(br)) return res('image/heic'); }
      const head = new TextDecoder().decode(b).trim().toLowerCase();
      if (head.startsWith('<svg') || head.startsWith('<?xml')) return res('image/svg+xml');
      res(file.type && file.type.startsWith('image/') ? file.type : '');
    };
    r.onerror = () => res(file.type || '');
    r.readAsArrayBuffer(file.slice(0, 32));
  });
}
const validImgURL = (u) => typeof u === 'string' && u.length > 200 && /^data:image\/(jpeg|png|webp|gif|svg\+xml|bmp|avif);/i.test(u);
function decodeImageFile(file) { /* via a blob: URL (no giant base64 string in memory) */
  return new Promise((res) => {
    const u = URL.createObjectURL(file), im = new Image();
    im.onload = () => res({ im, u }); im.onerror = () => { URL.revokeObjectURL(u); res(null); }; im.src = u;
  });
}
let lastImageError = '';
async function processImage(file, max = 1600, keepPng = false) {
  lastImageError = '';
  const mime = await sniffImageType(file);
  if (!mime || !mime.startsWith('image/')) { lastImageError = 'bad'; return null; }
  if (mime === 'image/svg+xml' || mime === 'image/gif') { const raw = await readAsDataURL(file); return raw ? raw.replace(/^data:[^;,]*/, 'data:' + mime) : null; }
  const dec = await decodeImageFile(file);
  if (!dec) { lastImageError = mime === 'image/heic' ? 'heic' : 'decode'; return null; } /* e.g. HEIC the browser cannot display: refuse instead of saving a broken picture */
  const { im, u } = dec;
  try {
    const W = im.naturalWidth || im.width, H = im.naturalHeight || im.height;
    if (!W || !H) { lastImageError = 'decode'; return null; }
    const png = keepPng || mime === 'image/png' || mime === 'image/webp';
    for (const lim of [max, 1400, 1000, 700]) { /* mobile browsers sometimes fail on big canvases: retry smaller */
      if (lim > max) continue;
      try {
        const k = Math.min(1, lim / Math.max(W, H)), w = Math.max(1, Math.round(W * k)), h = Math.max(1, Math.round(H * k));
        const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
        const g = cv.getContext('2d'); if (!png) { g.fillStyle = '#fff'; g.fillRect(0, 0, w, h); }
        g.drawImage(im, 0, 0, w, h);
        const out = cv.toDataURL(png ? 'image/png' : 'image/jpeg', 0.86);
        cv.width = cv.height = 0;
        if (validImgURL(out)) return out;
      } catch (e) { /* try a smaller size */ }
    }
    /* canvas failed but the browser did decode the file: keep the original bytes with the right mime */
    const raw = await readAsDataURL(file);
    if (raw) { const fixed = raw.replace(/^data:[^;,]*/, 'data:' + mime); if (validImgURL(fixed)) return fixed; }
    lastImageError = 'decode'; return null;
  } finally { URL.revokeObjectURL(u); }
}
document.addEventListener('error', (e) => { const t = e.target; if (t && t.tagName === 'IMG' && t.closest) { const g = t.closest('.gm'); if (g) g.classList.add('gm-bad'); } }, true);
const imageErrorMsg = (name) => lastImageError === 'heic' ? `«${name}» با فرمت HEIC است و مرورگر نمی‌تواند آن را نمایش دهد؛ عکس را با فرمت JPG یا PNG ذخیره کنید (یا در تنظیمات دوربین فرمت «سازگارتر» را بزنید).` : `«${name}» به‌عنوان تصویر خوانده نشد.`;
function download(name, text, type) {
  const blob = new Blob([text], { type: type || 'application/octet-stream' });
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

/* ---------- crop editor / logo preview / brand logo ---------- */
function cropCfg(path) {
  const R = (l, r) => ({ l, r });
  if (path === 'company.heroImage') return { title: 'کادر تصویر اصلی', ratios: [R('عریض ۳:۲ (پیشنهادی)', 3 / 2), R('پانوراما ۱۶:۹', 16 / 9), R('مربع ۱:۱', 1)], outW: 1600, free: true };
  if (path === 'company.aboutImage') return { title: 'کادر تصویر «درباره ما»', ratios: [R('عمودی ۳:۴', 3 / 4)], outW: 900 };
  if (path === 'company.aboutImage2') return { title: 'کادر تصویر دوم «درباره ما»', ratios: [R('۴:۳', 4 / 3)], outW: 900 };
  if (/^portfolio\.\d+\.coverImage$/.test(path)) return { title: 'کادر تصویر کاور پروژه', ratios: [R('۱۶:۱۰ (لیست پروژه‌ها)', 16 / 10), R('۴:۳ (صفحه اصلی)', 4 / 3), R('۲۱:۹ (صفحه پروژه)', 21 / 9)], outW: 1600, free: true };
  if (/^clients\.\d+\.logo$/.test(path)) return { title: 'کادر لوگوی مشتری', ratios: [R('کارت لوگو ۲:۱', 2), R('مربع ۱:۱', 1)], outW: 440, free: true, fit: 'contain', png: true };
  if (path === 'company.logoIcon') return { title: 'کادر لوگوی شرکت', ratios: [R('مربع ۱:۱', 1), R('عریض ۳:۱', 3)], outW: 600, free: true, fit: 'contain', png: true };
  if (/(^|\.)icon$|Icon$/.test(path)) return { title: 'ویرایش آیکون', ratios: [R('مربع ۱:۱', 1)], outW: 256, fit: 'contain', png: true };
  if (/\.media\.\d+\.url$/.test(path)) return { title: 'کادر تصویر گالری', ratios: [R('۴:۳', 4 / 3), R('۱۶:۹', 16 / 9), R('مربع ۱:۱', 1)], outW: 1600, free: true };
  return null;
}
function runCropper(path, orig, cfg, crop) {
  openCropper({ path, free: cfg.free, fit: cfg.fit, onCancel: cfg.onCancel, title: cfg.title, src: orig, ratios: cfg.ratios, crop, outW: cfg.outW, png: cfg.png || orig.startsWith('data:image/png'),
    onSave: (url, c) => { A.set(path, url); A.set(path + '_orig', orig); A.set(path + '_crop', c); if (cfg.after) cfg.after(url, c); A.persist(); A.render(true); toast('تصویر ذخیره شد.'); } });
}
function openCropper(o) {
  const im = new Image();
  im.onerror = () => toast('تصویر قابل خواندن نیست.', true);
  im.onload = () => {
    const W0 = im.naturalWidth, H0 = im.naturalHeight;
    if (!W0 || !H0) return toast('ابعاد تصویر نامعتبر است.', true);
    const DEG = Math.PI / 180, clamp = (v, a, b) => Math.min(b, Math.max(a, v)), fa = (n) => A.toFa(Math.round(n));
    const sugg = o.ratios.map((r) => ({ l: r.l, r: r.r }));
    const COMMON = [['۱:۱', 1], ['۴:۳', 4 / 3], ['۳:۲', 3 / 2], ['۱۶:۹', 16 / 9], ['۲۱:۹', 21 / 9], ['۳:۱', 3], ['۲:۱', 2], ['۴:۵', 4 / 5], ['۳:۴', 3 / 4], ['۲:۳', 2 / 3], ['۹:۱۶', 9 / 16]];
    const FILTERS = [['اصلی', 100, 100, 100, 0, 0], ['روشن', 112, 104, 105, 0, 0], ['شفاف', 104, 118, 125, 0, 0], ['ملایم', 104, 92, 90, 0, 0], ['دراماتیک', 94, 130, 110, 0, 0], ['سیاه‌وسفید', 100, 108, 100, 100, 0], ['قدیمی', 104, 94, 90, 0, 70]];
    const TABS = [['crop', 'کادر'], ['tr', 'چرخش'], ['adj', 'تنظیم و فیلتر'], ['out', 'خروجی']];
    const GRIDS = [['none', 'بدون'], ['thirds', 'سه‌قسمتی'], ['golden', 'طلایی'], ['grid', 'شبکه'], ['diag', 'قطری'], ['center', 'مرکز']];
    const c0 = o.crop || {};
    const st = { q: 0, ang: 0, fx: 0, fy: 0, ratio: sugg[0].r, fit: o.fit || 'cover', x: 0, y: 0, w: 1, h: 1, br: 100, ct: 100, sa: 100, gs: 0, sp: 0, bg: 'auto', bgc: '#ffffff', size: 'std', fmt: 'auto', qual: 88, grid: 'thirds' };
    let OC = null, OW = W0, OH = H0, tab = 'crop', compare = false, hist = [], hi = -1;

    /* ---------- oriented image (quarter turns + flips) ---------- */
    const buildO = () => {
      const odd = st.q % 2 === 1; OW = odd ? H0 : W0; OH = odd ? W0 : H0;
      OC = document.createElement('canvas'); OC.width = OW; OC.height = OH;
      const g = OC.getContext('2d'); g.imageSmoothingQuality = 'high';
      g.translate(OW / 2, OH / 2); g.scale(st.fx ? -1 : 1, st.fy ? -1 : 1); g.rotate(st.q * 90 * DEG); g.drawImage(im, -W0 / 2, -H0 / 2);
    };
    const baseW = (r) => {
      if (st.fit === 'contain') return Math.max(OW, r * OH);
      const a = st.ang * DEG, s = Math.abs(Math.sin(a)), c = Math.abs(Math.cos(a));
      return Math.min(OW / (c + s / r), OH / (s + c / r));
    };
    const zoomVal = () => Math.max(1, baseW(st.w / st.h) / st.w);
    const MINW = () => Math.max(24, Math.min(OW, OH) / 40);
    const LIM = () => 6 * Math.max(OW, OH);
    const clampRect = () => {
      let { x, y, w, h } = st; let cx = x + w / 2, cy = y + h / 2;
      if (st.ratio) h = w / st.ratio;
      const mn = MINW(), lim = LIM();
      let f = Math.min(1, lim / w, lim / h); w *= f; h *= f;
      f = Math.max(1, mn / w, mn / h); w *= f; h *= f;
      if (st.fit === 'contain') { cx = clamp(cx, 0, OW); cy = clamp(cy, 0, OH); }
      else {
        const a = st.ang * DEG, co = Math.cos(a), si = Math.sin(a), ac = Math.abs(co), as = Math.abs(si);
        const fit = Math.min(1, OW / (w * ac + h * as), OH / (w * as + h * ac)); w *= fit; h *= fit;
        const vx = cx - OW / 2, vy = cy - OH / 2;
        let rx = vx * co + vy * si, ry = -vx * si + vy * co;
        const lx = Math.max(0, OW / 2 - (w * ac + h * as) / 2), ly = Math.max(0, OH / 2 - (w * as + h * ac) / 2);
        rx = clamp(rx, -lx, lx); ry = clamp(ry, -ly, ly);
        cx = OW / 2 + rx * co - ry * si; cy = OH / 2 + rx * si + ry * co;
      }
      st.w = w; st.h = h; st.x = cx - w / 2; st.y = cy - h / 2;
    };
    const valid = (r) => {
      const mn = MINW() - 0.01, lim = LIM();
      if (r.w < mn || r.h < mn || r.w > lim || r.h > lim) return false;
      const cx = r.x + r.w / 2, cy = r.y + r.h / 2;
      if (st.fit === 'contain') return cx >= 0 && cx <= OW && cy >= 0 && cy <= OH;
      const a = st.ang * DEG, co = Math.cos(a), si = Math.sin(a), ac = Math.abs(co), as = Math.abs(si);
      const hw = (r.w * ac + r.h * as) / 2, hh = (r.w * as + r.h * ac) / 2;
      const vx = cx - OW / 2, vy = cy - OH / 2, rx = vx * co + vy * si, ry = -vx * si + vy * co;
      return Math.abs(rx) + hw <= OW / 2 + 0.5 && Math.abs(ry) + hh <= OH / 2 + 0.5;
    };
    const setZoom = (z) => {
      z = clamp(z, 1, 8); const r = st.w / st.h, cx = st.x + st.w / 2, cy = st.y + st.h / 2, w = baseW(r) / z;
      st.w = w; st.h = w / r; st.x = cx - st.w / 2; st.y = cy - st.h / 2; clampRect();
    };
    const setRatio = (r) => {
      const z0 = zoomVal(), cx = st.x + st.w / 2, cy = st.y + st.h / 2; st.ratio = r;
      if (r) { const w = baseW(r) / z0; st.w = w; st.h = w / r; st.x = cx - st.w / 2; st.y = cy - st.h / 2; }
      clampRect();
    };
    const keepZoom = (fn) => {
      const z0 = zoomVal(), r = st.w / st.h, cx = st.x + st.w / 2, cy = st.y + st.h / 2; fn();
      const w = baseW(r) / z0; st.w = w; st.h = w / r; st.x = cx - w / 2; st.y = cy - st.h / 2; clampRect();
    };
    const initRect = () => { const r = st.ratio || OW / OH, w = baseW(r); st.w = w; st.h = w / r; st.x = (OW - st.w) / 2; st.y = (OH - st.h) / 2; clampRect(); };

    /* ---------- restore saved state ---------- */
    if (c0.v === 2) {
      ['q', 'ang', 'fx', 'fy', 'ratio', 'fit', 'br', 'ct', 'sa', 'gs', 'sp', 'bg', 'bgc', 'size', 'fmt', 'qual', 'grid'].forEach((k) => { if (c0[k] !== undefined && c0[k] !== null) st[k] = c0[k]; });
      st.q = ((Math.round(st.q) % 4) + 4) % 4; buildO();
      st.x = c0.nx * OW; st.y = c0.ny * OH; st.w = c0.nw * OW; st.h = c0.nh * OH;
      if (!(st.w > 0 && st.h > 0)) initRect(); else clampRect();
    } else {
      buildO();
      if (c0.z) {
        const ri = Math.min(c0.ri || 0, sugg.length), r = ri < sugg.length ? sugg[ri].r : 0, rr = r || c0.fr || OW / OH;
        st.ratio = r; if (c0.fit) st.fit = c0.fit;
        const w = baseW(rr) / (c0.z || 1); st.w = w; st.h = w / rr; st.x = (c0.cx ?? OW / 2) - w / 2; st.y = (c0.cy ?? OH / 2) - st.h / 2; clampRect();
      } else initRect();
    }

    /* ---------- markup ---------- */
    const chip = (attr, val, label, on) => `<button type="button" class="crx-chip${on ? ' on' : ''}" ${attr}="${val}">${esc(label)}</button>`;
    const rng = (k, lab, min, max, step) => `<label class="crx-rg"><span>${lab}</span><input type="range" class="slider" data-s="${k}" min="${min}" max="${max}" step="${step}" value="0"><output data-o="${k}"></output></label>`;
    const num = (k, lab) => `<label class="crx-nm"><span>${lab}</span><input type="number" inputmode="numeric" data-n="${k}" min="0" step="1"></label>`;
    const AL = ['tl', 't', 'tr', 'l', 'c', 'r', 'bl', 'b', 'br'];
    /* gallery-only: two live previews (card in the gallery / full view on click) */
    const gm = /^portfolio\.(\d+)\.media\.(\d+)\.url$/.exec(o.path || '');
    let GAL = null;
    if (gm) { const pj = A.D.portfolio && A.D.portfolio[+gm[1]], n = pj && pj.media ? pj.media.length : 1; GAL = { wide: +gm[2] === 0 && n > 1 }; }
    const galHtml = GAL ? `<div class="crx-gp">
        <div><div class="t">۱) نمایش در گالری (هنگام اسکرول)</div>
          ${GAL.wide ? '<div class="crx-gp-l">کارت بزرگ (دسکتاپ)</div><canvas class="crx-gpc" data-gp="wide" data-ar="2.6667"></canvas><div class="crx-gp-l">کارت معمولی (موبایل)</div>' : ''}<canvas class="crx-gpc" data-gp="std" data-ar="1.3333"></canvas>
          <p class="crx-hint" data-gp-note></p></div>
        <div><div class="t">۲) نمایش هنگام کلیک روی عکس</div><canvas class="crx-gpc" data-gp="lb"></canvas></div>
      </div>` : '';
    const m = modal(`${mh(o.title)}
      <div class="crx">
        <div class="crx-main">
          <div class="crx-bar" role="toolbar" aria-label="ابزارهای کادربندی">
            <button type="button" class="tb" data-k="undo" aria-label="بازگشت (Ctrl+Z)" title="بازگشت">↶</button><button type="button" class="tb" data-k="redo" aria-label="جلو (Ctrl+Y)" title="جلو">↷</button><i class="vr"></i>
            <button type="button" class="tb" data-k="rotl" aria-label="چرخش ۹۰ درجه به چپ" title="چرخش به چپ">⟲ ۹۰°</button><button type="button" class="tb" data-k="rotr" aria-label="چرخش ۹۰ درجه به راست" title="چرخش به راست">⟳ ۹۰°</button><button type="button" class="tb" data-k="flipx" aria-label="قرینه‌ی افقی" title="قرینه افقی">⇋</button><button type="button" class="tb" data-k="flipy" aria-label="قرینه‌ی عمودی" title="قرینه عمودی">⇅</button><i class="vr"></i>
            <button type="button" class="tb" data-z="out" aria-label="کوچک‌نمایی">−</button><button type="button" class="tb" data-z="in" aria-label="بزرگ‌نمایی">+</button><button type="button" class="tb" data-k="fitall" title="کادر بیشینه">⛶</button><span class="sp"></span>
            <button type="button" class="tb cmp" data-k="cmp" aria-label="نگه دارید تا تصویر اصلی را ببینید">مقایسه با اصلی</button>
          </div>
          <div class="crx-stage" tabindex="0" aria-label="ناحیه‌ی کادربندی. با کلیدهای جهت‌نما کادر را جابه‌جا و با + و − بزرگ‌نمایی کنید.">
            <canvas class="crx-cv"></canvas>
            <div class="crx-box" data-grid="thirds"><span class="crx-dim" aria-live="polite"></span>${['tl', 't', 'tr', 'l', 'r', 'bl', 'b', 'br'].map((h) => `<i class="crx-h" data-h="${h}"></i>`).join('')}</div>
          </div>
          <p class="crx-hint">کادر را بکشید تا جابه‌جا شود؛ از گوشه‌ها و لبه‌ها اندازه‌اش را تغییر دهید. با چرخ ماوس یا دو انگشت بزرگ‌نمایی کنید.</p>
        </div>
        <div class="crx-side">
          <div class="crx-pvw"><canvas class="crx-pv"></canvas><div class="crx-info"><b>پیش‌نمایش خروجی</b><span data-info></span></div></div>
          ${galHtml}
          <div class="seg crx-tabs" role="tablist">${TABS.map(([k, l]) => `<button type="button" role="tab" data-tab="${k}" class="${k === tab ? 'on' : ''}">${l}</button>`).join('')}</div>
          <div class="crx-pane" data-pane="crop">
            <div class="crx-grp"><div class="t">نسبت کادر</div><div class="crx-chips">${sugg.map((r, i) => chip('data-r', 's' + i, r.l)).join('')}${chip('data-r', '0', 'آزاد')}${chip('data-r', 'orig', 'اصل عکس')}</div>
              <div class="crx-chips" style="margin-top:6px">${COMMON.map(([l, r]) => chip('data-r', r, l)).join('')}</div>
              <div class="crx-cust"><span>سفارشی</span><input type="number" min="1" max="99" step="0.1" value="16" data-cr="a" aria-label="عرض نسبت"><b>:</b><input type="number" min="1" max="99" step="0.1" value="9" data-cr="b" aria-label="ارتفاع نسبت"><button type="button" class="crx-chip" data-k="cr-apply">اعمال</button><button type="button" class="crx-chip" data-k="cr-swap" aria-label="جابه‌جایی افقی و عمودی">⇄ جابه‌جایی</button></div></div>
            <div class="crx-grp"><div class="t">حالت نمایش</div><div class="crx-chips">${chip('data-fit', 'cover', 'پر کردن کادر (برش)')}${chip('data-fit', 'contain', 'کامل‌نمایش (بدون برش)')}</div></div>
            <div class="crx-grp"><div class="t">بزرگ‌نمایی</div>${rng('z', '', 1, 8, 0.01)}</div>
            <div class="crx-grp"><div class="t">جای کادر روی تصویر</div><div class="crx-pos"><div class="crx-al">${AL.map((a) => `<button type="button" data-al="${a}" aria-label="تراز ${a}"><i></i></button>`).join('')}</div><div class="crx-nums">${num('x', 'X')}${num('y', 'Y')}${num('w', 'عرض')}${num('h', 'ارتفاع')}</div></div></div>
            <div class="crx-grp"><div class="t">خطوط راهنما</div><div class="crx-chips">${GRIDS.map(([k, l]) => chip('data-g', k, l)).join('')}</div></div>
          </div>
          <div class="crx-pane" data-pane="tr" hidden>
            <div class="crx-grp"><div class="t">چرخش و قرینه</div><div class="crx-chips"><button type="button" class="crx-chip" data-k="rotl">⟲ ۹۰° چپ</button><button type="button" class="crx-chip" data-k="rotr">⟳ ۹۰° راست</button><button type="button" class="crx-chip" data-k="flipx">⇋ قرینه افقی</button><button type="button" class="crx-chip" data-k="flipy">⇅ قرینه عمودی</button></div></div>
            <div class="crx-grp"><div class="t">صاف کردن افق (چرخش دقیق)</div>${rng('ang', '', -45, 45, 0.1)}<div class="crx-chips" style="margin-top:6px"><button type="button" class="crx-chip" data-ang="-0.5">−۰٫۵°</button><button type="button" class="crx-chip" data-ang="0.5">+۰٫۵°</button><button type="button" class="crx-chip" data-ang="0">صفر کردن زاویه</button></div><p class="crx-hint" style="margin:8px 0 0">در حالت «پر کردن کادر»، کادر به‌طور خودکار داخل تصویرِ چرخیده می‌ماند تا گوشه‌ی خالی ایجاد نشود.</p></div>
          </div>
          <div class="crx-pane" data-pane="adj" hidden>
            <div class="crx-grp"><div class="t">فیلترهای آماده</div><div class="crx-chips">${FILTERS.map((f, i) => chip('data-flt', i, f[0])).join('')}</div></div>
            <div class="crx-grp">${rng('br', 'روشنایی', 50, 150, 1)}${rng('ct', 'کنتراست', 50, 150, 1)}${rng('sa', 'اشباع رنگ', 0, 200, 1)}${rng('gs', 'سیاه‌وسفید', 0, 100, 1)}${rng('sp', 'قهوه‌ای قدیمی', 0, 100, 1)}<div class="crx-chips" style="margin-top:8px"><button type="button" class="crx-chip" data-k="adj-reset">بازنشانی تنظیمات رنگ</button></div></div>
          </div>
          <div class="crx-pane" data-pane="out" hidden>
            <div class="crx-grp"><div class="t">اندازه‌ی خروجی</div><div class="crx-chips">${chip('data-sz', 'small', 'کوچک')}${chip('data-sz', 'std', 'استاندارد')}${chip('data-sz', 'large', 'بزرگ')}${chip('data-sz', 'src', 'اندازه‌ی واقعی برش')}</div></div>
            <div class="crx-grp"><div class="t">فرمت فایل</div><div class="crx-chips">${chip('data-f', 'auto', 'خودکار')}${chip('data-f', 'jpeg', 'JPEG')}${chip('data-f', 'png', 'PNG')}${chip('data-f', 'webp', 'WebP')}</div><div data-qrow>${rng('qual', 'کیفیت', 50, 100, 1)}</div></div>
            <div class="crx-grp"><div class="t">پر کردن بخش‌های خالی</div><div class="crx-chips">${chip('data-bg', 'auto', 'خودکار')}${chip('data-bg', 'white', 'سفید')}${chip('data-bg', 'black', 'مشکی')}${chip('data-bg', 'custom', 'رنگ دلخواه')}<input type="color" class="crx-col" data-bgc value="#ffffff" aria-label="رنگ پس‌زمینه"></div></div>
            <p class="crx-hint" data-est></p>
          </div>
        </div>
      </div>
      <div class="mrow"><button type="button" class="btn btn-navy" data-k="ok">تأیید و ذخیره</button><button type="button" class="btn btn-soft" data-k="reset">بازنشانی همه</button><button type="button" class="btn btn-soft" data-k="cancel">انصراف</button></div>`, { wide: true });
    m.querySelector('.modal').classList.add('crx-m');
    modalCancel = o.onCancel || null; /* Esc / click outside / X = cancel, same as the cancel button */
    const $ = (s) => m.querySelector(s), $$$ = (s) => [...m.querySelectorAll(s)];
    const stage = $('.crx-stage'), cv = $('.crx-cv'), box = $('.crx-box'), pv = $('.crx-pv');
    let Vw = 0, Vh = 0, k = 1, ox = 0, oy = 0; const dpr = Math.min(2, window.devicePixelRatio || 1);

    /* ---------- view mapping ---------- */
    const fitView = () => {
      Vw = stage.clientWidth; Vh = stage.clientHeight; if (!Vw || !Vh) return;
      const a = st.ang * DEG, s = Math.abs(Math.sin(a)), c = Math.abs(Math.cos(a)), bw = OW * c + OH * s, bh = OW * s + OH * c;
      let l = OW / 2 - bw / 2, t = OH / 2 - bh / 2, r = l + bw, b = t + bh;
      l = Math.min(l, st.x); t = Math.min(t, st.y); r = Math.max(r, st.x + st.w); b = Math.max(b, st.y + st.h);
      const pad = 16; k = Math.min((Vw - 2 * pad) / (r - l), (Vh - 2 * pad) / (b - t));
      ox = (Vw - (r - l) * k) / 2 - l * k; oy = (Vh - (b - t) * k) / 2 - t * k;
      cv.width = Math.round(Vw * dpr); cv.height = Math.round(Vh * dpr);
    };
    const cssFilter = () => `brightness(${st.br}%) contrast(${st.ct}%) saturate(${st.sa}%)${st.gs ? ` grayscale(${st.gs}%)` : ''}${st.sp ? ` sepia(${st.sp}%)` : ''}`;
    const adjOn = () => st.br !== 100 || st.ct !== 100 || st.sa !== 100 || st.gs || st.sp;
    const fmtEff = () => (st.fmt !== 'auto' ? st.fmt : (o.png || st.fit === 'contain' ? 'png' : 'jpeg'));
    const fillEff = () => (st.bg === 'white' ? '#ffffff' : st.bg === 'black' ? '#000000' : st.bg === 'custom' ? st.bgc : (fmtEff() === 'jpeg' ? '#ffffff' : null));
    const outDims = () => {
      let ow = st.size === 'small' ? Math.round(o.outW * 0.6) : st.size === 'large' ? Math.min(2400, Math.round(o.outW * 1.5)) : st.size === 'src' ? Math.min(2400, Math.round(st.w)) : o.outW;
      ow = Math.max(16, ow); let oh = Math.max(1, Math.round(ow * st.h / st.w)); const px = ow * oh;
      if (px > 6e6) { const f = Math.sqrt(6e6 / px); ow = Math.max(16, Math.round(ow * f)); oh = Math.max(1, Math.round(oh * f)); }
      return { ow, oh };
    };
    const pixelAdjust = (g, w, h) => {
      const id = g.getImageData(0, 0, w, h), d = id.data, b = st.br / 100, c = st.ct / 100, s = st.sa / 100, gsv = st.gs / 100, sp = st.sp / 100;
      for (let i = 0; i < d.length; i += 4) {
        if (!d[i + 3]) continue; let r = d[i] / 255 * b, g2 = d[i + 1] / 255 * b, bl = d[i + 2] / 255 * b;
        r = (r - 0.5) * c + 0.5; g2 = (g2 - 0.5) * c + 0.5; bl = (bl - 0.5) * c + 0.5;
        let L = 0.2126 * r + 0.7152 * g2 + 0.0722 * bl; r = L + (r - L) * s; g2 = L + (g2 - L) * s; bl = L + (bl - L) * s;
        if (gsv) { L = 0.2126 * r + 0.7152 * g2 + 0.0722 * bl; r += (L - r) * gsv; g2 += (L - g2) * gsv; bl += (L - bl) * gsv; }
        if (sp) { const sr = 0.393 * r + 0.769 * g2 + 0.189 * bl, sg = 0.349 * r + 0.686 * g2 + 0.168 * bl, sb = 0.272 * r + 0.534 * g2 + 0.131 * bl; r += (sr - r) * sp; g2 += (sg - g2) * sp; bl += (sb - bl) * sp; }
        d[i] = clamp(r, 0, 1) * 255; d[i + 1] = clamp(g2, 0, 1) * 255; d[i + 2] = clamp(bl, 0, 1) * 255;
      }
      g.putImageData(id, 0, 0);
    };
    const renderOut = (ow, oh, fill) => {
      const out = document.createElement('canvas'); out.width = ow; out.height = oh; const g = out.getContext('2d');
      if (fill) { g.fillStyle = fill; g.fillRect(0, 0, ow, oh); }
      const tc = document.createElement('canvas'); tc.width = ow; tc.height = oh; const t = tc.getContext('2d'), kk = ow / st.w, nat = 'filter' in t;
      t.imageSmoothingQuality = 'high'; if (adjOn() && nat) t.filter = cssFilter();
      t.setTransform(kk, 0, 0, kk, -st.x * kk, -st.y * kk); t.translate(OW / 2, OH / 2); t.rotate(st.ang * DEG); t.drawImage(OC, -OW / 2, -OH / 2);
      if (adjOn() && !nat) { t.setTransform(1, 0, 0, 1, 0, 0); pixelAdjust(t, ow, oh); }
      g.drawImage(tc, 0, 0); return out;
    };
    const encode = (c) => { const f = fmtEff(), mime = f === 'png' ? 'image/png' : f === 'webp' ? 'image/webp' : 'image/jpeg'; let url = c.toDataURL(mime, st.qual / 100); if (f === 'webp' && !url.startsWith('data:image/webp')) url = c.toDataURL('image/jpeg', st.qual / 100); if (!validImgURL(url)) url = c.toDataURL('image/jpeg', st.qual / 100); if (!validImgURL(url)) throw new Error('canvas'); return url; };

    /* ---------- painting ---------- */
    let raf = 0, estT = 0;
    const paint = () => {
      if (!Vw) fitView(); if (!Vw) return;
      const g = cv.getContext('2d'); g.setTransform(1, 0, 0, 1, 0, 0); g.clearRect(0, 0, cv.width, cv.height);
      g.setTransform(dpr * k, 0, 0, dpr * k, dpr * ox, dpr * oy); g.translate(OW / 2, OH / 2); g.rotate(st.ang * DEG); g.imageSmoothingQuality = 'high'; g.drawImage(OC, -OW / 2, -OH / 2);
      cv.style.filter = compare || !adjOn() ? 'none' : cssFilter();
      box.style.left = ox + st.x * k + 'px'; box.style.top = oy + st.y * k + 'px'; box.style.width = st.w * k + 'px'; box.style.height = st.h * k + 'px'; box.dataset.grid = st.grid;
      $('.crx-dim').textContent = `${fa(st.w)} × ${fa(st.h)}`;
      const { ow, oh } = outDims(), sc = Math.min(200 / st.w, 120 / st.h), pvw = Math.max(24, Math.round(st.w * sc)), pvh = Math.max(24, Math.round(st.h * sc));
      pv.style.width = pvw + 'px'; pv.style.height = pvh + 'px'; pv.width = Math.round(pvw * dpr); pv.height = Math.round(pvh * dpr);
      const p = pv.getContext('2d'), kk = pv.width / st.w; p.imageSmoothingQuality = 'high'; p.setTransform(kk, 0, 0, kk, -st.x * kk, -st.y * kk); p.translate(OW / 2, OH / 2); p.rotate(st.ang * DEG); p.drawImage(OC, -OW / 2, -OH / 2);
      pv.style.filter = compare || !adjOn() ? 'none' : cssFilter(); pv.style.backgroundColor = fillEff() || '';
      if (GAL) {
        const RW = 480, RH = Math.max(1, Math.round(RW * st.h / st.w)), out = renderOut(RW, RH, fillEff()), r = st.w / st.h, notes = [];
        $$$('.crx-gpc').forEach((c) => {
          const mode = c.dataset.gp, ar = mode === 'lb' ? 16 / 9 : +c.dataset.ar, cw = 480, ch = Math.round(cw / ar);
          c.width = cw; c.height = ch; const g = c.getContext('2d'); g.imageSmoothingQuality = 'high';
          g.fillStyle = mode === 'lb' ? '#050a14' : '#000'; g.fillRect(0, 0, cw, ch);
          const s = mode === 'lb' ? Math.min(cw * 0.94 / RW, ch * 0.94 / RH) : Math.max(cw / RW, ch / RH);
          g.drawImage(out, (cw - RW * s) / 2, (ch - RH * s) / 2, RW * s, RH * s);
          if (mode !== 'lb') {
            const nm = mode === 'wide' ? 'کارت بزرگ' : 'کارت معمولی';
            if (r > ar * 1.01) notes.push(`${nm}: حدود ${fa((1 - ar / r) * 100)}٪ از چپ و راست عکس بریده می‌شود.`);
            else if (r < ar / 1.01) notes.push(`${nm}: حدود ${fa((1 - r / ar) * 100)}٪ از بالا و پایین عکس بریده می‌شود.`);
            else notes.push(`${nm}: چیزی بریده نمی‌شود ✓`);
          }
        });
        $('[data-gp-note]').textContent = notes.join('\n') + '\nبرای نمایش کامل در کارت، نسبت کادر را با نسبت کارت یکی کنید (۴:۳ برای کارت معمولی، ۸:۳ برای کارت بزرگ از بخش «سفارشی»). هنگام کلیک، همیشه کل کادر نمایش داده می‌شود.';
      }
      const q = st.w / ow, ql = q >= 1 ? 'کیفیت عالی' : q >= 0.7 ? 'کیفیت خوب' : 'بزرگ‌شده از وضوح کمتر';
      $('[data-info]').textContent = `${fa(ow)} × ${fa(oh)} پیکسل · ${ql}`;
    };
    const redraw = () => { if (raf) return; raf = requestAnimationFrame(() => { raf = 0; if (m.isConnected) paint(); }); };
    const estimate = () => {
      clearTimeout(estT); const el = $('[data-est]'); if (tab !== 'out') return; el.textContent = 'در حال برآورد حجم…';
      estT = setTimeout(() => { if (!m.isConnected) return; try { const { ow, oh } = outDims(), u = encode(renderOut(ow, oh, fillEff())); el.textContent = `حجم تقریبی فایل خروجی: ${A.toFa(Math.max(1, Math.round(u.length * 0.75 / 1024)))} کیلوبایت`; } catch (e) { el.textContent = ''; } }, 450);
    };

    /* ---------- UI sync ---------- */
    const setOn = (sel, attr, val) => $$$(sel).forEach((b) => b.classList.toggle('on', String(b.getAttribute(attr)) === String(val)));
    const sync = () => {
      const r = st.ratio;
      $$$('[data-r]').forEach((b) => { const v = b.dataset.r; let on = false; if (v === '0') on = !r; else if (v === 'orig') on = !!r && Math.abs(r - OW / OH) < 0.003; else if (v[0] === 's') on = !!r && Math.abs(r - sugg[+v.slice(1)].r) < 0.003; else on = !!r && Math.abs(r - +v) < 0.003; b.classList.toggle('on', on); });
      setOn('[data-fit]', 'data-fit', st.fit); setOn('[data-g]', 'data-g', st.grid); setOn('[data-sz]', 'data-sz', st.size); setOn('[data-f]', 'data-f', st.fmt); setOn('[data-bg]', 'data-bg', st.bg);
      $$$('[data-tab]').forEach((b) => b.classList.toggle('on', b.dataset.tab === tab)); $$$('[data-pane]').forEach((p) => { p.hidden = p.dataset.pane !== tab; });
      const vals = { z: zoomVal(), ang: st.ang, br: st.br, ct: st.ct, sa: st.sa, gs: st.gs, sp: st.sp, qual: st.qual };
      $$$('[data-s]').forEach((i) => { const v = vals[i.dataset.s]; i.value = v; const out = $(`[data-o="${i.dataset.s}"]`); if (out) out.textContent = i.dataset.s === 'z' ? A.toFa((+v).toFixed(2)) + '×' : i.dataset.s === 'ang' ? A.toFa((+v).toFixed(1)) + '°' : A.toFa(Math.round(+v)) + '٪'; });
      const nv = { x: st.x, y: st.y, w: st.w, h: st.h }; $$$('[data-n]').forEach((i) => { if (document.activeElement !== i) i.value = Math.round(nv[i.dataset.n]); });
      $('[data-qrow]').hidden = fmtEff() === 'png'; $('[data-bgc]').hidden = st.bg !== 'custom'; $('[data-bgc]').value = st.bgc;
      $('[data-k="undo"]').disabled = hi <= 0; $('[data-k="redo"]').disabled = hi >= hist.length - 1;
    };
    const commit = () => { const s = JSON.stringify(st); if (hist[hi] === s) return; hist = hist.slice(0, hi + 1); hist.push(s); if (hist.length > 80) hist.shift(); hi = hist.length - 1; sync(); };
    const restore = (s) => { const prev = st.q + '|' + st.fx + '|' + st.fy; Object.assign(st, JSON.parse(s)); if (prev !== st.q + '|' + st.fx + '|' + st.fy) buildO(); fitView(); sync(); paint(); estimate(); };
    const undo = () => { if (hi > 0) { hi--; restore(hist[hi]); } };
    const redo = () => { if (hi < hist.length - 1) { hi++; restore(hist[hi]); } };
    const refresh = (full) => { if (full) fitView(); sync(); redraw(); estimate(); };

    /* ---------- actions ---------- */
    const rotate = (dir) => {
      const { x, y, w, h } = st, oldW = OW, oldH = OH, z0 = zoomVal();
      if (dir > 0) { st.x = oldH - (y + h); st.y = x; } else { st.x = y; st.y = oldW - (x + w); }
      st.w = h; st.h = w; st.q = (st.q + (dir > 0 ? 1 : 3)) % 4; buildO();
      if (st.ratio) { const cx = st.x + st.w / 2, cy = st.y + st.h / 2; st.w = baseW(st.ratio) / z0; st.h = st.w / st.ratio; st.x = cx - st.w / 2; st.y = cy - st.h / 2; } /* keep the zoom level, restore the locked ratio */
      clampRect();
    };
    const flip = (ax) => { if (ax === 'x') { st.fx ^= 1; st.x = OW - (st.x + st.w); } else { st.fy ^= 1; st.y = OH - (st.y + st.h); } st.ang = -st.ang; buildO(); clampRect(); };
    const place = (a) => {
      const hz = a.includes('l') ? 'l' : a.includes('r') ? 'r' : 'c', vt = a.includes('t') ? 't' : a.includes('b') ? 'b' : 'c';
      if (st.fit === 'contain') { st.x = hz === 'l' ? 0 : hz === 'r' ? OW - st.w : (OW - st.w) / 2; st.y = vt === 't' ? 0 : vt === 'b' ? OH - st.h : (OH - st.h) / 2; }
      else { const cx = hz === 'l' ? -1e7 : hz === 'r' ? 1e7 : OW / 2, cy = vt === 't' ? -1e7 : vt === 'b' ? 1e7 : OH / 2; st.x = cx - st.w / 2; st.y = cy - st.h / 2; }
      clampRect();
    };
    const resetAll = () => { Object.assign(st, { q: 0, ang: 0, fx: 0, fy: 0, ratio: sugg[0].r, fit: o.fit || 'cover', br: 100, ct: 100, sa: 100, gs: 0, sp: 0, bg: 'auto', size: 'std', fmt: 'auto', qual: 88, grid: 'thirds' }); buildO(); initRect(); };

    /* ---------- pointer interaction on the stage ---------- */
    const pts = new Map(); let drag = null, pd = 0, pz = 1, pinched = false;
    const dist = () => { const [a, b] = [...pts.values()]; return Math.hypot(a.x - b.x, a.y - b.y); };
    const lerpR = (a, b, t) => ({ x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t, w: a.w + (b.w - a.w) * t, h: a.h + (b.h - a.h) * t });
    const resizeRect = (s0, hd, dx, dy) => {
      const mn = MINW(); let L = s0.x, T = s0.y, R = s0.x + s0.w, B = s0.y + s0.h; const r = st.ratio;
      const hl = hd.includes('l'), hr = hd.includes('r'), ht = hd.includes('t'), hb = hd.includes('b'), corner = (hl || hr) && (ht || hb);
      if (hl) L += dx; if (hr) R += dx; if (ht) T += dy; if (hb) B += dy;
      if (!r) { if (R - L < mn) { if (hl) L = R - mn; else R = L + mn; } if (B - T < mn) { if (ht) T = B - mn; else B = T + mn; } return { x: L, y: T, w: R - L, h: B - T }; }
      let w;
      if (corner) { const sc = Math.max((R - L) / s0.w, (B - T) / s0.h); w = Math.max(mn, s0.w * sc); const h2 = w / r; return { x: hl ? s0.x + s0.w - w : s0.x, y: ht ? s0.y + s0.h - h2 : s0.y, w, h: h2 }; }
      if (ht || hb) { const h2 = Math.max(mn, B - T); w = h2 * r; return { x: s0.x + s0.w / 2 - w / 2, y: ht ? s0.y + s0.h - h2 : s0.y, w, h: h2 }; }
      w = Math.max(mn, R - L); const h2 = w / r; return { x: hl ? s0.x + s0.w - w : s0.x, y: s0.y + s0.h / 2 - h2 / 2, w, h: h2 };
    };
    stage.addEventListener('pointerdown', (e) => {
      if (e.button > 0) return; try { stage.setPointerCapture(e.pointerId); } catch (er) {} pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pts.size === 2) { drag = null; pd = dist(); pz = zoomVal(); pinched = true; return; }
      const hn = e.target.closest && e.target.closest('.crx-h'); drag = { mode: hn ? hn.dataset.h : 'move', sx: e.clientX, sy: e.clientY, s0: { x: st.x, y: st.y, w: st.w, h: st.h }, last: { x: st.x, y: st.y, w: st.w, h: st.h } };
      stage.focus({ preventScroll: true });
    });
    stage.addEventListener('pointermove', (e) => {
      if (!pts.has(e.pointerId)) return; pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pts.size === 2 && pd) { setZoom(pz * dist() / pd); refresh(false); return; }
      if (!drag) return; const dx = (e.clientX - drag.sx) / k, dy = (e.clientY - drag.sy) / k;
      if (drag.mode === 'move') { st.x = drag.s0.x + dx; st.y = drag.s0.y + dy; st.w = drag.s0.w; st.h = drag.s0.h; clampRect(); }
      else { const cand = resizeRect(drag.s0, drag.mode, dx, dy); let rr = cand; if (!valid(cand)) { let lo = 0, hi2 = 1; for (let i = 0; i < 16; i++) { const mid = (lo + hi2) / 2; if (valid(lerpR(drag.last, cand, mid))) lo = mid; else hi2 = mid; } rr = lerpR(drag.last, cand, lo); } drag.last = rr; st.x = rr.x; st.y = rr.y; st.w = rr.w; st.h = rr.h; }
      refresh(false);
    });
    const up = (e) => { pts.delete(e.pointerId); if (pts.size < 2) pd = 0; if (!pts.size) { const was = drag || pinched; drag = null; pinched = false; if (was) { refresh(true); commit(); } } };
    stage.addEventListener('pointerup', up); stage.addEventListener('pointercancel', up);
    stage.addEventListener('wheel', (e) => { e.preventDefault(); setZoom(zoomVal() * (e.deltaY < 0 ? 1.08 : 1 / 1.08)); refresh(false); clearTimeout(stage._wt); stage._wt = setTimeout(commit, 250); }, { passive: false });
    stage.addEventListener('keydown', (e) => {
      const kk = e.key, step = (e.shiftKey ? 10 : 1) / k; let used = true;
      if ((e.ctrlKey || e.metaKey) && (kk === 'z' || kk === 'Z')) { if (e.shiftKey) redo(); else undo(); e.preventDefault(); e.stopPropagation(); return; }
      if ((e.ctrlKey || e.metaKey) && (kk === 'y' || kk === 'Y')) { redo(); e.preventDefault(); e.stopPropagation(); return; }
      if (kk === 'ArrowLeft') st.x -= step; else if (kk === 'ArrowRight') st.x += step; else if (kk === 'ArrowUp') st.y -= step; else if (kk === 'ArrowDown') st.y += step;
      else if (kk === '+' || kk === '=') setZoom(zoomVal() * 1.1); else if (kk === '-') setZoom(zoomVal() / 1.1);
      else if (kk === 'r' || kk === 'R') rotate(e.shiftKey ? -1 : 1); else used = false;
      if (!used) return; e.preventDefault(); clampRect(); refresh(kk === 'r' || kk === 'R'); clearTimeout(stage._kt); stage._kt = setTimeout(commit, 300);
    });
    const onResize = () => { if (!m.isConnected) return window.removeEventListener('resize', onResize); fitView(); paint(); };
    window.addEventListener('resize', onResize);

    /* ---------- panel events ---------- */
    m.addEventListener('input', (e) => {
      const t = e.target, s = t.dataset && t.dataset.s;
      if (s) { const v = +t.value; if (s === 'z') setZoom(v); else if (s === 'ang') { keepZoom(() => { st.ang = v; }); fitView(); } else st[s] = v; sync(); redraw(); if (s === 'qual' || s === 'ang') estimate(); }
      else if (t.dataset && t.dataset.bgc !== undefined) { st.bgc = t.value; redraw(); estimate(); }
    });
    m.addEventListener('change', (e) => {
      const t = e.target;
      if (t.dataset && t.dataset.s) { commit(); return; }
      if (t.dataset && t.dataset.bgc !== undefined) { commit(); return; }
      const n = t.dataset && t.dataset.n;
      if (n) { const v = Math.max(0, +t.value || 0); const cx = st.x + st.w / 2, cy = st.y + st.h / 2;
        if (n === 'x') st.x = v; else if (n === 'y') st.y = v; else if (n === 'w') { st.w = Math.max(MINW(), v); if (st.ratio) st.h = st.w / st.ratio; st.x = cx - st.w / 2; st.y = cy - st.h / 2; } else if (n === 'h') { st.h = Math.max(MINW(), v); if (st.ratio) st.w = st.h * st.ratio; st.x = cx - st.w / 2; st.y = cy - st.h / 2; }
        clampRect(); refresh(true); commit(); }
    });
    m.addEventListener('keydown', (e) => { if (e.target.dataset && e.target.dataset.n && e.key === 'Enter') { e.preventDefault(); e.target.blur(); } else if ((e.ctrlKey || e.metaKey) && /^[zy]$/i.test(e.key) && !/INPUT|TEXTAREA/.test(e.target.tagName)) { e.preventDefault(); if (e.key.toLowerCase() === 'y' || e.shiftKey) redo(); else undo(); } });
    const cmpOn = (v) => { compare = v; paint(); };
    const cmpBtn = $('[data-k="cmp"]'); cmpBtn.addEventListener('pointerdown', (e) => { e.preventDefault(); cmpOn(true); }); ['pointerup', 'pointerleave', 'pointercancel'].forEach((ev) => cmpBtn.addEventListener(ev, () => compare && cmpOn(false)));
    m.addEventListener('click', (e) => {
      const g = (s) => e.target.closest(s); let b;
      if ((b = g('[data-tab]'))) { tab = b.dataset.tab; sync(); estimate(); return; }
      if ((b = g('[data-r]'))) { const v = b.dataset.r; const r = v === '0' ? 0 : v === 'orig' ? OW / OH : v[0] === 's' ? sugg[+v.slice(1)].r : +v; setRatio(r); refresh(true); commit(); return; }
      if ((b = g('[data-fit]'))) { keepZoom(() => { st.fit = b.dataset.fit; }); refresh(true); commit(); return; }
      if ((b = g('[data-g]'))) { st.grid = b.dataset.g; refresh(false); commit(); return; }
      if ((b = g('[data-sz]'))) { st.size = b.dataset.sz; refresh(false); commit(); return; }
      if ((b = g('[data-f]'))) { st.fmt = b.dataset.f; refresh(false); commit(); return; }
      if ((b = g('[data-bg]'))) { st.bg = b.dataset.bg; refresh(false); commit(); return; }
      if ((b = g('[data-flt]'))) { const f = FILTERS[+b.dataset.flt]; [st.br, st.ct, st.sa, st.gs, st.sp] = f.slice(1); refresh(false); commit(); return; }
      if ((b = g('[data-al]'))) { place(b.dataset.al); refresh(true); commit(); return; }
      if ((b = g('[data-ang]'))) { const v = +b.dataset.ang; keepZoom(() => { st.ang = v === 0 ? 0 : clamp(Math.round((st.ang + v) * 10) / 10, -45, 45); }); refresh(true); commit(); return; }
      if ((b = g('[data-z]'))) { setZoom(zoomVal() * (b.dataset.z === 'in' ? 1.2 : 1 / 1.2)); refresh(false); commit(); return; }
      b = g('[data-k]'); if (!b) return; const a = b.dataset.k;
      if (a === 'undo') undo(); else if (a === 'redo') redo();
      else if (a === 'rotl') { rotate(-1); refresh(true); commit(); } else if (a === 'rotr') { rotate(1); refresh(true); commit(); }
      else if (a === 'flipx') { flip('x'); refresh(true); commit(); } else if (a === 'flipy') { flip('y'); refresh(true); commit(); }
      else if (a === 'fitall') { setZoom(1); st.x = (OW - st.w) / 2; st.y = (OH - st.h) / 2; clampRect(); refresh(true); commit(); }
      else if (a === 'adj-reset') { st.br = st.ct = st.sa = 100; st.gs = st.sp = 0; refresh(false); commit(); }
      else if (a === 'cr-apply') { const A1 = +$('[data-cr="a"]').value, B1 = +$('[data-cr="b"]').value; if (!(A1 > 0 && B1 > 0)) return toast('نسبت نامعتبر است.', true); setRatio(A1 / B1); refresh(true); commit(); }
      else if (a === 'cr-swap') { const r = st.ratio || st.w / st.h; setRatio(1 / r); refresh(true); commit(); }
      else if (a === 'reset') { resetAll(); hist = []; hi = -1; refresh(true); commit(); }
      else if (a === 'cancel') { window.removeEventListener('resize', onResize); closeModal(); if (o.onCancel) o.onCancel(); }
      else if (a === 'ok') {
        const { ow, oh } = outDims(); let url;
        try { url = encode(renderOut(ow, oh, fillEff())); } catch (er) { return toast('ذخیره‌ی تصویر انجام نشد.', true); }
        const saved = { v: 2, nx: st.x / OW, ny: st.y / OH, nw: st.w / OW, nh: st.h / OH }; ['q', 'ang', 'fx', 'fy', 'ratio', 'fit', 'br', 'ct', 'sa', 'gs', 'sp', 'bg', 'bgc', 'size', 'fmt', 'qual', 'grid'].forEach((kk) => { saved[kk] = st[kk]; });
        window.removeEventListener('resize', onResize); closeModal(); o.onSave(url, saved);
      }
    });
    fitView(); sync(); paint(); commit(); setTimeout(() => { const dlg = m.querySelector('.modal'); if (dlg) dlg.scrollTop = 0; if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur(); stage.focus({ preventScroll: true }); }, 70);
  };
  im.src = o.src;
}

function previewConfirm(url, ok) {
  const m = modal(`${mh('پیش‌نمایش لوگو')}<div class="cl-card" style="margin:16px auto 0;max-width:260px;cursor:default"><span class="cl-logo"><img src="${escAttr(url)}" alt=""></span></div><p class="desc">لوگو بدون برش و با حفظ نسبت ابعاد، به همین شکل در کارت مشتری نمایش داده می‌شود.</p><div class="mrow"><button type="button" class="btn btn-navy" data-k="ok">تأیید و ذخیره</button><button type="button" class="btn btn-soft" data-k="no">انصراف</button></div>`);
  m.addEventListener('click', (e) => { const b = e.target.closest('[data-k]'); if (!b) return; if (b.dataset.k === 'ok') ok(); closeModal(); });
}
let logoDraft = null; /* unsaved logo-editor state; survives the trip to the cropper and is only written to the site data by "ذخیره" */
function openLogoEditor(resume) {
  const c = D().company, dr = resume ? logoDraft : null; logoDraft = null;
  let url = dr ? dr.url : (c.logoIcon || ''), size = dr ? dr.size : (+c.logoSize || 44), backed = dr ? dr.backed : c.logoBacked !== false, oy = dr ? dr.oy : (+c.logoOffsetY || 0);
  let orig = dr ? dr.orig : (c.logoIcon_orig || ''), crop = dr ? dr.crop : (c.logoIcon_crop || null);
  const m = modal(`${mh('لوگوی شرکت (هدر و فوتر)')}<p class="desc">لوگو با حفظ نسبت ابعاد نمایش داده می‌شود. بهتر است PNG یا SVG با پس‌زمینه‌ی شفاف باشد.</p>
    <div class="lg-prev"><span class="brand" style="padding:0"><span data-p></span><span class="t">${esc(c.name)}</span></span></div>
    <div class="srow"><div><div class="t">اندازه (ارتفاع لوگو)</div></div><input type="range" class="slider" min="28" max="56" value="${size}" data-k="size"></div>
    <div class="srow"><div><div class="t">تراز عمودی نسبت به نام شرکت</div><div class="d">برای هم‌ترازی دقیق لوگو با متن (پیکسل)</div></div><input type="range" class="slider" min="-10" max="10" step="1" value="${oy}" data-k="oy" aria-label="تراز عمودی لوگو"></div>
    <div class="srow"><div><div class="t">زمینه‌ی روشن در تم تیره</div><div class="d">برای لوگوهای تیره که روی زمینه‌ی تیره دیده نمی‌شوند</div></div><button type="button" class="switch ${backed ? 'on' : ''}" data-k="back" aria-label="زمینه‌ی روشن در تم تیره"></button></div>
    <div class="mrow"><button type="button" class="btn btn-soft" data-k="pick">${icon('upload')} انتخاب لوگو</button><button type="button" class="btn btn-soft" data-k="recrop">${icon('sliders')} تنظیم کادر لوگو</button><button type="button" class="btn btn-soft" data-k="clear">حذف و بازگشت به آیکون</button></div>
    <div class="mrow"><button type="button" class="btn btn-navy" data-k="save">ذخیره</button><button type="button" class="btn btn-soft" data-k="cancel">انصراف</button></div>`);
  const paint = () => { const p = m.querySelector('[data-p]'); p.className = 'mark' + (url ? ' has-logo' + (backed ? ' backed' : '') : ''); p.style.setProperty('--logo-h', size + 'px'); p.style.setProperty('--logo-y', oy + 'px'); p.innerHTML = url ? `<img src="${escAttr(url)}" alt="">` : icon('zap'); };
  paint();
  const cropLogo = (src, cr) => {
    logoDraft = { url, size, backed, oy, orig, crop };
    const cfg = cropCfg('company.logoIcon');
    openCropper({ path: 'company.logoIcon', free: cfg.free, fit: cfg.fit, title: cfg.title, src, ratios: cfg.ratios, crop: cr, outW: cfg.outW, png: cfg.png || src.startsWith('data:image/png'),
      onCancel: () => openLogoEditor(true),
      onSave: (nu, nc) => { logoDraft = { url: nu, size, backed, oy, orig: src, crop: nc }; setTimeout(() => openLogoEditor(true), 0); } });
  };
  m.addEventListener('input', (e) => { if (e.target.dataset.k === 'size') { size = +e.target.value; paint(); } if (e.target.dataset.k === 'oy') { oy = +e.target.value; paint(); } });
  m.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-k]'); if (!b || b.tagName === 'INPUT') return; const k = b.dataset.k;
    if (k === 'back') { backed = !backed; b.classList.toggle('on', backed); paint(); }
    else if (k === 'pick') { const f = (await pickFiles('image/*'))[0]; if (!f) return; const vec = /svg|gif/.test(f.type), u = await processImage(f, 1200, true); if (!u) return toast('فایل تصویر معتبر نیست.', true); if (vec) { url = u; orig = ''; crop = null; paint(); return; }
      cropLogo(u, null); }
    else if (k === 'recrop') { if (!url || /^data:image\/(svg|gif)/.test(url)) return toast('این لوگو قابل برش نیست.', true); cropLogo(orig || url, orig ? crop : null); }
    else if (k === 'clear') { url = ''; orig = ''; crop = null; paint(); }
    else if (k === 'cancel') closeModal();
    else if (k === 'save') { Object.assign(D().company, { logoIcon: url, logoSize: size, logoBacked: backed, logoOffsetY: oy, logoIcon_orig: orig, logoIcon_crop: crop }); A.persist(); closeModal(); A.render(true); toast('لوگوی شرکت ذخیره شد.'); }
  });
}
/* ---------- portfolio categories ---------- */
document.addEventListener('change', (e) => {
  const sel = e.target.closest && e.target.closest('[data-catsel]'); if (!sel) return;
  A.set(sel.dataset.catsel, sel.value); A.persist(); A.render(true);
});
function openCategories() {
  const d = D(); const rows = A.allCats().map((n) => ({ orig: n, name: n })); const origs = rows.map((r) => r.orig);
  const count = (n) => d.portfolio.filter((p) => (p.category || '').trim() === n).length;
  const m = modal(`${mh('مدیریت دسته‌بندی‌ها')}<p class="desc">نام هر دسته را تغییر دهید، دسته‌ی جدید اضافه کنید یا دسته‌ای را حذف کنید. حذف دسته، پروژه‌ها را پاک نمی‌کند؛ فقط آن‌ها را «بدون دسته‌بندی» می‌کند.</p><div data-list></div><div class="cm-row"><input type="text" data-new placeholder="نام دسته‌ی جدید"><button type="button" class="btn btn-soft sm" data-k="add">${icon('plus')} افزودن</button></div><div class="mrow"><button type="button" class="btn btn-navy" data-k="save">ذخیره</button><button type="button" class="btn btn-soft" data-k="cancel">انصراف</button></div>`);
  const list = m.querySelector('[data-list]');
  const draw = () => { list.innerHTML = rows.length ? rows.map((r, i) => `<div class="cm-row"><input type="text" data-i="${i}" value="${escAttr(r.name)}" aria-label="نام دسته"><small>${r.orig ? A.toFa(count(r.orig)) + ' پروژه' : 'جدید'}</small><button type="button" class="cl-ic del" data-del="${i}" title="حذف دسته" aria-label="حذف دسته">${icon('trash')}</button></div>`).join('') : '<p class="hintbox">هنوز دسته‌ای وجود ندارد.</p>'; };
  draw();
  list.addEventListener('input', (e) => { const i = e.target.dataset.i; if (i != null) rows[+i].name = e.target.value; });
  const add = () => { const inp = m.querySelector('[data-new]'), v = inp.value.trim(); if (!v) return; rows.push({ orig: null, name: v }); inp.value = ''; draw(); };
  m.querySelector('[data-new]').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } });
  m.addEventListener('click', (e) => {
    const del = e.target.closest('[data-del]'); if (del) { rows.splice(+del.dataset.del, 1); draw(); return; }
    const b = e.target.closest('[data-k]'); if (!b) return;
    if (b.dataset.k === 'add') add();
    else if (b.dataset.k === 'cancel') closeModal();
    else if (b.dataset.k === 'save') {
      const map = {}; origs.forEach((o) => { map[o] = ''; });
      rows.forEach((r) => { if (r.orig) map[r.orig] = r.name.trim(); });
      d.portfolio.forEach((p) => { const c = (p.category || '').trim(); if (c in map) p.category = map[c]; });
      const names = []; rows.forEach((r) => { const n = r.name.trim(); if (n && !names.includes(n)) names.push(n); });
      d.categoryList = names; A.persist(); closeModal(); A.render(true); toast('دسته‌بندی‌ها ذخیره شد.');
    }
  });
}
/* ---------- list item factories ---------- */
function newItem(kind) {
  switch (kind) {
    case 'stat': return { id: uid(), value: '۱۰', suffix: '+', label: 'عنوان آمار' };
    case 'highlight': return { id: uid(), text: 'ویژگی جدید' };
    case 'service': return { id: uid(), title: 'خدمت جدید', description: 'توضیح کوتاه این خدمت را اینجا بنویسید.', icon: 'builtin:zap' };
    case 'step': return { id: uid(), title: 'مرحله جدید', description: 'توضیح این مرحله.' };
    case 'project': return { id: uid(), title: 'پروژه جدید', category: 'دسته‌بندی', description: 'توضیح کوتاه پروژه و نتیجه‌ای که برای کارفرما ایجاد شد.', coverImage: '', media: [], details: '', facts: [] };
    case 'client': return { id: uid(), name: 'مشتری جدید', logo: '' };
    case 'social': return { id: uid(), label: 'شبکه اجتماعی', url: '', icon: '' };
    case 'fact': return { id: uid(), k: 'عنوان', v: 'مقدار' };
    default: return { id: uid() };
  }
}

/* ---------- inline text editing ---------- */
let editing = null; // {el, path, orig}
let tbar = null;
/* ---------- color tools for the text toolbar ---------- */
const RECENT_KEY = 'site_recent_colors';
const COLOR_PALETTE = ['#FFFFFF', '#F1F5F9', '#CBD5E1', '#64748B', '#1E293B', '#000000', '#DC2626', '#EA580C', '#F59E0B', '#EAB308', '#16A34A', '#0D9488', '#0891B2', '#2563EB', '#7C3AED', '#DB2777'];
const isHex = (s) => /^#[0-9a-f]{6}$/i.test(s || '');
const normHex = (s) => { s = String(s || '').trim().replace(/^#/, ''); if (/^[0-9a-f]{3}$/i.test(s)) s = s.split('').map((x) => x + x).join(''); return /^[0-9a-f]{6}$/i.test(s) ? '#' + s.toLowerCase() : null; };
const getRecent = () => { try { const a = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); return Array.isArray(a) ? a.filter(isHex).slice(0, 8) : []; } catch (e) { return []; } };
const pushRecent = (c) => { try { localStorage.setItem(RECENT_KEY, JSON.stringify([c, ...getRecent().filter((x) => x !== c)].slice(0, 8))); } catch (e) { /* ignore */ } };
function colorPopHtml(cur) {
  const th = D().theme || {};
  const sw = (c, extra = '') => `<button type="button" class="c${cur === c.toLowerCase() ? ' on' : ''}" data-c="${c.toLowerCase()}" style="--c:${c}" title="${c}" aria-label="${c}"${extra}></button>`;
  const site = [th.primary, th.accent, th.text].filter(isHex);
  const rec = getRecent();
  return `<h4>رنگ‌های سایت</h4><div class="crow">${site.map((c) => sw(c)).join('')}</div>
    <h4>پالت</h4><div class="crow">${COLOR_PALETTE.map((c) => sw(c)).join('')}</div>
    ${rec.length ? `<h4>اخیراً استفاده‌شده</h4><div class="crow">${rec.map((c) => sw(c)).join('')}</div>` : ''}
    <div class="hexrow"><label class="sw nat" title="انتخاب رنگ دلخواه"><input type="color" data-tb="native" value="${cur}"></label>
      <input type="text" class="hex" data-tb="hex" dir="ltr" maxlength="7" spellcheck="false" autocomplete="off" value="${cur}" aria-label="کد رنگ">
      <button type="button" class="dflt" data-tb="cdef" title="حذف رنگ سفارشی و بازگشت به رنگ پیش‌فرض">پیش‌فرض</button></div>`;
}
function showToolbar(el) {
  hideToolbar();
  const path = el.dataset.edit;
  const multi = el.dataset.multi === '1';
  const curColor = () => { const c = toHex(getComputedStyle(el).color); return isHex(c) ? c : '#000000'; };
  tbar = document.createElement('div'); tbar.className = 'tbar';
  tbar.innerHTML = `<button type="button" data-tb="dec" title="کوچک‌تر">A−</button><button type="button" data-tb="inc" title="بزرگ‌تر">A+</button><span class="sep"></span>
    <button type="button" class="cbtn" data-tb="colors" title="رنگ متن" aria-haspopup="true" aria-expanded="false"><i style="--c:${curColor()}"></i></button>
    <button type="button" data-tb="reset" title="بازگشت به حالت پیش‌فرض (اندازه و رنگ)">${icon('reset')}</button><span class="sep"></span>
    <button type="button" class="w" data-tb="done">${icon('check')} ذخیره</button><span class="hint">${multi ? 'Ctrl+Enter ذخیره · Esc انصراف' : 'Enter ذخیره · Esc انصراف'}</span>
    <div class="cpop" role="dialog" aria-label="انتخاب رنگ متن"></div>`;
  const pop = tbar.querySelector('.cpop'), cbtn = tbar.querySelector('.cbtn');
  const refresh = () => {
    const c = curColor();
    cbtn.firstElementChild.style.setProperty('--c', c);
    $$('.c', pop).forEach((b) => b.classList.toggle('on', b.dataset.c === c));
    const nat = pop.querySelector('[data-tb="native"]'); if (nat) nat.value = c;
    const hx = pop.querySelector('[data-tb="hex"]'); if (hx && document.activeElement !== hx) hx.value = c;
  };
  const applyColor = (c) => {
    const st = { ...(D().styles[path] || {}) };
    if (c) { st.color = c; el.style.color = c; } else { delete st.color; el.style.color = ''; }
    if (Object.keys(st).length) D().styles[path] = st; else delete D().styles[path];
    A.persist(); refresh();
  };
  const openPop = (open) => {
    if (open) {
      pop.innerHTML = colorPopHtml(curColor()); pop.style.left = '0px'; pop.classList.add('open');
      const r = pop.getBoundingClientRect(); if (r.right > innerWidth - 8) pop.style.left = (innerWidth - 8 - r.right) + 'px';
      const r2 = pop.getBoundingClientRect(); if (r2.left < 8) pop.style.left = (parseFloat(pop.style.left) + 8 - r2.left) + 'px';
    } else pop.classList.remove('open');
    cbtn.setAttribute('aria-expanded', open ? 'true' : 'false'); cbtn.classList.toggle('on', open);
  };
  /* keep focus (and the caret) inside the text while using buttons; real inputs may take focus */
  tbar.addEventListener('mousedown', (e) => { if (e.target.tagName !== 'INPUT') e.preventDefault(); });
  tbar.addEventListener('click', (e) => {
    const sb = e.target.closest('[data-c]'); if (sb) { applyColor(sb.dataset.c); pushRecent(sb.dataset.c); return; }
    const b = e.target.closest('[data-tb]'); if (!b) return;
    const k = b.dataset.tb; const st = D().styles[path] || {};
    if (k === 'inc' || k === 'dec') { const cur = st.size || parseFloat(getComputedStyle(el).fontSize); const nv = Math.max(10, Math.min(96, Math.round(cur + (k === 'inc' ? 2 : -2)))); D().styles[path] = { ...st, size: nv }; el.style.fontSize = nv + 'px'; A.persist(); }
    if (k === 'colors') openPop(!pop.classList.contains('open'));
    if (k === 'cdef') { applyColor(''); openPop(true); }
    if (k === 'reset') { delete D().styles[path]; el.style.fontSize = ''; el.style.color = ''; A.persist(); refresh(); if (pop.classList.contains('open')) openPop(true); }
    if (k === 'done') finishEdit();
  });
  tbar.addEventListener('input', (e) => {
    const k = e.target.dataset && e.target.dataset.tb;
    if (k === 'native') { applyColor(e.target.value); const hx = pop.querySelector('[data-tb="hex"]'); if (hx) hx.value = e.target.value; }
    if (k === 'hex') { const n = normHex(e.target.value); e.target.classList.toggle('bad', !!e.target.value && !n); if (n) applyColor(n); }
  });
  tbar.addEventListener('change', (e) => {
    const k = e.target.dataset && e.target.dataset.tb;
    if (k === 'native') pushRecent(e.target.value);
    if (k === 'hex') { const n = normHex(e.target.value); if (n) { pushRecent(n); e.target.value = n; } else e.target.value = curColor(); e.target.classList.remove('bad'); }
  });
  tbar.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT') {
      if (e.key === 'Enter') { e.preventDefault(); e.stopPropagation(); const n = normHex(e.target.value); if (e.target.dataset.tb === 'hex' && n) { applyColor(n); pushRecent(n); } el.focus(); }
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); openPop(false); el.focus(); }
    }
  });
  /* focus left the toolbar for somewhere other than the text → finish editing */
  tbar.addEventListener('focusout', (e) => {
    const n = e.relatedTarget; if (n && (tbar.contains(n) || n === el)) return;
    setTimeout(() => { if (editing && editing.el === el && document.activeElement !== el && !(tbar && tbar.contains(document.activeElement))) finishEdit(); }, 0);
  });
  document.body.appendChild(tbar);
  positionToolbar(el);
}
function positionToolbar(el) {
  if (!tbar || !el.isConnected) return;
  const r = el.getBoundingClientRect(); const w = tbar.offsetWidth, h = tbar.offsetHeight;
  let top = r.top - h - 8; if (top < 8) top = Math.min(innerHeight - h - 8, r.bottom + 8);
  let left = Math.min(Math.max(8, r.right - w), innerWidth - w - 8);
  tbar.style.top = top + 'px'; tbar.style.left = left + 'px';
  tbar.classList.toggle('up', top + h + 300 > innerHeight && top > 300);
}
function hideToolbar() { if (tbar) { tbar.remove(); tbar = null; } }
function toHex(rgb) { const m = String(rgb).match(/\d+/g); if (!m) return '#000000'; return '#' + m.slice(0, 3).map((n) => (+n).toString(16).padStart(2, '0')).join(''); }
window.addEventListener('scroll', () => { if (editing) positionToolbar(editing.el); }, { passive: true });
window.addEventListener('resize', () => { if (editing) positionToolbar(editing.el); });

document.addEventListener('focusin', (e) => {
  const el = e.target.closest && e.target.closest('[data-edit]'); if (!el || !S.edit) return;
  if (editing && editing.el === el) return; /* focus came back from the toolbar */
  editing = { el, path: el.dataset.edit, orig: el.innerText };
  showToolbar(el);
});
function finishEdit() {
  if (!editing) return; const el = editing.el;
  const path = el.dataset.edit;
  let v = el.innerText.replace(/ /g, ' ');
  v = el.dataset.multi === '1' ? v.replace(/\n{3,}/g, '\n\n').trim() : v.replace(/\s+/g, ' ').trim();
  const changed = v !== (A.get(path) ?? '');
  editing = null; hideToolbar();
  if (changed) { A.set(path, v); A.persist(); A.render(true); }
}
document.addEventListener('focusout', (e) => {
  const el = e.target.closest && e.target.closest('[data-edit]'); if (!el || !editing || editing.el !== el) return;
  const n = e.relatedTarget; if (n && tbar && tbar.contains(n)) return; /* moving into the toolbar / color picker */
  finishEdit();
});
document.addEventListener('keydown', (e) => { const le = e.target.closest && e.target.closest('[data-act="logo-edit"]'); if (le && S.edit && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); openLogoEditor(); } });
document.addEventListener('keydown', (e) => {
  const el = e.target.closest && e.target.closest('[data-edit]'); if (!el || !editing) return;
  const multi = el.dataset.multi === '1';
  if (e.key === 'Escape') { e.preventDefault(); el.innerText = editing.orig; el.blur(); return; }
  if (e.key === 'Enter' && (!multi || e.ctrlKey || e.metaKey)) { e.preventDefault(); el.blur(); }
});
document.addEventListener('paste', (e) => {
  const el = e.target.closest && e.target.closest('[data-edit]'); if (!el || !S.edit) return;
  e.preventDefault(); const t = (e.clipboardData || window.clipboardData).getData('text/plain'); document.execCommand('insertText', false, el.dataset.multi === '1' ? t : t.replace(/\s+/g, ' '));
});

/* custom text size/colour is keyed by path (…media.N.caption); keep it attached to its image when media are moved or removed */
function reindexMediaStyles(listPath, mapIdx) {
  if (!/\.media$/.test(listPath || '')) return; const st = A.get('styles'); if (!st) return;
  const re = new RegExp('^' + listPath.replace(/\./g, '\\.') + '\\.(\\d+)\\.(.+)$'), moved = [];
  Object.keys(st).forEach((k) => { const m = re.exec(k); if (m) { moved.push([m[1], m[2], st[k]]); delete st[k]; } });
  moved.forEach(([n, rest, v]) => { const ni = mapIdx(+n); if (ni != null) st[`${listPath}.${ni}.${rest}`] = v; });
}
/* ---------- lightbox ---------- */
function lightbox(src) {
  const lb = document.createElement('div'); lb.className = 'lightbox';
  lb.innerHTML = `<button type="button" class="x" aria-label="بستن">${icon('x')}</button><img src="${escAttr(src)}" alt="">`;
  lb.addEventListener('click', () => lb.remove()); document.body.appendChild(lb);
}

/* ---------- click delegation ---------- */
document.addEventListener('click', async (e) => {
  const a = e.target.closest('a');
  if (a && S.edit && e.target.closest('[data-edit]')) { e.preventDefault(); return; }
  if (a && !(S.edit && e.target.closest('[data-act="logo-edit"]')) && false /* brand / home links are handled by the page navigation in site.js */) { e.preventDefault(); window.scrollTo({ top: 0, behavior: 'smooth' }); return; }
  if (a && S.edit && a.closest('.rimg') && e.target.closest('.medc')) e.preventDefault();
  const btn = e.target.closest('[data-act]'); if (!btn) return;
  const act = btn.dataset.act, path = btn.dataset.path;
  const d = D();
  switch (act) {
    case 'login': openLogin(); break;
    case 'admin-exit': logout(); break;
    case 'modal-close': dismissModal(); break;
    /* admin bar */
    case 'ab-toggle': $('.admin-bar').classList.toggle('open'); break;
    case 'ab-edit': S.edit = !S.edit; try { sessionStorage.setItem('company_site_edit', S.edit ? '1' : '0'); } catch (x) { /* ignore */ } A.render(true); toast(S.edit ? 'حالت ویرایش فعال شد — روی هر متن، تصویر یا آیکون کلیک کنید.' : 'از حالت ویرایش خارج شدید.'); break;
    case 'logo-edit': e.preventDefault(); openLogoEditor(); break;
    case 'cat-manage': openCategories(); break;
    case 'ab-settings': openSettings(); break;
    case 'ab-fonts': openFonts(); break;
    case 'ab-scheme': openSchemePanel(); break;
    case 'ab-sections': openSections(); break;
    case 'ab-hover': openHoverFx(); break;
    case 'ab-backup': openBackup(); break;
    case 'ab-logout': logout(); break;
    /* editing actions */
    case 'img-pick': {
      e.preventDefault(); const files = await pickFiles('image/*'); if (!files[0]) return; const f = files[0];
      if (f.size > 15e6) return toast('حجم فایل بیشتر از ۱۵ مگابایت است.', true);
      const cfg = cropCfg(path), vec = /svg|gif/.test(f.type);
      const orig = await processImage(f, cfg && cfg.png ? 1200 : 1800, !!(cfg && cfg.png)); if (!orig) return toast(imageErrorMsg(f.name), true);
      if (!cfg || vec || /^data:image\/(svg|gif)/.test(orig)) { A.set(path, orig); A.set(path + '_orig', ''); A.set(path + '_crop', null); A.persist(); A.render(true); toast('تصویر ذخیره شد.'); break; }
      runCropper(path, orig, cfg, null); break; }
    case 'hero-fx': { e.preventDefault(); openHeroFx(); break; }
    case 'img-url': { e.preventDefault(); askUrl('لینک تصویر', A.get(path) || '', (u) => { A.set(path, u); A.persist(); A.render(true); }); break; }
    case 'img-crop': { e.preventDefault(); const cur = A.get(path) || '', orig = A.get(path + '_orig') || cur, cfg = cropCfg(path); if (!orig || !cfg) return; if (/^data:image\/(svg|gif)/.test(orig) || /\.(svg|gif)(\?|$)/i.test(orig)) return toast('تصویر SVG/GIF قابل برش نیست و به‌صورت اصلی نمایش داده می‌شود.', true); runCropper(path, orig, cfg, A.get(path + '_orig') ? A.get(path + '_crop') : null); break; }
    case 'img-clear': { e.preventDefault(); A.set(path, ''); A.set(path + '_orig', ''); A.set(path + '_crop', null); A.persist(); A.render(true); break; }
    case 'media-pick': {
      const files = await pickFiles('image/*,video/*', true); if (!files.length) return;
      const list = A.get(path); let added = 0;
      for (const f of files) {
        if (f.type.startsWith('video/')) {
          if (f.size > 60e6) { toast(`«${f.name}» بزرگ‌تر از ۶۰ مگابایت است؛ از لینک ویدیو (یوتیوب/آپارات) استفاده کنید.`, true); continue; }
          const url = await readAsDataURL(f); if (url) { list.push({ id: uid(), type: 'video', url }); added++; }
        } else {
          const url = await processImage(f, 1800); if (!url) { toast(imageErrorMsg(f.name), true); continue; }
          list.push({ id: uid(), type: 'image', url }); added++; } 
      }
      if (added) { A.persist(); A.render(true); toast(`${A.toFa(added)} فایل اضافه شد.`); if (added === 1 && files.length === 1 && /^data:image\/(jpeg|png|webp)/.test(list[list.length - 1].url) && list[list.length - 1].type === 'image') { const np = `${path}.${list.length - 1}.url`; runCropper(np, list[list.length - 1].url, cropCfg(np), null); } }
      break;
    }
    case 'media-url': askUrl('لینک ویدیو یا تصویر (یوتیوب، آپارات، mp4، jpg…)', '', (u) => { A.get(path).push({ id: uid(), type: A.mediaKind(u), url: u }); A.persist(); A.render(true); }); break;
    case 'mv': { const list = A.get(btn.dataset.list), i = +btn.dataset.i, j = i + (+btn.dataset.d); if (j < 0 || j >= list.length) return; [list[i], list[j]] = [list[j], list[i]]; reindexMediaStyles(btn.dataset.list, (n) => (n === i ? j : n === j ? i : n)); A.persist(); A.render(true); break; }
    case 'rm': { const list = A.get(btn.dataset.list), i = +btn.dataset.i; if (btn.dataset.list === 'clients' && !confirm('این مشتری حذف شود؟')) return; if (btn.dataset.list === 'portfolio' && !confirm('این پروژه با همه تصاویر و ویدیوهایش حذف شود؟')) return; list.splice(i, 1); reindexMediaStyles(btn.dataset.list, (n) => (n === i ? null : n > i ? n - 1 : n)); A.persist(); if (S.route.page === 'project' && btn.dataset.list === 'portfolio') { A.persist(true).then(() => { location.href = 'portfolio.html'; }); } else A.render(true); break; }
    case 'add': { const list = A.get(btn.dataset.list); if (!Array.isArray(list)) { A.set(btn.dataset.list, []); } A.get(btn.dataset.list).push(newItem(btn.dataset.kind)); A.persist(); if (btn.dataset.kind === 'social') { A.render(true); openSocial(A.get('social').length - 1, true); } else A.render(true); if (btn.dataset.kind === 'project') toast('پروژه جدید اضافه شد — روی متن‌ها کلیک کنید و تصویر کاور را بگذارید.'); break; }
    case 'icon-pick': openIconPicker(btn, path, btn.dataset.fb); break;
    case 'link-pick': openLinkPicker(btn, path); break;
    case 'social-edit': openSocial(+btn.dataset.i); break;
    case 'nav-settings': openNavSettings(); break;
    default: break;
  }
});

let navDraft = null; /* address / coordinates typed but not saved yet - survives the trip to the image cropper */
function openNavSettings() {
  const c = A.get('contact'), dr = navDraft; navDraft = null;
  if (!c.navFrame || typeof c.navFrame !== 'object') c.navFrame = {};
  const opt = (v, l, cur) => `<option value="${v}"${v === cur ? ' selected' : ''}>${l}</option>`;
  const rowHtml = (p) => {
    const f = A.navFrame(c, p.id), has = !!c[p.id + 'Icon'];
    return `<div class="navico-row" data-prov="${p.id}"><span data-prev>${A.navIconHtml(p, c)}</span><div class="navico-main"><b>${esc(p.name)}</b>
      <div class="mrow"><button type="button" class="btn btn-soft sm" data-ni="pick">${icon('upload')} ${has ? 'تغییر آیکون' : 'آپلود آیکون'}</button><button type="button" class="btn btn-soft sm" data-ni="crop"${has ? '' : ' hidden'}>${icon('sliders')} برش و تنظیم تصویر</button><button type="button" class="btn btn-soft sm" data-ni="clear"${has ? '' : ' hidden'}>حذف آیکون</button></div>
      <div class="navico-frm"><label>شکل کادر<select data-nf="shape">${opt('round', 'گوشه گرد', f.shape)}${opt('circle', 'دایره', f.shape)}${opt('square', 'تقریباً مربع', f.shape)}</select></label><label>پس‌زمینه<select data-nf="bg">${opt('soft', 'پیش‌فرض سایت', f.bg)}${opt('none', 'شفاف', f.bg)}${opt('white', 'سفید', f.bg)}</select></label><label>فاصله داخلی<input type="range" class="slider" data-nf="pad" min="0" max="10" step="1" value="${f.pad}"><output data-po>${A.toFa(f.pad)}</output></label><label><input type="checkbox" data-nf="border"${f.border ? ' checked' : ''}> حاشیه</label><button type="button" class="btn btn-soft sm" data-ni="frreset">بازنشانی کادر</button></div></div></div>`;
  };
  const m = modal(`${mh('تنظیمات آدرس و مسیریابی')}
    <p class="desc">با کلیک روی آدرس، بازدیدکننده بین گوگل‌مپ، بلد و نشان انتخاب می‌کند. لینک هر سه از همین مختصات ساخته می‌شود.</p>
    <label class="fld">آدرس شرکت<input type="text" data-addr value="${escAttr(dr ? dr.a : (c.address || ''))}" autocomplete="off"><span class="err" data-addr-err hidden></span></label>
    <label class="fld">مختصات جغرافیایی (عرض، طول)<input type="text" dir="ltr" data-coords placeholder="30.337357, 48.282988" value="${escAttr(dr ? dr.c : (c.coords || '30.337357, 48.282988'))}" autocomplete="off" spellcheck="false"><span class="err" data-coords-err hidden></span></label>
    <div class="hintbox">عدد اول عرض جغرافیایی و عدد دوم طول جغرافیایی است. در گوگل‌مپ روی نقطه‌ی دلخواه کلیک راست کنید (در موبایل نگه دارید) و اعداد بالای منو را کپی کنید.</div>
    <div class="navico-sec"><h4>مدیریت آیکون‌های مسیریاب‌ها</h4><p class="desc" style="margin:0">برای هر مسیریاب جداگانه آیکون بگذارید، با همان ویرایشگر برش تصاویر سایت (نسبت کادر، جابه‌جایی، بزرگ‌نمایی، حالت نمایش، فیلتر) تنظیمش کنید و شکل کادر را انتخاب کنید. تغییرات آیکون‌ها و کادر بلافاصله ذخیره و در پنجره‌ی مسیریابی سایت اعمال می‌شود.</p>${A.NAV_PROVIDERS.map(rowHtml).join('')}</div>
    <div class="mrow"><button type="button" class="btn btn-navy" data-ok>ذخیره</button><button type="button" class="btn btn-soft" data-act="modal-close">انصراف</button></div>
    <div class="mrow" style="margin-top:10px;align-items:center"><span class="desc" style="margin:0">تست لینک‌ها:</span><button type="button" class="btn btn-soft sm" data-test="google">Google Maps</button><button type="button" class="btn btn-soft sm" data-test="balad">بلد</button><button type="button" class="btn btn-soft sm" data-test="neshan">نشان</button></div>`);
  const addr = m.querySelector('[data-addr]'), co = m.querySelector('[data-coords]'), aErr = m.querySelector('[data-addr-err]'), cErr = m.querySelector('[data-coords-err]');
  const check = () => {
    const a = addr.value.replace(/\s+/g, ' ').trim(), ce = A.coordsError(co.value);
    aErr.textContent = 'آدرس را وارد کنید.'; aErr.hidden = !!a;
    cErr.textContent = ce; cErr.hidden = !ce;
    return !!a && !ce;
  };
  addr.addEventListener('input', () => { aErr.hidden = true; }); co.addEventListener('input', () => { cErr.hidden = true; });
  const save = async () => {
    if (!check()) return (A.coordsError(co.value) ? co : addr).focus();
    const prev = { a: c.address, c: c.coords };
    c.address = addr.value.replace(/\s+/g, ' ').trim(); c.coords = A.parseCoords(co.value).text;
    const ok = await A.persist(true);
    if (!ok) { c.address = prev.a; c.coords = prev.c; return; }
    closeModal(); A.render(true); toast('تنظیمات آدرس و مسیریابی ذخیره شد.');
  };
  m.querySelector('[data-ok]').onclick = save;
  m.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.type === 'text') { e.preventDefault(); save(); } });
  m.addEventListener('click', (e) => {
    const b = e.target.closest('[data-test]'); if (!b) return;
    if (A.coordsError(co.value)) { cErr.textContent = A.coordsError(co.value); cErr.hidden = false; return co.focus(); }
    window.open(A.navUrl(b.dataset.test, { coords: co.value }), '_blank', 'noopener,noreferrer');
  });
  /* ----- navigation provider icons: same upload -> crop editor -> save pipeline as every other icon / image of the site ----- */
  const reopen = () => setTimeout(openNavSettings, 30);
  const refreshRow = (row) => {
    const id = row.dataset.prov, p = A.NAV_PROVIDERS.find((x) => x.id === id), has = !!c[id + 'Icon'];
    row.querySelector('[data-prev]').innerHTML = A.navIconHtml(p, c);
    row.querySelector('[data-ni="pick"]').innerHTML = `${icon('upload')} ${has ? 'تغییر آیکون' : 'آپلود آیکون'}`;
    row.querySelector('[data-ni="crop"]').hidden = !has; row.querySelector('[data-ni="clear"]').hidden = !has;
  };
  const frameOf = (id) => (c.navFrame[id] = { ...A.navFrame(c, id) });
  m.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-ni]'); if (!b) return;
    const row = b.closest('[data-prov]'), id = row.dataset.prov, path = 'contact.' + id + 'Icon', kind = b.dataset.ni;
    const cfg = { ...cropCfg(path), onCancel: reopen, after: reopen };
    const keep = () => { navDraft = { a: addr.value, c: co.value }; };
    if (kind === 'pick') {
      const files = await pickFiles('image/*'); const f = files[0]; if (!f) return;
      if (f.size > 15e6) return toast('حجم فایل بیشتر از ۱۵ مگابایت است.', true);
      const vec = /svg|gif/.test(f.type), url = await processImage(f, 512, true); if (!url) return toast('فایل تصویر معتبر نیست.', true);
      if (vec) { A.set(path, url); A.set(path + '_orig', ''); A.set(path + '_crop', null); A.persist(true); A.render(true); refreshRow(row); toast('آیکون ذخیره شد.'); return; }
      keep(); runCropper(path, url, cfg, null);
    } else if (kind === 'crop') {
      const cur = A.get(path) || '', orig = A.get(path + '_orig') || cur; if (!cur) return;
      if (/^data:image\/(svg|gif)/.test(orig) || /\.(svg|gif)(\?|$)/i.test(orig)) return toast('تصویر SVG/GIF قابل برش نیست و به‌صورت اصلی نمایش داده می‌شود.', true);
      keep(); runCropper(path, orig, cfg, A.get(path + '_orig') ? A.get(path + '_crop') : null);
    } else if (kind === 'clear') {
      A.set(path, ''); A.set(path + '_orig', ''); A.set(path + '_crop', null); A.persist(true); A.render(true); refreshRow(row);
    } else if (kind === 'frreset') {
      delete c.navFrame[id]; row.querySelectorAll('[data-nf]').forEach((el) => { const k = el.dataset.nf, d = A.navFrame(c, id); if (el.type === 'checkbox') el.checked = d.border; else el.value = d[k]; }); row.querySelector('[data-po]').textContent = A.toFa(0); A.persist(true); A.render(true); refreshRow(row);
    }
  });
  const frameChange = (e, final) => {
    const el = e.target.closest('[data-nf]'); if (!el) return;
    const row = el.closest('[data-prov]'), id = row.dataset.prov, f = frameOf(id), k = el.dataset.nf;
    if (k === 'border') f.border = el.checked; else if (k === 'pad') { f.pad = Math.min(10, Math.max(0, Math.round(+el.value) || 0)); row.querySelector('[data-po]').textContent = A.toFa(f.pad); } else f[k] = el.value;
    refreshRow(row); A.persist(); if (final) A.render(true);
  };
  m.addEventListener('input', (e) => frameChange(e, false));
  m.addEventListener('change', (e) => frameChange(e, true));
}
function askUrl(title, value, cb, allowEmpty) {
  const m = modal(`${mh(title)}<label class="fld"><input type="url" dir="ltr" placeholder="https://…" value="${escAttr(value)}"></label><div class="mrow"><button type="button" class="btn btn-navy" data-ok>ذخیره</button><button type="button" class="btn btn-soft" data-act="modal-close">انصراف</button></div>`);
  const inp = m.querySelector('input');
  const ok = () => { const u = inp.value.trim(); if (!u && !allowEmpty) return inp.focus(); closeModal(); cb(u); };
  m.querySelector('[data-ok]').onclick = ok; inp.onkeydown = (e) => { if (e.key === 'Enter') ok(); };
}

/* ---------- icon picker ---------- */
function openIconPicker(anchor, path, fb, o = {}) {
  closePops();
  const cur = A.get(path) || '';
  const pop = document.createElement('div'); pop.className = 'ipick';
  pop.innerHTML = `<div class="grid">${A.PICK_ICONS.map((n) => `<button type="button" data-ic="builtin:${n}" class="${cur === 'builtin:' + n ? 'on' : ''}" title="${n}">${icon(n)}</button>`).join('')}</div>
    <div class="foot"><button type="button" data-ic="upload">${icon('upload')} آپلود آیکون (PNG/SVG)</button>${!o.noCrop && cur && /^data:image\/(png|jpeg|webp)/.test(cur) ? `<button type="button" data-ic="edit">${icon('sliders')} تنظیم کادر آیکون</button>` : ''}${cur ? `<button type="button" class="del" data-ic="">${icon('x')} حذف</button>` : ''}</div>`;
  pop.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-ic]'); if (!b) return;
    if (b.dataset.ic === 'upload') { const f = await pickFiles('image/*'); if (!f[0]) return; const vec = /svg|gif/.test(f[0].type), url = await processImage(f[0], o.noCrop ? 160 : 512, true); if (!url) return; if (!vec && !o.noCrop) { closePops(); runCropper(path, url, cropCfg(path) || cropCfg('x.icon'), null); return; } A.set(path, url); A.set(path + '_orig', ''); }
    else if (b.dataset.ic === 'edit') { closePops(); runCropper(path, A.get(path + '_orig') || cur, cropCfg(path) || cropCfg('x.icon'), A.get(path + '_orig') ? A.get(path + '_crop') : null); return; }
    else { A.set(path, b.dataset.ic); A.set(path + '_orig', ''); }
    closePops(); A.persist(); A.render(true); if (o.onDone) o.onDone();
  });
  placePop(pop, anchor);
}
/* ---------- CTA link picker ---------- */
function openLinkPicker(anchor, path) {
  closePops();
  const cur = A.get(path) || {}; const t = cur.target || 'contact';
  const known = ['contact', 'portfolio', 'services', 'about', 'process'];  const isCustom = !known.includes(t);
  const pop = document.createElement('div'); pop.className = 'linkpick';
  pop.innerHTML = `<label>مقصد دکمه<select><option value="contact">بخش ارتباط با ما</option><option value="portfolio">صفحه نمونه کارها</option><option value="services">بخش خدمات</option><option value="about">بخش درباره ما</option><option value="process">بخش روند همکاری</option><option value="custom">لینک دلخواه</option></select></label>
    <label style="${isCustom ? '' : 'display:none'}">آدرس لینک<input type="url" dir="ltr" placeholder="https://… یا tel:… یا mailto:…" value="${escAttr(isCustom ? t : '')}"></label><button type="button" class="ok">ذخیره</button>`;
  const sel = pop.querySelector('select'), inp = pop.querySelector('input'); sel.value = isCustom ? 'custom' : t;
  sel.onchange = () => { inp.parentElement.style.display = sel.value === 'custom' ? '' : 'none'; };
  pop.querySelector('.ok').onclick = () => { const v = sel.value === 'custom' ? inp.value.trim() : sel.value; if (!v) return inp.focus(); cur.target = v; A.set(path, cur); closePops(); A.persist(); A.render(true); };
  placePop(pop, anchor);
}
/* ---------- social edit ---------- */
const FA_DIG = (t) => String(t == null ? '' : t).replace(/[۰-۹]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d)).replace(/[٠-٩]/g, (d) => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
/* Turns what the admin typed (full link, "t.me/x", "@name", a phone number…) into a safe href. ok:false = not understood. */
function socialUrl(raw, label) {
  let t = FA_DIG(raw).replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '').trim();
  if (!t) return { ok: true, url: '' };
  const lab = String(label || '').toLowerCase(), has = (...k) => k.some((x) => lab.includes(x));
  if (/^\/\//.test(t)) t = 'https:' + t;
  if (/^(javascript|data|vbscript|file|blob):/i.test(t)) return { ok: false };
  if (/^mailto:/i.test(t)) return /^mailto:[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(t) ? { ok: true, url: t } : { ok: false };
  if (/^tel:/i.test(t)) { const n = t.slice(4).replace(/[\s\-()]/g, ''); return /^\+?\d{5,}$/.test(n) ? { ok: true, url: 'tel:' + n } : { ok: false }; }
  if (/^https?:\/\//i.test(t)) { try { const u = new URL(t); return /\.[^.]+$/.test(u.hostname) ? { ok: true, url: t } : { ok: false }; } catch (e) { return { ok: false }; } }
  if (/^\+?[0-9][0-9\s\-()]{6,}$/.test(t) && has('واتس', 'whatsapp')) {
    let n = t.replace(/[^\d]/g, ''); if (n.startsWith('00')) n = n.slice(2); else if (n.startsWith('09')) n = '98' + n.slice(1);
    return n.length >= 8 ? { ok: true, url: 'https://wa.me/' + n } : { ok: false };
  }
  if (/^@[A-Za-z0-9_.]{2,}$/.test(t)) {
    const h = t.slice(1), net = [[['تلگرام', 'telegram'], 'https://t.me/'], [['اینستا', 'instagram'], 'https://instagram.com/'], [['لینکدین', 'linkedin'], 'https://linkedin.com/in/'], [['آپارات', 'aparat'], 'https://aparat.com/'], [['یوتیوب', 'youtube'], 'https://youtube.com/@'], [['ایتا', 'eitaa'], 'https://eitaa.com/'], [['بله'], 'https://ble.ir/'], [['توییتر', 'twitter', 'ایکس'], 'https://x.com/']].find(([k]) => has(...k));
    return net ? { ok: true, url: net[1] + h } : { ok: false };
  }
  if (/^(www\.)?[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.[a-z]{2,}(\/\S*)?$/i.test(t)) return { ok: true, url: 'https://' + t };
  return { ok: false };
}
function openSocial(i, isNew) {
  const s = D().social[i]; if (!s) return;
  const origIcon = s.icon || '';
  const m = modal(`${mh('شبکه اجتماعی')}
    <label class="fld">عنوان<input type="text" data-k="label" value="${escAttr(s.label)}" placeholder="مثلاً واتس‌اپ"></label>
    <label class="fld">لینک<input type="text" inputmode="url" dir="ltr" autocomplete="off" autocapitalize="off" spellcheck="false" data-k="url" value="${escAttr(s.url)}" placeholder="https://t.me/username"><span class="err hidden" role="alert" data-k="err"></span></label>
    <div class="hintbox" style="margin-top:-4px">لینک کامل یا بدون https بنویسید؛ مثل t.me/abc. اگر لینک خالی بماند، این آیکون در سایت نمایش داده نمی‌شود.</div>
    <div class="fld">آیکون<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><span class="tile" style="width:44px;height:44px" data-prev></span><button type="button" class="btn btn-soft sm" data-k="pick">انتخاب از آیکون‌ها</button><button type="button" class="btn btn-soft sm" data-k="auto">تشخیص خودکار</button></div><div class="hintbox">اگر آیکون انتخاب نشود، بر اساس عنوان یا لینک (واتس‌اپ، تلگرام، اینستاگرام، لینکدین، آپارات، یوتیوب…) به‌صورت خودکار نمایش داده می‌شود.</div></div>
    <div class="mrow"><button type="button" class="btn btn-navy" data-k="save">ذخیره</button><button type="button" class="btn btn-danger" data-k="del">حذف</button><button type="button" class="btn btn-soft" data-act="modal-close">انصراف</button></div>`);
  const lab = m.querySelector('[data-k="label"]'), url = m.querySelector('[data-k="url"]'), err = m.querySelector('[data-k="err"]'), prev = m.querySelector('[data-prev]');
  const showErr = (msg) => { err.textContent = msg || ''; err.classList.toggle('hidden', !msg); url.setAttribute('aria-invalid', msg ? 'true' : 'false'); };
  const refresh = () => { const r = socialUrl(url.value, lab.value); prev.innerHTML = A.socialIcon({ label: lab.value, url: r.ok ? r.url : url.value, icon: s.icon || '' }); };
  refresh();
  /* cancel / Esc / X: undo icon changes made inside this dialog; a just-added empty item is removed again */
  modalCancel = () => {
    const cur = D().social[i]; if (!cur) return;
    if (isNew) D().social.splice(i, 1); else cur.icon = origIcon;
    A.persist(); A.render(true);
  };
  const save = () => {
    const r = socialUrl(url.value, lab.value);
    if (!r.ok) { showErr('لینک معتبر نیست؛ مثلاً t.me/abc یا https://instagram.com/abc'); url.focus(); return; }
    s.label = lab.value.trim() || 'شبکه اجتماعی'; s.url = r.url; modalCancel = null; closeModal(); A.persist(); A.render(true);
    toast(r.url ? 'شبکه اجتماعی ذخیره شد.' : 'ذخیره شد؛ تا لینک وارد نشود، آیکون در سایت دیده نمی‌شود.');
  };
  url.addEventListener('input', () => { showErr(''); refresh(); });
  lab.addEventListener('input', refresh);
  url.addEventListener('blur', () => { const r = socialUrl(url.value, lab.value); if (r.ok && r.url && r.url !== url.value.trim()) { url.value = r.url; refresh(); } });
  [lab, url].forEach((el) => el.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); save(); } }));
  m.addEventListener('click', (e) => {
    const b = e.target.closest('[data-k]'); if (!b || b.tagName === 'INPUT' || b.dataset.k === 'err') return;
    const k = b.dataset.k;
    if (k === 'pick') { openIconPicker(b, `social.${i}.icon`, 'link', { noCrop: true, onDone: () => { const cur = D().social[i]; if (cur) s.icon = cur.icon || ''; refresh(); } }); return; }
    if (k === 'auto') { s.icon = ''; refresh(); return; }
    if (k === 'del') { D().social.splice(i, 1); modalCancel = null; closeModal(); A.persist(); A.render(true); return; }
    if (k === 'save') save();
  });
  setTimeout(() => { try { url.focus(); } catch (_) { /* ignore */ } }, 30);
}

/* ---------- login / logout ---------- */
function openLogin() {
  if (!hasPw()) return openSetPassword();
  const m = modal(`${mh('ورود به پنل مدیریت')}<p class="desc">پس از ورود می‌توانید همه متن‌ها، تصاویر، آیکون‌ها، ویدیوها، پروژه‌ها، رنگ‌ها و بخش‌های سایت را تغییر دهید.</p>
    <label class="fld">رمز عبور<input type="password" dir="ltr" autocomplete="current-password"><span class="err hidden">رمز عبور اشتباه است.</span></label>
    <div class="mrow"><button type="button" class="btn btn-navy" data-ok>ورود</button><button type="button" class="btn btn-soft" data-act="modal-close">انصراف</button></div>`);
  const inp = m.querySelector('input'), err = m.querySelector('.err');
  const ok = async () => { if (await checkPw(inp.value)) { closeModal(); S.admin = true; S.edit = true; try { sessionStorage.setItem('company_site_edit', '1'); sessionStorage.setItem(A.SESSION_KEY, '1'); } catch (e) { /* ignore */ } A.render(true); toast('خوش آمدید — حالت ویرایش فعال است؛ روی هر متن یا تصویر کلیک کنید.'); } else { loginFails++; await new Promise((r) => setTimeout(r, Math.min(loginFails * 700, 5000))); err.classList.remove('hidden'); inp.select(); } };
  m.querySelector('[data-ok]').onclick = ok; inp.onkeydown = (e) => { if (e.key === 'Enter') ok(); };
}
function logout() { S.admin = false; S.edit = false; try { sessionStorage.removeItem('company_site_edit'); sessionStorage.removeItem(A.SESSION_KEY); } catch (e) { /* ignore */ } closeModal(); closePops(); A.render(true); toast('از پنل مدیریت خارج شدید.'); }

/* ---------- admin bar ---------- */
function renderBar() {
  $$('.admin-bar').forEach((b) => b.remove());
  if (!S.admin) { const hx = document.getElementById('hoverfx'); if (hx) hx.remove(); return; }
  const bar = document.createElement('div'); bar.className = 'admin-bar';
  bar.innerHTML = `<button type="button" class="ab-toggle" data-act="ab-toggle">${icon('settings')} مدیریت</button><div class="ab-items"><span class="ab-gripwrap" style="display:contents"><button type="button" class="ab-grip" aria-label="جابه‌جایی نوار مدیریت (کلیدهای جهت‌دار؛ دو بار کلیک = بازنشانی)" title="بکشید تا جابه‌جا شود — دو بار کلیک: بازنشانی"><svg viewBox="0 0 14 16" fill="currentColor" aria-hidden="true"><circle cx="4" cy="3" r="1.4"/><circle cx="10" cy="3" r="1.4"/><circle cx="4" cy="8" r="1.4"/><circle cx="10" cy="8" r="1.4"/><circle cx="4" cy="13" r="1.4"/><circle cx="10" cy="13" r="1.4"/></svg></button></span>
    <button type="button" class="${S.edit ? 'on' : ''}" data-act="ab-edit">${icon('pencil')} ${S.edit ? 'پایان ویرایش' : 'ویرایش'}</button>
    <button type="button" data-act="ab-settings">${icon('sliders')} ظاهر</button>
    <button type="button" data-act="ab-fonts">${icon('type')} فونت‌ها</button>
    <button type="button" data-act="ab-scheme">${icon('palette')} تم رنگی سایت</button>
    <button type="button" data-act="ab-sections">${icon('layout')} بخش‌ها</button>
    <button type="button" data-act="ab-hover">${icon('cursor')} هاورها</button>
    <button type="button" data-act="ab-backup">${icon('database')} پشتیبان و خروجی</button>
    <button type="button" data-act="ab-logout">${icon('logout')} خروج</button><span class="ab-sz" role="group" aria-label="اندازه نوار"><button type="button" data-ab="smaller" aria-label="کوچک‌تر کردن نوار" title="کوچک‌تر">−</button><button type="button" data-ab="bigger" aria-label="بزرگ‌تر کردن نوار" title="بزرگ‌تر">+</button></span></div>`;
  document.body.appendChild(bar);
  abSetup(bar);
}

/* ---------- admin bar: draggable + resizable (position/size kept per browser, not in site data) ---------- */
const AB_KEY = 'admin_bar_ui';
function abLoad() { try { const o = JSON.parse(localStorage.getItem(AB_KEY) || 'null'); return (o && typeof o === 'object') ? o : {}; } catch (e) { return {}; } }
function abStore(o) { try { localStorage.setItem(AB_KEY, JSON.stringify(o)); } catch (e) { /* ignore */ } }
function abSetup(bar) {
  const st = abLoad();
  let sc = (typeof st.s === 'number' && isFinite(st.s)) ? Math.min(1.5, Math.max(.6, st.s)) : 1;
  let pos = (typeof st.x === 'number' && typeof st.y === 'number' && isFinite(st.x) && isFinite(st.y)) ? { x: st.x, y: st.y } : null;
  const vw = () => document.documentElement.clientWidth || window.innerWidth;
  const save = () => abStore({ s: sc, x: pos ? Math.round(pos.x) : null, y: pos ? Math.round(pos.y) : null });
  function keepIn() {
    if (!pos) return;
    const r = bar.getBoundingClientRect();
    pos.x = Math.min(Math.max(pos.x, 6), Math.max(6, vw() - r.width - 6));
    pos.y = Math.min(Math.max(pos.y, 6), Math.max(6, window.innerHeight - r.height - 6));
    bar.style.setProperty('--abx', pos.x + 'px'); bar.style.setProperty('--aby', pos.y + 'px');
  }
  function side() {
    const r = bar.getBoundingClientRect();
    bar.classList.toggle('ab-down', r.top + r.height / 2 < window.innerHeight / 2);
    bar.classList.toggle('ab-left', r.left + r.width / 2 < vw() / 2);
  }
  function btns() {
    const m = bar.querySelector('[data-ab="smaller"]'), p = bar.querySelector('[data-ab="bigger"]');
    if (m) m.disabled = sc <= .6; if (p) p.disabled = sc >= 1.5;
  }
  function apply() {
    bar.style.setProperty('--abs', sc);
    if (pos) { bar.classList.add('ab-free'); bar.style.setProperty('--abx', pos.x + 'px'); bar.style.setProperty('--aby', pos.y + 'px'); }
    else { bar.classList.remove('ab-free'); bar.style.removeProperty('--abx'); bar.style.removeProperty('--aby'); }
    keepIn(); side(); btns();
  }
  function startFree() { if (!pos) { const r = bar.getBoundingClientRect(); pos = { x: r.left, y: r.top }; } }
  function reset() { pos = null; sc = 1; save(); apply(); }
  bar._abFix = () => { keepIn(); side(); };
  apply();

  let drag = null, suppress = false;
  /* move/up are listened on window (not on the bar) so a fast drag that leaves the bar keeps working */
  const onMove = (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
    if (!drag.started) {
      if (Math.hypot(dx, dy) < 6) return;
      drag.started = true; startFree(); bar.classList.add('ab-drag');
    }
    pos = { x: drag.ox + dx, y: drag.oy + dy }; apply(); e.preventDefault();
  };
  const end = (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    const was = drag.started; drag = null; bar.classList.remove('ab-drag');
    window.removeEventListener('pointermove', onMove); window.removeEventListener('pointerup', end); window.removeEventListener('pointercancel', end);
    if (was) { suppress = true; setTimeout(() => { suppress = false; }, 80); save(); }
  };
  bar.addEventListener('pointerdown', (e) => {
    if (e.button > 0 || !e.target.closest('.ab-grip,.ab-toggle')) return;
    if (drag) end({ pointerId: drag.id });
    const r = bar.getBoundingClientRect();
    drag = { id: e.pointerId, sx: e.clientX, sy: e.clientY, ox: r.left, oy: r.top, started: false };
    window.addEventListener('pointermove', onMove, { passive: false }); window.addEventListener('pointerup', end); window.addEventListener('pointercancel', end);
  });
  /* a drag that started on the mobile toggle must not also open/close the menu */
  bar.addEventListener('click', (e) => { if (suppress) { e.stopPropagation(); e.preventDefault(); suppress = false; } }, true);
  bar.addEventListener('click', (e) => {
    const b = e.target.closest('[data-ab]');
    if (b) {
      e.stopPropagation();
      sc = Math.round((sc + (b.dataset.ab === 'bigger' ? .1 : -.1)) * 100) / 100; sc = Math.min(1.5, Math.max(.6, sc));
      save(); apply(); return;
    }
    if (e.target.closest('.ab-toggle')) requestAnimationFrame(() => { keepIn(); side(); });
  });
  bar.addEventListener('dblclick', (e) => { if (e.target.closest('.ab-grip,.ab-toggle')) reset(); });
  bar.addEventListener('keydown', (e) => {
    if (!e.target.closest('.ab-grip')) return;
    const k = e.key, step = e.shiftKey ? 40 : 12;
    if (k === 'Home') { e.preventDefault(); reset(); return; }
    const d = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[k];
    if (!d) return;
    e.preventDefault(); startFree(); pos = { x: pos.x + d[0], y: pos.y + d[1] }; apply(); save();
  });
  if (!window.__abRz) { window.__abRz = 1; window.addEventListener('resize', () => { const b = document.querySelector('.admin-bar'); if (b && b._abFix) b._abFix(); }); }
}

/* ---------- settings ---------- */
/* Each preset is a theme family: the entry itself is the original; `v` lists its related variations (same text colour). */
const PRESETS = [
  { n: 'سرمه‌ای (پیش‌فرض)', primary: '#12305B', accent: '#2F6FB5', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#194077', accent: '#3B7EC8' },
      { n: 'تیره‌تر', primary: '#0D2444', accent: '#2B64A5' },
      { n: 'ملایم', primary: '#243753', accent: '#4A739F' },
      { n: 'تأکید دیگر', primary: '#12275B', accent: '#3C59C6' },
  ] },
  { n: 'نیلی تیره', primary: '#1E1B4B', accent: '#4F46E5', text: '#475569', v: [
      { n: 'روشن‌تر', primary: '#292564', accent: '#7069E6' },
      { n: 'تیره‌تر', primary: '#161436', accent: '#453DE6' },
      { n: 'ملایم', primary: '#2B2947', accent: '#6D68C8' },
      { n: 'تأکید دیگر', primary: '#1B1E4B', accent: '#4C66DF' },
  ] },
  { n: 'سبز زیتونی', primary: '#2F3E2E', accent: '#7A8F3C', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#3F523E', accent: '#7F9441' },
      { n: 'تیره‌تر', primary: '#232E22', accent: '#657631' },
      { n: 'ملایم', primary: '#374036', accent: '#75824E' },
      { n: 'تأکید دیگر', primary: '#2E3E2F', accent: '#638C3F' },
  ] },
  { n: 'سبز تیره', primary: '#0F3D3E', accent: '#1F8A70', text: '#44515F', v: [
      { n: 'روشن‌تر', primary: '#17585A', accent: '#249075' },
      { n: 'تیره‌تر', primary: '#0A2727', accent: '#19715B' },
      { n: 'ملایم', primary: '#1C3A3B', accent: '#357969' },
      { n: 'تأکید دیگر', primary: '#0F383E', accent: '#238286' },
  ] },
  { n: 'زغالی و نارنجی', primary: '#1F2937', accent: '#EA580C', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#2C3A4D', accent: '#EE641D' },
      { n: 'تیره‌تر', primary: '#151C25', accent: '#C84B0A' },
      { n: 'ملایم', primary: '#282F38', accent: '#C46737' },
      { n: 'تأکید دیگر', primary: '#1F2637', accent: '#C07F12' },
  ] },
  { n: 'قهوه‌ای و طلایی', primary: '#3F2A1D', accent: '#B8860B', text: '#574B42', v: [
      { n: 'روشن‌تر', primary: '#573A29', accent: '#BD8B10' },
      { n: 'تیره‌تر', primary: '#2C1D14', accent: '#966D09' },
      { n: 'ملایم', primary: '#3E3128', accent: '#9B7B2D' },
      { n: 'تأکید دیگر', primary: '#3F261D', accent: '#B15612' },
  ] },
  { n: 'آبی نفتی', primary: '#0B3C5D', accent: '#1D9BF0', text: '#475569', v: [
      { n: 'روشن‌تر', primary: '#10507B', accent: '#229AEB' },
      { n: 'تیره‌تر', primary: '#082C44', accent: '#0F88DB' },
      { n: 'ملایم', primary: '#1F3E53', accent: '#4995C9' },
      { n: 'تأکید دیگر', primary: '#0B325D', accent: '#2562E8' },
  ] },
  { n: 'بنفش دودی', primary: '#312E51', accent: '#7C5CBF', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#3F3C67', accent: '#886DC3' },
      { n: 'تیره‌تر', primary: '#26243F', accent: '#714EB9' },
      { n: 'ملایم', primary: '#3C3A50', accent: '#8572AE' },
      { n: 'تأکید دیگر', primary: '#352E51', accent: '#9760BB' },
  ] },
  { n: 'مشکی و کهربایی', primary: '#111827', accent: '#B45309', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#1C273F', accent: '#C85F0F' },
      { n: 'تیره‌تر', primary: '#090D15', accent: '#A14907' },
      { n: 'ملایم', primary: '#1A1E29', accent: '#975A2B' },
      { n: 'تأکید دیگر', primary: '#111527', accent: '#9F760F' },
  ] },
  { n: 'آبی سلطنتی', primary: '#14296B', accent: '#2563EB', text: '#475569', v: [
      { n: 'روشن‌تر', primary: '#1B3587', accent: '#4579E9' },
      { n: 'تیره‌تر', primary: '#102053', accent: '#1455E2' },
      { n: 'ملایم', primary: '#293760', accent: '#4E74C7' },
      { n: 'تأکید دیگر', primary: '#141F6B', accent: '#4B4CE9' },
  ] },
  { n: 'یاقوتی و قرمز', primary: '#4A1220', accent: '#C62839', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#661A2D', accent: '#D33E4E' },
      { n: 'تیره‌تر', primary: '#330D16', accent: '#BC2735' },
      { n: 'ملایم', primary: '#45212A', accent: '#AC4852' },
      { n: 'تأکید دیگر', primary: '#4A1219', accent: '#C0482E' },
  ] },
  { n: 'فیروزه‌ای تیره', primary: '#0E3B43', accent: '#0E7490', text: '#44515F', v: [
      { n: 'روشن‌تر', primary: '#15545F', accent: '#1488A8' },
      { n: 'تیره‌تر', primary: '#09272C', accent: '#0B6A83' },
      { n: 'ملایم', primary: '#1C3A3F', accent: '#28697B' },
      { n: 'تأکید دیگر', primary: '#0E4143', accent: '#138B83' },
  ] },
  { n: 'سبز جنگلی', primary: '#14532D', accent: '#4D7C0F', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#196236', accent: '#588B14' },
      { n: 'تیره‌تر', primary: '#0F3C21', accent: '#45700F' },
      { n: 'ملایم', primary: '#254D34', accent: '#4D6B25' },
      { n: 'تأکید دیگر', primary: '#145334', accent: '#307813' },
  ] },
  { n: 'زرشکی و طلایی', primary: '#5B1A2B', accent: '#A16207', text: '#574B42', v: [
      { n: 'روشن‌تر', primary: '#752339', accent: '#B16D0C' },
      { n: 'تیره‌تر', primary: '#451421', accent: '#8E5606' },
      { n: 'ملایم', primary: '#542B36', accent: '#885F25' },
      { n: 'تأکید دیگر', primary: '#5B1A33', accent: '#AA3F0D' },
  ] },
  { n: 'سرخابی', primary: '#4A1D44', accent: '#BE185D', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#63285B', accent: '#D9216D' },
      { n: 'تیره‌تر', primary: '#361531', accent: '#B21855' },
      { n: 'ملایم', primary: '#472A43', accent: '#A23965' },
      { n: 'تأکید دیگر', primary: '#4A1D49', accent: '#B71F89' },
  ] },
  { n: 'گرافیت و آبی‌سبز', primary: '#23272F', accent: '#0F766E', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#323843', accent: '#158981' },
      { n: 'تیره‌تر', primary: '#171A1F', accent: '#116E68' },
      { n: 'ملایم', primary: '#2A2D32', accent: '#266E69' },
      { n: 'تأکید دیگر', primary: '#23262F', accent: '#166A7E' },
  ] },
  { n: 'آبی یخی', primary: '#0F2A43', accent: '#0369A1', text: '#475569', v: [
      { n: 'روشن‌تر', primary: '#173C5F', accent: '#087EBF' },
      { n: 'تیره‌تر', primary: '#0A1C2C', accent: '#02649C' },
      { n: 'ملایم', primary: '#1D2F3F', accent: '#226387' },
      { n: 'تأکید دیگر', primary: '#0F2443', accent: '#0954D2' },
  ] },
  { n: 'خاکستری و بنفش', primary: '#2E2A3B', accent: '#6D28D9', text: '#4B5563', v: [
      { n: 'روشن‌تر', primary: '#3E3950', accent: '#824ADB' },
      { n: 'تیره‌تر', primary: '#211E2B', accent: '#6625CC' },
      { n: 'ملایم', primary: '#35323D', accent: '#774DB9' },
      { n: 'تأکید دیگر', primary: '#302A3B', accent: '#9D2FD2' },
  ] },
  { n: 'نفتی و نارنجی', primary: '#16323F', accent: '#C2410C', text: '#475569', v: [
      { n: 'روشن‌تر', primary: '#204759', accent: '#D94C13' },
      { n: 'تیره‌تر', primary: '#0F222A', accent: '#AF3C0A' },
      { n: 'ملایم', primary: '#22343D', accent: '#A35130' },
      { n: 'تأکید دیگر', primary: '#162D3F', accent: '#B26D12' },
  ] },
  { n: 'قهوه‌ای شکلاتی', primary: '#2B1B14', accent: '#9A3412', text: '#574B42', v: [
      { n: 'روشن‌تر', primary: '#432B20', accent: '#B6411A' },
      { n: 'تیره‌تر', primary: '#180F0B', accent: '#8E3112' },
      { n: 'ملایم', primary: '#2C221D', accent: '#84432D' },
      { n: 'تأکید دیگر', primary: '#2B1E14', accent: '#955A17' },
  ] },
];
/* ---------- colour themes panel (تم رنگی سایت): live preview on the real page, saved only on confirmation ---------- */
const SCHEMES = [
  { id: 'burgundy', n: 'زرشکی عمیق', c: { primary: '#8f2338', secondary: '#5c1727', accent: '#e45b69' }, dark: { background: '#190c12', surface: '#29141d', text: '#f8eef1' }, light: { background: '#f7f0f2', surface: '#ffffff', text: '#4a3a40' } },
  { id: 'purple', n: 'بنفش سلطنتی', c: { primary: '#7939c9', secondary: '#4d1b83', accent: '#a66af0' }, dark: { background: '#120b1b', surface: '#20122f', text: '#f5eeff' }, light: { background: '#f4f0fa', surface: '#ffffff', text: '#463c57' } },
  { id: 'midnight', n: 'آبی نیمه‌شب', c: { primary: '#2f6db3', secondary: '#173a68', accent: '#65a7f5' }, dark: { background: '#0a1424', surface: '#111f34', text: '#edf4ff' }, light: { background: '#eef3f9', surface: '#ffffff', text: '#3f4d63' } },
  { id: 'emerald', n: 'سبز زمردی', c: { primary: '#16866a', secondary: '#105642', accent: '#43c99a' }, dark: { background: '#0a1714', surface: '#122820', text: '#e9fff5' }, light: { background: '#eef6f3', surface: '#ffffff', text: '#3a4f48' } },
  { id: 'graphite', n: 'گرافیت و نقره‌ای', c: { primary: '#596579', secondary: '#374151', accent: '#a8b7cc' }, dark: { background: '#11151d', surface: '#1c2430', text: '#f2f5fa' }, light: { background: '#f1f3f6', surface: '#ffffff', text: '#434c5a' } },
  { id: 'teal', n: 'فیروزه‌ای اقیانوسی', c: { primary: '#087f8c', secondary: '#075661', accent: '#42d5d0' }, dark: { background: '#08191f', surface: '#102a32', text: '#ecfeff' }, light: { background: '#edf6f7', surface: '#ffffff', text: '#3b4f54' } },
];
const SCH_PROPS = [
  ['primary', 'رنگ اصلی', 'c', 'سرتیترها، دکمه‌های اصلی و پنل‌های رنگی'],
  ['secondary', 'رنگ مکمل', 'c', 'پنل‌های تیره (مثلاً هیرو و تماس) در حالت تیره'],
  ['accent', 'رنگ تأکیدی', 'c', 'آیکون‌ها، لینک‌ها، برچسب‌ها و هایلایت‌ها'],
  ['background', 'رنگ پس‌زمینه', 'm', 'پس‌زمینه‌ی صفحه'],
  ['surface', 'رنگ سطح کارت‌ها', 'm', 'کارت‌ها و بخش‌های سفید/تیره'],
  ['text', 'رنگ متن', 'm', 'متن‌های اصلی سایت'],
];
const cloneS = (o) => JSON.parse(JSON.stringify(o));
const schName = (id) => (id === 'original' ? 'سایت اصلی' : id === 'custom' ? 'سفارشی' : (SCHEMES.find((s) => s.id === id) || {}).n || 'سفارشی');
/* the website's own current palette expressed as a full scheme, so any colour can be edited even when no preset is active */
function originalScheme(t) {
  const p = A.normHex(t.primary) || '#12305b', a = A.normHex(t.accent) || '#2f6fb5', tx = A.normHex(t.text) || '#4b5563';
  return { id: 'original', c: { primary: p, secondary: A.mixHex(p, '#000000', 0.22), accent: a }, light: { background: '#eef2f7', surface: '#ffffff', text: tx }, dark: { background: '#0a1220', surface: '#111e33', text: '#e6ebf3' } };
}
/* colour generation: ONE deterministic function. The entered / preset primary colour is kept exactly; everything else is derived from its hue, saturation and lightness. */
function hexToHsl(h) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255), mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2;
  let hh = 0, s = 0;
  if (mx !== mn) { const d = mx - mn; s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn); hh = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; hh *= 60; }
  return [hh, s * 100, l * 100];
}
function hslToHex(h, s, l) {
  h = ((h % 360) + 360) % 360; s = Math.max(0, Math.min(100, s)) / 100; l = Math.max(0, Math.min(100, l)) / 100;
  const k = (n) => (n + h / 30) % 12, a = s * Math.min(l, 1 - l), f = (n) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return '#' + [f(0), f(8), f(4)].map((x) => Math.round(x * 255).toString(16).padStart(2, '0')).join('');
}
const clampN = (v, a, b) => Math.max(a, Math.min(b, v));
function generateScheme(primary) {
  const p = A.normHex(primary), [h, s, l] = hexToHsl(p), ns = s < 8 ? 4 : clampN(s * 0.3, 10, 26);
  return {
    id: 'custom',
    c: { primary: p, secondary: hslToHex(h - 8, clampN(s, 25, 85), clampN(l * 0.55, 14, 30)), accent: hslToHex(h + 28, clampN(s, 50, 90), l > 62 ? 42 : 60) },
    light: { background: hslToHex(h, ns, 96), surface: '#ffffff', text: hslToHex(h, clampN(ns, 10, 22), 26) },
    dark: { background: hslToHex(h, clampN(ns + 8, 14, 34), 8), surface: hslToHex(h, clampN(ns + 6, 14, 30), 13), text: hslToHex(h, clampN(ns, 10, 30), 95) },
  };
}
/* "تم رنگی سایت" — two steps in one panel. Step 1: presets + the primary brand colour (picker + HEX). Step 2 ("ویرایش رنگ‌ها"): the six generated colours, each editable. */
function openSchemePanel() {
  const old = document.getElementById('schemefx'); if (old) { old.querySelector('[data-sfx="cancel"]').click(); return; }
  closeModal();
  const t = D().theme, root = document.documentElement;
  const canon = (s) => JSON.stringify(A.cleanScheme(s));
  let saved = A.cleanScheme(t.scheme), orig = originalScheme(t), raf = 0, step = 'select';
  let w = saved.id === 'original' ? cloneS(orig) : cloneS(saved);
  let touched = saved.id === 'custom';     /* true once colours were edited by hand: a new base colour then asks before replacing them */
  let lastPrimary = w.c.primary;           /* last VALID value of the step-1 primary field */
  const mode = () => (root.classList.contains('dark') ? 'dark' : 'light');
  const eff = () => (w.id === 'original' ? { id: 'original' } : w);
  const dirty = () => canon(eff()) !== canon(saved);
  const modeFa = () => (mode() === 'dark' ? 'تیره' : 'روشن');
  const valOf = (p) => (p[2] === 'c' ? w.c[p[0]] : w[mode()][p[0]]);
  const cardHtml = (id, n, s) => { const m = s[mode()], c = s.c; return `<button type="button" class="scard" data-sc="${id}" aria-pressed="false"><span class="smini" style="--bg:${m.background};--sf:${m.surface};--pr:${c.primary};--ac:${c.accent}"><i></i><b></b><em></em></span><span class="sname">${esc(n)}</span><span class="sdots" aria-hidden="true"><u style="background:${c.primary}"></u><u style="background:${c.secondary}"></u><u style="background:${c.accent}"></u><u style="background:${m.surface}"></u><u style="background:${m.text}"></u></span></button>`; };
  const cards = () => cardHtml('original', 'سایت اصلی', orig) + SCHEMES.map((s) => cardHtml(s.id, s.n, s)).join('');
  const erow = (p) => `<div class="sfx-erow"><label class="sfx-el" for="pk-${p[0]}"><span class="sfx-sw" data-sw="${p[0]}"></span><span><b>${p[1]}</b><small>${p[3]}</small></span></label><input type="color" data-pk="${p[0]}" aria-label="انتخاب ${p[1]} با نمایشگر رنگ"><input type="text" id="pk-${p[0]}" data-ph="${p[0]}" dir="ltr" autocomplete="off" spellcheck="false" aria-label="کد HEX ${p[1]}" aria-describedby="pe-${p[0]}"></div><p class="err" id="pe-${p[0]}" data-pe="${p[0]}" role="alert" hidden>کد رنگ معتبر نیست؛ شش رقم HEX وارد کنید.</p>`;
  const el = document.createElement('div'); el.id = 'schemefx'; el.className = 'schemefx'; el.setAttribute('role', 'dialog'); el.setAttribute('aria-label', 'تم رنگی سایت');
  el.innerHTML = `<div class="sfx-h"><span>تم رنگی سایت</span><button type="button" data-sfx="x" aria-label="بستن">${icon('x')}</button></div>
    <div class="sfx-b">
      <p class="sfx-status" data-s="status" aria-live="polite"></p>
      <div class="sfx-row"><span class="sfx-t" style="margin:0">حالت نمایش سایت</span><span class="seg" role="group" aria-label="حالت نمایش"><button type="button" data-sfx-mode="light">روشن</button><button type="button" data-sfx-mode="dark">تیره</button></span></div>
      <div class="sfx-step" data-step="select">
        <div class="sfx-t">تم‌های آماده</div><div class="sfx-cards" data-s="cards">${cards()}</div>
        <p class="sfx-hint">با انتخاب هر تم، همان پالت طراحی‌شده روی سایت پیش‌نمایش می‌شود و بخش «ویرایش رنگ‌ها» باز می‌شود. انتخاب تم، حالت نمایش را تغییر نمی‌دهد.</p>
        <div class="sfx-t">رنگ اصلی سایت من</div>
        <p class="sfx-note">رنگی که اینجا وارد می‌کنید «رنگ اصلی» هویت سایت است؛ رنگ مکمل، تأکیدی، پس‌زمینه، سطح کارت‌ها و متن به‌صورت خودکار از آن ساخته می‌شوند.</p>
        <div class="sfx-gen"><input type="color" class="sfx-pick" data-s="ppick" aria-label="انتخاب رنگ اصلی با نمایشگر رنگ"><div class="sfx-hexw"><label for="sfx-phex">کد رنگ HEX</label><input type="text" id="sfx-phex" data-s="phex" dir="ltr" autocomplete="off" spellcheck="false" aria-describedby="sfx-perr" placeholder="#7939C9"></div><button type="button" class="btn btn-navy" data-sfx="gen">ساخت پالت</button></div>
        <p class="err" id="sfx-perr" data-s="perr" role="alert" hidden>کد رنگ معتبر نیست؛ شش رقم HEX وارد کنید. مثال: #7939C9</p>
        <p class="sfx-hint" data-s="warn" hidden>رنگ‌هایی که دستی تغییر داده‌اید با ساخت پالت جدید جایگزین می‌شوند (قبل از جایگزینی تأیید می‌گیریم).</p>
      </div>
      <div class="sfx-step" data-step="edit" hidden>
        <div class="sfx-row"><button type="button" class="sfx-back" data-sfx="back">بازگشت به تم‌ها</button><span class="sfx-t" style="margin:0">مرحلهٔ ۲ از ۲</span></div>
        <h4 class="sfx-h2" tabindex="-1" data-s="h2">ویرایش رنگ‌ها</h4>
        <p class="sfx-note" data-s="note"></p>
        ${SCH_PROPS.map(erow).join('')}
        <p class="sfx-contrast" data-s="contrast"></p>
        <button type="button" class="btn btn-soft sm" data-sfx="regen">ساخت دوباره پالت از رنگ اصلی</button>
        <p class="sfx-hint">تغییر یک رنگ، بقیهٔ رنگ‌ها را عوض نمی‌کند. فقط دکمهٔ بالا پالت را دوباره می‌سازد.</p>
      </div>
    </div>
    <div class="sfx-f"><button type="button" class="btn btn-navy" data-sfx="save">${icon('check')} ذخیره</button><button type="button" class="btn btn-soft" data-sfx="cancel">انصراف</button><button type="button" class="btn btn-soft" data-sfx="reset">${icon('reset')} بازگشت به رنگ اصلی</button></div>`;
  document.body.appendChild(el);
  const q = (s) => el.querySelector(`[data-s="${s}"]`), phex = q('phex'), ppick = q('ppick'), perr = q('perr');
  const sync = () => {
    const base = w.id === 'custom' && w.base ? ` — بر پایه‌ی «${schName(w.base)}»` : (w.id === 'custom' && w.gen ? ` — ساخته‌شده از ${w.gen.toUpperCase()}` : '');
    q('status').textContent = `تم فعال: ${schName(w.id)}${base}${dirty() ? ' · ذخیره‌نشده' : ''}`;
    $$('.scard', el).forEach((b) => { const on = b.dataset.sc === w.id; b.setAttribute('aria-pressed', String(on)); b.classList.toggle('base', w.id === 'custom' && b.dataset.sc === w.base); });
    $$('[data-sfx-mode]', el).forEach((b) => b.classList.toggle('on', b.dataset.sfxMode === mode()));
    el.querySelector('[data-step="select"]').hidden = step !== 'select'; el.querySelector('[data-step="edit"]').hidden = step !== 'edit';
    q('warn').hidden = !touched;
    if (document.activeElement !== phex) { phex.value = lastPrimary; perr.hidden = true; phex.removeAttribute('aria-invalid'); }
    ppick.value = lastPrimary;
    SCH_PROPS.forEach((p) => {
      const v = valOf(p), tx = el.querySelector(`[data-ph="${p[0]}"]`), pk = el.querySelector(`[data-pk="${p[0]}"]`);
      el.querySelector(`[data-sw="${p[0]}"]`).style.background = v; pk.value = v;
      if (document.activeElement !== tx) { tx.value = v; tx.removeAttribute('aria-invalid'); el.querySelector(`[data-pe="${p[0]}"]`).hidden = true; }
    });
    q('note').textContent = `رنگ‌های اصلی، مکمل و تأکیدی در هر دو حالت روشن و تیره استفاده می‌شوند. پس‌زمینه، سطح کارت‌ها و متن فقط برای حالت «${modeFa()}» ویرایش می‌شوند؛ برای حالت دیگر، حالت نمایش را تغییر دهید.`;
    const m = w[mode()], r = A.contrast(m.text, m.surface);
    q('contrast').textContent = `${r >= 4.5 ? '✓ خوانایی متن روی کارت‌ها مناسب است' : '⚠ خوانایی متن روی کارت‌ها کم است'} (${A.toFa(r.toFixed(1))}:۱)`; q('contrast').classList.toggle('bad', r < 4.5);
    el.querySelector('[data-sfx="save"]').disabled = !dirty();
  };
  const schedule = () => { if (raf) return; raf = requestAnimationFrame(() => { raf = 0; A.setSchemePreview(eff()); }); };
  const goStep = (n) => { step = n; sync(); const f = n === 'edit' ? q('h2') : el.querySelector('.scard'); if (f) f.focus({ preventScroll: true }); el.querySelector('.sfx-b').scrollTop = 0; };
  const setVal = (pr, v) => {
    if (w.id !== 'custom') { w.base = w.id; w.id = 'custom'; delete w.gen; }
    const p = SCH_PROPS.find((x) => x[0] === pr); if (p[2] === 'c') w.c[pr] = v; else w[mode()][pr] = v;
    if (pr === 'primary') lastPrimary = v;
    touched = true; schedule(); sync();
  };
  const okReplace = () => !touched || confirm('رنگ‌هایی که دستی تغییر داده‌اید با پالت جدید جایگزین می‌شود. ادامه می‌دهید؟');
  const choose = (id) => {
    if (!okReplace()) return;
    w = id === 'original' ? cloneS(orig) : A.cleanScheme(SCHEMES.find((s) => s.id === id)); lastPrimary = w.c.primary; touched = false;
    schedule(); goStep('edit');
  };
  const generate = (v, src) => { if (!okReplace()) return; w = generateScheme(v); w.gen = v; lastPrimary = v; touched = false; schedule(); goStep('edit'); };
  const tryGen = () => { const v = A.normHex(phex.value); if (!v) { perr.hidden = false; phex.setAttribute('aria-invalid', 'true'); phex.focus(); return; } generate(v); };
  const stop = () => { cancelAnimationFrame(raf); mo.disconnect(); document.removeEventListener('keydown', onKey, true); el.remove(); };
  const cancel = () => { if (dirty() && !confirm('تغییرات ذخیره‌نشده‌ی رنگ‌ها حذف شود؟')) return; A.setSchemePreview(null); stop(); };
  const save = async () => {
    const prev = t.scheme; t.scheme = A.cleanScheme(eff());
    const ok = await A.persist(true); if (!ok) { t.scheme = prev; return; }
    saved = A.cleanScheme(t.scheme); A.setSchemePreview(null); sync(); toast('تم رنگی سایت ذخیره شد.');
  };
  const reset = async () => {
    if (!confirm('رنگ‌های سایت به حالت اصلی برمی‌گردد. محتوا، لوگوها، نمونه‌کارها و رمز مدیر تغییری نمی‌کنند. ادامه می‌دهید؟')) return;
    const prev = t.scheme; t.scheme = { id: 'original' };
    const ok = await A.persist(true); if (!ok) { t.scheme = prev; return; }
    saved = { id: 'original' }; orig = originalScheme(t); w = cloneS(orig); lastPrimary = w.c.primary; touched = false; step = 'select';
    A.setSchemePreview(null); q('cards').innerHTML = cards(); sync(); toast('تم رنگی به حالت اصلی برگشت.');
  };
  el.addEventListener('click', (e) => {
    const b = e.target.closest('[data-sc],[data-sfx],[data-sfx-mode]'); if (!b) return;
    if (b.dataset.sc) choose(b.dataset.sc);
    else if (b.dataset.sfxMode) { if (mode() !== b.dataset.sfxMode) A.toggleDark(); }
    else if (b.dataset.sfx === 'save') save();
    else if (b.dataset.sfx === 'cancel' || b.dataset.sfx === 'x') cancel();
    else if (b.dataset.sfx === 'reset') reset();
    else if (b.dataset.sfx === 'gen') tryGen();
    else if (b.dataset.sfx === 'back') goStep('select');
    else if (b.dataset.sfx === 'regen') generate(w.c.primary);
  });
  /* step 1: typing / picking only previews the swatch; the website changes when the colour is confirmed ("ساخت پالت" or Enter) */
  ppick.addEventListener('input', () => { phex.value = ppick.value; lastPrimary = ppick.value.toLowerCase(); perr.hidden = true; phex.removeAttribute('aria-invalid'); });
  phex.addEventListener('input', () => {
    const v = A.normHex(phex.value);
    if (v) { perr.hidden = true; phex.removeAttribute('aria-invalid'); ppick.value = v; lastPrimary = v; }
    else { const bad = phex.value.trim() !== ''; perr.hidden = !bad; if (bad) phex.setAttribute('aria-invalid', 'true'); }
  });
  phex.addEventListener('blur', () => { phex.value = lastPrimary; phex.removeAttribute('aria-invalid'); perr.hidden = true; });
  phex.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); tryGen(); } });
  /* step 2: every property has its own picker + HEX field, all reading/writing the same pending palette */
  el.addEventListener('input', (e) => {
    const pk = e.target.dataset && e.target.dataset.pk, ph = e.target.dataset && e.target.dataset.ph;
    if (pk) setVal(pk, e.target.value.toLowerCase());
    else if (ph) {
      const v = A.normHex(e.target.value), er = el.querySelector(`[data-pe="${ph}"]`);
      if (v) { er.hidden = true; e.target.removeAttribute('aria-invalid'); setVal(ph, v); }   /* invalid / half-typed codes are never applied */
      else { const bad = e.target.value.trim() !== ''; er.hidden = !bad; if (bad) e.target.setAttribute('aria-invalid', 'true'); }
    }
  });
  el.addEventListener('focusout', (e) => { if (e.target.dataset && e.target.dataset.ph) sync(); });
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target.dataset && e.target.dataset.ph) { e.preventDefault(); e.target.blur(); } });
  const onKey = (e) => { if (e.key === 'Escape' && !document.querySelector('.modal-bg,.navsel-bg')) { e.preventDefault(); e.stopPropagation(); cancel(); } };
  document.addEventListener('keydown', onKey, true);
  const mo = new MutationObserver(() => { q('cards').innerHTML = cards(); sync(); }); mo.observe(root, { attributes: true, attributeFilter: ['class'] }); /* header toggle / panel toggle: keep mini-previews & values in sync */
  sync();
}
/* ---------- font picker (admin settings) ---------- */
const FONT_MAX = 6, FONT_FILE_MAX = 3e6, FONT_WARN = 3e5;
const FW_LABELS = [['100', '۱۰۰ — نازک'], ['200', '۲۰۰ — خیلی سبک'], ['300', '۳۰۰ — سبک'], ['400', '۴۰۰ — عادی'], ['500', '۵۰۰ — متوسط'], ['600', '۶۰۰ — نیمه‌ضخیم'], ['700', '۷۰۰ — ضخیم'], ['800', '۸۰۰ — خیلی ضخیم'], ['900', '۹۰۰ — سیاه'], ['100 900', 'متغیر — همهٔ وزن‌ها']];
function guessFontWeight(n) {
  n = String(n).toLowerCase();
  if (/variable|\[wght\]|[-_]vf\b/.test(n)) return '100 900';
  if (/extra-?light|ultra-?light|xlight/.test(n)) return '200';
  if (/semi-?bold|demi-?bold/.test(n)) return '600';
  if (/extra-?bold|ultra-?bold|heavy/.test(n)) return '800';
  if (/black|\bfat\b/.test(n)) return '900';
  if (/thin|hairline/.test(n)) return '100';
  if (/light/.test(n)) return '300';
  if (/medium/.test(n)) return '500';
  if (/bold/.test(n)) return '700';
  return '400';
}
function guessFontName(fn) {
  const base = String(fn).replace(/\.[a-z0-9]+$/i, '').replace(/\[.*?\]/g, '');
  const c = base.replace(/[-_ ](thin|hairline|extra-?light|ultra-?light|light|regular|normal|book|medium|semi-?bold|demi-?bold|extra-?bold|ultra-?bold|bold|heavy|black|fat|variable|vf)\b.*$/i, '').replace(/[-_]+/g, ' ').trim();
  return (c || base || 'فونت من').slice(0, 40);
}
function fontPreviewHtml(t) {
  const c = D().company || {}, st = (D().stats || []).slice(0, 3);
  const list = Array.isArray(t.customFonts) ? t.customFonts : [];
  const cur = list.find((f) => 'custom:' + f.id === t.font);
  const label = cur ? cur.name : (t.font === 'system' ? 'فونت سیستم' : 'وزیرمتن (پیش‌فرض)');
  const nav = (D().nav && Array.isArray(D().nav.items)) ? '' : '';
  return `<div class="ff-prevbox" id="ff-preview"><div class="t">پیش‌نمایش سایت <small>با فونت: ${esc(label)}</small></div><div class="ff-site"><div class="fs-nav"><b class="brand" style="padding:0 8px">${esc(c.name || 'نام شرکت')}</b><span class="on">خانه</span><span>خدمات</span><span>نمونه‌کارها</span><span>تماس</span></div><div><span class="pill">${esc(c.eyebrow || 'معرفی')}</span><h3 class="h2" style="margin-top:10px">${esc(c.tagline || 'عنوان اصلی سایت')}</h3><p class="lead" style="margin-top:8px">این یک متن نمونه برای دیدن خوانایی پاراگراف‌ها با فونت انتخاب‌شده است؛ اعداد ۰۱۲۳۴۵۶۷۸۹ و حروف Latin هم دیده می‌شوند.</p><div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px"><span class="btn btn-navy sm">دکمهٔ اصلی</span><span class="btn btn-soft sm">دکمهٔ دوم</span></div></div>${st.length ? `<div class="stats">${st.map((x) => `<div class="stat"><div class="n">${esc(x.value || '۰')}<small>${esc(x.suffix || '')}</small></div><div class="l">${esc(x.label || '')}</div></div>`).join('')}</div>` : ''}<div class="fs-card"><h4>عنوان کارت نمونه</h4><p>متن توضیحی کارت‌ها و بخش‌ها اینجا با همین فونت نمایش داده می‌شود.</p></div></div></div>`;
}
function fontBoxInner(t, pend) {
  const list = Array.isArray(t.customFonts) ? t.customFonts : [];
  const cur = list.find((f) => 'custom:' + f.id === t.font);
  const sample = 'نمونه متن فارسی ۱۲۳۴ — Aa';
  const row = (val, name, fam, meta, del, on) => `<div class="ff-item${on ? ' on' : ''}" role="radio" aria-checked="${on}"><button type="button" class="ff-pick" data-font="${escAttr(val)}"><span class="ff-name">${esc(name)}${meta ? `<small>${meta}</small>` : ''}</span><span class="ff-prev" style="font-family:${fam}">${sample}</span></button>${del ? `<button type="button" class="ff-del" data-font-del="${escAttr(del)}" aria-label="حذف فونت ${escAttr(name)}" title="حذف این فونت">${icon('trash')} حذف</button>` : ''}</div>`;
  const rows = row('vazirmatn', 'وزیرمتن (پیش‌فرض)', "'Vazirmatn',Tahoma,sans-serif", '', '', !cur && t.font !== 'system')
    + row('system', 'فونت سیستم', "system-ui,'Segoe UI',Tahoma,sans-serif", '', '', t.font === 'system')
    + list.map((f) => row('custom:' + f.id, f.name, `'uf-${f.id}','Vazirmatn',Tahoma,sans-serif`, `${A.toFa(f.files.length)} وزن · ${A.fmtSize(f.files.reduce((a, x) => a + (x.size || 0), 0))}`, f.id, !!cur && cur.id === f.id)).join('');
  const add = pend
    ? `<div class="ff-pend"><label class="ff-lbl">نام فونت<input type="text" data-ff-name value="${escAttr(pend.name)}" maxlength="40"></label>${pend.files.map((f, i) => `<div class="ff-file"><div><b>${esc(f.file.name)}</b><small class="${f.size > FONT_WARN ? 'warn' : ''}">${A.fmtSize(f.size)} · ${f.fmt.toUpperCase()}${f.size > FONT_WARN ? ' — حجم زیاد است؛ فایل WOFF2 یا نسخهٔ فقط‌حروف‌فارسی، فایل خروجی را سبک‌تر می‌کند' : ''}</small></div><select data-ff-w="${i}" aria-label="وزن فایل ${i + 1}">${FW_LABELS.map(([v, l]) => `<option value="${v}"${v === f.w ? ' selected' : ''}>${l}</option>`).join('')}</select></div>`).join('')}<div class="mrow"><button type="button" class="btn btn-navy sm" data-font-save>افزودن و استفاده</button><button type="button" class="btn btn-soft sm" data-font-cancel>انصراف</button></div></div>`
    : `<button type="button" class="btn btn-soft sm" data-font-add${list.length >= FONT_MAX ? ' disabled' : ''}>${icon('upload')} بارگذاری فونت دلخواه</button><div class="ff-note">فرمت‌های WOFF2 ،WOFF ،TTF و OTF. چند وزن (مثلاً عادی و ضخیم) را می‌توانید همزمان انتخاب کنید. برای کمترین حجم، WOFF2 بگیرید. حداکثر ${A.toFa(FONT_MAX)} فونت.</div>`;
  return `<div class="ff-list" role="radiogroup" aria-label="فونت سایت">${rows}</div><div class="ff-add">${add}</div>`;
}
function openFonts() {
  const t = D().theme;
  const m = modal(`${mh('فونت‌ها')}
    <div class="fontbox" style="border:0"><div class="d">فونت دلخواه را بارگذاری کنید؛ داخل فایل سایت ذخیره می‌شود و در خروجی HTML هم همراه است. اگر فونتی را نپسندیدید، با «حذف» پاکش کنید.</div><div id="fontbox-in">${fontBoxInner(t, null)}</div><input type="file" id="ff-file" accept=".woff2,.woff,.ttf,.otf,font/woff2,font/woff,font/ttf,font/otf" multiple hidden></div>
    <div id="ff-pv">${fontPreviewHtml(t)}</div>
    <div class="mrow"><button type="button" class="btn btn-navy" data-act="modal-close">بستن و دیدن سایت</button></div>`, { wide: true });
  const apply = () => { A.applyTheme(); A.persist(); };
  /* ----- fonts: upload, preview, choose, remove ----- */
  const box = $('#fontbox-in', m), inp = $('#ff-file', m), pv = $('#ff-pv', m); let pend = null;
    const draw = () => { box.innerHTML = fontBoxInner(t, pend); pv.innerHTML = fontPreviewHtml(t); };
    const setFont = (v) => { t.font = v; draw(); apply(); };
    const sniff = (u) => { const h = String.fromCharCode(u[0], u[1], u[2], u[3]); if (h === 'wOF2') return 'woff2'; if (h === 'wOFF') return 'woff'; if (h === 'OTTO') return 'otf'; if (h === 'true' || (u[0] === 0 && u[1] === 1 && u[2] === 0 && u[3] === 0)) return 'ttf'; return ''; };
    const b64 = (buf) => { const u = new Uint8Array(buf); let r = ''; for (let i = 0; i < u.length; i += 0x8000) r += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(r); };
    inp.addEventListener('change', async () => {
      const files = Array.from(inp.files || []).slice(0, 8); inp.value = '';
      const ok = [];
      for (const file of files) {
        if (file.size > FONT_FILE_MAX) { toast(`«${file.name}» بزرگ‌تر از ۳ مگابایت است؛ نسخهٔ WOFF2 یا فشرده‌تر را بارگذاری کنید.`, true); continue; }
        const buf = await file.arrayBuffer(); const fmt = buf.byteLength > 4 ? sniff(new Uint8Array(buf, 0, 4)) : '';
        if (!fmt) { toast(`«${file.name}» فایل فونت معتبری نیست (فقط WOFF2، WOFF، TTF، OTF).`, true); continue; }
        if (window.FontFace) { try { await new FontFace('uf-check', buf.slice(0)).load(); } catch (x) { toast(`«${file.name}» خوانده نشد یا خراب است.`, true); continue; } }
        ok.push({ file, size: file.size, fmt, buf, w: guessFontWeight(file.name) });
      }
      if (!ok.length) return;
      pend = { name: guessFontName(ok[0].file.name), files: ok }; draw();
    });
    m.addEventListener('input', (e) => {
      if (!pend) return;
      if (e.target.matches('[data-ff-name]')) pend.name = e.target.value;
      else if (e.target.matches('[data-ff-w]')) pend.files[+e.target.dataset.ffW].w = e.target.value;
    });
    m.addEventListener('click', (e) => {
      const pick = e.target.closest('[data-font]'); if (pick) { setFont(pick.dataset.font); return; }
      const del = e.target.closest('[data-font-del]');
      if (del) {
        if (!window.confirm('این فونت حذف شود؟')) return;
        t.customFonts = (t.customFonts || []).filter((f) => f.id !== del.dataset.fontDel);
        if (!(t.customFonts || []).some((f) => 'custom:' + f.id === t.font) && String(t.font).startsWith('custom:')) t.font = 'vazirmatn';
        draw(); apply(); A.persist(true); return;
      }
      if (e.target.closest('[data-font-add]')) { if ((t.customFonts || []).length >= FONT_MAX) return toast('به حداکثر تعداد فونت دلخواه رسیده‌اید؛ یکی را حذف کنید.', true); inp.click(); return; }
      if (e.target.closest('[data-font-cancel]')) { pend = null; draw(); return; }
      if (e.target.closest('[data-font-save]')) {
        if (!pend) return;
        const ws = pend.files.map((f) => f.w);
        if (new Set(ws).size !== ws.length) return toast('دو فایل وزن یکسان دارند؛ وزن هر فایل را متفاوت انتخاب کنید.', true);
        if (ws.includes('100 900') && ws.length > 1) return toast('فونت متغیر خودش همهٔ وزن‌ها را دارد؛ همراه فایل‌های دیگر نمی‌شود.', true);
        const id = 'f' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
        const files = pend.files.map((f) => ({ w: f.w, fmt: f.fmt, size: f.size, data: `data:font/${f.fmt};base64,${b64(f.buf)}` }));
        t.customFonts = [...(t.customFonts || []), { id, name: (pend.name || '').trim().slice(0, 40) || 'فونت من', files }];
        t.font = 'custom:' + id; pend = null; draw(); apply(); A.persist(true); toast('فونت اضافه و روی سایت اعمال شد؛ پیش‌نمایش زیر را ببینید.'); const pb = $('#ff-preview', m); if (pb) pb.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      }
    });
}
function openSettings() {
  const t = D().theme;
  const m = modal(`${mh('ظاهر سایت')}
    <div class="presets">${PRESETS.map((p, i) => `<div class="pfam" data-fam="${i}"><button type="button" class="preset" data-preset="${i}" aria-pressed="false"><i style="background:linear-gradient(90deg,${p.primary} 60%,${p.accent} 60%)"></i>${esc(p.n)}</button>${p.v && p.v.length ? `<button type="button" class="pfam-t" data-fam-toggle="${i}" aria-expanded="false" aria-controls="pfv-${i}" aria-label="رنگ‌های مشابه ${escAttr(p.n)}" title="رنگ‌های مشابه">${icon('chevd')}</button><div class="pfam-v" id="pfv-${i}" role="group" aria-label="رنگ‌های مشابه ${escAttr(p.n)}" hidden><span class="pfam-cap" aria-hidden="true">رنگ‌های مشابه</span>${p.v.map((v, j) => `<button type="button" class="pv" data-preset="${i}" data-var="${j}" aria-pressed="false"><i style="background:linear-gradient(90deg,${v.primary} 60%,${v.accent} 60%)"></i><span>${esc(v.n)}</span></button>`).join('')}</div>` : ''}</div>`).join('')}</div>
    <div class="srow"><div><div class="t">رنگ اصلی</div><div class="d">سرتیترها، دکمه‌ها و پنل‌های تیره</div></div><span class="swatch"><code data-code="primary">${t.primary}</code><input type="color" data-t="primary" value="${t.primary}"></span></div>
    <div class="srow"><div><div class="t">رنگ تأکیدی</div><div class="d">آیکون‌ها، برچسب‌ها و هایلایت‌ها</div></div><span class="swatch"><code data-code="accent">${t.accent}</code><input type="color" data-t="accent" value="${t.accent}"></span></div>
    <div class="srow"><div><div class="t">رنگ متن‌ها</div></div><span class="swatch"><code data-code="text">${t.text}</code><input type="color" data-t="text" value="${t.text}"></span></div>
    <div class="srow"><div><div class="t">فونت‌ها</div><div class="d">بارگذاری، انتخاب و حذف فونت سایت (بخش جداگانه)</div></div><button type="button" class="btn btn-soft sm" data-open-fonts>${icon('type')} مدیریت فونت‌ها</button></div>
    <div class="srow"><div><div class="t">اندازه کلی متن‌ها</div><div class="d"><span data-val="fontScale">${A.toFa(t.fontScale)}</span>٪</div></div><input type="range" class="slider" data-r="fontScale" min="85" max="120" step="1" value="${t.fontScale}"></div>
    <div class="srow"><div><div class="t">گردی گوشه‌ها</div><div class="d"><span data-val="radius">${A.toFa(t.radius)}</span>٪</div></div><input type="range" class="slider" data-r="radius" min="0" max="100" step="5" value="${t.radius}"></div>
    <div class="srow"><div><div class="t">شفافیت تصویر پس‌زمینه هیرو</div><div class="d"><span data-val="heroImgOpacity">${A.toFa(t.heroImgOpacity)}</span>٪ — فقط روی تصویر اعمال می‌شود، نه متن و دکمه‌ها</div></div><div class="hop"><input type="range" class="slider" data-r="heroImgOpacity" min="0" max="100" step="1" value="${t.heroImgOpacity}" aria-label="شفافیت تصویر پس‌زمینه هیرو"><button type="button" class="btn btn-soft sm" data-hero-op-reset>پیش‌فرض</button></div></div>
    ${D().company.heroImage ? `<div class="hop-prev" aria-hidden="true"><img src="${escAttr(D().company.heroImage)}" alt="" style="opacity:${t.heroImgOpacity / 100}"></div>` : ''}
    <div class="srow"><div><div class="t">حالت پیش‌فرض برای بازدیدکننده</div><div class="d">هر کاربر می‌تواند از هدر تغییر دهد</div></div><span class="seg" data-seg="darkDefault"><button type="button" data-v="light" class="${t.darkDefault === 'light' ? 'on' : ''}">روشن</button><button type="button" data-v="dark" class="${t.darkDefault === 'dark' ? 'on' : ''}">تیره</button><button type="button" data-v="system" class="${t.darkDefault === 'system' ? 'on' : ''}">سیستم</button></span></div>
    <div class="srow"><div><div class="t">دکمه روشن/تیره در هدر</div></div><button type="button" class="switch ${t.showThemeToggle !== false ? 'on' : ''}" data-sw="showThemeToggle"></button></div>
    <div class="srow"><div><div class="t">انیمیشن‌ها</div><div class="d">ظاهر شدن تدریجی بخش‌ها هنگام اسکرول</div></div><button type="button" class="switch ${t.animations ? 'on' : ''}" data-sw="animations"></button></div>
    <div class="srow"><div><div class="t">اسکرول نرم</div></div><button type="button" class="switch ${t.smoothScroll ? 'on' : ''}" data-sw="smoothScroll"></button></div>
    <div class="mrow"><button type="button" class="btn btn-navy" data-act="modal-close">بستن</button><button type="button" class="btn btn-soft" data-reset-theme>${icon('reset')} بازگشت به پیش‌فرض</button></div>`);
  const apply = () => { A.applyTheme(); A.persist(); };
  const dropScheme = () => { if (t.scheme && t.scheme.id !== 'original') { t.scheme = { id: 'original' }; A.setSchemePreview(null); toast('تم رنگی سایت به حالت اصلی برگشت تا رنگ‌های بخش «ظاهر» اعمال شود.'); } };
  /* the active preset/variation is derived from the saved colours, so themes saved before families existed still show as selected */
  const same = (x, y) => String(x || '').toLowerCase() === String(y || '').toLowerCase();
  const presetColors = (i, j) => { const b = PRESETS[i], s = j == null ? b : b.v[j]; return { primary: s.primary, accent: s.accent, text: s.text || b.text }; };
  const syncPresets = () => {
    $$('.pfam', m).forEach((f) => {
      const i = +f.dataset.fam; let inner = false;
      $$('[data-preset]', f).forEach((b) => {
        const c = presetColors(i, b.dataset.var === undefined ? null : +b.dataset.var);
        const on = same(t.primary, c.primary) && same(t.accent, c.accent) && same(t.text, c.text);
        b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on));
        if (on && b.dataset.var !== undefined) inner = true;
      });
      f.classList.toggle('has-on', inner);
    });
  };
  syncPresets();
  m.addEventListener('input', (e) => {
    const el = e.target;
    if (el.dataset.t) { dropScheme(); t[el.dataset.t] = el.value; m.querySelector(`[data-code="${el.dataset.t}"]`).textContent = el.value; apply(); syncPresets(); }
    if (el.dataset.r) { t[el.dataset.r] = +el.value; m.querySelector(`[data-val="${el.dataset.r}"]`).textContent = A.toFa(el.value); apply(); if (el.dataset.r === 'heroImgOpacity') { const pi = m.querySelector('.hop-prev img'); if (pi) pi.style.opacity = t.heroImgOpacity / 100; } }
  });
  m.addEventListener('click', (e) => {
    if (e.target.closest('[data-open-fonts]')) { closeModal(); openFonts(); return; }
    const ft = e.target.closest('[data-fam-toggle]');
    if (ft) { const open = ft.getAttribute('aria-expanded') !== 'true'; ft.setAttribute('aria-expanded', String(open)); const pv = m.querySelector('#pfv-' + ft.dataset.famToggle); if (pv) pv.hidden = !open; return; }
    const p = e.target.closest('[data-preset]'); if (p) { dropScheme(); Object.assign(t, presetColors(+p.dataset.preset, p.dataset.var === undefined ? null : +p.dataset.var)); ['primary', 'accent', 'text'].forEach((k) => { m.querySelector(`[data-t="${k}"]`).value = t[k]; m.querySelector(`[data-code="${k}"]`).textContent = t[k]; }); apply(); syncPresets(); return; }
    const sw = e.target.closest('[data-sw]'); if (sw) { t[sw.dataset.sw] = !sw.classList.contains('on'); sw.classList.toggle('on'); apply(); if (sw.dataset.sw === 'showThemeToggle' || sw.dataset.sw === 'animations') A.render(true); return; }
    const sg = e.target.closest('[data-seg] button'); if (sg) { const seg = sg.closest('[data-seg]'); t[seg.dataset.seg] = sg.dataset.v; $$('button', seg).forEach((b) => b.classList.toggle('on', b === sg)); apply(); if (seg.dataset.seg === 'darkDefault') { try { localStorage.removeItem(A.THEME_KEY || 'site_theme'); } catch (x) { /* ignore */ } A.initDark(); A.applyTheme(); } return; }
    if (e.target.closest('[data-hero-op-reset]')) {
      const dv = A.defaults().theme.heroImgOpacity; t.heroImgOpacity = dv;
      const sl = m.querySelector('[data-r="heroImgOpacity"]'); if (sl) sl.value = dv;
      m.querySelector('[data-val="heroImgOpacity"]').textContent = A.toFa(dv);
      const pi = m.querySelector('.hop-prev img'); if (pi) pi.style.opacity = dv / 100;
      apply(); return;
    }
    if (e.target.closest('[data-reset-theme]')) { const keepFonts = t.customFonts; Object.assign(t, A.defaults().theme); t.customFonts = keepFonts; closeModal(); apply(); A.render(true); openSettings(); }
  });
}
/* ---------- hero image: shadow / fade panel (opened from the hero's own image controls, live) ---------- */
function openHeroFx() {
  const old = document.getElementById('herofx'); if (old) { old.remove(); return; }
  const t = D().theme, dd = A.defaults().theme;
  const rows = [['heroImgOpacity', 'شفافیت تصویر', 'فقط تصویر؛ متن و دکمه‌ها تغییر نمی‌کنند'], ['heroFadePos', 'میزان پوشش تصویر', 'بیشتر = تصویر بیشتری دیده می‌شود و از سمت چپ دیرتر محو می‌شود'], ['heroFadeHard', 'سختی لبهٔ محو', 'کمتر = محو نرم‌تر و طولانی‌تر؛ بیشتر = لبهٔ تیزتر']];
  const p = document.createElement('div'); p.id = 'herofx'; p.className = 'herofx'; p.setAttribute('role', 'dialog'); p.setAttribute('aria-label', 'سایه و محو تصویر هیرو');
  p.innerHTML = `<h4>سایه و محو تصویر هیرو<button type="button" class="btn btn-soft sm" data-x aria-label="بستن">بستن</button></h4>` +
    rows.map(([k, l, d]) => `<div class="srow"><div><div class="t">${l}</div><div class="d"><span data-v="${k}">${A.toFa(t[k])}</span>٪ — ${d}</div></div><input type="range" class="slider" data-k="${k}" min="0" max="100" step="1" value="${t[k]}" aria-label="${l}"></div>`).join('') +
    `<div class="row2"><button type="button" class="btn btn-soft sm" data-reset>بازگشت به پیش‌فرض</button></div>`;
  document.body.appendChild(p);
  const upd = (k) => { p.querySelector(`[data-v="${k}"]`).textContent = A.toFa(t[k]); A.applyTheme(); A.persist(); };
  p.addEventListener('input', (e) => { const k = e.target.dataset.k; if (!k) return; t[k] = +e.target.value; upd(k); });
  p.addEventListener('click', (e) => {
    if (e.target.closest('[data-x]')) { p.remove(); return; }
    if (e.target.closest('[data-reset]')) rows.forEach(([k]) => { t[k] = dd[k]; p.querySelector(`[data-k="${k}"]`).value = dd[k]; upd(k); });
  });
  const guard = () => { if (!A.S.edit || !document.body.contains(p)) { p.remove(); document.removeEventListener('click', guard, true); } };
  document.addEventListener('click', guard, true);
}
/* ---------- hover effects panel (live, non-blocking: the site stays hoverable while it is open) ---------- */
function openHoverFx() {
  const old = document.getElementById('hoverfx'); if (old) { old.remove(); return; }
  closeModal();
  const sch = document.getElementById('schemefx'); if (sch) { const c = sch.querySelector('[data-sfx="cancel"]'); if (c) c.click(); }
  const groups = A.HOVER_GROUPS, ids = groups.flatMap((g) => g.items.map((i) => i[0]));
  const H = () => { const d = D(); if (!d.hover || !Array.isArray(d.hover.off)) d.hover = { off: [] }; return d.hover; };
  const isOn = (id) => !H().off.includes(id);
  const commit = (off) => { H().off = ids.filter((id) => off.includes(id)); A.applyHover(); A.persist(); sync(); }; /* only data-hv-off changes: no re-render, no other setting is touched */
  const row = ([id, t, d]) => `<div class="srow"><div><div class="t">${esc(t)}</div><div class="d">${esc(d)}</div></div><button type="button" class="switch ${isOn(id) ? 'on' : ''}" role="switch" aria-checked="${isOn(id)}" aria-label="${escAttr(t)}" data-hv="${id}"></button></div>`;
  const el = document.createElement('div'); el.id = 'hoverfx'; el.className = 'schemefx hoverfx'; el.setAttribute('role', 'dialog'); el.setAttribute('aria-label', 'هاورها');
  el.innerHTML = `<div class="sfx-h"><span>هاورها <small style="font-weight:500;color:var(--muted)">Hover Effects</small></span><button type="button" data-hx="x" aria-label="بستن">${icon('x')}</button></div>
    <div class="sfx-b">
      <p class="sfx-status" data-s="count" aria-live="polite"></p>
      <div class="hx-bulk"><button type="button" class="btn btn-soft sm" data-hx="all-on">روشن کردن همه</button><button type="button" class="btn btn-soft sm" data-hx="all-off">خاموش کردن همه</button><button type="button" class="btn btn-soft sm" data-hx="defaults">بازگشت به پیش‌فرض</button></div>
      ${groups.map((g) => `<div class="sfx-t">${esc(g.title)}</div>${g.items.map(row).join('')}`).join('')}
      <div class="hintbox" style="margin-bottom:6px">تغییرها همان لحظه روی سایت اعمال و ذخیره می‌شوند. این تنظیم‌ها فقط برای ماوس و تاچ‌پد است؛ روی گوشی و تبلت، افکت تا زمانی که انگشت روی کارت است (حتی هنگام اسکرول) فعال می‌ماند و با برداشتن انگشت خاموش می‌شود. برای دیدن دقیق افکت‌ها، حالت ویرایش را خاموش کنید.</div>
    </div>`;
  document.body.appendChild(el);
  function sync() {
    const n = ids.filter(isOn).length;
    el.querySelector('[data-s="count"]').textContent = `${A.toFa(n)} از ${A.toFa(ids.length)} افکت فعال است`;
    $$('[data-hv]', el).forEach((b) => { const on = isOn(b.dataset.hv); b.classList.toggle('on', on); b.setAttribute('aria-checked', String(on)); });
  }
  const bulk = (target, msg) => { const cur = H().off, next = target.filter((id) => ids.includes(id)); const changed = ids.filter((id) => cur.includes(id) !== next.includes(id)).length; if (!changed) { toast('تغییری لازم نبود.'); return; } if (changed > 1 && !confirm(msg(changed))) return; commit(next); };
  el.addEventListener('click', (e) => {
    const sw = e.target.closest('[data-hv]');
    if (sw) { const id = sw.dataset.hv, off = H().off.slice(), i = off.indexOf(id); if (i >= 0) off.splice(i, 1); else off.push(id); commit(off); return; }
    const a = e.target.closest('[data-hx]'); if (!a) return;
    if (a.dataset.hx === 'x') { el.remove(); return; }
    if (a.dataset.hx === 'all-on') bulk([], (n) => `هاور ${A.toFa(n)} بخش دوباره روشن شود؟`);
    if (a.dataset.hx === 'all-off') bulk(ids, (n) => `هاور ${A.toFa(n)} بخش خاموش شود؟ (کارت‌ها و دکمه‌ها همچنان کار می‌کنند؛ فقط افکت اشاره‌گر حذف می‌شود.)`);
    if (a.dataset.hx === 'defaults') bulk(A.defaults().hover.off, (n) => `تنظیم هاور ${A.toFa(n)} بخش به حالت پیش‌فرض برگردد؟`);
  });
  sync();
}
/* ---------- sections ---------- */
function openSections() {
  const d = D();
  const items = [['hero', 'هدر اصلی (معرفی)'], ['stats', 'آمار و ارقام'], ['about', 'درباره ما'], ['services', 'خدمات'], ['process', 'روند همکاری'], ['portfolio', 'نمونه کارها (در صفحه اصلی)'], ['clients', 'همکاران و مشتریان'], ['contact', 'ارتباط با ما']];
  const navKeys = [['home', 'خانه'], ['about', 'درباره ما'], ['services', 'خدمات'], ['process', 'روند همکاری'], ['portfolio', 'نمونه کارها'], ['contact', 'ارتباط با ما']];
  const m = modal(`${mh('بخش‌های سایت')}<p class="desc">بخش‌هایی را که نمی‌خواهید نمایش داده شوند خاموش کنید؛ محتوای آن‌ها حذف نمی‌شود.</p>
    ${items.map(([k, l]) => `<div class="srow"><div class="t">${l}</div><button type="button" class="switch ${d.sections[k].on !== false ? 'on' : ''}" data-sec="${k}"></button></div>`).join('')}
    <div class="hintbox" style="margin-top:18px">برای تغییر عنوان‌های منو، در حالت ویرایش مستقیماً روی عنوان در هدر سایت کلیک کنید؛ نوار قالب‌بندی (رنگ، اندازه، ضخامت) همان‌جا ظاهر می‌شود.</div>
    <div class="mrow"><button type="button" class="btn btn-navy" data-act="modal-close">بستن</button></div>`);
  m.addEventListener('click', (e) => { const b = e.target.closest('[data-sec]'); if (!b) return; d.sections[b.dataset.sec].on = !b.classList.contains('on'); b.classList.toggle('on'); A.persist(); A.render(true); });
}
/* ---------- backup / restore / export ---------- */
function exportJSON() { download(`site-backup-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify({ ...D(), admin: {} }, null, 2), 'application/json'); }
/* minimal ZIP writer (stored, no compression) so one click delivers every file of the multi-page site */
const CRC_T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(b) { let c = 0xFFFFFFFF; for (let i = 0; i < b.length; i++) c = CRC_T[(c ^ b[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
function makeZip(files) {
  const enc = new TextEncoder(), now = new Date();
  const tm = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1), dt = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  const parts = [], central = []; let off = 0;
  files.forEach((f) => {
    const nm = enc.encode(f.name), data = enc.encode(f.text), crc = crc32(data);
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true); lh.setUint16(8, 0, true); lh.setUint16(10, tm, true); lh.setUint16(12, dt, true);
    lh.setUint32(14, crc, true); lh.setUint32(18, data.length, true); lh.setUint32(22, data.length, true); lh.setUint16(26, nm.length, true); lh.setUint16(28, 0, true);
    parts.push(new Uint8Array(lh.buffer), nm, data);
    const ch = new DataView(new ArrayBuffer(46));
    ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true); ch.setUint16(8, 0x0800, true); ch.setUint16(10, 0, true); ch.setUint16(12, tm, true); ch.setUint16(14, dt, true);
    ch.setUint32(16, crc, true); ch.setUint32(20, data.length, true); ch.setUint32(24, data.length, true); ch.setUint16(28, nm.length, true); ch.setUint32(42, off, true);
    central.push(new Uint8Array(ch.buffer), nm);
    off += 30 + nm.length + data.length;
  });
  const csize = central.reduce((n, x) => n + x.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true); end.setUint32(12, csize, true); end.setUint32(16, off, true);
  return new Blob([...parts, ...central, new Uint8Array(end.buffer)], { type: 'application/zip' });
}
function exportHTML(mode) {
  const editable = mode === 'editable';
  const name = editable ? 'site-editable.zip' : 'site-public.zip';
  A.updateFavicon(); /* make sure the tab icon matches the current logo before the pages are copied */
  if (A.favPending()) { A.favReady().then(() => exportHTML(mode)); return name; }
  const compName = String((D().company && D().company.name) || '').trim();
  const titles = { home: compName || 'سایت', portfolio: (compName ? compName + ' — ' : '') + (D().nav && D().nav.portfolio || 'نمونه کارها') };
  const hv = ((D().hover && D().hover.off) || []).filter((id) => A.HOVER_GROUPS.some((g) => g.items.some((i) => i[0] === id)));
  const buildPage = (pg) => {
    const root = document.documentElement.cloneNode(true);
    { const uf = root.querySelector('#user-fonts'); if (uf) uf.remove(); } /* font data lives once, inside the site data; applyTheme rebuilds the stylesheet on load */
    root.removeAttribute('style'); root.className = ''; root.setAttribute('data-site-mode', editable ? 'editable' : 'public'); root.setAttribute('data-page', pg);
    const body = root.querySelector('body'); body.className = ''; body.removeAttribute('style');
    if (hv.length) root.setAttribute('data-hv-off', hv.join(' ')); else root.removeAttribute('data-hv-off'); /* saved hover configuration travels with both exports */
    { const sp = root.querySelector('.spbar'); if (sp) { sp.classList.remove('off'); const f = sp.firstElementChild; if (f) f.removeAttribute('style'); } } /* scroll progress: reset live state */
    { const nl = root.querySelector('.nl'); if (nl) { nl.className = 'nl'; const f = nl.firstElementChild; if (f) f.removeAttribute('style'); } } /* navigation progress: reset live state */
    /* transient UI never belongs in a file: toolbar, dialogs, popovers, toasts, lightbox, hero-fade panel */
    $$('.admin-bar,.modal-bg,.navsel-bg,.toast,.tbar,.ipick,.linkpick,.lightbox,.to-top,.herofx,.schemefx,.hoverfx', root).forEach((n) => n.remove());
    const app = root.querySelector('#app'); if (app) app.innerHTML = '';
    { const se = root.querySelector('#scheme-vars'); if (se) { se.textContent = A.schemeCss(D().theme.scheme); se.setAttribute('data-export', '1'); } } /* saved scheme only - never a live preview */
    { const t = root.querySelector('title'); if (t) t.textContent = titles[pg]; }
    if (!editable) $$('script[src="admin.js"]', root).forEach((sc) => sc.remove()); /* public pages carry no admin code at all */
    return '<!DOCTYPE html>\n' + root.outerHTML;
  };
  /* Public: no verifier, publicMode true (no login entry, no admin script). Editable: publicMode false keeps "ورود مدیر"; only the salted verifier is embedded so the login dialog (not first-time setup) appears after deployment */
  const adm = D().admin || {};
  const verifier = (editable && adm.hash && adm.salt) ? { salt: adm.salt, hash: adm.hash, ...(adm.kdf ? { kdf: adm.kdf } : {}) } : {}; /* salt+hash only; no plaintext */
  const data = JSON.parse(JSON.stringify({ ...D(), admin: verifier, publicMode: !editable, updatedAt: Date.now() }));
  if (!editable && data.theme) data.theme.customFonts = (data.theme.customFonts || []).filter((f) => 'custom:' + f.id === data.theme.font); /* the public file only carries the font actually in use */
  (function strip(o) { if (Array.isArray(o)) o.forEach(strip); else if (o && typeof o === 'object') Object.keys(o).forEach((k) => { if (k.endsWith('_orig')) delete o[k]; else strip(o[k]); }); })(data);
  const dataJs = 'window.__SITE_DATA__=' + JSON.stringify(data).replace(/<\//g, '<\\/') + ';\n';
  const blob = makeZip([{ name: 'index.html', text: buildPage('home') }, { name: 'portfolio.html', text: buildPage('portfolio') }, { name: 'site-data.js', text: dataJs }]);
  const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
  return name;
}
function restoreFromText(text) {
  let raw; try { raw = JSON.parse(text); } catch (e) { return toast('فایل یا متن پشتیبان معتبر نیست.', true); }
  if (!raw || typeof raw !== 'object' || (!raw.company && !raw.portfolio)) return toast('ساختار فایل پشتیبان شناخته نشد.', true);
  const keepAdmin = D().admin; A.D = A.normalize(raw); A.D.admin = keepAdmin || {}; A.persist(true); closeModal(); A.initDark(); A.applyTheme(); A.render(true); toast('اطلاعات سایت بازیابی شد.');
}
function openBackup() {
  const size = A.fmtSize(A.sizeOf(D()));
  const m = modal(`${mh('پشتیبان‌گیری، بازیابی و خروجی')}
    <div class="srow"><div><div class="t">${icon('download')} دانلود فایل پشتیبان (JSON)</div><div class="d">تمام محتوا (متن‌ها، تصاویر، ویدیوها، تنظیمات). حجم فعلی: ${size}</div></div><button type="button" class="btn btn-soft sm" data-b="json">دانلود</button></div>
    <fieldset class="expbox"><legend class="t">${icon('code')} خروجی سایت نهایی (HTML)</legend>
      <label class="expopt"><input type="radio" name="exp-mode" value="public" checked><span><b>خروجی عمومی — بدون پنل مدیریت</b><small>فایل site-public.zip شامل index.html، portfolio.html و site-data.js برای بازدیدکنندگان؛ بدون نوار مدیریت، بدون «ورود مدیر» و بدون رمز یا اطلاعات مدیریتی. کلید روشن/تیره، منو و فیلترها کار می‌کنند.</small></span></label>
      <label class="expopt"><input type="radio" name="exp-mode" value="editable"><span><b>خروجی قابل ویرایش — همراه پنل مدیریت</b><small>فایل site-editable.zip (index.html، portfolio.html و site-data.js؛ فایل admin.js باید کنار آن‌ها باشد) با «ورود مدیر» و ویرایشگر؛ هنگام ساخت رمزی پرسیده نمی‌شود. رمز فعلی شما (فقط به‌صورت هش و نمک، نه متن اصلی) داخل فایل می‌رود و رمز در خود سایت میزبان هنگام «ورود مدیر» پرسیده می‌شود. این فقط کنترل سمت مرورگر است، نه احراز هویت روی سرور؛ ویرایش‌ها در مرورگر همان فرد می‌مانند و فایل روی هاست را تغییر نمی‌دهند. رمز قوی و طولانی انتخاب کنید.</small></span></label>
      <div class="mrow" style="margin-top:10px"><button type="button" class="btn btn-navy sm" data-b="html">ساخت فایل</button></div></fieldset>
    <div class="srow"><div><div class="t">${icon('upload')} بازیابی از فایل پشتیبان</div><div class="d">فایل JSON قبلی (نسخه قدیم سایت هم پشتیبانی می‌شود)</div></div><button type="button" class="btn btn-soft sm" data-b="file">انتخاب فایل</button></div>
    <label class="fld">یا متن پشتیبان را اینجا بچسبانید<textarea data-paste placeholder='{"version":4, ...}'></textarea></label>
    <div class="mrow" style="margin-top:8px"><button type="button" class="btn btn-soft sm" data-b="paste">بازیابی از متن</button></div>
    <div class="srow" style="margin-top:14px"><div><div class="t">${icon('key')} تغییر رمز مدیر</div><div class="d">رمز به‌صورت رمزنگاری‌شده فقط در همین مرورگر می‌ماند و در خروجی HTML و فایل پشتیبان قرار نمی‌گیرد.</div></div><button type="button" class="btn btn-soft sm" data-b="pw">تغییر</button></div>
    <div class="srow"><div><div class="t">${icon('reset')} بازنشانی کامل سایت</div><div class="d">همه محتوا به حالت اولیه برمی‌گردد (قابل بازگشت نیست — اول پشتیبان بگیرید).</div></div><button type="button" class="btn btn-danger sm" data-b="reset">بازنشانی</button></div>
    <div class="hintbox">توجه: تغییرات شما در همین مرورگر ذخیره می‌شود. برای اینکه بازدیدکننده‌ها هم محتوای جدید را ببینند، «خروجی سایت نهایی» را بسازید و سه فایل index.html، portfolio.html و site-data.js را روی هاست جایگزین کنید (فایل‌های site.css، site.js، nav-loader.js و admin.js تغییر نمی‌کنند).</div>
    <div class="mrow"><button type="button" class="btn btn-navy" data-act="modal-close">بستن</button></div>`, { wide: true });
  m.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-b]'); if (!b) return;
    const k = b.dataset.b;
    if (k === 'json') exportJSON();
    if (k === 'html') {
      const sel = m.querySelector('input[name="exp-mode"]:checked'); const mode = sel && sel.value === 'editable' ? 'editable' : 'public';
      /* the editable file can only be used after deployment if the password verifier exists; it is never created silently */
      if (mode === 'editable' && !(D().admin && D().admin.hash && D().admin.salt)) { toast('برای خروجی قابل ویرایش ابتدا رمز مدیر را تعیین کنید؛ سپس دوباره «ساخت فایل» را بزنید.', true); openSetPassword(); return; }
      const nm = exportHTML(mode); toast('فایل ' + nm + ' ساخته شد.');
    }
    if (k === 'file') { const f = await pickFiles('.json,application/json'); if (!f[0]) return; restoreFromText(await f[0].text()); }
    if (k === 'paste') { const t = m.querySelector('[data-paste]').value.trim(); if (t) restoreFromText(t); }
    if (k === 'pw') openPassword();
    if (k === 'reset') { if (!confirm('همه محتوای سایت به حالت اولیه برمی‌گردد. ادامه می‌دهید؟')) return; const keepAdmin = D().admin; A.D = A.normalize(null); A.D.admin = keepAdmin || {}; A.persist(true); try { localStorage.removeItem(A.STORE_KEY); } catch (x) { /* ignore */ } closeModal(); A.initDark(); A.applyTheme(); A.render(true); toast('سایت بازنشانی شد.'); }
  });
}
function openPassword() {
  const m = modal(`${mh('تغییر رمز مدیر')}<label class="fld">رمز فعلی<input type="password" dir="ltr" data-p="old"></label><label class="fld">رمز جدید (حداقل ۸ کاراکتر)<input type="password" dir="ltr" data-p="new"></label><label class="fld">تکرار رمز جدید<input type="password" dir="ltr" data-p="new2"><span class="err hidden"></span></label><div class="mrow"><button type="button" class="btn btn-navy" data-ok>ذخیره</button><button type="button" class="btn btn-soft" data-act="modal-close">انصراف</button></div>`);
  m.querySelector('[data-ok]').onclick = async () => {
    const o = m.querySelector('[data-p="old"]').value, n = m.querySelector('[data-p="new"]').value, n2 = m.querySelector('[data-p="new2"]').value, err = m.querySelector('.err');
    const fail = (t) => { err.textContent = t; err.classList.remove('hidden'); };
    if (!(await checkPw(o))) return fail('رمز فعلی اشتباه است.');
    if (n.length < 8) return fail('رمز جدید باید حداقل ۸ کاراکتر باشد.');
    if (n !== n2) return fail('تکرار رمز یکسان نیست.');
    await setPw(n); closeModal(); toast('رمز مدیر تغییر کرد.');
  };
}

window.__ADMIN__ = { init() { renderBar(); }, renderBar };
})();

