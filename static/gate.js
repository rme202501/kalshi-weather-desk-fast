/* Sign-in for the GitHub Pages copy of the desk (pipeline/dashboard/publish.py, access.py). Only that copy loads
   this file: the localhost / Tailscale page has no sign-in. No account can be made here; users exist only in
   access.py's store on the mini. A user's key is Argon2id(username + "\n" + password, the site salt) (hash-wasm,
   vendored); it unwraps the desk keys from one of data/keys.json's slots, which open the AES-256-GCM data files
   (stored under HMAC names), and the page's own markup and script, which are sealed the same way: signed out,
   a visitor gets nothing but this form. Signed in for this browser session, or on this device when asked. */
"use strict";
(function (root) {
  if (typeof document !== "undefined" && root.top !== root.self) { document.documentElement.textContent = ""; return; }  // never framed
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const tob64 = (u) => { let s = ""; for (const b of u) s += String.fromCharCode(b); return btoa(s); };
  const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
  const subtle = () => root.crypto.subtle;
  class Denied extends Error {}

  async function keys(base) {
    const r = await root.fetch(base + "data/keys.json", { cache: "no-store" });
    if (!r.ok) throw new Error("data/keys.json " + r.status);
    return r.json();
  }
  async function userKey(name, password, ks) {
    if (!root.hashwasm) throw new Error("the sign-in library did not load");
    const k = ks.kdf;
    return root.hashwasm.argon2id({ password: name + "\n" + password, salt: b64(ks.salt), parallelism: k.p,
      iterations: k.t, memorySize: k.m, hashLength: 32, outputType: "binary" });
  }
  async function unwrap(ukey, ks) {
    const kk = await subtle().importKey("raw", ukey, "AES-GCM", false, ["decrypt"]);
    for (const s of ks.slots) {
      let sec;
      try { sec = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: b64(s.iv), additionalData: enc.encode(ks.kid) }, kk, b64(s.wk))); }
      catch { continue; }                                          // not this user's slot (or a decoy)
      return { kid: ks.kid,
        dk: await subtle().importKey("raw", sec.slice(0, 32), "AES-GCM", false, ["decrypt"]),
        nk: await subtle().importKey("raw", sec.slice(32, 64), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]) };
    }
    throw new Denied("wrong username or password");
  }
  async function fileName(desk, path) {
    return "data/" + hex(new Uint8Array(await subtle().sign("HMAC", desk.nk, enc.encode(path)))).slice(0, 32) + ".bin";
  }
  async function inflate(z) {
    const s = new Blob([z]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }
  async function open(desk, path, buf) {
    const b = new Uint8Array(buf), magic = dec.decode(b.subarray(0, 4));
    if ((magic !== "KWP2" && magic !== "KWP3") || hex(b.subarray(4, 12)) !== desk.kid) return null;   // under other keys
    const pt = new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: b.subarray(12, 24), additionalData: enc.encode(path) }, desk.dk, b.subarray(24)));
    if (magic === "KWP2") return dec.decode(pt);
    const n = new DataView(pt.buffer, pt.byteOffset, 4).getUint32(0);   // KWP3: length, gzip member, zero padding
    return dec.decode(await inflate(pt.subarray(4, 4 + n)));
  }
  // a session: the user's key -> the desk keys, refetched when a publish rotated them; get(path) -> the JSON
  function session(ukey, base = "", onDenied = () => {}) {
    let desk = null;
    async function refresh() {
      try { desk = await unwrap(ukey, await keys(base)); }
      catch (e) { if (e instanceof Denied) onDenied(); throw e; }
    }
    async function text(path, again = true) {
      if (!desk) await refresh();
      const r = await root.fetch(base + await fileName(desk, path), { cache: "no-store" });
      if (!r.ok && r.status !== 404) throw new Error(path + " " + r.status);
      const body = r.ok ? await open(desk, path, await r.arrayBuffer()) : null;
      if (body !== null) return body;
      const old = desk.kid;                                       // a 404 or other keys: did a publish rotate them?
      await refresh();
      if (!again || desk.kid === old) throw new Error(path + " " + (r.ok ? "is not readable yet" : 404));
      return text(path, false);
    }
    return { get: async (path) => JSON.parse(await text(path)), text, refresh };
  }
  const core = { keys, userKey, unwrap, fileName, open, session, Denied, b64, tob64 };
  if (typeof document === "undefined") { root.KWPGate = core; return; }          // node (tests)

  // ---------------------------------------------------------------- the page
  root.KWP_STATIC = true;
  const me = document.currentScript, { app: APP, page: PAGE, lib: LIB, libIntegrity: LIB_SRI } = me.dataset;
  const KEY = "desk.gate", MSG = "desk.gate.msg";
  const tryst = (f) => { try { return f(); } catch { return null; } };
  const saved = () => { for (const st of [sessionStorage, localStorage]) { const v = tryst(() => st.getItem(KEY)); if (v) return tryst(() => b64(v)); } return null; };
  const forget = () => { tryst(() => sessionStorage.removeItem(KEY)); tryst(() => localStorage.removeItem(KEY)); };
  const remember = (k, keep) => { forget(); tryst(() => (keep ? localStorage : sessionStorage).setItem(KEY, tob64(k))); };
  function signOut(msg) { forget(); if (msg) tryst(() => sessionStorage.setItem(MSG, msg)); location.reload(); }
  function load(src, integrity) {
    return new Promise((ok, bad) => {
      const s = document.createElement("script"); s.src = src;
      if (integrity) s.integrity = integrity;
      s.onload = ok; s.onerror = () => bad(new Error("could not load " + src.split("?")[0]));
      document.body.appendChild(s);
    });
  }

  async function start(ukey) {
    const s = session(ukey, "", () => signOut("Your access has changed. Sign in again."));
    root.KWP_GATE = { get: s.get };
    let page, app;
    try { [page, app] = await Promise.all([s.text(PAGE), s.text(APP)]); }
    catch (e) { if (e instanceof Denied) return; form("Could not open the desk: " + e.message); return; }
    document.body.innerHTML = page;                                // the page's own markup, opened
    const b = document.createElement("button");
    b.className = "iconbtn"; b.type = "button"; b.id = "signout"; b.textContent = "Sign out";
    b.addEventListener("click", () => signOut());
    const th = document.getElementById("theme");
    if (th) th.after(b); else document.querySelector(".top")?.appendChild(b);
    const url = URL.createObjectURL(new Blob([app], { type: "text/javascript" }));
    return load(url).finally(() => URL.revokeObjectURL(url));
  }

  function form(msg) {
    const t = tryst(() => JSON.parse(localStorage.getItem("desk.theme")));     // the desk's own theme choice
    if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
    const lib = load(LIB, LIB_SRI);
    lib.catch(() => {});
    const g = document.createElement("div");
    g.className = "gate";
    g.innerHTML = `<form class="gate-card" novalidate>
  <div class="brand"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="2" width="6" height="14" rx="3" fill="currentColor"/><circle cx="12" cy="18" r="4.5" fill="var(--market)"/></svg>Weather desk</div>
  <h1>Sign in</h1>
  <p class="muted">Access is by invitation only.</p>
  <label>Username<input name="u" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" required></label>
  <label>Password<input name="p" type="password" autocomplete="current-password" required></label>
  <label class="gate-keep"><input name="keep" type="checkbox"> Keep me signed in on this device</label>
  <button class="iconbtn gate-go" type="submit">Sign in</button>
  <p class="gate-err" role="alert"></p>
</form>`;
    document.body.appendChild(g);
    const f = g.querySelector("form"), err = g.querySelector(".gate-err"), go = g.querySelector(".gate-go");
    if (msg) err.textContent = msg;
    f.u.focus();
    f.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const u = f.u.value.trim().toLowerCase(), p = f.p.value;
      if (!u || !p) { err.textContent = "Enter your username and password."; return; }
      go.disabled = true; go.textContent = "Signing in…"; err.textContent = "";
      try {
        await lib;
        const ks = await keys("");
        const k = await userKey(u, p, ks);
        await unwrap(k, ks);
        remember(k, f.keep.checked);
        f.p.value = "";
        g.remove();
        await start(k);
      } catch (e) {
        err.textContent = e instanceof Denied ? "Wrong username or password." : "Could not sign in: " + e.message;
        go.disabled = false; go.textContent = "Sign in";
        f.p.select();
      }
    });
  }

  const k = saved();
  const msg = tryst(() => sessionStorage.getItem(MSG));
  tryst(() => sessionStorage.removeItem(MSG));
  if (k) start(k); else form(msg);
})(globalThis);
