#!/usr/bin/env python3
"""Local iCloud promo cleanup.

Setup:   pip install flask
Run:     python promo_cleanup.py   then open http://127.0.0.1:5000
Needs:   an app-specific password (account.apple.com > Sign-In and Security).
Privacy: only message headers are fetched. Nothing leaves your machine except
         the unsubscribe requests themselves. Credentials live in memory only.

How it works:
  1. The page (served at "/") sends your credentials to this local server.
  2. /api/scan reads message headers over IMAP and groups every sender that
     includes a List-Unsubscribe header (the marker of bulk/marketing mail).
     iCloud's own "Promotions" tag is not exposed over IMAP, so this header is
     used as the stand-in.
  3. You select senders in the page, then press "Update Preferences".
  4. /api/unsubscribe unsubscribes each one by the safest available method.

Files created next to this script:
  unsubscribe_log.jsonl  audit log of every attempt (dry runs included)
  unsubscribed.json      senders already unsubscribed, hidden on later scans
"""
# Standard library only, plus Flask for the local web server.
import email, imaplib, json, re, smtplib, ssl, time, urllib.request
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlparse, parse_qs, unquote

from flask import Flask, jsonify, request

# --- Configuration ---
# iCloud mail servers: IMAP to read headers, SMTP to send mailto-style unsubscribes.
IMAP_HOST, SMTP_HOST = "imap.mail.me.com", "smtp.mail.me.com"
# Append-only audit log of every unsubscribe attempt, including dry runs.
LOG = "unsubscribe_log.jsonl"
# Persistent {sender address: time unsubscribed}, so rescans can hide handled senders.
UNSUB_FILE = "unsubscribed.json"
GRACE = timedelta(days=10)  # senders legally get ~10 days to stop
# Fetch only the headers we need. BODY.PEEK avoids marking messages as read.
HDRS = "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST)])"
# --- Session state (lives in memory only) ---
app = Flask(__name__)
# Credentials for the SMTP step, plus the latest scan keyed by sender address
# so /api/unsubscribe can look senders up by id.
STATE = {"email": None, "password": None, "senders": {}}


def dh(v):
    """Decode an encoded header (e.g. '=?UTF-8?B?...?=') to plain text; return the raw value on failure."""
    try:
        return str(make_header(decode_header(v or "")))
    except Exception:
        return v or ""


def load_unsub():
    """Return {sender address: datetime unsubscribed} from UNSUB_FILE, or {} if missing or unreadable."""
    try:
        with open(UNSUB_FILE) as f:
            return {k: datetime.fromisoformat(v) for k, v in json.load(f).items()}
    except Exception:
        return {}


def save_unsub(addr):
    """Record that we just unsubscribed from `addr` (UTC timestamp), keeping earlier entries."""
    try:
        with open(UNSUB_FILE) as f:
            d = json.load(f)
    except Exception:
        d = {}
    d[addr] = datetime.now(timezone.utc).isoformat()
    with open(UNSUB_FILE, "w") as f:
        json.dump(d, f)


def scan(addr, pw, limit):
    """
    Read the newest `limit` INBOX messages (headers only) and group marketing senders.

    A message counts as marketing if it has a List-Unsubscribe header. The mailbox
    is opened read-only, so nothing can be changed or deleted.

    Returns (senders, scanned, hidden):
      senders  list of dicts sorted by email count, highest first
      scanned  number of messages examined
      hidden   senders already unsubscribed that have stopped emailing, so they
               are left out. Ones still emailing after GRACE are kept and carry
               an "after" count (emails received since the grace period ended).
    """
    unsub = load_unsub()
    # Connect over SSL and log in. select(readonly=True) below guarantees we can't alter mail.
    M = imaplib.IMAP4_SSL(IMAP_HOST)
    M.login(addr, pw)
    M.select("INBOX", readonly=True)
    # IMAP lists oldest first, so slice off the newest `limit` messages.
    ids = M.search(None, "ALL")[1][0].split()[-limit:]
    senders, total = {}, len(ids)
    # Fetch headers in batches of 200 to keep each request small and fast.
    for i in range(0, total, 200):
        _, resp = M.fetch(b",".join(ids[i:i + 200]), HDRS)
        for part in resp:
            if not isinstance(part, tuple):
                continue
            msg = email.message_from_bytes(part[1])
            # No List-Unsubscribe header means it isn't bulk mail, so skip it.
            lu = msg.get("List-Unsubscribe")
            if not lu:
                continue
            # Group by the sender's email address, lowercased.
            name, a = parseaddr(dh(msg.get("From")))
            a = a.lower()
            if not a:
                continue
            # Parse the date to UTC; fall back to the earliest date if it is malformed.
            try:
                when = parsedate_to_datetime(msg.get("Date")).astimezone(timezone.utc)
            except Exception:
                when = datetime.min.replace(tzinfo=timezone.utc)
            # The header holds <...> entries: an https link and/or a mailto: address.
            items = re.findall(r"<([^>]+)>", lu)
            link = next((x for x in items if x.lower().startswith(("https:", "http:"))), None)
            mailto = next((x for x in items if x.lower().startswith("mailto:")), None)
            post = (msg.get("List-Unsubscribe-Post") or "").lower()
            # RFC 8058 one-click: an https link plus a List-Unsubscribe-Post header
            # means we can safely unsubscribe with a single automated POST.
            one_click = bool(link and link.lower().startswith("https:") and "one-click" in post)
            # One record per sender; the count accumulates across messages.
            s = senders.setdefault(a, {"id": a, "name": name or a, "address": a, "count": 0, "last": when})
            s["count"] += 1
            # Already unsubscribed? Count mail arriving after the grace period: that
            # means the sender ignored the request.
            u = unsub.get(a)
            if u and when > u + GRACE:
                s["after"] = s.get("after", 0) + 1
            # Keep the newest message's subject and unsubscribe details (old links may expire).
            if when >= s["last"] or "link" not in s:
                s.update(last=when, subject=dh(msg.get("Subject")), link=link, mailto=mailto, one_click=one_click)
    M.logout()
    # Build the result list, hiding senders we unsubscribed from unless they keep emailing.
    out, hidden = [], 0
    for s in senders.values():
        if s["id"] in unsub and not s.get("after"):
            hidden += 1  # unsubscribed and no new mail past the grace period
            continue
        # Method preference: one-click POST, then mailto, then a manual link.
        s["method"] = "one-click" if s["one_click"] else "mailto" if s["mailto"] else "link"
        s["last"] = s["last"].strftime("%Y-%m-%d")
        out.append(s)
    out.sort(key=lambda s: -s["count"])
    return out, total, hidden


def unsubscribe(s, dry):
    """
    Unsubscribe from one sender using the best method found in its headers.

    Returns {"status": ..., "detail": ...} where status is one of:
      "dry-run"  nothing sent, reports what would happen
      "done"     the vendor accepted the request (not proof that emails stop)
      "manual"   link-only sender; the user must open "link" and confirm
    Errors are raised and handled by the caller.
    """
    m = s["method"]
    # Dry run: report what would happen without sending anything.
    if dry:
        return {"status": "dry-run", "detail": f"Would use {m}"}
    # One-click: POST the standard form body; the vendor's server does the rest.
    if m == "one-click":
        req = urllib.request.Request(
            s["link"], data=b"List-Unsubscribe=One-Click", method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.status >= 400:
                raise RuntimeError(f"HTTP {r.status}")
        return {"status": "done", "detail": "One-click request accepted"}
    # Mailto: send the unsubscribe email from the user's own iCloud account over SMTP.
    if m == "mailto":
        u = urlparse(s["mailto"])
        q = parse_qs(u.query)
        msg = EmailMessage()
        msg["From"], msg["To"] = STATE["email"], unquote(u.path)
        msg["Subject"] = q.get("subject", ["unsubscribe"])[0]
        msg.set_content(q.get("body", ["unsubscribe"])[0])
        with smtplib.SMTP(SMTP_HOST, 587, timeout=20) as S:
            S.starttls(context=ssl.create_default_context())
            S.login(STATE["email"], STATE["password"])
            S.send_message(msg)
        return {"status": "done", "detail": "Unsubscribe email sent"}
    # Link-only: never auto-click. A link can confirm the address is live or go somewhere unsafe.
    return {"status": "manual", "detail": "Open the page and confirm yourself", "link": s["link"]}


@app.post("/api/scan")
def api_scan():
    """POST /api/scan: log in, scan, return {senders, scanned, hidden}. Credentials are kept in STATE for the unsubscribe step."""
    d = request.get_json()
    try:
        senders, total, hidden = scan(d["email"].strip(), d["password"].strip(), int(d.get("limit", 1000)))
    except imaplib.IMAP4.error as e:
        return jsonify(error=f"Login or mailbox error: {e}"), 400
    except Exception as e:
        return jsonify(error=str(e)), 400
    STATE.update(email=d["email"].strip(), password=d["password"].strip(),
                 senders={s["id"]: s for s in senders})
    return jsonify(senders=senders, scanned=total, hidden=hidden)


@app.post("/api/unsubscribe")
def api_unsub():
    """
    POST /api/unsubscribe with {ids: [...], dry: bool}.

    Returns {results: [{id, status, detail[, link]}]}, one entry per sender, where
    status is "done", "dry-run", "manual" or "error". Dry run is the default.
    """
    d = request.get_json()
    results = []
    for sid in d["ids"]:
        # Ignore ids that weren't part of the latest scan.
        s = STATE["senders"].get(sid)
        if not s:
            continue
        # One sender failing must not stop the rest of the batch.
        try:
            r = unsubscribe(s, d.get("dry", True))
        except Exception as e:
            r = {"status": "error", "detail": str(e)}
        r["id"] = sid
        # Remember real successes so later scans hide this sender.
        if r["status"] == "done":
            save_unsub(sid)
        results.append(r)
        # Audit trail of what was attempted and how it went.
        with open(LOG, "a") as f:
            f.write(json.dumps({"t": time.time(), "sender": sid, "dry": d.get("dry", True), **r}) + "\n")
        # Pause between real requests so we don't hammer vendors' servers.
        if not d.get("dry", True):
            time.sleep(1)
    return jsonify(results=results)


@app.get("/")
def home():
    """Serve the single-page UI."""
    return PAGE


# The entire front end is this one string, served at "/". It is a raw string so the
# JavaScript's backslashes survive. Sections inside: CSS, HTML, then JS.
PAGE = r"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Promo cleanup</title>
<style>
/* Color tokens: --acc is the brand teal, --bad marks selected/destructive state. */
:root{--bg:#eef1f4;--card:#fff;--ink:#1d2733;--mute:#5d6b7a;--line:#d5dce3;--acc:#0f6b6b;--bad:#b3261b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 "Avenir Next","Segoe UI",system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 16px 80px}
h1{font-size:28px;margin:0 0 4px}.sub{color:var(--mute);margin:0 0 24px}
form,.bar,.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
/* Sign-in form */
form{display:grid;grid-template-columns:1fr 1fr auto auto;gap:12px;align-items:end}
label{display:grid;gap:4px;font-size:14px;color:var(--mute)}
input,select{font:inherit;padding:9px 10px;border:1px solid var(--line);border-radius:6px;color:var(--ink);background:#fff}
button{font:inherit;padding:9px 16px;border-radius:6px;border:1px solid var(--acc);background:var(--acc);color:#fff;cursor:pointer}
button.ghost{background:#fff;color:var(--acc)}button.bad{background:var(--bad);border-color:var(--bad)}
button:disabled{opacity:.5;cursor:default}
:focus-visible{outline:3px solid #7fb8b8;outline-offset:2px}
/* Toolbar above the list: summary, filter box, Select all */
.bar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:20px 0 12px}
.bar .grow{flex:1;min-width:140px}.chk{display:flex;gap:6px;align-items:center;color:var(--ink);font-size:15px}
/* One card per sender */
#list{display:grid;gap:10px}.card{display:grid;grid-template-columns:1fr auto;gap:6px 16px}
.card h2{font-size:17px;margin:0}.meta,.subj{color:var(--mute);font-size:14px;margin:0}
.subj{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:48ch}
.badge{font-size:13px;border:1px solid var(--line);border-radius:99px;padding:1px 9px;margin-left:6px;color:var(--mute)}
.act{display:flex;gap:8px;align-items:center;grid-row:1/3;grid-column:2}
.st{grid-column:1/3;font-size:14px}.ok{color:var(--acc)}.err{color:var(--bad)}
/* Card states: gone = unsubscribed, sel = selected. .foot is the fixed bottom action bar. */
.card.gone{opacity:.6}.card.sel{border-color:var(--bad);background:#fdf1ef}button.sel{background:var(--bad);border-color:var(--bad);color:#fff}.foot{position:fixed;left:0;right:0;bottom:0;background:#fff;border-top:1px solid var(--line);padding:12px 16px;display:flex;gap:16px;align-items:center;justify-content:center;flex-wrap:wrap}
/* #msg = error text, #ok = success banner shown after Update Preferences */
#msg{margin-top:12px;color:var(--bad)}
#ok:not(:empty){background:#e4f2f0;border:1px solid var(--acc);border-radius:10px;padding:12px 16px;margin-bottom:12px;font-weight:600}
/* Phone layout: stack everything in one column */
@media(max-width:640px){form{grid-template-columns:1fr}.card{grid-template-columns:1fr}.act{grid-row:auto;grid-column:1}.st{grid-column:1}}
</style>
<main>
<h1>Promo cleanup</h1>
<p class="sub">Finds every sender in your iCloud inbox that offers an unsubscribe option, then lets you unsubscribe one by one or all at once.</p>
<!-- Step 1: sign in and scan -->
<form id="f">
<label>iCloud address<input id="em" type="email" required autocomplete="username"></label>
<label>App-specific password<input id="pw" type="password" required autocomplete="current-password"></label>
<label>Recent emails to scan<select id="lim"><option>500</option><option selected>1000</option><option>2000</option><option>5000</option></select></label>
<button id="go">Scan inbox</button>
</form>
<div id="msg" role="alert"></div>
<!-- Step 2: results, hidden until a scan finishes -->
<section id="res" hidden>
<div class="bar">
<strong id="sum" class="grow"></strong>
<input id="q" placeholder="Filter senders" aria-label="Filter senders">
<button id="all" class="ghost"></button>
</div>
<div id="ok" role="status"></div>
<div id="list"></div>
<!-- Fixed bottom bar: selection count, Dry run toggle, and the button that applies everything -->
<div class="foot"><span id="n"></span><label class="chk"><input id="dry" type="checkbox" checked> Dry run</label><button id="upd" disabled>Update Preferences</button></div>
</section>
</main>
<script>
// Helpers: $ = querySelector; esc = HTML-escape, because sender names are untrusted text.
const $=s=>document.querySelector(s);
const esc=t=>String(t==null?"":t).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
// State: S = senders from the scan, R = last result per sender, sel = ids selected
// for unsubscribe, meta = counts shown in the summary line.
let S=[],R={},sel=new Set(),meta={scanned:0,hidden:0};
// POST JSON to the local server; throw the server's error message on failure.
async function post(u,b){const r=await fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});const j=await r.json();if(!r.ok)throw new Error(j.error||"Request failed");return j}
// Scan: send credentials to the local server, then draw the sender list.
$("#f").onsubmit=async e=>{
  e.preventDefault();$("#msg").textContent="";$("#go").disabled=true;$("#go").textContent="Scanning...";
  try{const j=await post("/api/scan",{email:$("#em").value,password:$("#pw").value,limit:$("#lim").value});
    S=j.senders;R={};sel.clear();$("#res").hidden=false;
    meta={scanned:j.scanned,hidden:j.hidden};$("#ok").textContent="";render()}
  catch(x){$("#msg").textContent=x.message}
  $("#go").disabled=false;$("#go").textContent="Scan inbox"};
// gone(s): already unsubscribed this session. vis(): senders matching the filter box.
const gone=s=>R[s.id]&&R[s.id].status==="done";
function vis(){const q=$("#q").value.toLowerCase();return S.filter(s=>(s.name+s.address).toLowerCase().includes(q))}
// Redraw cards, summary line, bottom bar and the Select all label from current state.
function render(){
  const v=vis();
  $("#list").innerHTML=v.map(s=>{
    const r=R[s.id],done=gone(s),on=sel.has(s.id);
    let st="";const warn=s.after?'<div class="st err">Still sending: '+s.after+" emails arrived more than 10 days after you unsubscribed. Unsubscribe again or block the sender.</div>":"";
    if(r){const c=r.status==="error"?"err":"ok";
      st='<div class="st '+c+'">'+esc(r.detail)+(r.link?' <a href="'+esc(r.link)+'" target="_blank" rel="noopener noreferrer">Open unsubscribe page</a>':"")+"</div>"}
    return '<div class="card'+(done?" gone":"")+(on?" sel":"")+'"><div><h2>'+esc(s.name)+'<span class="badge">'+esc(s.method)+"</span></h2>"+
      '<p class="meta">'+esc(s.address)+" &middot; "+s.count+" emails &middot; last "+esc(s.last)+'</p><p class="subj">'+esc(s.subject)+"</p></div>"+
      '<div class="act"><button class="'+(on?"sel":"ghost")+'" data-u="'+esc(s.id)+'" aria-pressed="'+on+'"'+(done?" disabled":"")+">"+(done?"Unsubscribed":on?"Selected \u2713":"Unsubscribe")+"</button></div>"+st+warn+"</div>"}).join("");
  $("#sum").textContent=S.length+" senders found in the last "+meta.scanned+" emails"+(meta.hidden?", "+meta.hidden+" already unsubscribed":"");
  const n=sel.size,open=v.filter(s=>!gone(s));
  $("#n").textContent=n+(n===1?" sender":" senders")+" selected";
  $("#upd").disabled=!n;
  $("#all").textContent=open.length&&open.every(s=>sel.has(s.id))?"Clear selection":"Select all"}
// Update Preferences: send every selected sender to the server, show a result
// banner, and drop successful unsubscribes from the list.
async function run(){
  const ids=[...sel],dry=$("#dry").checked;if(!ids.length)return;
  if(!dry&&!confirm("Unsubscribe from "+ids.length+" senders? This sends real requests."))return;
  document.querySelectorAll("button").forEach(b=>b.disabled=true);$("#upd").textContent="Updating...";
  let note="";
  try{const j=await post("/api/unsubscribe",{ids,dry});
    j.results.forEach(r=>{R[r.id]=r;if(r.status==="done"||r.status==="manual")sel.delete(r.id)});
    const n=k=>j.results.filter(r=>r.status===k).length,d=new Set(j.results.filter(r=>r.status==="done").map(r=>r.id));
    if(dry)note="Dry run complete. Nothing was sent. Untick Dry run to unsubscribe for real.";
    else{note=d.size?"Successfully unsubscribed from "+d.size+(d.size===1?" sender":" senders")+". They have been removed from this list.":"No senders were unsubscribed.";
      if(n("manual"))note+=" "+n("manual")+" need a manual step: use the link on their card.";
      if(n("error"))note+=" "+n("error")+" failed and are still selected.";
      S=S.filter(s=>!d.has(s.id));meta.hidden+=d.size}}
  catch(x){$("#msg").textContent=x.message}
  document.querySelectorAll("button").forEach(b=>b.disabled=false);$("#upd").textContent="Update Preferences";render();
  if(note){$("#ok").textContent=note;$("#ok").scrollIntoView()}}
// Clicking Unsubscribe only toggles selection. Nothing is sent until Update Preferences.
$("#list").onclick=e=>{const b=e.target.closest("button");if(!b||!b.dataset.u)return;
  const id=b.dataset.u;sel.has(id)?sel.delete(id):sel.add(id);render()};
// Select all / Clear selection, limited to senders visible under the current filter.
$("#all").onclick=()=>{const open=vis().filter(s=>!gone(s)),every=open.every(s=>sel.has(s.id));
  open.forEach(s=>every?sel.delete(s.id):sel.add(s.id));render()};
$("#upd").onclick=run;
$("#q").oninput=render;
</script></html>"""

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)