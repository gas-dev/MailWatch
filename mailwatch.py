#!/usr/bin/env python3
"""MailWatch, by GAS DEV. First deployable release."""
import os, sqlite3, threading, imaplib, email, smtplib, ssl, fnmatch, secrets, time, logging
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.header import decode_header, make_header
from email.utils import parseaddr
from email.parser import BytesParser
from email import policy
from html.parser import HTMLParser
from collections import Counter
from zoneinfo import ZoneInfo
from pathlib import Path
from flask import Flask, request, redirect, session, render_template_string, flash, abort
from markupsafe import escape
import google_mail
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet

BASE=Path(os.getenv("MAILWATCH_DATA","/var/lib/mailwatch"))
BASE.mkdir(parents=True, exist_ok=True)
DB=BASE/"mailwatch.sqlite3"
KEYFILE=BASE/"secret.key"
if not KEYFILE.exists():
    fd=os.open(KEYFILE,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as f:f.write(Fernet.generate_key())
crypt=Fernet(KEYFILE.read_bytes())
TZ=ZoneInfo("Europe/Rome")
app=Flask(__name__)
app.secret_key=os.getenv("MAILWATCH_SESSION_KEY","")
if not app.secret_key: raise RuntimeError("MAILWATCH_SESSION_KEY is required")
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Strict",SESSION_COOKIE_SECURE=os.getenv("MAILWATCH_HTTPS","0")=="1",PERMANENT_SESSION_LIFETIME=timedelta(hours=8))
lock=threading.RLock()
logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
def db():
    c=sqlite3.connect(DB,timeout=30)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c
def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY,address TEXT UNIQUE NOT NULL,host TEXT NOT NULL,port INTEGER DEFAULT 993,login TEXT NOT NULL,password TEXT NOT NULL,enabled INTEGER DEFAULT 1,last_ok TEXT,last_error TEXT);
        CREATE TABLE IF NOT EXISTS blocked(id INTEGER PRIMARY KEY,pattern TEXT UNIQUE NOT NULL);
        CREATE TABLE IF NOT EXISTS options(k TEXT PRIMARY KEY,v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS messages(account_id INTEGER,uidvalidity TEXT,uid INTEGER,received TEXT,sender TEXT,subject TEXT,blocked INTEGER,alerted INTEGER DEFAULT 0,PRIMARY KEY(account_id,uidvalidity,uid));
        CREATE TABLE IF NOT EXISTS jobs(k TEXT PRIMARY KEY,created TEXT,status TEXT,details TEXT);
        CREATE TABLE IF NOT EXISTS account_baselines(
          account_id INTEGER PRIMARY KEY,uidvalidity TEXT NOT NULL,
          first_uid INTEGER NOT NULL,created TEXT NOT NULL);
        """)
        if "preview" not in [col[1] for col in c.execute("PRAGMA table_info(messages)")]:
            c.execute("ALTER TABLE messages ADD COLUMN preview TEXT DEFAULT ''")
        if "sender_name" not in [col[1] for col in c.execute("PRAGMA table_info(messages)")]:
            c.execute("ALTER TABLE messages ADD COLUMN sender_name TEXT DEFAULT ''")
        c.execute("""CREATE TABLE IF NOT EXISTS notification_recipients(
            id INTEGER PRIMARY KEY, address TEXT NOT NULL COLLATE NOCASE UNIQUE,
            label TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1)""")
        # Existing indexed emails are historical at upgrade, not fresh alerts.
        if not c.execute("SELECT 1 FROM options WHERE k='notification_baseline_v1'").fetchone():
            c.execute("UPDATE messages SET alerted=1")
            c.execute("INSERT INTO options(k,v) VALUES ('notification_baseline_v1',?)",
                      (datetime.now(timezone.utc).isoformat(),))
        c.execute("INSERT OR IGNORE INTO options VALUES ('recipients','')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('daily_time','08:00')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('alert_times','12:00,16:00,20:00,23:55')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('delivery_mode','both')")
        if not c.execute("SELECT 1 FROM options WHERE k='recipients_migrated'").fetchone():
            previous=c.execute("SELECT v FROM options WHERE k='recipients'").fetchone()[0]
            for value in previous.replace(";",",").replace("\n",",").split(","):
                address=value.strip().lower()
                if address and "@" in address:
                    c.execute("INSERT OR IGNORE INTO notification_recipients(address) VALUES (?)",(address,))
            c.execute("INSERT INTO options(k,v) VALUES ('recipients_migrated','1')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('smtp_host','smtp.gmail.com')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('smtp_port','465')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('smtp_user','')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('smtp_password','')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('sender','')")
        c.execute("INSERT OR IGNORE INTO options VALUES ('smtp_mode','ssl')")
        for k,v in [("send_provider","smtp"),("google_client_id",""),("google_client_secret",""),("google_refresh_token",""),("google_sender","")]:
            c.execute("INSERT OR IGNORE INTO options(k,v) VALUES (?,?)",(k,v))
init()
def opts():
    with db() as c:return {r["k"]:r["v"] for r in c.execute("SELECT * FROM options")}
def decrypt(s):
    return crypt.decrypt(s.encode()).decode() if s else ""
def decode(s):
    try:return str(make_header(decode_header(s or "")))
    except Exception:return str(s or "")
def sender_identity(msg):
    # Decode RFC 2047 encoded display names, retaining original address separately.
    raw=str(msg.get("From",""))
    display,address=parseaddr(decode(raw))
    return display.strip(),address.lower().strip()
def utc_str(dt):return dt.astimezone(timezone.utc).isoformat()
def local_now():return datetime.now(TZ)
def all_accounts():
    with db() as c:return c.execute("SELECT * FROM accounts ORDER BY address").fetchall()
class _PreviewHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts=[]
        self.ignored=0
    def handle_starttag(self,tag,attrs):
        if tag in ("script","style","head"):
            self.ignored+=1
        if tag in ("p","div","br","li","tr"):
            self.parts.append("\n")
    def handle_endtag(self,tag):
        if tag in ("script","style","head") and self.ignored:
            self.ignored-=1
        if tag in ("p","div","li","tr"):
            self.parts.append("\n")
    def handle_data(self,data):
        if not self.ignored:
            self.parts.append(data)
def preview_text(conn,uid):
    """Fetch a small MIME fragment using BODY.PEEK, never changing any IMAP flags."""
    typ,data=conn.uid("FETCH",uid,"(BODY.PEEK[]<0.32768>)")
    if typ!="OK":
        return "[Preview unavailable]"
    blobs=[part[1] for part in data if isinstance(part,tuple) and isinstance(part[1],bytes)]
    if not blobs:
        return "[Preview unavailable]"
    msg=BytesParser(policy=policy.default).parsebytes(blobs[0])
    def render(part):
        try:
            raw=part.get_payload(decode=True)
            if raw is None:
                text=part.get_content()
                if not isinstance(text,str):
                    return ""
            else:
                text=raw.decode(part.get_content_charset() or "utf-8","replace")
            if part.get_content_type()=="text/html":
                parser=_PreviewHTML()
                parser.feed(text)
                text="".join(parser.parts)
            return text
        except Exception:
            return ""
    candidates=[]
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition()=="attachment":
                continue
            if part.get_content_type() in ("text/plain","text/html"):
                candidates.append(part)
    else:
        candidates=[msg]
    candidates.sort(key=lambda part:part.get_content_type()!="text/plain")
    result=""
    for part in candidates:
        result=render(part)
        if result.strip():
            break
    cleaned=[]
    for line in result.splitlines():
        line=" ".join(line.split())
        if line:
            cleaned.append(line)
        if len(cleaned)>=4 or sum(map(len,cleaned))>=380:
            break
    preview="\n".join(cleaned)[:380]
    return preview if preview else "[No readable text preview]"

def scan():
    """Read-only EXAMINE and BODY.PEEK only. Never change IMAP flags."""
    rows=all_accounts()
    block=[]
    with db() as c:block=[x["pattern"].lower() for x in c.execute("SELECT pattern FROM blocked")]
    for a in rows:
        if not a["enabled"]:continue
        conn=None
        try:
            conn=imaplib.IMAP4_SSL(a["host"],a["port"],timeout=25)
            conn.login(a["login"],decrypt(a["password"]))
            typ,_=conn.select("INBOX",readonly=True)
            if typ!="OK":raise RuntimeError("Cannot open INBOX readonly")
            typ,info=conn.response("UIDVALIDITY")
            validity=info[0].decode() if typ in ("OK","UIDVALIDITY") and info and info[0] else "unknown"
            # First contact establishes an IMAP UID watermark. Everything already in the
            # mailbox is historical, regardless of its Date/INTERNALDATE timestamp.
            with db() as c:
                baseline=c.execute("SELECT uidvalidity,first_uid FROM account_baselines WHERE account_id=?",(a["id"],)).fetchone()
            if not baseline or baseline["uidvalidity"]!=validity:
                t,next_data=conn.response("UIDNEXT")
                first_uid=None
                if t in ("OK","UIDNEXT") and next_data and next_data[0]:
                    try:first_uid=int(next_data[0])
                    except (ValueError,TypeError):pass
                if first_uid is None:
                    t,all_data=conn.uid("SEARCH",None,"ALL")
                    if t!="OK":raise RuntimeError("Cannot establish safe IMAP UID baseline")
                    first_uid=max((int(x) for x in all_data[0].split()),default=0)+1
                with db() as c:
                    c.execute("""INSERT INTO account_baselines(account_id,uidvalidity,first_uid,created)
                      VALUES (?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET
                      uidvalidity=excluded.uidvalidity,first_uid=excluded.first_uid,created=excluded.created""",
                      (a["id"],validity,first_uid,utc_str(datetime.now(timezone.utc))))
                    c.execute("UPDATE messages SET alerted=1 WHERE account_id=?",(a["id"],))
                baseline_uid=first_uid
                logging.info("IMAP baseline set for %s (UIDNEXT=%d)",a["address"],first_uid)
            else:
                baseline_uid=baseline["first_uid"]
            # Search from two days ago to cover DST and IMAP server-local date differences.
            since=(local_now()-timedelta(days=2)).strftime("%d-%b-%Y")
            typ,res=conn.uid("SEARCH",None,"SINCE",since)
            if typ!="OK":raise RuntimeError("IMAP SEARCH failed")
            uids=res[0].split() if res and res[0] else []
            with db() as c:
                existing={r["uid"]:(r["blocked"],r["preview"],r["sender_name"]) for r in c.execute(
                    "SELECT uid,blocked,preview,sender_name FROM messages WHERE account_id=? AND uidvalidity=?",
                    (a["id"],validity))}
            for uidb in uids:
                uid=int(uidb)
                if uid in existing:
                    was_blocked,previous_preview,previous_name=existing[uid]
                    if not was_blocked and not previous_preview:
                        value=preview_text(conn,uidb)
                        with db() as c:
                            c.execute("UPDATE messages SET preview=? WHERE account_id=? AND uidvalidity=? AND uid=? AND (preview IS NULL OR preview='')",
                                      (value,a["id"],validity,uid))
                    if not previous_name:
                        typ,data=conn.uid("FETCH",uidb,"(BODY.PEEK[HEADER.FIELDS (FROM)])")
                        if typ=="OK":
                            parts=[part for part in data if isinstance(part,tuple)]
                            if parts:
                                header=BytesParser(policy=policy.default).parsebytes(parts[0][1])
                                sender_name,_=sender_identity(header)
                                with db() as c:
                                    c.execute("UPDATE messages SET sender_name=? WHERE account_id=? AND uidvalidity=? AND uid=?",
                                              (sender_name,a["id"],validity,uid))
                    continue
                typ,data=conn.uid("FETCH",uidb,"(INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])")
                if typ!="OK":continue
                parts=[item for item in data if isinstance(item,tuple)]
                if not parts:continue
                from email.parser import BytesParser
                from email import policy
                msg=BytesParser(policy=policy.default).parsebytes(parts[0][1])
                meta=parts[0][0]
                from imaplib import Internaldate2tuple
                imapdate=Internaldate2tuple(meta)
                if not imapdate:continue
                # IMAP INTERNALDATE supplies local offset; use imaplib parsing to preserve instant.
                import re
                match=re.search(rb'INTERNALDATE "([^"]+)"',meta)
                if not match:continue
                from email.utils import parsedate_to_datetime
                dt=parsedate_to_datetime(match.group(1).decode())
                sender_name,sender=sender_identity(msg)
                subject=decode(str(msg.get("Subject","")))
                isblocked=any(fnmatch.fnmatchcase(sender,p if not p.startswith("@") else "*"+p) for p in block)
                preview="" if isblocked else preview_text(conn,uidb)
                with db() as c:c.execute("INSERT OR IGNORE INTO messages(account_id,uidvalidity,uid,received,sender,subject,blocked,preview,sender_name,alerted) VALUES (?,?,?,?,?,?,?,?,?,?)",(a["id"],validity,uid,utc_str(dt),sender,subject,int(isblocked),preview,sender_name,int(uid<baseline_uid)))
            with db() as c:c.execute("UPDATE accounts SET last_ok=?,last_error=NULL WHERE id=?",(utc_str(datetime.now(timezone.utc)),a["id"]))
        except Exception as exc:
            logging.exception("IMAP failure for account %s",a["address"])
            with db() as c:c.execute("UPDATE accounts SET last_error=? WHERE id=?",(str(exc)[:300],a["id"]))
        finally:
            if conn:
                try:conn.logout()
                except Exception:pass
def recipients(o):
    with db() as c:
        return [r["address"] for r in c.execute(
            "SELECT address FROM notification_recipients WHERE enabled=1 ORDER BY address")]

def report_counts(items, mailbox_names=None):
    counts=Counter(item["address"] for item in items)
    return [(address,counts.get(address,0)) for address in sorted(set(mailbox_names or [])|set(counts))]

def report_text(title,items,mailboxes=None,note="",part=None,summary_items=None):
    summary=report_counts(items if summary_items is None else summary_items,mailboxes)
    intro=["MailWatch | Created by Techitapp",title]
    if part:intro.append("Part %d of %d"%part)
    if note:intro.append(note)
    intro.extend(["="*62,"MAILBOX SUMMARY",
                  "Total emails: %d"%sum(n for _,n in summary),"Mailboxes: %d"%len(summary)])
    for address,count in summary:
        intro.append("%s  |  %d emails"%(address,count))
    intro.extend(["="*62,"",lines(items)])
    return "\n".join(intro)

def report_html(title,items,mailboxes=None,note="",part=None,summary_items=None):
    from html import escape as esc
    summary=report_counts(items if summary_items is None else summary_items,mailboxes)
    count=sum(n for _,n in summary)
    header='''<!doctype html><html><head><meta charset="utf-8"></head>
    <body style="margin:0;padding:28px 12px;background:#f2f6fb;color:#26374a;font:14px Arial,Helvetica,sans-serif">
    <div style="max-width:760px;margin:auto;background:#fff;border:1px solid #dce5f0;border-radius:15px;overflow:hidden">
    <div style="padding:27px 30px;background:#142945;color:#fff">
      <div style="font-size:13px;letter-spacing:1.4px;color:#87def2">MAILWATCH</div>
      <h1 style="font-size:23px;margin:9px 0 5px;font-weight:700">'''+esc(title)+'''</h1>
      <div style="font-size:12px;color:#a9c2d9">Created by Techitapp</div>
    </div>
    <div style="padding:25px 28px">'''
    if part:header+='<p style="color:#63758c">Part %d of %d</p>'%part
    if note:header+='<p style="background:#edf4ff;border-left:4px solid #3b82f6;padding:12px 14px;color:#224b7d">'+esc(note)+'</p>'
    header+='<div style="margin:14px 0 18px;padding:16px;background:#f0f5fc;border-radius:11px"><strong style="font-size:22px;color:#1c4a84">%d</strong> emails across <strong>%d</strong> monitored mailboxes</div>'%(count,len(summary))
    header+='<h2 style="font-size:14px;margin:20px 0 10px">Mailbox summary</h2><table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse;margin-bottom:22px">'
    for address,n in summary:
        header+='<tr><td style="padding:10px 8px;border-bottom:1px solid #edf1f7;overflow-wrap:anywhere">'+esc(address)+'</td><td align="right" style="padding:10px 8px;border-bottom:1px solid #edf1f7;color:#174e90;font-weight:bold">%d</td></tr>'%n
    header+='</table>'
    prev=None
    for m in sorted(items,key=lambda x:(x["address"].lower(),-datetime.fromisoformat(x["received"]).timestamp())):
        if m["address"]!=prev:
            prev=m["address"]
            header+='<h2 style="font-size:15px;margin:25px 0 12px;color:#174e90;border-bottom:2px solid #dbe8f6;padding-bottom:9px">📩 '+esc(prev)+'</h2>'
        at=datetime.fromisoformat(m["received"]).astimezone(TZ).strftime("%d/%m/%Y %H:%M")
        from_text=(m["sender_name"]+" <"+m["sender"]+">") if m["sender_name"] else m["sender"]
        header+='''<div style="border:1px solid #e4ebf3;border-radius:10px;padding:14px;margin:10px 0;background:#fff">
          <div style="font-size:12px;color:#667c93">'''+esc(at)+'''</div>
          <div style="padding-top:7px;font-size:13px"><strong>From:</strong> '''+esc(from_text)+'''</div>
          <div style="padding-top:5px;font-size:13px"><strong>Subject:</strong> '''+esc(m["subject"])+'''</div>
          <div style="padding-top:9px;color:#52677e;font-size:13px;white-space:pre-line">'''+esc(m["preview"] or "[Preview not available]")+'''</div></div>'''
    return header+'''</div><div style="padding:17px 28px;background:#f8fafd;border-top:1px solid #e4ebf3;color:#8492a6;font-size:11px">
    MailWatch · Created by Techitapp. Original mailbox messages and read/unread states were not changed.</div></div></body></html>'''

def email_send(subject,body,html_body=None):
    o=opts()
    rcpts=recipients(o)
    if not rcpts:raise RuntimeError("No notification recipients configured")
    if o.get("send_provider")=="google":
        if not o.get("google_refresh_token"):raise RuntimeError("Google OAuth not connected")
    elif not o["smtp_user"] or not o["smtp_password"]:
        raise RuntimeError("SMTP not configured")
    m=EmailMessage()
    m["From"]=o.get("google_sender","") if o.get("send_provider")=="google" else (o["sender"] or o["smtp_user"])
    m["To"]=", ".join(rcpts)
    m["Subject"]=subject
    m.set_content(body)
    if html_body:m.add_alternative(html_body,subtype="html")
    if o.get("send_provider")=="google":
        if not o.get("google_sender"):raise RuntimeError("Gmail sender address not configured")
        return google_mail.send(o["google_client_id"],decrypt(o["google_client_secret"]),
                                decrypt(o["google_refresh_token"]),m)
    if o.get("smtp_mode")=="starttls":
        with smtplib.SMTP(o["smtp_host"],int(o["smtp_port"]),timeout=30) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(o["smtp_user"],decrypt(o["smtp_password"]))
            server.send_message(m)
    else:
        with smtplib.SMTP_SSL(o["smtp_host"],int(o["smtp_port"]),timeout=30,context=ssl.create_default_context()) as server:
            server.login(o["smtp_user"],decrypt(o["smtp_password"]))
            server.send_message(m)

def lines(items):
    # Group by mailbox, newest first inside each mailbox.
    ordered=sorted(items,key=lambda m:m["received"],reverse=True)
    ordered.sort(key=lambda m:m["address"].lower())
    out=[]
    last=None
    for m in ordered:
        if m["address"]!=last:
            last=m["address"]
            out.extend(["","MAILBOX: "+last,"="*60])
        at=datetime.fromisoformat(m["received"]).astimezone(TZ).strftime("%d/%m/%Y %H:%M")
        name=m["sender_name"] if "sender_name" in m.keys() else ""
        sender=m["sender"]
        preview=m["preview"] if "preview" in m.keys() else ""
        out.extend(["Received: "+at,"From: "+(name+" <"+sender+">" if name else sender),
                    "Subject: "+m["subject"],"Preview:",
                    preview or "[Preview not yet collected]","-"*60])
    return "\n".join(out)

def notify(kind,day):
    """Send only previously unreported messages. Empty reports are never emailed."""
    with lock:
        ident=kind+":"+day
        with db() as c:
            previous=c.execute("SELECT status FROM jobs WHERE k=?",(ident,)).fetchone()
            if previous and previous["status"] in ("sent","sending"):
                return "already processed"
            items=c.execute("""SELECT m.*,a.address FROM messages m JOIN accounts a
              ON a.id=m.account_id WHERE m.alerted=0 AND m.blocked=0 AND a.enabled=1
              ORDER BY a.address,m.received DESC""").fetchall()
        if not items:
            logging.info("MailWatch: no new mail, no %s email sent",kind)
            return "no new mail"
        title=("Daily digest: new mail pending" if kind=="daily" else "New mail alert")
        title_date=(day+" · " if kind=="daily" else "")
        summary=report_text(title,items,[a["address"] for a in all_accounts() if a["enabled"]])
        formatted=report_html(title,items,[a["address"] for a in all_accounts() if a["enabled"]])
        with db() as c:
            c.execute("""INSERT INTO jobs(k,created,status,details) VALUES (?,?,?,?)
                         ON CONFLICT(k) DO UPDATE SET status=excluded.status,details=excluded.details""",
                      (ident,utc_str(datetime.now(timezone.utc)),"sending",
                       "%d new emails"%len(items)))
        try:
            email_send("[MailWatch] "+title_date+str(len(items))+" new emails",summary,formatted)
        except Exception as exc:
            with db() as c:
                c.execute("UPDATE jobs SET status='error',details=? WHERE k=?",
                          (type(exc).__name__+": "+str(exc)[:200],ident))
            raise
        with db() as c:
            c.execute("UPDATE jobs SET status='sent',details=? WHERE k=?",
                      ("%d new messages"%len(items),ident))
            c.executemany("""UPDATE messages SET alerted=1 WHERE account_id=? AND uidvalidity=? AND uid=?""",
                          [(m["account_id"],m["uidvalidity"],m["uid"]) for m in items])
        return "sent %d new messages"%len(items)

def run_due():
    now=local_now()
    hm=now.strftime("%H:%M")
    o=opts()
    daily=o.get("daily_time","08:00")
    alerts=[x.strip() for x in o.get("alert_times","").split(",") if x.strip()]
    mode=o.get("delivery_mode","both")
    if hm!=daily and hm not in alerts:return
    with lock:
        key="scan:"+now.strftime("%Y-%m-%d:%H:%M")
        with db() as c:
            if c.execute("SELECT 1 FROM jobs WHERE k=?",(key,)).fetchone():return
            c.execute("INSERT INTO jobs VALUES (?,?,?,?)",(key,utc_str(datetime.now(timezone.utc)),"running",""))
        scan()
        with db() as c:c.execute("UPDATE jobs SET status='done' WHERE k=?",(key,))
        if hm==daily and mode in ("both","daily"):
            notify("daily",(now.date()-timedelta(days=1)).isoformat())
        if hm in alerts and mode in ("both","alerts"):
            notify("alert",now.strftime("%Y-%m-%d:%H:%M"))
def loop():
    while True:
        try:run_due()
        except Exception:logging.exception("Scheduled task error")
        time.sleep(20)
PAGE= """
<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MailWatch | Created by Techitapp</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;color:#202e40;background:#f3f6fb;font-synthesis:none}
*{box-sizing:border-box}body{margin:0;background:#f3f6fb;color:#1b2c40;font:14px/1.55 Inter,system-ui,Arial}
a{color:#2563eb;text-decoration:none}a:hover{text-decoration:underline}
header{position:sticky;top:0;z-index:2;background:#101f36;color:#f8fafc;box-shadow:0 2px 15px #14264020}
.header-inner{max-width:1250px;margin:auto;padding:17px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px}
header strong{font-size:21px;font-weight:800;letter-spacing:-.6px}.logo-dot{display:inline-block;background:#67e8f9;width:12px;height:12px;border-radius:4px;margin-right:10px;transform:rotate(17deg)}
header small,header small a{color:#a6bad4;font-size:12px}
main{max-width:1250px;margin:28px auto;padding:0 24px 35px}
h1{font-size:29px;letter-spacing:-.8px;margin:0;font-weight:750}h2{margin:0 0 6px;font-size:19px;letter-spacing:-.35px}h3{margin:22px 0 12px;font-size:15px}
p{margin:6px 0 14px}.muted{color:#6b7b90}.small{font-size:12px}
section{background:white;border:1px solid #e1e8f1;border-radius:16px;padding:25px;margin:18px 0;box-shadow:0 5px 20px #253d6610}
.section-head{display:flex;align-items:start;justify-content:space-between;gap:20px;margin-bottom:18px}
.section-head p{margin:2px 0 0}
.subtitle{color:#6b7b90;margin:2px 0 22px}.overview{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:20px 0}
.metric{background:#fff;border:1px solid #e1e8f1;border-radius:14px;padding:19px 22px;box-shadow:0 4px 16px #253d660c}
.metric strong{display:block;color:#162c47;font-size:30px;font-weight:760}.metric span{color:#637892;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:16px}
.form-field{min-width:0}label{display:block;font-size:12px;font-weight:650;color:#40536a;margin:9px 0 7px}
input,select{width:100%;padding:11px 12px;border:1px solid #d2dce9;border-radius:9px;background:#fff;color:#20324a;outline:none;font:inherit}
input:focus,select:focus{border-color:#4e84e8;box-shadow:0 0 0 3px #3b82f620}
button{border:0;background:#1764d5;color:#fff;padding:10px 16px;border-radius:9px;font:inherit;font-weight:650;cursor:pointer;transition:background .15s}
button:hover{background:#104fae}button:focus-visible{outline:3px solid #93c5fd}
.btn-soft{background:#edf4ff;color:#1757ae}.btn-soft:hover{background:#daeaff}
.btn-danger{background:#fff0f0;color:#bb3845}.btn-danger:hover{background:#ffe2e5}
.action-row{display:flex;flex-wrap:wrap;gap:9px;align-items:center}
.action-row form{margin:0}
table{border-collapse:collapse;width:100%}th{color:#75879b;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
td,th{padding:13px 10px;border-bottom:1px solid #eef1f6;text-align:left;vertical-align:middle;overflow-wrap:anywhere}
tr:last-child td{border-bottom:0}.table-scroll{overflow-x:auto}
.badge{display:inline-block;padding:3px 9px;border-radius:50px;background:#e5f6ed;color:#127a4f;font-size:11px;font-weight:700}
.badge.off{background:#fff0e9;color:#a75c1f}
.notice{background:#e7f6ee;color:#176b49;padding:13px 16px;border:1px solid #b8e6ce;border-radius:10px;margin:15px 0}
.error{color:#b34b51}.pill{padding:5px 11px;border-radius:8px;background:#edf4ff;color:#2b5998;font-weight:650}
.toolbar{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
footer{text-align:center;color:#7b899c;margin:25px auto 35px;font-size:12px}
.login-box{max-width:450px;margin:70px auto}.help{color:#75859a;font-size:12px;margin:10px 0}
.quick-nav{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 22px}.quick-nav a{padding:7px 12px;border:1px solid #e0e8f4;border-radius:40px;background:white;color:#42617f;font-size:12px;font-weight:650}.quick-nav a:hover{background:#eaf3ff;text-decoration:none}
html{scroll-behavior:smooth}section[id]{scroll-margin-top:85px}
/* Refined SaaS presentation */
body{background:radial-gradient(circle at 12% 0%,#eaf3ff 0%,transparent 32%),#f3f6fb}
header{background:linear-gradient(120deg,#0e2039,#16345d);border-bottom:1px solid #36567c}
main>section{position:relative;overflow:visible}
section{box-shadow:0 12px 32px rgba(30,52,86,.055)}
.section-head h2{display:flex;align-items:center;gap:9px}
.heading-icon{display:inline-flex;align-items:center;justify-content:center;width:31px;height:31px;background:#eaf2ff;color:#1b60bd;border-radius:10px;font-size:17px}
.metric{position:relative;overflow:hidden;border-color:#e0e9f5}
.metric:after{content:"";position:absolute;width:82px;height:82px;right:-20px;top:-30px;border-radius:50%;background:#e8f1ff}
.metric strong,.metric span{position:relative;z-index:1}
.btn-quiet{background:transparent!important;color:#a5adba!important;border:1px solid #e3e8ef!important;font-size:12px!important;font-weight:500!important;padding:8px 12px!important;opacity:.7}
.btn-quiet:hover{background:#f8fafc!important;color:#53647a!important;opacity:1}
.button-link{display:inline-flex;align-items:center;justify-content:center;padding:10px 16px;border-radius:9px;font-weight:650;font-size:14px;text-decoration:none}
.button-link:hover{text-decoration:none}
.mailbox-cell{display:flex;align-items:center;gap:10px;font-weight:600}
.mailbox-icon{width:31px;height:31px;flex-shrink:0;background:#f0f5ff;color:#336bb2;border-radius:10px;display:inline-flex;align-items:center;justify-content:center;font-size:16px}
.edit-row td{padding:0 8px 12px;border-bottom:1px solid #e7edf5}
.edit-panel{border:1px solid #e3ecf8;border-radius:12px;background:#f8fbff;padding:0 18px}
.edit-panel:not([open]){background:#fff;border-color:#e8eef6}
.edit-panel summary{cursor:pointer;color:#416993;font-weight:700;padding:11px 0;font-size:12px}
.edit-panel summary:hover{color:#1454a5}
.edit-panel[open]{margin-bottom:8px}
.edit-panel form{padding:0 0 16px}
.edit-panel .grid{grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
input,select{transition:border-color .15s,box-shadow .15s}
@media(max-width:650px){main{padding:0 12px;margin:16px auto}.header-inner{padding:16px}.overview{grid-template-columns:1fr}section{padding:18px}h1{font-size:24px}td,th{padding:10px 7px}}
</style><header><div class="header-inner"><div><span class="logo-dot"></span><strong>MailWatch</strong></div><small>Created by <a href="https://techitapp.com" target="_blank" rel="noopener noreferrer">Techitapp</a></small></div></header><main>
{% with messages=get_flashed_messages() %}{% for msg in messages %}<div class="notice">{{msg}}</div>{% endfor %}{% endwith %}
{% if not authed %}
<section class="login-box"><h2>Administrator login</h2><form method="post" action="/login"><input type="hidden" name="csrf" value="{{csrf}}">
<label>Password</label><input type="password" name="password" autocomplete="current-password" required><button>Sign in</button></form></section>
{% else %}
<nav class="quick-nav" aria-label="Dashboard sections"><a href="#schedule">Schedule</a><a href="#recipients">Receivers</a><a href="#mailboxes">Mailboxes</a><a href="#blacklist">Blacklist</a><a href="#smtp">SMTP</a><a href="#activity">Activity</a></nav>
<div class="toolbar"><div><h1>Operations dashboard</h1><p class="subtitle">Monitor mailboxes, control notifications and manage delivery.</p></div><span class="pill">Europe/Rome</span></div>
<div class="overview">
<div class="metric"><strong>{{stats.mailboxes}}</strong><span>Active IMAP mailboxes</span></div>
<div class="metric"><strong>{{stats.indexed}}</strong><span>Indexed messages</span></div>
<div class="metric"><strong>{{stats.recipients}}</strong><span>Active receivers</span></div>
</div>
<section id="schedule"><div class="section-head"><div><h2>Notification schedule</h2><p class="muted">Choose when reports are delivered and which reports to send.</p></div><span class="pill">Automatic</span></div>
<form method="post" action="/schedule"><input type="hidden" name="csrf" value="{{csrf}}">
<div class="grid">
<div><label for="daily-time">Daily digest time</label><input id="daily-time" name="daily_time" type="time" value="{{options.daily_time}}" required><p class="help">Sends only newly detected, unreported messages. No mail means no digest.</p></div>
<div><label for="send-mode">Delivery mode</label><select id="send-mode" name="delivery_mode">
<option value="both" {% if options.delivery_mode=='both' %}selected{% endif %}>Daily digest + new-mail alerts</option>
<option value="daily" {% if options.delivery_mode=='daily' %}selected{% endif %}>Daily digest only</option>
<option value="alerts" {% if options.delivery_mode=='alerts' %}selected{% endif %}>New-mail alerts only</option>
</select><p class="help">Manual digests are available in every mode.</p></div>
<div><label for="alert-times">Alert times (HH:MM, comma-separated)</label><input id="alert-times" name="alert_times" value="{{options.alert_times}}" placeholder="12:00,16:00,20:00,23:55"><p class="help">Up to 12 checks per day. Time zone: Europe/Rome.</p></div></div>
<button>Save notification schedule</button>
</form></section>
<section id="actions"><div class="section-head"><div><h2>Manual operations</h2><p class="muted">Read-only IMAP collection. Emails remain unchanged and unread flags are preserved.</p></div></div>
<form class="action-row" method="post" action="/action"><input type="hidden" name="csrf" value="{{csrf}}">
<button name="what" value="scan" class="btn-soft">Check IMAP now</button>
<button name="what" value="alert" class="btn-soft">Send new-mail alert</button>
<button name="what" value="daily" class="btn-soft">Send pending-mail digest</button>
<button name="what" value="last60" class="btn-quiet" title="Manually send all available INBOX mail from the last sixty days, preserving read/unread flags">Request last 60 days</button></form>
<p class="help">The 60-day report is requested manually, reads INBOX without changing flags, and may be split into parts. Automated notifications are sent only for newly detected messages.</p></section>
<section id="recipients"><div class="section-head"><div><h2>Notification receivers</h2><p class="muted">Add or remove destinations one at a time. Only enabled receivers get notifications.</p></div><span class="pill">{{stats.recipients}} active</span></div>
<div class="table-scroll"><table><thead><tr><th>Receiver</th><th>Name / description</th><th>Status</th><th>Actions</th></tr></thead><tbody>
{% for rec in recipients_list %}<tr><td>{{rec.address}}</td><td>{{rec.label or '—'}}</td><td><span class="badge {% if not rec.enabled %}off{% endif %}">{{'Enabled' if rec.enabled else 'Paused'}}</span></td>
<td><div class="action-row"><form method="post" action="/recipient/update"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{rec.id}}"><button class="btn-soft" name="operation" value="{{'disable' if rec.enabled else 'enable'}}">{{'Pause' if rec.enabled else 'Enable'}}</button></form>
<form method="post" action="/recipient/update" onsubmit="return confirm('Remove this receiver?')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{rec.id}}"><button class="btn-danger" name="operation" value="remove">Remove</button></form></div></td></tr>
{% else %}<tr><td colspan="4">No receivers configured yet.</td></tr>{% endfor %}
</tbody></table></div><h3>Add a receiver</h3>
<form method="post" action="/recipient/add"><input type="hidden" name="csrf" value="{{csrf}}"><div class="grid">
<div><label>Destination email</label><input type="email" name="address" placeholder="person@example.com" required></div>
<div><label>Display name (optional)</label><input name="label" maxlength="100" placeholder="Legal team / manager"></div>
</div><button>Add receiver</button></form></section>
<section id="mailboxes"><div class="section-head"><div><h2><span class="heading-icon">✉</span> IMAP mailboxes</h2><p class="muted">Secure read-only connection for regular email and certified PEC accounts.</p></div><span class="pill">SSL / TLS</span></div>
<div class="table-scroll"><table><thead><tr><th>Mailbox</th><th>Last successful check</th><th>Connection</th><th>Manage</th></tr></thead><tbody>
{% for a in accounts %}
<tr><td><div class="mailbox-cell"><span class="mailbox-icon">✉</span><span>{{a.address}}</span></div></td><td>{{a.last_ok or 'Never'}}</td><td><span class="badge {% if a.last_error %}off{% endif %}">{{'Attention' if a.last_error else 'Ready'}}</span></td>
<td><div class="action-row">
<form method="post" action="/test-imap" target="mailwatch_test_popup" onsubmit="window.open('','mailwatch_test_popup','width=720,height=560,resizable=yes,scrollbars=yes')"><input type="hidden" name="csrf" value="{{csrf}}"><button class="btn-soft" name="id" value="{{a.id}}">Test</button></form>

<form method="post" action="/remove" onsubmit="return confirm('Remove this mailbox and its configuration?')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="type" value="account"><button class="btn-danger" name="id" value="{{a.id}}">Remove</button></form>
</div></td></tr>
<tr class="edit-row"><td colspan="4"><details id="mailbox-edit-{{a.id}}" class="edit-panel"><summary>✎ Edit mailbox settings · {{a.address}}</summary>
<form method="post" action="/account/edit" autocomplete="off"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{a.id}}">
<div class="grid">
<div><label>Email address</label><input type="email" name="address" value="{{a.address}}" required></div>
<div><label>IMAP server</label><input name="host" value="{{a.host}}" required></div>
<div><label>TLS port</label><input name="port" inputmode="numeric" value="{{a.port}}" required></div>
<div><label>Username</label><input name="login" value="{{a.login}}" required></div>
<div><label>New IMAP password (optional)</label><input type="password" name="password" autocomplete="new-password" placeholder="Leave blank to keep saved password"></div>
</div><p class="help">Updating an account preserves its record, message history and alert tracking. A blank password does not change the stored secret.</p>
<button type="submit">Save mailbox changes</button>
</form></details></td></tr>
{% else %}<tr><td colspan="4">No mailboxes configured yet.</td></tr>{% endfor %}
</tbody></table></div>
<h3>Add IMAP account</h3><form method="post" action="/account"><input type="hidden" name="csrf" value="{{csrf}}"><div class="grid">
<div><label>Email address</label><input type="email" name="address" required></div><div><label>IMAP server</label><input name="host" placeholder="imaps.pec.aruba.it" required></div>
<div><label>TLS port</label><input name="port" value="993" required></div><div><label>Username</label><input name="login" required></div>
<div><label>Password IMAP/app password</label><input type="password" name="password" required></div></div><button>Save account</button></form></section>
<section id="blacklist"><div class="section-head"><div><h2>Sender blacklist</h2><p class="muted">Messages matching these rules are excluded from delivery.</p></div></div><table>{% for b in blocked %}<tr><td>{{b.pattern}}</td><td><form method="post" action="/remove"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="type" value="block"><button name="id" value="{{b.id}}">Remove</button></form></td></tr>{% endfor %}</table>
<form method="post" action="/block"><input type="hidden" name="csrf" value="{{csrf}}"><label>Address, @domain, or wildcard pattern (*)</label><input name="pattern" required placeholder="newsletter@example.com"><button>Add rule</button></form></section>
<section id="smtp"><div class="section-head"><div><h2>Outbound SMTP</h2><p class="muted">Google app password or your own authenticated SMTP provider.</p></div></div><p class="muted">Use authenticated SMTP with TLS. For Gmail, enter a Google App Password instead of your normal account password, when supported. The password is encrypted locally and never displayed again.</p>
<form method="post" action="/settings"><input type="hidden" name="csrf" value="{{csrf}}"><div class="grid">

<div><label>Server SMTP</label><input name="smtp_host" value="{{options.smtp_host}}"></div>
<div><label>Port</label><input name="smtp_port" value="{{options.smtp_port}}"></div>
<div><label>TLS mode</label><select name="smtp_mode"><option value="ssl" {% if options.smtp_mode=='ssl' %}selected{% endif %}>SSL/TLS (465)</option><option value="starttls" {% if options.smtp_mode=='starttls' %}selected{% endif %}>STARTTLS (587)</option></select></div>
<div><label>SMTP account</label><input name="smtp_user" value="{{options.smtp_user}}"></div>
<div><label>Sender</label><input name="sender" value="{{options.sender}}"></div>
<div><label>SMTP app password (leave blank to keep unchanged)</label><input type="password" name="smtp_password"></div></div><button>Save SMTP settings</button></form><form method="post" action="/test-smtp" target="mailwatch_smtp_popup" onsubmit="window.open('','mailwatch_smtp_popup','width=720,height=560,resizable=yes,scrollbars=yes')"><input type="hidden" name="csrf" value="{{csrf}}"><button type="submit">Test SMTP connection &amp; app password</button></form><p class="muted">Save settings before testing. This checks encrypted connection and login only. No email is sent.</p></section>
<section id="activity"><div class="section-head"><div><h2>Recent activity</h2><p class="muted">Scans, delivery status, and operational messages.</p></div></div><table><tr><th>Operation</th><th>Status</th><th>Details</th></tr>{% for j in jobs %}<tr><td>{{j.k}}</td><td>{{j.status}}</td><td>{{j.details}}</td></tr>{% endfor %}</table></section>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button>Sign out</button></form>
{% endif %}</main><footer>MailWatch · Created by <a href="https://techitapp.com/" target="_blank" rel="noopener noreferrer">Techitapp</a></footer></html>
"""
def token():
    if "csrf" not in session:session["csrf"]=secrets.token_urlsafe(24)
    return session["csrf"]
def guard():
    if not session.get("ok"):abort(403)
    if not secrets.compare_digest(str(request.form.get("csrf","")),str(token())):abort(403)
@app.after_request
def headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Cache-Control"]="no-store"
    response.headers["Content-Security-Policy"]="default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    return response
@app.route("/")
def home():
    if session.get("ok"):
        with db() as c:
            blocks=c.execute("SELECT * FROM blocked ORDER BY pattern").fetchall()
            jobs=c.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 15").fetchall()
            recipients_list=c.execute("SELECT * FROM notification_recipients ORDER BY enabled DESC,address").fetchall()
            stats={"mailboxes":c.execute("SELECT COUNT(*) FROM accounts WHERE enabled=1").fetchone()[0],
                   "indexed":c.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
                   "recipients":c.execute("SELECT COUNT(*) FROM notification_recipients WHERE enabled=1").fetchone()[0]}
        o=opts()
        return render_template_string(PAGE,authed=True,csrf=token(),accounts=all_accounts(),blocked=blocks,jobs=jobs,options=o,recipients_list=recipients_list,stats=stats,alert_schedule=o.get("alert_times","").split(","))
    return render_template_string(PAGE,authed=False,csrf=token())
@app.post("/login")
def login():
    if not secrets.compare_digest(str(request.form.get("csrf","")),str(token())):abort(403)
    # Password stored as password hash in root-owned service environment.
    hashed=os.environ["MAILWATCH_ADMIN_HASH"]
    time.sleep(0.5)
    if check_password_hash(hashed,request.form.get("password","")):
        session.clear();session["ok"]=True;session.permanent=True;token()
        return redirect("/")
    flash("Invalid credentials")
    return redirect("/")
@app.post("/logout")
def logout():
    guard();session.clear();return redirect("/")
@app.post("/account")
def account():
    guard()
    try:
        port=int(request.form["port"])
        if not 1<=port<=65535:raise ValueError("invalid port")
        with db() as c:c.execute("INSERT INTO accounts(address,host,port,login,password) VALUES (?,?,?,?,?)",(request.form["address"].strip().lower(),request.form["host"].strip(),port,request.form["login"].strip(),crypt.encrypt(request.form["password"].encode()).decode()))
        flash("Account added")
    except Exception as exc:flash("Unable to add account: "+str(exc))
    return redirect("/")
@app.post("/account/edit")
def edit_account():
    guard()
    account_id=request.form.get("id",type=int)
    if account_id is None:abort(400)
    address=request.form.get("address","").strip().lower()
    host=request.form.get("host","").strip()
    login=request.form.get("login","").strip()
    password=request.form.get("password","")
    try:
        port=int(request.form.get("port","0"))
        if not is_email_address(address):raise ValueError("Invalid mailbox address")
        if not host or not login or not (1<=port<=65535):
            raise ValueError("Please complete all connection fields")
        with db() as c:
            current=c.execute("SELECT id FROM accounts WHERE id=?",(account_id,)).fetchone()
            if not current:abort(404)
            if password:
                c.execute("""UPDATE accounts SET address=?,host=?,port=?,login=?,password=?,
                             last_error=NULL,last_ok=NULL WHERE id=?""",
                          (address,host,port,login,crypt.encrypt(password.encode()).decode(),account_id))
            else:
                c.execute("""UPDATE accounts SET address=?,host=?,port=?,login=?,
                             last_error=NULL,last_ok=NULL WHERE id=?""",
                          (address,host,port,login,account_id))
        flash("Mailbox updated. Stored password was "+("replaced." if password else "preserved."))
    except sqlite3.IntegrityError:
        flash("Another mailbox already uses this address.")
    except ValueError as exc:
        flash(str(exc))
    return redirect("/#mailboxes")

@app.post("/block")
def block():
    guard()
    pat=request.form["pattern"].strip().lower()
    if pat and len(pat)<=250:
        with db() as c:c.execute("INSERT OR IGNORE INTO blocked(pattern) VALUES (?)",(pat,))
    flash("Rule saved. It applies to messages collected from now on.")
    return redirect("/")
@app.post("/remove")
def remove():
    guard()
    table={"block":"blocked","account":"accounts"}.get(request.form.get("type"))
    if not table:abort(400)
    with db() as c:c.execute("DELETE FROM "+table+" WHERE id=?",(request.form.get("id"),))
    flash("Item removed")
    return redirect("/")
def is_email_address(value):
    from email.utils import parseaddr
    address=value.strip().lower()
    return bool(address and len(address)<255 and " " not in address and parseaddr(address)[1]==address and address.count("@")==1 and "." in address.rsplit("@",1)[1])

@app.post("/recipient/add")
def add_recipient():
    guard()
    address=request.form.get("address","").strip().lower()
    label=request.form.get("label","").strip()[:100]
    if not is_email_address(address):
        flash("Enter a valid email address.")
    else:
        with db() as c:
            c.execute("INSERT INTO notification_recipients(address,label,enabled) VALUES (?,?,1) ON CONFLICT(address) DO UPDATE SET label=excluded.label,enabled=1",(address,label))
        flash("Recipient added.")
    return redirect("/#recipients")
@app.post("/recipient/update")
def update_recipient():
    guard()
    rid=request.form.get("id",type=int)
    operation=request.form.get("operation")
    if operation not in ("enable","disable","remove") or rid is None:abort(400)
    with db() as c:
        if operation=="remove":c.execute("DELETE FROM notification_recipients WHERE id=?",(rid,))
        else:c.execute("UPDATE notification_recipients SET enabled=? WHERE id=?",(int(operation=="enable"),rid))
    flash("Recipient updated.")
    return redirect("/#recipients")
@app.post("/schedule")
def save_schedule():
    guard()
    import re
    valid=lambda t:bool(re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]",t))
    daily=request.form.get("daily_time","")
    mode=request.form.get("delivery_mode","both")
    raw=request.form.get("alert_times","")
    alerts=[v.strip() for v in raw.replace(";",",").split(",") if v.strip()]
    if not valid(daily) or mode not in ("both","daily","alerts") or len(alerts)>12 or any(not valid(x) for x in alerts):
        flash("Invalid schedule. Use HH:MM and up to 12 alert times.")
        return redirect("/#schedule")
    times=",".join(sorted(set(alerts)))
    if mode in ("both","alerts") and not times:
        flash("Add at least one alert time.")
        return redirect("/#schedule")
    with db() as c:
        for k,v in (("daily_time",daily),("alert_times",times),("delivery_mode",mode)):
            c.execute("INSERT INTO options(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(k,v))
    flash("Notification schedule saved.")
    return redirect("/#schedule")

@app.post("/settings")
def settings():
    guard()
    keys=("smtp_host","smtp_port","smtp_mode","smtp_user","sender")
    if request.form.get("smtp_mode") not in ("ssl","starttls"):abort(400)
    with db() as c:
        for k in keys:c.execute("INSERT INTO options(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(k,request.form.get(k,"").strip()))
        if request.form.get("smtp_password"):
            c.execute("INSERT INTO options(k,v) VALUES ('smtp_password',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(crypt.encrypt(request.form["smtp_password"].encode()).decode(),))
    with db() as c:c.execute("INSERT INTO options(k,v) VALUES ('send_provider','smtp') ON CONFLICT(k) DO UPDATE SET v=excluded.v")
    flash("Settings saved");return redirect("/")
@app.post("/test-smtp")
def test_smtp():
    guard()
    o=opts()
    log=["MailWatch | SMTP connection test",
         "Server: "+o.get("smtp_host","")+" : "+o.get("smtp_port",""),
         "TLS mode: "+o.get("smtp_mode",""),
         "Account: "+o.get("smtp_user",""),
         "Starting SMTP connection..."]
    started=time.monotonic()
    try:
        host=o.get("smtp_host","")
        port=int(o.get("smtp_port","0"))
        if not host or not (1<=port<=65535):
            raise ValueError("Please configure a valid SMTP server and port")
        if not o.get("smtp_user") or not o.get("smtp_password"):
            raise ValueError("Save the SMTP account and app password first")
        mode=o.get("smtp_mode")
        if mode=="ssl":
            with smtplib.SMTP_SSL(host,port,timeout=20,context=ssl.create_default_context()) as conn:
                log.append("TLS connection: OK")
                conn.login(o["smtp_user"],decrypt(o["smtp_password"]))
                log.append("SMTP authentication: OK")
        elif mode=="starttls":
            with smtplib.SMTP(host,port,timeout=20) as conn:
                conn.ehlo()
                if not conn.has_extn("starttls"):
                    raise RuntimeError("Server does not advertise STARTTLS")
                conn.starttls(context=ssl.create_default_context())
                conn.ehlo()
                log.append("STARTTLS connection: OK")
                conn.login(o["smtp_user"],decrypt(o["smtp_password"]))
                log.append("SMTP authentication: OK")
        else:
            raise ValueError("Unsupported SMTP security mode")
        log.append("RESULT: SUCCESS")
        log.append("No email was sent.")
    except smtplib.SMTPAuthenticationError as exc:
        log.append("RESULT: FAILED")
        log.append("SMTP authentication rejected (code %s). Check the app password and account."%exc.smtp_code)
    except Exception as exc:
        logging.warning("SMTP diagnostic failed: %s",type(exc).__name__)
        log.append("RESULT: FAILED")
        log.append("Error type: "+type(exc).__name__)
        log.append("Check the SMTP server, port, TLS mode, and saved app password.")
    log.append("Duration: %.2f seconds"%(time.monotonic()-started))
    output=str(escape("\n".join(log)))
    return ("<!doctype html><html lang='en'><meta charset='utf-8'><title>MailWatch SMTP test</title>"
            "<body style='font:15px system-ui;background:#f1f5f9;padding:20px'>"
            "<h2>MailWatch | SMTP test</h2>"
            "<pre style='padding:20px;white-space:pre-wrap;background:white;border-radius:10px'>"
            +output+"</pre><button onclick='window.close()'>Close</button></body></html>")

def send_test_digest_all():
    with lock:
        with db() as c:
            items=c.execute("""SELECT m.*,a.address FROM messages m JOIN accounts a ON a.id=m.account_id
                WHERE m.blocked=0 ORDER BY a.address,m.received""").fetchall()
            excluded=c.execute("SELECT COUNT(*) AS n FROM messages WHERE blocked=1").fetchone()["n"]
        active=all_accounts()
        errors=[a["address"]+": "+a["last_error"] for a in active if a["enabled"] and a["last_error"]]
        body=("MailWatch | Created by Techitapp\n"
              "Manual test digest: all messages currently collected\n"
              "Included messages: "+str(len(items))+"\n"
              "Excluded by blacklist: "+str(excluded)+"\n"
              +lines(items))
        if errors:
            body+="\nWARNING: Mailbox errors:\n"+"\n".join(errors)
        key="manual-test:"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")+"-"+secrets.token_hex(3)
        with db() as c:
            c.execute("INSERT INTO jobs(k,created,status,details) VALUES (?,?,?,?)",
                      (key,utc_str(datetime.now(timezone.utc)),"sending",str(len(items))+" messages"))
        try:
            email_send("[MailWatch] Test digest - "+str(len(items))+" messages",body)
        except Exception as exc:
            logging.exception("Test digest delivery failed")
            with db() as c:
                c.execute("UPDATE jobs SET status='error',details=? WHERE k=?",
                          (type(exc).__name__+": "+str(exc)[:180],key))
            raise
        with db() as c:
            c.execute("UPDATE jobs SET status='sent',details=? WHERE k=?",
                      (str(len(items))+" messages",key))
        return len(items)

def sixty_day_digest():
    """Manual sixty-day INBOX report; read-only IMAP, mark only successfully emailed UIDs locally."""
    now=local_now()
    cutoff=now-timedelta(days=60)
    key="last60:"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")+"-"+secrets.token_hex(3)
    with db() as c:
        c.execute("INSERT INTO jobs(k,created,status,details) VALUES (?,?,?,?)",
                  (key,utc_str(datetime.now(timezone.utc)),"scanning","Scanning last 60 days"))
    with lock:
        all_items=[]
        excluded=0
        errors=[]
        accounts=[a for a in all_accounts() if a["enabled"]]
        with db() as c:
            patterns=[r["pattern"].lower() for r in c.execute("SELECT pattern FROM blocked")]
        from email.utils import parsedate_to_datetime
        import re
        for a in accounts:
            conn=None
            processed=0
            try:
                conn=imaplib.IMAP4_SSL(a["host"],a["port"],timeout=30)
                conn.login(a["login"],decrypt(a["password"]))
                typ,_=conn.select("INBOX",readonly=True)
                if typ!="OK":raise RuntimeError("Unable to select INBOX read-only")
                typ,validity_data=conn.response("UIDVALIDITY")
                validity=(validity_data[0].decode() if typ in ("OK","UIDVALIDITY") and validity_data and validity_data[0] else "unknown")
                typ,res=conn.uid("SEARCH",None,"SINCE",cutoff.strftime("%d-%b-%Y"))
                if typ!="OK":raise RuntimeError("IMAP date search failed")
                uids=res[0].split() if res and res[0] else []
                for uid in uids:
                    typ,data=conn.uid("FETCH",uid,"(INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])")
                    if typ!="OK":raise RuntimeError("IMAP fetch failed")
                    parts=[entry for entry in data if isinstance(entry,tuple)]
                    if not parts:raise RuntimeError("IMAP header data missing")
                    meta,raw=parts[0]
                    match=re.search(rb'INTERNALDATE "([^"]+)"',meta)
                    if not match:raise RuntimeError("IMAP INTERNALDATE missing")
                    dt=parsedate_to_datetime(match.group(1).decode())
                    if dt.astimezone(TZ)<cutoff:
                        continue
                    msg=BytesParser(policy=policy.default).parsebytes(raw)
                    sender_name,sender=sender_identity(msg)
                    subject=decode(str(msg.get("Subject","")))
                    isblocked=any(fnmatch.fnmatchcase(sender,p if not p.startswith("@") else "*"+p) for p in patterns)
                    if isblocked:
                        excluded+=1
                    else:
                        all_items.append({"account_id":a["id"],"uidvalidity":validity,"uid":int(uid),
                                          "address":a["address"],"received":utc_str(dt),"sender":sender,
                                          "sender_name":sender_name,"subject":subject,
                                          "preview":preview_text(conn,uid)})
                    processed+=1
                    if processed%100==0:
                        with db() as c:
                            c.execute("UPDATE jobs SET details=? WHERE k=?",
                                      ("%s: %d/%d checked"%(a["address"],processed,len(uids)),key))
            except Exception as exc:
                errors.append("%s: %s"%(a["address"],type(exc).__name__))
                logging.exception("60-day scan failed for %s",a["address"])
            finally:
                if conn:
                    try:conn.logout()
                    except Exception:pass
        if errors:
            with db() as c:
                c.execute("UPDATE jobs SET status='error',details=? WHERE k=?",
                          ("Scan incomplete. No email sent. "+" | ".join(errors)[:320],key))
            return
        if not all_items:
            with db() as c:
                c.execute("UPDATE jobs SET status='done',details=? WHERE k=?",
                          ("No messages in the last 60 days. No email sent.",key))
            return
        all_items.sort(key=lambda m:m["received"],reverse=True)
        all_items.sort(key=lambda m:m["address"].lower())
        chunks=[]
        batch=[]
        chars=0
        for item in all_items:
            estimate=sum(len(str(item[k])) for k in ("address","sender","sender_name","subject","preview"))+300
            if batch and (len(batch)>=100 or chars+estimate>200000):
                chunks.append(batch)
                batch=[]
                chars=0
            batch.append(item)
            chars+=estimate
        if batch:chunks.append(batch)
        mailboxes=[a["address"] for a in accounts]
        title="Last 60 days · monitored mailboxes"
        note="Requested report: last 60 days of monitored mailboxes."
        for part_number,batch in enumerate(chunks,1):
            part=(part_number,len(chunks))
            subject="[MailWatch] Requested last 60 days (%d/%d) · %d emails"%(
                part_number,len(chunks),len(all_items))
            body=report_text(title,batch,mailboxes,note,part,summary_items=all_items)
            html=report_html(title,batch,mailboxes,note,part,summary_items=all_items)
            with db() as c:
                c.execute("UPDATE jobs SET status='sending',details=? WHERE k=?",
                          ("Sending %d of %d"%(part_number,len(chunks)),key))
            try:
                email_send(subject,body,html)
            except Exception as exc:
                logging.exception("60-day report delivery error")
                with db() as c:
                    c.execute("UPDATE jobs SET status='error',details=? WHERE k=?",
                              ("SMTP error on part %d/%d: %s"%(
                                  part_number,len(chunks),type(exc).__name__),key))
                return
            # SMTP accepted this part. These messages must not reappear in polling.
            with db() as c:
                for item in batch:
                    c.execute("""INSERT OR IGNORE INTO messages(
                        account_id,uidvalidity,uid,received,sender,subject,blocked,alerted,preview,sender_name)
                        VALUES (?,?,?,?,?,?,0,1,?,?)""",
                        (item["account_id"],item["uidvalidity"],item["uid"],item["received"],
                         item["sender"],item["subject"],item["preview"],item["sender_name"]))
                    c.execute("""UPDATE messages SET alerted=1
                        WHERE account_id=? AND uidvalidity=? AND uid=?""",
                        (item["account_id"],item["uidvalidity"],item["uid"]))
        with db() as c:
            c.execute("UPDATE jobs SET status='sent',details=? WHERE k=?",
                      ("%d emails, %d blacklisted, %d parts"%(
                          len(all_items),excluded,len(chunks)),key))

@app.post("/action")
def action():
    guard()
    action=request.form.get("what")
    if action not in ("scan","alert","daily","last60"):abort(400)
    def worker():
        try:
            if action=="scan":scan()
            elif action=="daily":
                scan();notify("daily",(local_now().date()-timedelta(days=1)).isoformat())
            elif action=="last60":
                scan();sixty_day_digest()
            else:
                scan();notify("alert",local_now().strftime("%Y-%m-%d:%H:%M")+":manual")
        except Exception:logging.exception("Manual action failed")
    threading.Thread(target=worker,daemon=True).start()
    flash("Operation started. Refresh the activity log shortly.")
    return redirect("/")

GOOGLE_REDIRECT=os.getenv("MAILWATCH_GOOGLE_REDIRECT","")
@app.post("/test-imap")
def test_imap():
    guard()
    with db() as c:a=c.execute("SELECT * FROM accounts WHERE id=?",(request.form.get("id"),)).fetchone()
    if not a:abort(404)
    log=["MailWatch | Test IMAP","Account: "+a["address"],"Server: "+a["host"]+":"+str(a["port"]),"Connecting over TLS..."]
    start=time.monotonic()
    im=None
    try:
        im=imaplib.IMAP4_SSL(a["host"],a["port"],timeout=20)
        log.append("TLS: OK")
        log.append("Authenticating...")
        im.login(a["login"],decrypt(a["password"]))
        log.append("Authentication: OK")
        typ,info=im.select("INBOX",readonly=True)
        if typ!="OK":raise RuntimeError("Unable to open INBOX")
        log.append("Read-only INBOX: OK")
        log.append("Messages in INBOX: "+str(info[0].decode() if info and info[0] else "unknown"))
        log.append("No message flags modified; no messages marked as read.")
        log.append("RESULT: CONNECTION SUCCESSFUL")
    except Exception as exc:
        log.append("RESULT: ERROR")
        log.append("Details: "+str(exc)[:350])
    finally:
        if im:
            try:im.logout()
            except Exception:pass
    log.append("Duration: %.2f seconds"%(time.monotonic()-start))
    payload="\n".join(log)
    logging.info("IMAP diagnostic %s status=%s",a["address"],"OK" if "SUCCESSFUL" in payload else "ERROR")
    return "<!doctype html><html lang='en'><meta charset='utf-8'><title>MailWatch | Test IMAP</title><body style='font:15px system-ui;background:#f1f5f9;padding:20px'><h2>MailWatch | IMAP connection test</h2><pre style='padding:20px;white-space:pre-wrap;background:#fff;border-radius:10px'>"+str(escape(payload))+"</pre><button onclick='window.close()'>Close</button></body></html>"
@app.post("/google-settings")
def google_settings():
    guard()
    with db() as c:
        for k,v in (("google_client_id",request.form.get("client_id","").strip()),("google_sender",request.form.get("google_sender","").strip())):
            c.execute("INSERT INTO options(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(k,v))
        if request.form.get("client_secret"):
            c.execute("INSERT INTO options(k,v) VALUES ('google_client_secret',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(crypt.encrypt(request.form["client_secret"].encode()).decode(),))
        c.execute("DELETE FROM options WHERE k='google_refresh_token'")
        c.execute("INSERT INTO options(k,v) VALUES ('google_refresh_token','')")
    flash("Credentials saved. Connect your Google account.")
    return redirect("/")
@app.post("/google-connect")
def google_connect():
    guard()
    o=opts()
    if not GOOGLE_REDIRECT.startswith("https://"):
        flash("Configure HTTPS OAuth redirect URL first.");return redirect("/")
    if not o.get("google_client_id") or not o.get("google_client_secret"):
        flash("Save Client ID and Client Secret first");return redirect("/")
    state=secrets.token_urlsafe(32)
    session["google_oauth_state"]=state
    return redirect(google_mail.authorization_url(o["google_client_id"],GOOGLE_REDIRECT,state))
@app.get("/google/callback")
def google_callback():
    if not session.get("ok"):abort(403)
    state=session.pop("google_oauth_state",None)
    if not state or not secrets.compare_digest(state,request.args.get("state","")):abort(403)
    if request.args.get("error"):
        flash("Google authorization declined: "+request.args["error"][:100]);return redirect("/")
    code=request.args.get("code","")
    if not code:abort(400)
    o=opts()
    try:
        refresh=google_mail.exchange_code(o["google_client_id"],decrypt(o["google_client_secret"]),GOOGLE_REDIRECT,code)
        with db() as c:
            c.execute("INSERT INTO options(k,v) VALUES ('google_refresh_token',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(crypt.encrypt(refresh.encode()).decode(),))
        flash("Google connected. Select Use Google for sending.")
    except Exception:
        logging.exception("OAuth token exchange failed")
        flash("Google not connected. Check OAuth settings and service logs.")
    return redirect("/")
@app.post("/google-provider")
def google_provider():
    guard()
    mode=request.form.get("mode")
    if mode not in ("google","smtp"):abort(400)
    if mode=="google" and not opts().get("google_refresh_token"):
        flash("Connect a Google account first.");return redirect("/")
    with db() as c:c.execute("INSERT INTO options(k,v) VALUES ('send_provider',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(mode,))
    flash("Delivery method: "+mode)
    return redirect("/")

if __name__=="__main__":
    threading.Thread(target=loop,daemon=True).start()
    from waitress import serve
    serve(app,host=os.getenv("MAILWATCH_BIND","127.0.0.1"),port=8092,threads=4)
