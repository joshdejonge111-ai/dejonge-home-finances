\
import os, json, sqlite3, io, re, math, pdfplumber
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, send_file, jsonify, abort, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
import pandas as pd
from apscheduler.schedulers.background import BackgroundScheduler
from ics import Calendar, Event

load_dotenv()

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "app.db"
UPLOADS_DIR = APP_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    con = db()
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        settings_json TEXT DEFAULT '{}'
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS plans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        plan_json TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    con.commit()

init_db()

SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-change-me")
app = Flask(__name__)
app.secret_key = SECRET_KEY

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ----- User model -----
class User(UserMixin):
    def __init__(self, id, email, password_hash, role, settings_json):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.role = role or "user"
        self.settings = json.loads(settings_json or "{}")

    @staticmethod
    def row_to_user(row):
        return User(row["id"], row["email"], row["password_hash"], row["role"], row["settings_json"])

    @staticmethod
    def get_by_email(email):
        con = db()
        cur = con.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
        row = cur.fetchone()
        if not row: return None
        return User.row_to_user(row)

    @staticmethod
    def get_by_id(uid):
        con = db()
        cur = con.execute("SELECT * FROM users WHERE id = ?", (uid,))
        row = cur.fetchone()
        if not row: return None
        return User.row_to_user(row)

    @staticmethod
    def create(email, password_hash, role="user"):
        con = db()
        try:
            con.execute("INSERT INTO users(email, password_hash, role) VALUES(?,?,?)", (email.lower(), password_hash, role))
            con.commit()
            return User.get_by_email(email)
        except sqlite3.IntegrityError:
            return None

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# ----- Defaults & simulation -----
DEFAULTS = {
    "weekly_income_initial": 930.0,
    "weekly_income_after_raise": 1116.0,
    "raise_week": 13,
    "savings_rate_initial": 0.25,
    "savings_rate_after_raise": 0.30,
    "savings_goal": 15000.0,
    "debt_balance": 20000.0,
    "housing_weekly": 203.0,
    "variable_weekly": 367.0,
    "weeks_total": 52
}

def settings_for(user):
    s = dict(DEFAULTS)
    s.update(user.settings or {})
    return s

def save_settings(user_id, settings):
    con = db()
    con.execute("UPDATE users SET settings_json=? WHERE id=?", (json.dumps(settings), user_id))
    con.commit()

def simulate_plan(s):
    rows = []
    savings_balance = 0.0
    debt_remaining = float(s["debt_balance"])
    for week in range(1, int(s["weeks_total"])+1):
        income = s["weekly_income_after_raise"] if week >= int(s["raise_week"]) else s["weekly_income_initial"]
        rate = s["savings_rate_after_raise"] if week >= int(s["raise_week"]) else s["savings_rate_initial"]
        saved = income * rate
        extra_to_debt = 0.0
        if savings_balance >= s["savings_goal"]:
            extra_to_debt = saved; saved = 0.0
        debt_payment = max(0.0, income - (s["housing_weekly"] + s["variable_weekly"] + saved)) + extra_to_debt
        debt_remaining = max(0.0, debt_remaining - debt_payment)
        savings_balance += saved
        rows.append({
            "Week": week,
            "Net Income": round(income, 2),
            "Savings Rate": f"{int(rate*100)}%",
            "Saved This Week": round(saved, 2),
            "Total Savings": round(savings_balance, 2),
            "Debt Payment": round(debt_payment, 2),
            "Debt Remaining": round(debt_remaining, 2),
            "Housing & Utilities": round(s["housing_weekly"], 2),
            "Variable Spending": round(s["variable_weekly"], 2)
        })
    return rows

def latest_plan(user_id):
    con = db()
    cur = con.execute("SELECT * FROM plans WHERE user_id=? ORDER BY id DESC LIMIT 1", (user_id,))
    row = cur.fetchone()
    if not row: return None
    return json.loads(row["plan_json"])

def save_plan(user_id, rows):
    con = db()
    con.execute("INSERT INTO plans(user_id, created_at, plan_json) VALUES (?,?,?)",
        (user_id, datetime.utcnow().isoformat(), json.dumps(rows)))
    con.commit()

# ---- Parsers ----
def parse_paystub_csv(bytes_):
    try:
        df = pd.read_csv(io.BytesIO(bytes_))
    except Exception:
        return None
    net_col = None
    for c in df.columns:
        if str(c).strip().lower() in ("net","net pay","net_pay","net_amount","take_home"):
            net_col = c; break
    if net_col is None: net_col = df.columns[-1]
    try:
        nets = pd.to_numeric(df[net_col], errors="coerce").dropna().tolist()
    except Exception:
        return None
    if not nets: return None
    last = nets[-4:] if len(nets) >= 4 else nets
    return sum(last)/len(last)

def parse_qfx(bytes_):
    try:
        text = bytes_.decode("utf-8", errors="ignore")
    except Exception:
        text = bytes_.decode("latin-1", errors="ignore")
    blocks = re.split(r"(?i)<STMTTRN>", text)[1:]
    tx = []
    for b in blocks:
        chunk = re.split(r"(?i)</STMTTRN>", b)[0]
        m = re.search(r"(?i)<TRNAMT>([^<\n]+)", chunk)
        if m:
            amt = float(m.group(1).strip())
            if amt > 0: tx.append(amt)
    if not tx: return None
    last = tx[-8:] if len(tx) >= 8 else tx
    return sum(last)/len(last)

def parse_pdf_paystub(bytes_):
    # Simple text scan for NET PAY lines; works for text-based PDFs.
    nets = []
    with pdfplumber.open(io.BytesIO(bytes_)) as pdf:
        for page in pdf.pages:
            txt = page.extract_text() or ""
            for line in txt.splitlines():
                if re.search(r"\bNET\b.*\bPAY\b", line, re.I):
                    nums = re.findall(r"[\$]?\s?([0-9]{2,3}(?:[,][0-9]{3})*(?:\.[0-9]{2})?)", line)
                    for n in nums:
                        try:
                            nets.append(float(n.replace(",","")))
                        except:
                            pass
    if nets:
        last = nets[-4:] if len(nets) >= 4 else nets
        return sum(last)/len(last)
    return None

# ---- Auth ----
@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email","").lower().strip()
        pwd = request.form.get("password","")
        role = request.form.get("role","user")
        if not email or not pwd:
            return render_template("register.html", error="Email and password required")
        if User.get_by_email(email):
            return render_template("register.html", error="Email already registered")
        ph = generate_password_hash(pwd)
        u = User.create(email, ph, role=role if role in ("user","admin") else "user")
        login_user(u)
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").lower().strip()
        pwd = request.form.get("password","")
        u = User.get_by_email(email)
        if not u or not check_password_hash(u.password_hash, pwd):
            return render_template("login_multi.html", error="Invalid credentials"), 401
        login_user(u)
        return redirect(url_for("dashboard"))
    # seed optional admin from env
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_hash = os.getenv("ADMIN_PASSWORD_HASH")
    if admin_email and admin_hash and not User.get_by_email(admin_email):
        User.create(admin_email, admin_hash, role="admin")
    return render_template("login_multi.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---- Dashboard ----
@app.route("/")
@login_required
def dashboard():
    s = settings_for(current_user)
    # fetch household list (other users) for aggregation
    con = db()
    cur = con.execute("SELECT id,email FROM users WHERE id != ?", (current_user.id,))
    others = [dict(id=row["id"], email=row["email"]) for row in cur.fetchall()]
    return render_template("dashboard_pro.html", settings=s, email=current_user.email, others=others, role=current_user.role)

@app.route("/api/plan")
@login_required
def api_plan():
    plan = latest_plan(current_user.id)
    if not plan:
        s = settings_for(current_user)
        plan = simulate_plan(s)
        save_plan(current_user.id, plan)
    return jsonify(plan)

@app.route("/api/aggregate", methods=["POST"])
@login_required
def api_aggregate():
    # Aggregate current user with selected partner(s)
    data = request.json or {}
    user_ids = data.get("user_ids") or []
    # include self
    ids = [current_user.id] + [int(x) for x in user_ids if isinstance(x, (int,str)) and str(x).isdigit()]
    agg = None
    for uid in ids:
        p = latest_plan(uid)
        if not p:
            u = User.get_by_id(uid)
            if not u: continue
            s = settings_for(u)
            p = simulate_plan(s); save_plan(uid, p)
        df = pd.DataFrame(p)
        subset = df[["Week","Total Savings","Debt Remaining","Saved This Week","Debt Payment"]].copy()
        subset.rename(columns={
            "Total Savings":f"Total Savings {uid}",
            "Debt Remaining":f"Debt Remaining {uid}",
            "Saved This Week":f"Saved {uid}",
            "Debt Payment":f"Debt {uid}"
        }, inplace=True)
        agg = subset if agg is None else agg.merge(subset, on="Week")
    if agg is None:
        return jsonify([])
    # Sum columns by type
    out = pd.DataFrame({"Week": agg["Week"]})
    out["Household Savings"] = agg.filter(like="Total Savings").sum(axis=1)
    out["Household Debt"] = agg.filter(like="Debt Remaining").sum(axis=1)
    out["Household Weekly Saved"] = agg.filter(like="Saved ").sum(axis=1)
    out["Household Weekly Debt Payment"] = agg.filter(like="Debt ").sum(axis=1)
    return out.to_json(orient="records")

@app.route("/api/recalc", methods=["POST"])
@login_required
def api_recalc():
    data = request.json or {}
    s = settings_for(current_user)
    for k in list(s.keys()):
        if k in data: s[k] = data[k]
    save_settings(current_user.id, s)
    plan = simulate_plan(s)
    save_plan(current_user.id, plan)
    return jsonify({"ok": True})

@app.route("/api/upload", methods=["POST"])
@login_required
def api_upload():
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "No file"}), 400
    user_dir = UPLOADS_DIR / str(current_user.id)
    user_dir.mkdir(exist_ok=True, parents=True)
    path = user_dir / f.filename
    b = f.read()
    path.write_bytes(b)
    weekly_net = None
    name = f.filename.lower()
    if name.endswith(".csv"):
        weekly_net = parse_paystub_csv(b)
    elif name.endswith(".qfx") or name.endswith(".ofx"):
        weekly_net = parse_qfx(b)
    elif name.endswith(".pdf"):
        weekly_net = parse_pdf_paystub(b)
    if weekly_net is None:
        return jsonify({"ok": False, "error": "Could not parse paystub"}), 400
    s = settings_for(current_user)
    s["weekly_income_initial"] = round(float(weekly_net), 2)
    s["weekly_income_after_raise"] = round(float(weekly_net) * 1.20, 2)
    save_settings(current_user.id, s)
    plan = simulate_plan(s)
    save_plan(current_user.id, plan)
    return jsonify({"ok": True, "weekly_net": weekly_net})

@app.route("/download/csv")
@login_required
def download_csv():
    plan = latest_plan(current_user.id)
    if not plan:
        s = settings_for(current_user)
        plan = simulate_plan(s)
        save_plan(current_user.id, plan)
    df = pd.DataFrame(plan)
    buf = io.BytesIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="weekly_financial_plan.csv", mimetype="text/csv")

@app.route("/download/milestones.ics")
@login_required
def download_ics():
    # generate ICS with savings-goal and debt-free milestones
    plan = latest_plan(current_user.id)
    if not plan:
        s = settings_for(current_user); plan = simulate_plan(s); save_plan(current_user.id, plan)
    df = pd.DataFrame(plan)
    goal_row = df[df["Total Savings"] >= settings_for(current_user)["savings_goal"]].head(1)
    debt_row = df[df["Debt Remaining"] <= 0].head(1)
    c = Calendar()
    today = datetime.utcnow().date()
    if len(goal_row):
        e = Event(name="Savings Goal Reached", begin=today + timedelta(weeks=int(goal_row["Week"].iloc[0])), duration=timedelta(hours=1))
        c.events.add(e)
    if len(debt_row):
        e = Event(name="Debt-Free 🎉", begin=today + timedelta(weeks=int(debt_row["Week"].iloc[0])), duration=timedelta(hours=1))
        c.events.add(e)
    ics = str(c)
    return send_file(io.BytesIO(ics.encode("utf-8")), as_attachment=True, download_name="milestones.ics", mimetype="text/calendar")

# ---- Nightly Scheduler (unchanged logic) ----
def auto_apply_for_all_users():
    con = db()
    cur = con.execute("SELECT * FROM users")
    users = cur.fetchall()
    for row in users:
        uid = row["id"]
        user_dir = UPLOADS_DIR / str(uid) / "auto"
        if not user_dir.exists(): continue
        for p in user_dir.glob("*.*"):
            try:
                b = p.read_bytes()
                weekly_net = None
                lower = p.name.lower()
                if lower.endswith(".csv"):
                    weekly_net = parse_paystub_csv(b)
                elif lower.endswith(".qfx") or lower.endswith(".ofx"):
                    weekly_net = parse_qfx(b)
                elif lower.endswith(".pdf"):
                    weekly_net = parse_pdf_paystub(b)
                if weekly_net:
                    # update settings & plan
                    con2 = db()
                    cur2 = con2.execute("SELECT * FROM users WHERE id=?", (uid,))
                    urow = cur2.fetchone()
                    if not urow: continue
                    settings_json = json.loads(urow["settings_json"] or "{}")
                    s = dict(DEFAULTS); s.update(settings_json)
                    s["weekly_income_initial"] = round(float(weekly_net), 2)
                    s["weekly_income_after_raise"] = round(float(weekly_net) * 1.20, 2)
                    con2.execute("UPDATE users SET settings_json=? WHERE id=?", (json.dumps(s), uid))
                    con2.commit()
                    plan = simulate_plan(s)
                    con2.execute("INSERT INTO plans(user_id, created_at, plan_json) VALUES(?,?,?)",
                        (uid, datetime.utcnow().isoformat(), json.dumps(plan)))
                    con2.commit()
            except Exception as e:
                print("Auto-apply failed for", p, "err:", e)

def schedule_nightly(app):
    hhmm = os.getenv("SCHEDULER_DAILY_HHMM", "03:00")
    try:
        hh, mm = [int(x) for x in hhmm.split(":")]
    except Exception:
        hh, mm = 3, 0
    sched = BackgroundScheduler(daemon=True)
    sched.add_job(auto_apply_for_all_users, 'cron', hour=hh, minute=mm)
    sched.start()

schedule_nightly(app)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
