import sqlite3, re, json, secrets
from datetime import datetime, timedelta, date
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, session,
                   flash, jsonify, abort)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
DB = "crm.db"
ROLES = ["Admin", "Manager", "SalesExecutive"]
OPTIONAL = {"address", "company", "remarks", "source"}
LEAD_ST = ["New", "Contacted", "Qualified", "Unqualified", "Converted", "Lost"]
STAGES = ["Qualification", "Proposal", "Negotiation", "Won", "Lost"]

# Each module = list of (column, label, type, select-options)
MODULES = {
 "customers": {"title": "Customers", "fields": [
   ("name", "Customer Name", "text", None), ("email", "Email", "email", None),
   ("phone", "Phone", "phone", None), ("company", "Company", "text", None),
   ("address", "Address", "text", None),
   ("status", "Status", "select", ["Active", "Inactive"])]},
 "leads": {"title": "Leads", "fields": [
   ("name", "Lead Name", "text", None), ("email", "Email", "email", None),
   ("phone", "Phone", "phone", None), ("company", "Company", "text", None),
   ("source", "Source", "text", None),
   ("expected_value", "Expected Value", "number", None),
   ("status", "Status", "select", LEAD_ST)]},
 "opportunities": {"title": "Opportunities", "fields": [
   ("name", "Opportunity Name", "text", None), ("customer", "Customer", "text", None),
   ("amount", "Amount", "number", None), ("probability", "Probability %", "number", None),
   ("stage", "Stage", "select", STAGES),
   ("close_date", "Expected Close Date", "date", None)]},
 "followups": {"title": "Follow-Ups", "fields": [
   ("subject", "Subject", "text", None), ("related", "Customer / Lead", "text", None),
   ("followup_date", "Follow-Up Date", "date", None),
   ("type", "Type", "select", ["Call", "Meeting", "Email", "Task"]),
   ("status", "Status", "select", ["Planned", "Completed", "Missed", "Cancelled"]),
   ("remarks", "Remarks", "text", None)]},
}

# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e):
    d = g.pop("db", None)
    if d:
        d.close()

def init_db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password_hash TEXT, role TEXT, active INTEGER DEFAULT 1, failed INTEGER DEFAULT 0, lock_until TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, entity TEXT, record_id INTEGER, old_value TEXT, new_value TEXT, created TEXT, ip TEXT)")
    for t, m in MODULES.items():
        cols = ",".join(f"{f[0]} {'REAL' if f[2] == 'number' else 'TEXT'}" for f in m["fields"])
        c.execute(f"CREATE TABLE IF NOT EXISTS {t} (id INTEGER PRIMARY KEY AUTOINCREMENT, owner INTEGER, created TEXT, {cols})")
    if not c.execute("SELECT 1 FROM users").fetchone():
        for n, e, p, r in [("Admin", "admin@acxiom.com", "Admin@123", "Admin"),
                           ("Manager", "manager@acxiom.com", "Manager@123", "Manager"),
                           ("Sales Exec", "sales@acxiom.com", "Sales@123", "SalesExecutive")]:
            c.execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
                      (n, e, generate_password_hash(p), r))
    c.commit()
    c.close()

def audit(action, entity="", rid=None, old=None, new=None, uid=None):
    db().execute("INSERT INTO audit (user_id,action,entity,record_id,old_value,new_value,created,ip) VALUES (?,?,?,?,?,?,?,?)",
                 (uid or session.get("uid"), action, entity, rid,
                  json.dumps(old) if old else None, json.dumps(new) if new else None,
                  datetime.now().strftime("%Y-%m-%d %H:%M:%S"), request.remote_addr))
    db().commit()

# ---------- security ----------
def login_required(roles=None):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            api = request.path.startswith("/api/")
            if "uid" not in session:
                return (jsonify(error="Login required"), 401) if api else redirect("/login")
            if roles and session["role"] not in roles:
                abort(403)
            return f(*a, **k)
        return w
    return deco

@app.before_request
def csrf():
    if "token" not in session:
        session["token"] = secrets.token_hex(16)
    if request.method == "POST" and not request.path.startswith("/api/"):
        if request.form.get("token") != session["token"]:
            abort(400)

@app.context_processor
def inject():
    return {"token": session.get("token"), "optional": OPTIONAL}

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def error(e):
    if request.path.startswith("/api/"):
        return jsonify(error=e.name), e.code
    return render_template("error.html", e=e), e.code

def pw_ok(p):
    return len(p) >= 8 and re.search(r"[A-Za-z]", p) and re.search(r"\d", p)

# ---------- validation ----------
def validate(t, d, rid=None):
    e = {}
    for n, label, typ, opts in MODULES[t]["fields"]:
        v = str(d.get(n) or "").strip()
        if not v:
            if n not in OPTIONAL:
                e[n] = f"{label} is required."
        elif len(v) > 100:
            e[n] = f"{label} must be at most 100 characters."
        elif typ == "email" and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            e[n] = "Enter a valid email address."
        elif typ == "phone" and not re.match(r"^[6-9]\d{9}$", v):
            e[n] = "Enter a valid 10-digit phone number."
        elif typ == "select" and v not in opts:
            e[n] = f"Invalid {label}."
        elif typ == "number":
            try:
                float(v)
            except ValueError:
                e[n] = f"{label} must be a number."
        elif typ == "date":
            try:
                datetime.strptime(v, "%Y-%m-%d")
            except ValueError:
                e[n] = "Enter a valid date."
    if e:
        return e
    val = lambda k: str(d.get(k) or "").strip()
    today = str(date.today())
    if t == "customers":
        if db().execute("SELECT 1 FROM customers WHERE (email=? OR phone=?) AND id!=?",
                        (val("email"), val("phone"), rid or 0)).fetchone():
            e["email"] = "A customer with this email or phone already exists."
    if t == "leads":
        if float(val("expected_value")) < 0:
            e["expected_value"] = "Expected value cannot be negative."
        old = db().execute("SELECT status FROM leads WHERE id=?", (rid or 0,)).fetchone()
        os_ = old["status"] if old else None
        if val("status") == "Converted" and os_ != "Converted":
            e["status"] = "Use the Convert button to convert a lead."
        elif os_ in ("Converted", "Lost") and val("status") != os_:
            e["status"] = f"A {os_} lead cannot change status."
    if t == "opportunities":
        active = val("stage") not in ("Won", "Lost")
        if float(val("amount")) < 0 or (active and float(val("amount")) <= 0):
            e["amount"] = "Opportunity Amount must be greater than 0."
        if not 0 <= float(val("probability")) <= 100:
            e["probability"] = "Probability must be between 0 and 100."
        if active and val("close_date") < today:
            e["close_date"] = "Expected Close Date cannot be in the past."
    if t == "followups" and val("status") == "Planned" and val("followup_date") < today:
        e["followup_date"] = "Follow-up date cannot be earlier than today."
    return e

# ---------- data helpers ----------
def mod(t):
    if t not in MODULES:
        abort(404)
    return MODULES[t]

def fetch(t, q=""):
    cols = [f[0] for f in MODULES[t]["fields"]]
    sql = f"SELECT x.*, u.name AS owner_name FROM {t} x LEFT JOIN users u ON u.id=x.owner WHERE 1=1"
    p = []
    if session["role"] == "SalesExecutive":
        sql += " AND x.owner=?"
        p.append(session["uid"])
    if q:
        sql += " AND (" + " OR ".join(f"x.{c} LIKE ?" for c in cols) + ")"
        p += ["%" + q + "%"] * len(cols)
    return db().execute(sql + " ORDER BY x.id DESC", p).fetchall()

def get_rec(t, rid):
    r = db().execute(f"SELECT * FROM {t} WHERE id=?", (rid,)).fetchone()
    if not r:
        abort(404)
    if session["role"] == "SalesExecutive" and r["owner"] != session["uid"]:
        abort(403)
    return r

def save(t, d, rid=None, old=None):
    cols = [f[0] for f in MODULES[t]["fields"]]
    vals = [str(d.get(c) or "").strip() for c in cols]
    new = dict(zip(cols, vals))
    if rid:
        db().execute(f"UPDATE {t} SET " + ",".join(c + "=?" for c in cols) + " WHERE id=?", vals + [rid])
        audit("Update", t, rid, old, new)
    else:
        marks = ",".join("?" * len(cols))
        names = ",".join(cols)
        rid = db().execute(f"INSERT INTO {t} (owner,created,{names}) VALUES (?,?,{marks})",
                           [session["uid"], str(date.today())] + vals).lastrowid
        audit("Create", t, rid, None, new)
    db().commit()
    return rid

# ---------- authentication ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if u and u["lock_until"] and u["lock_until"] > now:
            flash("Account locked. Try again after 5 minutes.", "danger")
            audit("Failed Login (Locked)", "users", u["id"], uid=u["id"])
        elif u and u["active"] and check_password_hash(u["password_hash"], pw):
            db().execute("UPDATE users SET failed=0, lock_until=NULL WHERE id=?", (u["id"],))
            db().commit()
            session.clear()
            session.update(uid=u["id"], role=u["role"], name=u["name"], token=secrets.token_hex(16))
            audit("Login", "users", u["id"])
            return redirect("/")
        else:
            flash("Invalid email or password.", "danger")
            if u:
                f, lock = u["failed"] + 1, None
                if f >= 3:
                    lock = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
                    f = 0
                db().execute("UPDATE users SET failed=?, lock_until=? WHERE id=?", (f, lock, u["id"]))
                db().commit()
                audit("Failed Login" + (" (Locked)" if lock else ""), "users", u["id"], uid=u["id"])
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    e = {}
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        if not name or len(name) > 100:
            e["name"] = "Name is required (max 100 characters)."
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            e["email"] = "Enter a valid email address."
        elif db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            e["email"] = "Email already registered."
        if not pw_ok(pw):
            e["password"] = "Password needs 8+ characters with letters and numbers."
        if not e:
            uid = db().execute("INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)",
                               (name, email, generate_password_hash(pw), "SalesExecutive")).lastrowid
            db().commit()
            audit("Register", "users", uid, uid=uid)
            flash("Registered. Please login.", "success")
            return redirect("/login")
    return render_template("register.html", errors=e)

@app.route("/logout", methods=["POST"])
@login_required()
def logout():
    audit("Logout", "users", session["uid"])
    session.clear()
    return redirect("/login")

# ---------- dashboard ----------
@app.route("/")
@login_required()
def dashboard():
    own = f" AND owner={int(session['uid'])}" if session["role"] == "SalesExecutive" else ""
    one = lambda sql: db().execute(sql).fetchone()[0]
    stats = {
        "Total Customers": one(f"SELECT COUNT(*) FROM customers WHERE 1=1{own}"),
        "Total Leads": one(f"SELECT COUNT(*) FROM leads WHERE 1=1{own}"),
        "Open Leads": one(f"SELECT COUNT(*) FROM leads WHERE status IN ('New','Contacted','Qualified'){own}"),
        "Open Opportunities": one(f"SELECT COUNT(*) FROM opportunities WHERE stage NOT IN ('Won','Lost'){own}"),
        "Won Opportunities": one(f"SELECT COUNT(*) FROM opportunities WHERE stage='Won'{own}"),
        "Lost Opportunities": one(f"SELECT COUNT(*) FROM opportunities WHERE stage='Lost'{own}"),
        "Pipeline Value": one(f"SELECT COALESCE(SUM(amount),0) FROM opportunities WHERE stage NOT IN ('Won','Lost'){own}"),
        "Pending Follow-Ups": one(f"SELECT COUNT(*) FROM followups WHERE status='Planned'{own}"),
    }
    lc = {r[0]: r[1] for r in db().execute(f"SELECT status, COUNT(*) FROM leads WHERE 1=1{own} GROUP BY status")}
    oc = {r[0]: r[1] for r in db().execute(f"SELECT stage, COUNT(*) FROM opportunities WHERE 1=1{own} GROUP BY stage")}
    return render_template("dashboard.html", stats=stats,
                           lead_labels=LEAD_ST, lead_data=[lc.get(s, 0) for s in LEAD_ST],
                           opp_labels=STAGES, opp_data=[oc.get(s, 0) for s in STAGES])

# ---------- CRUD pages ----------
@app.route("/m/<t>")
@login_required()
def lst(t):
    m = mod(t)
    q = request.args.get("q", "").strip()
    return render_template("list.html", t=t, m=m, rows=fetch(t, q), q=q)

@app.route("/m/<t>/new", methods=["GET", "POST"])
@app.route("/m/<t>/<int:rid>/edit", methods=["GET", "POST"])
@login_required()
def item(t, rid=None):
    m = mod(t)
    old = dict(get_rec(t, rid)) if rid else None
    d, errors = old or {}, {}
    if request.method == "POST":
        d = {k: v.strip() for k, v in request.form.items()}
        errors = validate(t, d, rid)
        if not errors:
            save(t, d, rid, old)
            flash("Saved successfully.", "success")
            return redirect(f"/m/{t}")
    return render_template("form.html", t=t, m=m, d=d, errors=errors, edit=bool(rid))

@app.route("/m/<t>/<int:rid>/delete", methods=["POST"])
@login_required(["Admin", "Manager"])
def delete(t, rid):
    mod(t)
    old = dict(get_rec(t, rid))
    db().execute(f"DELETE FROM {t} WHERE id=?", (rid,))
    db().commit()
    audit("Delete", t, rid, old)
    flash("Deleted.", "success")
    return redirect(f"/m/{t}")

@app.route("/m/leads/<int:rid>/convert", methods=["POST"])
@login_required()
def convert(rid):
    l = get_rec("leads", rid)
    if l["status"] != "Qualified":
        flash("Only Qualified leads can be converted.", "danger")
    elif db().execute("SELECT 1 FROM customers WHERE email=? OR phone=?", (l["email"], l["phone"])).fetchone():
        flash("A customer with this email/phone already exists.", "danger")
    else:
        cid = db().execute("INSERT INTO customers (owner,created,name,email,phone,company,address,status) VALUES (?,?,?,?,?,?,?,?)",
                           (l["owner"], str(date.today()), l["name"], l["email"], l["phone"], l["company"], "", "Active")).lastrowid
        db().execute("UPDATE leads SET status='Converted' WHERE id=?", (rid,))
        db().commit()
        audit("Lead Converted", "leads", rid, {"status": l["status"]}, {"status": "Converted", "customer_id": cid})
        flash("Lead converted to customer.", "success")
    return redirect("/m/leads")

# ---------- admin ----------
@app.route("/users", methods=["GET", "POST"])
@login_required(["Admin"])
def users():
    if request.method == "POST":
        uid, role = int(request.form["id"]), request.form["role"]
        active = 1 if request.form.get("active") else 0
        if role not in ROLES:
            abort(400)
        if uid == session["uid"]:
            role, active = "Admin", 1
        old = db().execute("SELECT role, active FROM users WHERE id=?", (uid,)).fetchone()
        db().execute("UPDATE users SET role=?, active=?, failed=0, lock_until=NULL WHERE id=?", (role, active, uid))
        db().commit()
        audit("Role Change", "users", uid, dict(old), {"role": role, "active": active})
        flash("User updated (lockout cleared).", "success")
    rows = db().execute("SELECT id,name,email,role,active,lock_until FROM users").fetchall()
    return render_template("users.html", rows=rows, roles=ROLES)

@app.route("/audit")
@login_required(["Admin"])
def audit_log():
    a = request.args.get("action", "").strip()
    rows = db().execute("SELECT a.*, u.email FROM audit a LEFT JOIN users u ON u.id=a.user_id WHERE (?='' OR a.action LIKE ?) ORDER BY a.id DESC LIMIT 200",
                        (a, "%" + a + "%")).fetchall()
    return render_template("audit.html", rows=rows, a=a)

# ---------- REST API ----------
@app.route("/api/<t>", methods=["GET", "POST"])
@app.route("/api/<t>/<int:rid>", methods=["GET", "PUT", "DELETE"])
@login_required()
def api(t, rid=None):
    mod(t)
    if request.method == "GET":
        if rid:
            return jsonify(dict(get_rec(t, rid)))
        return jsonify([dict(r) for r in fetch(t, request.args.get("q", ""))])
    if request.method == "DELETE":
        if session["role"] not in ("Admin", "Manager"):
            abort(403)
        old = dict(get_rec(t, rid))
        db().execute(f"DELETE FROM {t} WHERE id=?", (rid,))
        db().commit()
        audit("Delete", t, rid, old)
        return jsonify(message="Deleted"), 200
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="JSON body required"), 400
    old = dict(get_rec(t, rid)) if rid else None
    errors = validate(t, d, rid)
    if errors:
        code = 409 if any("exists" in v for v in errors.values()) else 400
        return jsonify(errors=errors), code
    new_id = save(t, d, rid, old)
    return jsonify(dict(get_rec(t, new_id))), (200 if rid else 201)

init_db()
if __name__ == "__main__":
    app.run(debug=True)
