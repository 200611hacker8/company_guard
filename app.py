from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import os, json, hashlib, datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------- Config ----------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key')

# ---------- Paths ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
USERS_FILE = os.path.join(DATA_DIR, "users.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
LOGS_FILE = os.path.join(DATA_DIR, "logs.json")
INSTRUCTIONS_FILE = os.path.join(DATA_DIR, "instructions.json")

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt', 'xlsx', 'csv'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 MB

# ---------- Helpers ----------
def load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=4)
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256')

def check_password(hashed, password):
    return check_password_hash(hashed, password)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_files(user):
    user_dir = os.path.join(UPLOAD_DIR, user)
    if not os.path.exists(user_dir):
        return []
    files = []
    for f in os.listdir(user_dir):
        path = os.path.join(user_dir, f)
        if os.path.isfile(path):
            stat = os.stat(path)
            files.append({
                'name': f,
                'size_kb': round(stat.st_size / 1024, 2),
                'mtime': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            })
    return files

def log_action(user, action):
    logs = load_json(LOGS_FILE, {"events": []})
    logs["events"].append({
        "user": user,
        "action": action,
        "time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    save_json(LOGS_FILE, logs)

# ---------- Routes ----------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "employee")
        if not username or not password:
            flash("Username and password required!", "danger")
            return redirect(url_for("register"))
        users = load_json(USERS_FILE, {})
        if username in users:
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))
        users[username] = {"password": hash_password(password), "role": role, "must_change_pw": False}
        save_json(USERS_FILE, users)
        log_action("system", f"User {username} registered as {role}")
        flash("Account created successfully!", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        users = load_json(USERS_FILE, {})
        if username in users and check_password(users[username]["password"], password):
            session["user"] = username
            session["role"] = users[username]["role"]
            log_action(username, "logged in")
            flash("Login successful!", "success")
            role = users[username]["role"]
            if role == "admin":
                return redirect(url_for("admin"))
            elif role == "assistant":
                return redirect(url_for("assistant"))
            else:
                return redirect(url_for("employee"))
        flash("Invalid credentials!", "danger")
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    user = session["user"]
    files = get_user_files(user)
    settings = load_json(SETTINGS_FILE, {})
    return render_template("dashboard.html", user=user, files=files, global_password=settings.get("global_password", ""), last_updated=settings.get("last_updated", ""), hint=settings.get("hint", ""))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        file = request.files.get("file")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            user_dir = os.path.join(UPLOAD_DIR, session["user"])
            os.makedirs(user_dir, exist_ok=True)
            file_path = os.path.join(user_dir, filename)
            if os.path.exists(file_path):
                flash("File already exists!", "warning")
            else:
                file.save(file_path)
                log_action(session["user"], f"uploaded file {filename}")
                flash("File uploaded successfully!", "success")
        else:
            flash("Invalid file type!", "danger")
    return render_template("upload.html")

@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect(url_for("login"))
    user_dir = os.path.join(UPLOAD_DIR, session["user"])
    return send_from_directory(user_dir, filename)

@app.route("/delete/<filename>", methods=["POST"])
def delete(filename):
    if "user" not in session:
        return redirect(url_for("login"))
    user_dir = os.path.join(UPLOAD_DIR, session["user"])
    file_path = os.path.join(user_dir, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        log_action(session["user"], f"deleted file {filename}")
        flash("File deleted!", "success")
    return redirect(url_for("dashboard"))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        new_password = request.form.get("password", "")
        if new_password:
            users = load_json(USERS_FILE, {})
            users[session["user"]]["password"] = hash_password(new_password)
            users[session["user"]]["must_change_pw"] = False
            save_json(USERS_FILE, users)
            log_action(session["user"], "changed password")
            flash("Password changed!", "success")
            return redirect(url_for("dashboard"))
        flash("Password required!", "danger")
    return render_template("change_password.html")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    settings = load_json(SETTINGS_FILE, {})
    users = load_json(USERS_FILE, {})
    logs = load_json(LOGS_FILE, {"events": []})["events"]
    instructions = load_json(INSTRUCTIONS_FILE, {"instructions": []})["instructions"]
    files_overview = {}
    for u in users:
        files_overview[u] = get_user_files(u)
    if request.method == "POST":
        action = request.form.get("action")
        if action == "set_global":
            global_pw = request.form.get("global_password", "")
            admin_code = request.form.get("admin_code", "")
            hint = request.form.get("hint", "")
            settings["global_password"] = global_pw
            settings["admin_code"] = admin_code
            settings["hint"] = hint
            settings["last_updated"] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            save_json(SETTINGS_FILE, settings)
            log_action(session["user"], "updated global settings")
            flash("Settings updated!", "success")
        elif action == "add_user":
            new_email = request.form.get("new_email", "").strip().lower()
            new_pw = request.form.get("new_user_password", "")
            new_role = request.form.get("new_role", "employee")
            if new_email and new_pw:
                users[new_email] = {"password": hash_password(new_pw), "role": new_role, "must_change_pw": False}
                save_json(USERS_FILE, users)
                log_action(session["user"], f"added user {new_email}")
                flash("User added!", "success")
        elif action == "delete_user":
            delete_email = request.form.get("delete_email", "").strip().lower()
            if delete_email in users and delete_email != session["user"]:
                del users[delete_email]
                save_json(USERS_FILE, users)
                log_action(session["user"], f"deleted user {delete_email}")
                flash("User deleted!", "success")
        elif action == "admin_set_pw_logout":
            new_pw = request.form.get("admin_new_password", "")
            if new_pw:
                users[session["user"]]["password"] = hash_password(new_pw)
                save_json(USERS_FILE, users)
                log_action(session["user"], "changed own password and logged out")
                session.clear()
                flash("Password set and logged out!", "info")
                return redirect(url_for("login"))
        elif action == "add_instruction":
            instr = request.form.get("instruction", "").strip()
            recipient = request.form.get("recipient", "all")
            if instr:
                instrs = load_json(INSTRUCTIONS_FILE, {"instructions": []})
                instrs["instructions"].append({
                    "time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "by": session["user"],
                    "text": instr,
                    "recipient": recipient
                })
                save_json(INSTRUCTIONS_FILE, instrs)
                log_action(session["user"], "added instruction")
                flash("Instruction added!", "success")
        return redirect(url_for("admin"))
    return render_template("admin.html", settings=settings, files_overview=files_overview, instructions=instructions, logs=logs)

@app.route("/employee")
def employee():
    if "user" not in session:
        return redirect(url_for("login"))
    role = session.get("role")
    users = load_json(USERS_FILE, {})
    if role == "admin":
        files_overview = {u: get_user_files(u) for u in users}
        files = []
    else:
        files_overview = None
        files = get_user_files(session["user"])
    instructions = load_json(INSTRUCTIONS_FILE, {"instructions": []})["instructions"]
    filtered_instructions = [i for i in instructions if i.get("recipient", "all") in ["all", "employee"] or role == "admin"]
    return render_template("employee.html", files=files, instructions=filtered_instructions, files_overview=files_overview)

@app.route("/assistant")
def assistant():
    if "user" not in session:
        return redirect(url_for("login"))
    role = session.get("role")
    users = load_json(USERS_FILE, {})
    if role == "admin":
        files_overview = {u: get_user_files(u) for u in users}
    else:
        files_overview = {u: get_user_files(u) for u in users}
    instructions = load_json(INSTRUCTIONS_FILE, {"instructions": []})["instructions"]
    filtered_instructions = [i for i in instructions if i.get("recipient", "all") in ["all", "assistant"] or role == "admin"]
    return render_template("assistant.html", files_overview=files_overview, instructions=filtered_instructions)

@app.route("/add_instruction", methods=["POST"])
def add_instruction():
    if "user" not in session:
        return redirect(url_for("login"))
    action = request.form.get("action")
    if action == "add_instruction":
        instr = request.form.get("instruction", "").strip()
        if instr:
            instrs = load_json(INSTRUCTIONS_FILE, {"instructions": []})
            instrs["instructions"].append({
                "time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "by": session["user"],
                "text": instr
            })
            save_json(INSTRUCTIONS_FILE, instrs)
            log_action(session["user"], "added instruction")
            flash("تم إضافة التعليم!", "success")
    return redirect(url_for("assistant"))

@app.route("/upload_file", methods=["POST"])
def upload_file():
    if "user" not in session:
        return redirect(url_for("login"))
    file = request.files.get("file")
    if file and allowed_file(file.filename) and file.content_length <= MAX_FILE_SIZE:
        filename = secure_filename(file.filename)
        user_dir = os.path.join(UPLOAD_DIR, session["user"])
        os.makedirs(user_dir, exist_ok=True)
        file_path = os.path.join(user_dir, filename)
        if os.path.exists(file_path):
            flash("File already exists!", "warning")
        else:
            file.save(file_path)
            log_action(session["user"], f"uploaded file {filename}")
            flash("File uploaded!", "success")
    else:
        flash("Invalid file or too large!", "danger")
    role = session.get("role")
    if role == "admin":
        return redirect(url_for("admin"))
    elif role == "assistant":
        return redirect(url_for("assistant"))
    else:
        return redirect(url_for("employee"))

@app.route("/delete_file", methods=["POST"])
def delete_file():
    if "user" not in session:
        return redirect(url_for("login"))
    file_user = request.form.get("file_user")
    file_name = request.form.get("file_name")
    if file_user == session["user"] or session.get("role") == "admin":
        user_dir = os.path.join(UPLOAD_DIR, file_user)
        file_path = os.path.join(user_dir, file_name)
        if os.path.exists(file_path):
            os.remove(file_path)
            log_action(session["user"], f"deleted file {file_name} for {file_user}")
            flash("File deleted!", "success")
    return redirect(url_for("employee"))

@app.route("/map")
def map():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("map.html")

@app.route("/send_location", methods=["POST"])
def send_location():
    if "user" not in session:
        return {"error": "Not logged in"}, 401
    data = request.get_json()
    lat = data.get("lat")
    lng = data.get("lng")
    if lat and lng:
        log_action(session["user"], f"sent location: {lat}, {lng}")
        # Here you can save the location to a file or database if needed
        return {"message": "Location sent successfully"}
    return {"error": "Invalid data"}, 400

@app.route("/users")
def users():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    users_data = load_json(USERS_FILE, {})
    return render_template("users.html", users=users_data)

@app.route("/add_reply", methods=["POST"])
def add_reply():
    if "user" not in session:
        return redirect(url_for("login"))
    instr_index = int(request.form.get("instr_index"))
    reply_text = request.form.get("reply", "").strip()
    if reply_text:
        instrs = load_json(INSTRUCTIONS_FILE, {"instructions": []})
        if "replies" not in instrs["instructions"][instr_index]:
            instrs["instructions"][instr_index]["replies"] = []
        instrs["instructions"][instr_index]["replies"].append({
            "time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "by": session["user"],
            "text": reply_text
        })
        save_json(INSTRUCTIONS_FILE, instrs)
        log_action(session["user"], f"replied to instruction {instr_index}")
        flash("تم إضافة الرد!", "success")
    role = session.get("role")
    if role == "admin":
        return redirect(url_for("admin"))
    elif role == "assistant":
        return redirect(url_for("assistant"))
    else:
        return redirect(url_for("employee"))

@app.route("/logout")
def logout():
    if "user" in session:
        log_action(session["user"], "logged out")
    session.clear()
    flash("Logged out!", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
