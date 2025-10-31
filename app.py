import os
import io
import csv
import uuid
import sqlite3
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_file,
    jsonify,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import qrcode
import zipfile

# 👇 this is the only global we need for QR
# on Render, set VERIFY_BASE_URL in the dashboard
VERIFY_BASE_URL = os.getenv("VERIFY_BASE_URL", "http://localhost:5000")

app = Flask(__name__)
app.secret_key = "your-secret-key-change-this"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ===================== DB SETUP =====================
def init_db():
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()

    # users
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )

    # certificates
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            course_name TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            email TEXT,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """
    )

    # seed admin
    c.execute("SELECT * FROM users WHERE username='admin'")
    if not c.fetchone():
        admin_pass = generate_password_hash("admin123")
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", admin_pass, "admin"),
        )

    conn.commit()
    conn.close()


# ===================== USER MODEL =====================
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1], row[2])
    return None


# ===================== PDF HELPER =====================
def build_pdf_from_row(cert, style="default"):
    """
    cert = (certificate_id, name, course_name, issue_date)
    """
    cert_id, name, course_name, issue_date = cert

    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=landscape(letter))
    width, height = landscape(letter)

    # background
    if style == "classic":
        c.setFillColorRGB(1, 1, 1)
        c.rect(0, 0, width, height, fill=True, stroke=False)
        c.setStrokeColorRGB(0.1, 0.1, 0.1)
        c.setLineWidth(4)
        c.rect(25, 25, width - 50, height - 50, fill=False, stroke=True)
    else:
        c.setFillColorRGB(0.95, 0.95, 1)
        c.rect(0, 0, width, height, fill=True, stroke=False)
        c.setStrokeColorRGB(0.2, 0.2, 0.6)
        c.setLineWidth(3)
        c.rect(30, 30, width - 60, height - 60, fill=False, stroke=True)

    # title
    c.setFillColorRGB(0.1, 0.1, 0.5)
    c.setFont("Helvetica-Bold", 40)
    c.drawCentredString(width / 2, height - 100, "CERTIFICATE OF COMPLETION")

    # divider
    c.setStrokeColorRGB(0.7, 0.7, 0.7)
    c.line(150, height - 130, width - 150, height - 130)

    # body text
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 16)
    c.drawCentredString(width / 2, height - 180, "This is to certify that")

    # name
    c.setFillColorRGB(0.1, 0.1, 0.5)
    c.setFont("Helvetica-Bold", 32)
    c.drawCentredString(width / 2, height - 230, name)

    # course text
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 16)
    c.drawCentredString(width / 2, height - 280, "has successfully completed the course")

    c.setFont("Helvetica-Bold", 24)
    c.drawCentredString(width / 2, height - 320, course_name)

    # date
    c.setFont("Helvetica", 14)
    c.drawCentredString(width / 2, height - 370, f"Date of Completion: {issue_date}")

    # ✅ QR (here we DO have cert_id)
    verify_url = f"{VERIFY_BASE_URL}/verify/{cert_id}"
    qr = qrcode.QRCode(version=1, box_size=3, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    c.drawImage(ImageReader(qr_buffer), 50, 50, width=80, height=80)
    c.setFont("Helvetica", 8)
    c.drawString(50, 35, "Scan to verify")

    # ✅ text signature (Joshna)
    c.setStrokeColorRGB(0, 0, 0)
    c.line(width - 250, 100, width - 100, 100)  # base line
    c.setFont("Helvetica-Oblique", 18)
    c.setFillColorRGB(0.1, 0.1, 0.1)
    c.drawCentredString(width - 175, 108, "Joshna")
    c.setFont("Helvetica", 10)
    c.setFillColorRGB(0, 0, 0)
    c.drawCentredString(width - 175, 88, "Authorized Signature")

    # footer cert id
    c.setFont("Helvetica", 8)
    c.drawString(width - 200, 35, f"Certificate ID: {cert_id}")

    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer.getvalue()


# ===================== ROUTES =====================

@app.route("/")
def index():
    return render_template("index.html")


# ---------- AUTH ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect("certificates.db")
        c = conn.cursor()
        c.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,),
        )
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[2], password):
            user = User(row[0], row[1], row[3])
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for("index"))


# ---------- DASHBOARD ----------
@app.route("/dashboard")
@login_required
def dashboard():
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()

    if current_user.role == "admin":
        c.execute("SELECT COUNT(*) FROM certificates")
        total_certs = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]
    else:
        c.execute(
            "SELECT COUNT(*) FROM certificates WHERE created_by = ?",
            (current_user.id,),
        )
        total_certs = c.fetchone()[0]
        total_users = 0

    conn.close()
    return render_template(
        "dashboard.html",
        total_certs=total_certs,
        total_users=total_users,
    )


# ---------- GENERATE ----------
@app.route("/generate", methods=["GET", "POST"])
@login_required
def generate():
    if request.method == "POST":
        course_name = request.form.get("course_name")
        issue_date = request.form.get("issue_date")

        names = []
        emails = {}

        # CSV upload
        file = request.files.get("csv_file")
        if file and file.filename.endswith(".csv"):
            stream = io.StringIO(file.stream.read().decode("utf-8"))
            reader = csv.reader(stream)
            for row in reader:
                if not row:
                    continue
                name = row[0].strip()
                if not name:
                    continue
                names.append(name)
                if len(row) > 1 and row[1].strip():
                    emails[name] = row[1].strip()
        else:
            # textarea
            names_input = request.form.get("names", "")
            for line in names_input.splitlines():
                line = line.strip()
                if line:
                    names.append(line)

        conn = sqlite3.connect("certificates.db")
        c = conn.cursor()
        generated = 0

        for name in names:
            unique_part = uuid.uuid4().hex[:6].upper()
            cert_id = f"CERT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{unique_part}"
            email = emails.get(name, None)
            try:
                c.execute(
                    """
                    INSERT INTO certificates
                    (certificate_id, name, course_name, issue_date, email, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (
                        cert_id,
                        name,
                        course_name,
                        issue_date,
                        email,
                        current_user.id,
                    ),
                )
                generated += 1
            except sqlite3.IntegrityError:
                # skip duplicate
                continue

        conn.commit()
        conn.close()

        flash(f"Successfully generated {generated} certificates!", "success")
        return redirect(url_for("view_certificates"))

    return render_template("generate.html")


# ---------- LIST CERTS ----------
@app.route("/certificates")
@login_required
def view_certificates():
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()

    if current_user.role == "admin":
        c.execute(
            """
            SELECT certificate_id, name, course_name, issue_date, created_at
            FROM certificates
            ORDER BY created_at DESC
        """
        )
    else:
        c.execute(
            """
            SELECT certificate_id, name, course_name, issue_date, created_at
            FROM certificates
            WHERE created_by = ?
            ORDER BY created_at DESC
        """,
            (current_user.id,),
        )

    certs = c.fetchall()
    conn.close()

    return render_template("certificates.html", certificates=certs)


# ---------- DOWNLOAD SINGLE ----------
@app.route("/download/<cert_id>")
@login_required
def download_certificate(cert_id):
    style = request.args.get("style", "default")

    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()
    c.execute(
        """
        SELECT certificate_id, name, course_name, issue_date
        FROM certificates
        WHERE certificate_id = ?
    """,
        (cert_id,),
    )
    row = c.fetchone()
    conn.close()

    if not row:
        flash("Certificate not found", "error")
        return redirect(url_for("view_certificates"))

    pdf_bytes = build_pdf_from_row(row, style=style)
    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=True,
        download_name=f"{cert_id}.pdf",
        mimetype="application/pdf",
    )


# ---------- DOWNLOAD ALL AS ZIP ----------
@app.route("/download_all")
@login_required
def download_all():
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()

    if current_user.role == "admin":
        c.execute(
            "SELECT certificate_id, name, course_name, issue_date FROM certificates"
        )
    else:
        c.execute(
            """
            SELECT certificate_id, name, course_name, issue_date
            FROM certificates
            WHERE created_by = ?
        """,
            (current_user.id,),
        )

    rows = c.fetchall()
    conn.close()

    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for row in rows:
            pdf_bytes = build_pdf_from_row(row)
            zf.writestr(f"{row[0]}.pdf", pdf_bytes)

    mem_zip.seek(0)
    return send_file(
        mem_zip,
        as_attachment=True,
        download_name="certificates.zip",
        mimetype="application/zip",
    )


# ---------- VERIFY ----------
@app.route("/verify/<cert_id>")
def verify_certificate(cert_id):
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()
    c.execute(
        """
        SELECT certificate_id, name, course_name, issue_date
        FROM certificates
        WHERE certificate_id = ?
    """,
        (cert_id,),
    )
    row = c.fetchone()
    conn.close()

    if row:
        cert = {
            "id": row[0],
            "name": row[1],
            "course": row[2],
            "date": row[3],
            "valid": True,
        }
    else:
        cert = {"valid": False}

    return render_template("verify.html", cert=cert)


# ---------- USERS (ADMIN) ----------
@app.route("/users")
@login_required
def manage_users():
    if current_user.role != "admin":
        flash("Access denied", "error")
        return redirect(url_for("dashboard"))

    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at FROM users")
    users = c.fetchall()
    conn.close()

    return render_template("users.html", users=users)


@app.route("/add_user", methods=["POST"])
@login_required
def add_user():
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403

    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role", "user")

    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()

    try:
        hashed = generate_password_hash(password)
        c.execute(
            "INSERT INTO users (username, password, role) VALUES (?,?,?)",
            (username, hashed, role),
        )
        conn.commit()
        flash(f"User {username} created", "success")
    except sqlite3.IntegrityError:
        flash("Username already exists", "error")

    conn.close()
    return redirect(url_for("manage_users"))


# ---------- API ----------
@app.route("/api/certificates", methods=["GET"])
@login_required
def api_list_certificates():
    conn = sqlite3.connect("certificates.db")
    c = conn.cursor()

    if current_user.role == "admin":
        c.execute("SELECT certificate_id, name, course_name, issue_date FROM certificates")
    else:
        c.execute(
            """
            SELECT certificate_id, name, course_name, issue_date
            FROM certificates
            WHERE created_by = ?
        """,
            (current_user.id,),
        )

    rows = c.fetchall()
    conn.close()

    data = [
        {
            "certificate_id": r[0],
            "name": r[1],
            "course_name": r[2],
            "issue_date": r[3],
        }
        for r in rows
    ]
    return jsonify(data)


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 5000))
    # debug=False for Render
    app.run(debug=False, host="0.0.0.0", port=port)
