from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib import colors
import qrcode
import sqlite3
import os
from datetime import datetime
import io
import csv
from PIL import Image
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import threading
import re
import uuid
from utils.template_selector import pick_template

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ALLOWED_CSV = {'csv'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size

# Email configuration (unused directly; settings now come from DB via /email-settings)
EMAIL_CONFIG = {
    'SMTP_SERVER': 'smtp.gmail.com',
    'SMTP_PORT': 587,
    'SMTP_USERNAME': 'your-email@gmail.com',
    'SMTP_PASSWORD': 'your-app-password',
    'FROM_EMAIL': 'your-email@gmail.com',
    'FROM_NAME': 'Certificate System'
}

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'logos'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'signatures'), exist_ok=True)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

# ---------- TEMPLATE MAPPING (PERCENTAGE -> TEMPLATE) ----------

# Change these IDs to match your real template IDs in the "templates" table.
# Example:
# 50–60  → template id 2
# 60–70  → template id 3
# 70–80  → template id 4
# 80–90  → template id 5
# 90–100 → template id 6
TEMPLATE_ID_50_60  = 2
TEMPLATE_ID_60_70  = 3
TEMPLATE_ID_70_80  = 4
TEMPLATE_ID_80_90  = 5
TEMPLATE_ID_90_100 = 6

# Fallback template if no percentage / out of range / no record
DEFAULT_TEMPLATE_ID = 1

def get_template_for_percentage(pct):
    """
    Given a percentage (0–100), return a template_id.
    Adjust the ranges and IDs above to whatever you want.
    """
    if pct is None:
        return DEFAULT_TEMPLATE_ID

    try:
        pct = float(pct)
    except (ValueError, TypeError):
        return DEFAULT_TEMPLATE_ID

    if 50 <= pct < 60:
        return TEMPLATE_ID_50_60
    elif 60 <= pct < 70:
        return TEMPLATE_ID_60_70
    elif 70 <= pct < 80:
        return TEMPLATE_ID_70_80
    elif 80 <= pct < 90:
        return TEMPLATE_ID_80_90
    elif 90 <= pct <= 100:
        return TEMPLATE_ID_90_100
    else:
        # < 50 or > 100 or anything weird
        return DEFAULT_TEMPLATE_ID

# ---------- DB bootstrap ----------

def init_db():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("PRAGMA foreign_keys = ON")

    # users
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  role TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # courses
    c.execute('''CREATE TABLE IF NOT EXISTS courses
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  course_name TEXT UNIQUE NOT NULL,
                  course_code TEXT UNIQUE NOT NULL,
                  description TEXT,
                  duration TEXT,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id))''')

    # templates
    c.execute('''CREATE TABLE IF NOT EXISTS templates
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  template_name TEXT UNIQUE NOT NULL,
                  title_text TEXT NOT NULL,
                  border_color TEXT DEFAULT '#3333cc',
                  title_color TEXT DEFAULT '#1a1a80',
                  bg_color TEXT DEFAULT '#f2f2ff',
                  logo_path TEXT,
                  signature_path TEXT,
                  signature_name TEXT DEFAULT 'Authorized Signature',
                  is_default INTEGER DEFAULT 0,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id))''')

    # certificates
    c.execute('''CREATE TABLE IF NOT EXISTS certificates
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  certificate_id TEXT UNIQUE NOT NULL,
                  name TEXT NOT NULL,
                  email TEXT,
                  course_id INTEGER,
                  course_name TEXT NOT NULL,
                  issue_date TEXT NOT NULL,
                  template_id INTEGER DEFAULT 1,
                  revoked INTEGER DEFAULT 0,
                  revoked_reason TEXT,
                  revoked_at TIMESTAMP,
                  revoked_by INTEGER,
                  email_sent INTEGER DEFAULT 0,
                  email_sent_at TIMESTAMP,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id),
                  FOREIGN KEY (course_id) REFERENCES courses(id),
                  FOREIGN KEY (template_id) REFERENCES templates(id),
                  FOREIGN KEY (revoked_by) REFERENCES users(id))''')

    # email_settings
    c.execute('''CREATE TABLE IF NOT EXISTS email_settings
                 (id INTEGER PRIMARY KEY,
                  smtp_server TEXT,
                  smtp_port INTEGER,
                  smtp_username TEXT,
                  smtp_password TEXT,
                  from_email TEXT,
                  from_name TEXT,
                  email_subject TEXT,
                  email_body TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP)''')

    # NEW: course_results – stores percentage for each learner per course
    c.execute('''CREATE TABLE IF NOT EXISTS course_results
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  course_id INTEGER NOT NULL,
                  name TEXT,
                  email TEXT,
                  percentage REAL,
                  completed INTEGER DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (course_id) REFERENCES courses(id))''')

    # helper migration funcs
    def col_exists(table, col):
        c.execute(f"PRAGMA table_info({table})")
        return any(row[1] == col for row in c.fetchall())

    def add_col_if_missing(table, col, ddl):
        if not col_exists(table, col):
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")

    # templates backfill
    add_col_if_missing('templates', 'signature_path', 'TEXT')
    add_col_if_missing('templates', 'signature_name', "TEXT DEFAULT 'Authorized Signature'")
    add_col_if_missing('templates', 'border_color', "TEXT DEFAULT '#3333cc'")
    add_col_if_missing('templates', 'title_color', "TEXT DEFAULT '#1a1a80'")
    add_col_if_missing('templates', 'bg_color',    "TEXT DEFAULT '#f2f2ff'")
    add_col_if_missing('templates', 'is_default',  "INTEGER DEFAULT 0")
    add_col_if_missing('templates', 'created_by',  "INTEGER")

    # certificates backfill
    add_col_if_missing('certificates', 'email', 'TEXT')
    add_col_if_missing('certificates', 'email_sent', 'INTEGER DEFAULT 0')
    add_col_if_missing('certificates', 'email_sent_at', 'TIMESTAMP')
    add_col_if_missing('certificates', 'course_id',   'INTEGER')
    add_col_if_missing('certificates', 'template_id', 'INTEGER DEFAULT 1')
    add_col_if_missing('certificates', 'revoked',     'INTEGER DEFAULT 0')
    add_col_if_missing('certificates', 'revoked_reason', 'TEXT')
    add_col_if_missing('certificates', 'revoked_at',  'TIMESTAMP')
    add_col_if_missing('certificates', 'revoked_by',  'INTEGER')

    # seed admin
    c.execute("SELECT 1 FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_pass = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', admin_pass, 'admin'))

    # seed default template id=1
    c.execute("SELECT 1 FROM templates WHERE id = 1")
    if not c.fetchone():
        c.execute('''INSERT INTO templates
                     (id, template_name, title_text, border_color, title_color, bg_color,
                      is_default, signature_name)
                     VALUES (1, ?, ?, ?, ?, ?, ?, ?)''',
                  ('Default Template', 'CERTIFICATE OF COMPLETION',
                   '#3333cc', '#1a1a80', '#f2f2ff', 1, 'Authorized Signature'))

    conn.commit()
    conn.close()

# ---------- helpers ----------

def hex_to_rgb(hex_color):
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) / 255.0 for i in (0, 2, 4))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def parse_manual_recipients(text: str):
    recipients = []
    for raw in (line.strip() for line in text.splitlines()):
        if not raw:
            continue
        m = re.match(r"^(?P<name>.+?)\s*<(?P<email>[^>]+)>$", raw)
        if m:
            name = m.group("name").strip()
            email = m.group("email").strip()
            recipients.append({"name": name, "email": email if EMAIL_RE.match(email) else None})
            continue
        m = re.match(r"^(?P<name>.+?)[,;|-]+\s*(?P<email>.+)$", raw)
        if m:
            name = m.group("name").strip()
            email = m.group("email").strip()
            recipients.append({"name": name, "email": email if EMAIL_RE.match(email) else None})
            continue
        recipients.append({"name": raw, "email": None})
    return recipients

def make_cert_id():
    """Collision-resistant ID like CERT-20251110-AB12CD"""
    return f"CERT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

def generate_certificate_pdf(cert_data):
    """Generate PDF certificate and return as BytesIO"""
    pdf_buffer = io.BytesIO()
    pdf_canvas = canvas.Canvas(pdf_buffer, pagesize=landscape(letter))
    width, height = landscape(letter)

    # Template fields
    title_text = cert_data.get('title_text', "CERTIFICATE OF COMPLETION")
    border_color = hex_to_rgb(cert_data.get('border_color', '#3333cc'))
    title_color = hex_to_rgb(cert_data.get('title_color', '#1a1a80'))
    bg_color = hex_to_rgb(cert_data.get('bg_color', '#f2f2ff'))
    logo_path = cert_data.get('logo_path')
    signature_path = cert_data.get('signature_path')
    signature_name = cert_data.get('signature_name', "Authorized Signature")

    # Background
    pdf_canvas.setFillColorRGB(*bg_color)
    pdf_canvas.rect(0, 0, width, height, fill=True, stroke=False)

    # Border
    pdf_canvas.setStrokeColorRGB(*border_color)
    pdf_canvas.setLineWidth(3)
    pdf_canvas.rect(30, 30, width-60, height-60, fill=False, stroke=True)

    # Logo
    if logo_path and os.path.exists(logo_path):
        try:
            pdf_canvas.drawImage(logo_path, width/2 - 40, height - 80, width=80, height=80,
                                 preserveAspectRatio=True, mask='auto')
        except:
            pass

    # Title
    pdf_canvas.setFillColorRGB(*title_color)
    pdf_canvas.setFont("Helvetica-Bold", 40)
    pdf_canvas.drawCentredString(width/2, height-100 if not logo_path else height-150, title_text)

    # Divider
    pdf_canvas.setStrokeColorRGB(0.7, 0.7, 0.7)
    pdf_canvas.line(150, height-130 if not logo_path else height-180,
                    width-150, height-130 if not logo_path else height-180)

    # Name and course
    pdf_canvas.setFillColorRGB(0, 0, 0)
    pdf_canvas.setFont("Helvetica", 16)
    pdf_canvas.drawCentredString(width/2, height-180 if not logo_path else height-230, "This is to certify that")

    pdf_canvas.setFillColorRGB(*title_color)
    pdf_canvas.setFont("Helvetica-Bold", 32)
    pdf_canvas.drawCentredString(width/2, height-230 if not logo_path else height-280, cert_data['name'])

    pdf_canvas.setFillColorRGB(0, 0, 0)
    pdf_canvas.setFont("Helvetica", 16)
    pdf_canvas.drawCentredString(width/2, height-280 if not logo_path else height-330, "has successfully completed the course")

    pdf_canvas.setFont("Helvetica-Bold", 24)
    pdf_canvas.drawCentredString(width/2, height-320 if not logo_path else height-370, cert_data['course_name'])

    # Date
    pdf_canvas.setFont("Helvetica", 14)
    pdf_canvas.drawCentredString(width/2, height-370 if not logo_path else height-420, f"Date of Completion: {cert_data['issue_date']}")

    # QR Code (local verify)
    verify_url = f"http://localhost:5000/verify/{cert_data['certificate_id']}"
    qr = qrcode.QRCode(version=1, box_size=3, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")

    qr_buffer = io.BytesIO()
    qr_img.save(qr_buffer, format='PNG')
    qr_buffer.seek(0)

    pdf_canvas.drawImage(ImageReader(qr_buffer), 50, 50, width=80, height=80)
    pdf_canvas.setFont("Helvetica", 8)
    pdf_canvas.drawString(50, 35, "Scan to verify")

    # Signature
    if signature_path and os.path.exists(signature_path):
        try:
            pdf_canvas.drawImage(signature_path, width-250, 85, width=150, height=60,
                                 preserveAspectRatio=True, mask='auto')
            pdf_canvas.setStrokeColorRGB(0, 0, 0)
            pdf_canvas.line(width-250, 80, width-100, 80)
        except:
            pdf_canvas.setStrokeColorRGB(0, 0, 0)
            pdf_canvas.line(width-250, 100, width-100, 100)
    else:
        pdf_canvas.setStrokeColorRGB(0, 0, 0)
        pdf_canvas.line(width-250, 100, width-100, 100)

    pdf_canvas.setFont("Helvetica", 12)
    pdf_canvas.drawCentredString(width-175, 65, signature_name)

    # Certificate ID
    pdf_canvas.setFont("Helvetica", 8)
    pdf_canvas.drawString(width-200, 35, f"Certificate ID: {cert_data['certificate_id']}")

    pdf_canvas.save()
    pdf_buffer.seek(0)
    return pdf_buffer

def send_email_with_certificate(recipient_email, recipient_name, cert_id, pdf_buffer):
    """Send email with certificate attachment"""
    try:
        # Get email settings
        conn = sqlite3.connect('certificates.db')
        c = conn.cursor()
        c.execute("""SELECT smtp_server, smtp_port, smtp_username, smtp_password,
                            from_email, from_name, email_subject, email_body
                     FROM email_settings WHERE id = 1""")
        settings = c.fetchone()
        conn.close()

        if not settings or not all(settings[:4]) or not settings[4]:
            return False, "Email settings not configured"

        smtp_server, smtp_port, smtp_username, smtp_password, from_email, from_name, subject, body = settings

        msg = MIMEMultipart()
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = recipient_email
        msg['Subject'] = subject

        email_text = (body or "").replace('{name}', recipient_name).replace('{cert_id}', cert_id)
        msg.attach(MIMEText(email_text, 'plain'))

        pdf_buffer.seek(0)
        part = MIMEBase('application', 'pdf')
        part.set_payload(pdf_buffer.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="certificate_{cert_id}.pdf"')
        msg.attach(part)

        server = smtplib.SMTP(smtp_server, int(smtp_port))
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()

        return True, "Email sent successfully"
    except Exception as e:
        return False, str(e)

# ---------- Auth ----------

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2])
    return None

# ---------- Routes ----------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('certificates.db')
        c = conn.cursor()
        c.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            user_obj = User(user[0], user[1], user[3])
            login_user(user_obj)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    if current_user.role == 'admin':
        c.execute("SELECT COUNT(*) FROM certificates")
        total_certs = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]
    else:
        c.execute("SELECT COUNT(*) FROM certificates WHERE created_by = ?", (current_user.id,))
        total_certs = c.fetchone()[0]
        total_users = 0

    conn.close()
    return render_template('dashboard.html', total_certs=total_certs, total_users=total_users)

@app.route('/generate', methods=['GET', 'POST'])
@login_required
def generate():
    try:
        from utils.template_selector import pick_template
    except Exception:
        def pick_template(pct):
            return None

    if request.method == 'POST':
        course_id = request.form.get('course_id')
        course_name = request.form.get('course_name', '').strip()
        issue_date = request.form.get('issue_date')
        base_template_id = int(request.form.get('template_id', DEFAULT_TEMPLATE_ID))
        send_emails = request.form.get('send_emails') == 'on'
        auto_template_is_on = request.form.get('auto_template') == 'on'

        # Backfill course_name from DB if missing
        if not course_name and course_id:
            _conn = sqlite3.connect('certificates.db')
            _c = _conn.cursor()
            _c.execute("SELECT course_name FROM courses WHERE id = ?", (course_id,))
            row = _c.fetchone()
            _conn.close()
            if row:
                course_name = row[0]

        # Check email settings if sending emails
        if send_emails:
            _conn = sqlite3.connect('certificates.db')
            _c = _conn.cursor()
            _c.execute("""SELECT smtp_server, smtp_port, smtp_username, smtp_password, from_email
                          FROM email_settings WHERE id = 1""")
            s = _c.fetchone()
            _conn.close()
            if not (s and all(s[:4]) and s[4]):
                flash('Email sending is enabled, but email settings are not configured. Configure them first.', 'error')
                return redirect(url_for('email_settings'))

        # Build recipients list
        recipients = []
        if 'csv_file' in request.files and request.files['csv_file'].filename:
            csv_file = request.files['csv_file']
            if csv_file and allowed_file(csv_file.filename, ALLOWED_CSV):
                try:
                    stream = io.StringIO(csv_file.stream.read().decode("utf-8-sig"), newline=None)
                    csv_reader = csv.DictReader(stream)
                    for row in csv_reader:
                        name = (row.get('name') or '').strip()
                        email = (row.get('email') or '').strip()
                        if name:
                            recipients.append({'name': name, 'email': email if email else None})
                except Exception as e:
                    flash(f'Error reading CSV: {str(e)}', 'error')
                    return redirect(url_for('generate'))
            else:
                flash('Invalid CSV file', 'error')
                return redirect(url_for('generate'))
        else:
            names_input = request.form.get('names', '')
            recipients = [r for r in parse_manual_recipients(names_input) if r['name']]

        if not recipients:
            flash('No recipients provided', 'error')
            return redirect(url_for('generate'))

        conn = sqlite3.connect('certificates.db')
        c = conn.cursor()

        generated_count = 0
        email_count = 0
        skipped = []

        # Helper: look up percentage for this recipient
        def lookup_percentage_for_recipient(name, email, course_id_val):
            if not course_id_val:
                return None
            if email:
                c.execute("""SELECT percentage FROM course_results
                             WHERE course_id = ? AND email = ?
                             ORDER BY created_at DESC LIMIT 1""",
                          (course_id_val, email))
                row = c.fetchone()
                if row and row[0] is not None:
                    return row[0]
            if name:
                c.execute("""SELECT percentage FROM course_results
                             WHERE course_id = ? AND name = ?
                             ORDER BY created_at DESC LIMIT 1""",
                          (course_id_val, name))
                row = c.fetchone()
                if row and row[0] is not None:
                    return row[0]
            return None

        # Main loop
        for recipient in recipients:
            recipient_name = recipient['name']
            recipient_email = recipient.get('email')

            # Choose template based on percentage if auto_template_on
            if course_id and auto_template_is_on:
                pct = lookup_percentage_for_recipient(recipient_name, recipient_email, course_id)
                template_id_to_use = base_template_id
                if pct is not None:
                    try:
                        picked = pick_template(pct)
                        if picked:
                            template_id_to_use = int(picked)
                    except Exception as e:
                        print(f"[template select] pick_template error: {e}")
                        template_id_to_use = base_template_id
            else:
                template_id_to_use = base_template_id

            # Insert certificate record
            attempts = 0
            inserted = False
            last_error = None
            cert_id = None
            while attempts < 3 and not inserted:
                cert_id = make_cert_id()
                try:
                    c.execute('''INSERT INTO certificates 
                                 (certificate_id, name, email, course_id, course_name, issue_date, template_id, created_by)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                              (cert_id, recipient_name, recipient_email, course_id, course_name, issue_date,
                               template_id_to_use, current_user.id))
                    generated_count += 1
                    inserted = True
                except sqlite3.IntegrityError as e:
                    attempts += 1
                    last_error = e
            if not inserted:
                skipped.append((recipient_name, f'Insert failed: {last_error}'))
                continue

            # Email certificate
            if send_emails and recipient_email:
                try:
                    c.execute('''SELECT c.certificate_id, c.name, c.course_name, c.issue_date,
                                        t.title_text, t.border_color, t.title_color, t.bg_color,
                                        t.logo_path, t.signature_path, t.signature_name
                                 FROM certificates c
                                 LEFT JOIN templates t ON c.template_id = t.id
                                 WHERE c.certificate_id = ?''', (cert_id,))
                    row = c.fetchone()
                    if row:
                        cert_data = {
                            'certificate_id': row[0],
                            'name': row[1],
                            'course_name': row[2],
                            'issue_date': row[3],
                            'title_text': row[4],
                            'border_color': row[5],
                            'title_color': row[6],
                            'bg_color': row[7],
                            'logo_path': row[8],
                            'signature_path': row[9],
                            'signature_name': row[10]
                        }
                        pdf_buffer = generate_certificate_pdf(cert_data)
                        success, message = send_email_with_certificate(recipient_email, recipient_name, cert_id, pdf_buffer)
                        if success:
                            c.execute('''UPDATE certificates
                                         SET email_sent = 1, email_sent_at = CURRENT_TIMESTAMP
                                         WHERE certificate_id = ?''', (cert_id,))
                            email_count += 1
                        else:
                            flash(f'Email failed for {recipient_name}: {message}', 'error')
                except Exception as e:
                    print(f"[email] error for {recipient_email}: {e}")
                    flash(f'Email failed for {recipient_name}: {e}', 'error')

        conn.commit()
        conn.close()

        msg = f'Successfully generated {generated_count} certificates!'
        if send_emails:
            msg += f' Emails sent: {email_count}/{generated_count}'
        if skipped:
            preview = ", ".join(n for n, _ in skipped[:3])
            more = f" (+{len(skipped)-3} more)" if len(skipped) > 3 else ""
            msg += f' | Skipped: {len(skipped)} (e.g., {preview}{more})'
        flash(msg, 'success')
        return redirect(url_for('view_certificates'))


    # ---------- GET: lists for dropdowns ----------
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, course_name, course_code FROM courses ORDER BY course_name")
    courses = [{'id': r[0], 'name': r[1], 'code': r[2]} for r in c.fetchall()]
    c.execute("SELECT id, template_name FROM templates ORDER BY is_default DESC, template_name")
    templates = [{'id': r[0], 'name': r[1]} for r in c.fetchall()]
    conn.close()

    return render_template('generate.html', courses=courses, templates=templates)

    # ---------- GET: lists for dropdowns ----------
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, course_name, course_code FROM courses ORDER BY course_name")
    courses = [{'id': r[0], 'name': r[1], 'code': r[2]} for r in c.fetchall()]
    c.execute("SELECT id, template_name FROM templates ORDER BY is_default DESC, template_name")
    templates = [{'id': r[0], 'name': r[1]} for r in c.fetchall()]
    conn.close()

    return render_template('generate.html', courses=courses, templates=templates)

@app.route('/certificates')
@login_required
def view_certificates():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    if current_user.role == 'admin':
        c.execute('''SELECT c.id, c.certificate_id, c.name, c.email, c.course_name, 
                     c.issue_date, c.created_at, c.email_sent
                     FROM certificates c ORDER BY c.created_at DESC''')
    else:
        c.execute('''SELECT c.id, c.certificate_id, c.name, c.email, c.course_name, 
                     c.issue_date, c.created_at, c.email_sent
                     FROM certificates c WHERE c.created_by = ? ORDER BY c.created_at DESC''',
                  (current_user.id,))

    certificates = c.fetchall()
    conn.close()

    return render_template('certificates.html', certificates=certificates)

@app.route('/certificate/<cert_id>')
def public_certificate(cert_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute('''SELECT name, course_name, issue_date FROM certificates WHERE certificate_id = ?''', (cert_id,))
    cert = c.fetchone()
    conn.close()

    if not cert:
        flash('Certificate not found', 'error')
        return redirect(url_for('index'))

    return render_template('public_certificate.html', certificate={
        'id': cert_id,
        'name': cert[0],
        'course_name': cert[1],
        'issue_date': cert[2]
    })


@app.route('/send_email/<cert_id>', methods=['POST'])
@login_required
def send_certificate_email(cert_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    c.execute('''SELECT c.certificate_id, c.name, c.email, c.course_name, c.issue_date, 
                 t.title_text, t.border_color, t.title_color, t.bg_color, 
                 t.logo_path, t.signature_path, t.signature_name
                 FROM certificates c
                 LEFT JOIN templates t ON c.template_id = t.id
                 WHERE c.certificate_id = ?''', (cert_id,))
    cert = c.fetchone()

    if not cert:
        conn.close()
        flash('Certificate not found', 'error')
        return redirect(url_for('view_certificates'))

    if not cert[2]:
        conn.close()
        flash('No email address for this certificate', 'error')
        return redirect(url_for('view_certificates'))

    cert_data = {
        'certificate_id': cert[0],
        'name': cert[1],
        'course_name': cert[3],
        'issue_date': cert[4],
        'title_text': cert[5],
        'border_color': cert[6],
        'title_color': cert[7],
        'bg_color': cert[8],
        'logo_path': cert[9],
        'signature_path': cert[10],
        'signature_name': cert[11]
    }

    pdf_buffer = generate_certificate_pdf(cert_data)
    success, message = send_email_with_certificate(cert[2], cert[1], cert[0], pdf_buffer)

    if success:
        c.execute('''UPDATE certificates 
                   SET email_sent = 1, email_sent_at = CURRENT_TIMESTAMP 
                   WHERE certificate_id = ?''', (cert_id,))
        conn.commit()
        flash('Email sent successfully!', 'success')
    else:
        flash(f'Failed to send email: {message}', 'error')

    conn.close()
    return redirect(url_for('view_certificates'))

@app.route('/download/<cert_id>')
@login_required
def download_certificate(cert_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute('''SELECT c.certificate_id, c.name, c.course_name, c.issue_date, 
                 t.title_text, t.border_color, t.title_color, t.bg_color, 
                 t.logo_path, t.signature_path, t.signature_name
                 FROM certificates c
                 LEFT JOIN templates t ON c.template_id = t.id
                 WHERE c.certificate_id = ?''', (cert_id,))
    cert = c.fetchone()
    conn.close()

    if not cert:
        flash('Certificate not found', 'error')
        return redirect(url_for('view_certificates'))

    cert_data = {
        'certificate_id': cert[0],
        'name': cert[1],
        'course_name': cert[2],
        'issue_date': cert[3],
        'title_text': cert[4],
        'border_color': cert[5],
        'title_color': cert[6],
        'bg_color': cert[7],
        'logo_path': cert[8],
        'signature_path': cert[9],
        'signature_name': cert[10]
    }

    pdf_buffer = generate_certificate_pdf(cert_data)

    return send_file(pdf_buffer, as_attachment=True,
                     download_name=f"certificate_{cert[0]}.pdf",
                     mimetype='application/pdf')

@app.route('/verify/<cert_id>')
def verify_certificate(cert_id):
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute('''SELECT certificate_id, name, course_name, issue_date 
                 FROM certificates WHERE certificate_id = ?''', (cert_id,))
    cert = c.fetchone()
    conn.close()

    if cert:
        return render_template('verify.html', cert={
            'id': cert[0],
            'name': cert[1],
            'course': cert[2],
            'date': cert[3],
            'valid': True
        })
    else:
        return render_template('verify.html', cert={'valid': False})

@app.route('/users')
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role, created_at FROM users")
    users = c.fetchall()
    conn.close()

    return render_template('users.html', users=users)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    try:
        hashed_password = generate_password_hash(password)
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, hashed_password, role))
        conn.commit()
        flash(f'User {username} added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists', 'error')

    conn.close()
    return redirect(url_for('manage_users'))

# Course Management
@app.route('/courses')
@login_required
def manage_courses():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute('''SELECT c.id, c.course_name, c.course_code, c.description, 
                 c.duration, c.created_at, u.username
                 FROM courses c
                 LEFT JOIN users u ON c.created_by = u.id
                 ORDER BY c.created_at DESC''')
    courses = c.fetchall()
    conn.close()

    return render_template('courses.html', courses=courses)

# ----------------------------
# Course Results (percentages)
# ----------------------------
# ----------------------------
# Course Results (percentages)
# ----------------------------
@app.route('/course-results', methods=['GET', 'POST'])
@login_required
def manage_course_results():
    # Only admin can manage scores
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    # Load courses for dropdown
    c.execute("SELECT id, course_name, course_code FROM courses ORDER BY course_name")
    courses = [{'id': r[0], 'name': r[1], 'code': r[2]} for r in c.fetchall()]

    selected_course_id = request.args.get('course_id') or request.form.get('course_id')

    if request.method == 'POST':
        course_id = request.form.get('course_id')
        if not course_id:
            flash('Please select a course before submitting results.', 'error')
            conn.close()
            return redirect(url_for('manage_course_results'))

        course_id = int(course_id)

        # --- CSV Upload path ---
        if 'csv_file' in request.files and request.files['csv_file'].filename:
            csv_file = request.files['csv_file']
            if csv_file and allowed_file(csv_file.filename, ALLOWED_CSV):
                try:
                    stream = io.StringIO(csv_file.stream.read().decode("utf-8-sig"), newline=None)
                    reader = csv.DictReader(stream)

                    inserted = 0
                    for row in reader:
                        name = (row.get('name') or '').strip()
                        email = (row.get('email') or '').strip()
                        pct_raw = (row.get('percentage') or '').strip()
                        completed_raw = (row.get('completed') or '').strip().lower()

                        if not name and not email:
                            continue  # skip empty rows

                        try:
                            percentage = float(pct_raw) if pct_raw != '' else None
                        except ValueError:
                            percentage = None

                        # completed column: treat "0", "false", "no" as 0, else 1
                        completed = 1
                        if completed_raw in ('0', 'false', 'no', 'n', ''):
                            completed = 0 if completed_raw in ('0', 'false', 'no', 'n') else 1

                        c.execute(
                            '''INSERT INTO course_results (course_id, name, email, percentage, completed)
                               VALUES (?, ?, ?, ?, ?)''',
                            (course_id, name or None, email or None, percentage, completed)
                        )
                        inserted += 1

                    conn.commit()
                    flash(f'Imported {inserted} result(s) for the selected course.', 'success')
                    conn.close()
                    return redirect(url_for('manage_course_results', course_id=course_id))

                except Exception as e:
                    conn.rollback()
                    conn.close()
                    flash(f'Error reading CSV: {e}', 'error')
                    return redirect(url_for('manage_course_results'))
            else:
                conn.close()
                flash('Invalid CSV file.', 'error')
                return redirect(url_for('manage_course_results'))

        # --- Manual single-entry form (name,email,percentage,completed checkbox) ---
        if request.form.get('manual_action') == 'single':
            name = (request.form.get('manual_name') or '').strip()
            email = (request.form.get('manual_email') or '').strip()
            pct_raw = (request.form.get('manual_percentage') or '').strip()
            completed_checked = request.form.get('manual_completed') == 'on'

            if not name and not email:
                flash('Provide at least a name or an email for manual entry.', 'error')
                conn.close()
                return redirect(url_for('manage_course_results', course_id=course_id))

            try:
                percentage = float(pct_raw) if pct_raw != '' else None
            except ValueError:
                percentage = None

            completed = 1 if completed_checked else 0

            try:
                c.execute(
                    '''INSERT INTO course_results (course_id, name, email, percentage, completed)
                       VALUES (?, ?, ?, ?, ?)''',
                    (course_id, name or None, email or None, percentage, completed)
                )
                conn.commit()
                flash('Result saved.', 'success')
            except Exception as e:
                conn.rollback()
                flash(f'Failed to save result: {e}', 'error')

            conn.close()
            return redirect(url_for('manage_course_results', course_id=course_id))

        # --- Manual bulk textarea (one per line, CSV-like) ---
        if request.form.get('manual_action') == 'bulk':
            bulk_text = request.form.get('manual_bulk', '')
            lines = [ln.strip() for ln in bulk_text.splitlines() if ln.strip()]
            inserted = 0
            for line in lines:
                # Accept formats:
                # name,email,percentage,completed
                # name,email
                parts = [p.strip() for p in re.split(r',\s*', line)]
                name = parts[0] if len(parts) > 0 else ''
                email = parts[1] if len(parts) > 1 else ''
                pct_raw = parts[2] if len(parts) > 2 else ''
                completed_raw = parts[3] if len(parts) > 3 else ''

                if not name and not email:
                    continue

                try:
                    percentage = float(pct_raw) if pct_raw != '' else None
                except ValueError:
                    percentage = None

                completed = 1
                if str(completed_raw).strip().lower() in ('0', 'false', 'no', 'n'):
                    completed = 0

                try:
                    c.execute(
                        '''INSERT INTO course_results (course_id, name, email, percentage, completed)
                           VALUES (?, ?, ?, ?, ?)''',
                        (course_id, name or None, email or None, percentage, completed)
                    )
                    inserted += 1
                except Exception:
                    # skip problematic row but continue
                    continue

            conn.commit()
            flash(f'Imported {inserted} manual result(s).', 'success')
            conn.close()
            return redirect(url_for('manage_course_results', course_id=course_id))

        # If none matched, just close and redirect
        conn.close()
        flash('No action performed.', 'warning')
        return redirect(url_for('manage_course_results'))

    # GET (or after redirect) – show results for selected course, if any
    results = []
    if selected_course_id:
        try:
            cid = int(selected_course_id)
            c.execute(
                '''SELECT id, name, email, percentage, completed, created_at
                   FROM course_results
                   WHERE course_id = ?
                   ORDER BY created_at DESC''',
                (cid,)
            )
            rows = c.fetchall()
            for r in rows:
                results.append({
                    'id': r[0],
                    'name': r[1],
                    'email': r[2],
                    'percentage': r[3],
                    'completed': bool(r[4]),
                    'created_at': r[5]
                })
        except ValueError:
            pass

    conn.close()

    return render_template(
        'course_results.html',
        courses=courses,
        selected_course_id=selected_course_id,
        results=results
    )


@app.route('/add_course', methods=['POST'])
@login_required
def add_course():
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    course_name = request.form['course_name']
    course_code = request.form['course_code']
    description = request.form.get('description', '')
    duration = request.form.get('duration', '')

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    try:
        c.execute('''INSERT INTO courses (course_name, course_code, description, duration, created_by)
                     VALUES (?, ?, ?, ?, ?)''',
                  (course_name, course_code, description, duration, current_user.id))
        conn.commit()
        flash(f'Course "{course_name}" added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Course name or code already exists', 'error')

    conn.close()
    return redirect(url_for('manage_courses'))

@app.route('/delete_course/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM certificates WHERE course_id = ?", (course_id,))
    cert_count = c.fetchone()[0]

    if cert_count > 0:
        flash(f'Cannot delete course: {cert_count} certificates are linked to it', 'error')
    else:
        c.execute("DELETE FROM courses WHERE id = ?", (course_id,))
        conn.commit()
        flash('Course deleted successfully', 'success')

    conn.close()
    return redirect(url_for('manage_courses'))

@app.route('/get_courses_json')
@login_required
def get_courses_json():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, course_name, course_code FROM courses ORDER BY course_name")
    courses = c.fetchall()
    conn.close()

    return jsonify([{'id': c[0], 'name': c[1], 'code': c[2]} for c in courses])

# Template Management
@app.route('/templates')
@login_required
def manage_templates():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    # Fetch templates
    c.execute('''
        SELECT t.id, t.template_name, t.title_text, t.border_color, 
               t.title_color, t.bg_color, t.logo_path, t.signature_path, 
               t.signature_name, t.is_default, t.created_at, u.username
        FROM templates t
        LEFT JOIN users u ON t.created_by = u.id
        ORDER BY t.is_default DESC, t.created_at DESC
    ''')
    templates = c.fetchall()

    # Fetch grades for dropdown
    c.execute('SELECT id, name FROM grades ORDER BY name')
    grades = c.fetchall()

    conn.close()

    return render_template('templates.html', templates=templates, grades=grades)


@app.route('/add_template', methods=['POST'])
@login_required
def add_template():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('manage_templates'))

    # Get form data
    template_name = request.form['template_name']
    title_text = request.form['title_text']
    border_color = request.form['border_color']
    title_color = request.form['title_color']
    bg_color = request.form['bg_color']
    signature_name = request.form.get('signature_name', 'Authorized Signature')
    grade_id = request.form.get('grade')  # dropdown value
    min_percent = request.form.get('min_percent')
    max_percent = request.form.get('max_percent')

    # Convert percentage values to integers if provided
    min_percent = int(min_percent) if min_percent else None
    max_percent = int(max_percent) if max_percent else None

    # Handle logo upload
    logo_path = None
    if 'logo' in request.files:
        logo = request.files['logo']
        if logo and logo.filename and allowed_file(logo.filename, ALLOWED_EXTENSIONS):
            filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{logo.filename}")
            logo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'logos', filename)
            logo.save(logo_path)

    # Handle signature upload
    signature_path = None
    if 'signature' in request.files:
        signature = request.files['signature']
        if signature and signature.filename and allowed_file(signature.filename, ALLOWED_EXTENSIONS):
            filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{signature.filename}")
            signature_path = os.path.join(app.config['UPLOAD_FOLDER'], 'signatures', filename)
            signature.save(signature_path)

    # Insert into database
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO templates 
            (template_name, title_text, border_color, title_color, bg_color, 
             logo_path, signature_path, signature_name, grade_id, min_percent, max_percent, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            template_name, title_text, border_color, title_color, bg_color,
            logo_path, signature_path, signature_name, grade_id, min_percent, max_percent,
            current_user.id
        ))
        conn.commit()
        flash(f'Template "{template_name}" created successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Template name already exists', 'error')
    finally:
        conn.close()

    return redirect(url_for('manage_templates'))



@app.route('/delete_template/<int:template_id>', methods=['POST'])
@login_required
def delete_template(template_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Access denied'}), 403

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    c.execute("SELECT is_default FROM templates WHERE id = ?", (template_id,))
    result = c.fetchone()
    if result and result[0] == 1:
        flash('Cannot delete the default template', 'error')
        conn.close()
        return redirect(url_for('manage_templates'))

    c.execute("SELECT COUNT(*) FROM certificates WHERE template_id = ?", (template_id,))
    cert_count = c.fetchone()[0]

    if cert_count > 0:
        flash(f'Cannot delete template: {cert_count} certificates use this template', 'error')
    else:
        c.execute("SELECT logo_path, signature_path FROM templates WHERE id = ?", (template_id,))
        paths = c.fetchone()

        c.execute("DELETE FROM templates WHERE id = ?", (template_id,))
        conn.commit()

        if paths:
            for path in paths:
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                    except:
                        pass

        flash('Template deleted successfully', 'success')

    conn.close()
    return redirect(url_for('manage_templates'))

@app.route('/get_templates_json')
@login_required
def get_templates_json():
    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()
    c.execute("SELECT id, template_name FROM templates ORDER BY is_default DESC, template_name")
    templates = c.fetchall()
    conn.close()

    return jsonify([{'id': t[0], 'name': t[1]} for t in templates])

# Email Settings
@app.route('/email-settings', methods=['GET', 'POST'])
@login_required
def email_settings():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('certificates.db')
    c = conn.cursor()

    if request.method == 'POST':
        smtp_server = request.form['smtp_server']
        smtp_port = request.form['smtp_port']
        smtp_username = request.form['smtp_username']
        smtp_password = request.form['smtp_password']
        from_email = request.form['from_email']
        from_name = request.form['from_name']
        email_subject = request.form['email_subject']
        email_body = request.form['email_body']

        c.execute("SELECT id FROM email_settings WHERE id = 1")
        exists = c.fetchone()

        if exists:
            c.execute('''UPDATE email_settings SET 
                        smtp_server=?, smtp_port=?, smtp_username=?, smtp_password=?,
                        from_email=?, from_name=?, email_subject=?, email_body=?,
                        updated_at=CURRENT_TIMESTAMP
                        WHERE id = 1''',
                      (smtp_server, smtp_port, smtp_username, smtp_password,
                       from_email, from_name, email_subject, email_body))
        else:
            c.execute('''INSERT INTO email_settings 
                        (id, smtp_server, smtp_port, smtp_username, smtp_password,
                         from_email, from_name, email_subject, email_body)
                        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (smtp_server, smtp_port, smtp_username, smtp_password,
                       from_email, from_name, email_subject, email_body))

        conn.commit()
        flash('Email settings saved successfully!', 'success')

    c.execute("SELECT * FROM email_settings WHERE id = 1")
    settings = c.fetchone()
    conn.close()

    return render_template('email_settings.html', settings=settings)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)