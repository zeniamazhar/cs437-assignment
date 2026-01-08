"""
SCADA Alarm Management Console - PATCHED VERSION (WITH WORKING MONITORING)
Task 9 - CS 437 Assignment

This version contains security patches for:
1. CSRF Protection - Added CSRF tokens to all POST forms
2. SSRF Protection - Removed user-supplied URLs; only predefined report sections selectable
3. Path Traversal Protection - Input sanitization and path validation
4. SQL Injection Protection - Parameterized queries for all encodings

*** FULLY WORKING MONITORING INTEGRATION ***
SECURITY IMPROVEMENTS IMPLEMENTED
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask import make_response
import sqlite3
import os
import hashlib
import secrets
from datetime import datetime, timedelta
import requests
from jinja2 import Template, Environment, select_autoescape
from jinja2.sandbox import SandboxedEnvironment
import json
import re
from urllib.parse import urlparse
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['DATABASE'] = 'scada_alarms.db'
app.config['LOG_DIR'] = 'logs'
app.config['REPORT_DIR'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# TRACKING
failed_login_attempts = defaultdict(list)
session_usage_tracker = {}  # Track session usage

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('backups', exist_ok=True)

# *** MONITORING INTEGRATION ***
MONITORING_URL = "http://scada_monitoring:5002"

def log_to_monitoring(event_data):
    """Send security event to monitoring system"""
    try:
        # FIXED: Properly capture and send cookies as dictionary
        cookies_dict = {}
        for key, value in request.cookies.items():
            cookies_dict[key] = value
        
        # Enrich event data
        event_data['cookies'] = cookies_dict  # Send as dict
        event_data['session_id'] = request.cookies.get('session', '')
        event_data['referer'] = request.headers.get('Referer', '')
        event_data['user_agent'] = request.headers.get('User-Agent', '')
        event_data['source_ip'] = request.remote_addr
        event_data['response_status'] = event_data.get('response_status', 200)
        
        requests.post(
            f"{MONITORING_URL}/api/log_event",
            json=event_data,
            timeout=1
        )
    except Exception as e:
        pass

def detect_sqli_pattern(input_str):
    """Simple SQL injection pattern detection"""
    if not input_str:
        return False
    sqli_patterns = ["'", "OR", "UNION", "SELECT", "--", ";", "/*", "*/", "DROP", "DELETE"]
    return any(pattern.lower() in str(input_str).lower() for pattern in sqli_patterns)

def detect_path_traversal(path):
    """Detect path traversal attempts"""
    if not path:
        return False
    return '..' in path or path.startswith('/') or path.startswith('\\')

def check_cookie_suspicious(cookie_value):
    """Check if cookie looks suspicious"""
    if not cookie_value:
        return False, None
    
    if len(cookie_value) > 500:
        return True, "Unusually long session cookie"
    
    if '..' in cookie_value:
        return True, "Path traversal pattern in cookie"
    
    if '<script>' in cookie_value.lower() or 'javascript:' in cookie_value.lower():
        return True, "XSS attempt in cookie"
    
    if 'admin' in cookie_value.lower() or 'role=' in cookie_value.lower():
        if session.get('role') != 'admin':
            return True, "Privilege escalation attempt in cookie"
    
    if detect_sqli_pattern(cookie_value):
        return True, "SQL injection pattern in cookie"
    
    if any(pattern in cookie_value for pattern in ['|', ';', '&&', '$(', '`']):
        return True, "Command injection pattern in cookie"
    
    return False, None

def generate_csrf_token():
    """Generate CSRF token for session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return token == session.get('csrf_token')

@app.context_processor
def inject_csrf_token():
    """Make CSRF token available to all templates"""
    return dict(csrf_token=generate_csrf_token)

def sanitize_path(user_input, base_dir):
    """SECURITY PATCH: Sanitize file paths to prevent directory traversal"""
    user_input = user_input.replace('..', '').replace('//', '/')
    requested_path = os.path.abspath(os.path.join(base_dir, user_input))
    base_path = os.path.abspath(base_dir)
    
    if not requested_path.startswith(base_path):
        raise ValueError("Invalid path: Directory traversal detected")
    
    return requested_path

def get_db():
    """Get database connection"""
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with schema"""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alarms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarm_code TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT NOT NULL,
            triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            acknowledged BOOLEAN DEFAULT 0,
            acknowledged_by TEXT,
            acknowledged_at TIMESTAMP,
            silenced BOOLEAN DEFAULT 0,
            silenced_until TIMESTAMP,
            escalated BOOLEAN DEFAULT 0,
            escalated_to TEXT,
            status TEXT DEFAULT 'active'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alarm_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarm_id INTEGER,
            action TEXT NOT NULL,
            performed_by TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            FOREIGN KEY (alarm_id) REFERENCES alarms (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_name TEXT NOT NULL,
            report_type TEXT NOT NULL,
            generated_by TEXT NOT NULL,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT
        )
    ''')
    
    admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('admin', admin_hash, 'admin'))
    except sqlite3.IntegrityError:
        pass
    
    operator_hash = hashlib.sha256('operator123'.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('operator', operator_hash, 'operator'))
    except sqlite3.IntegrityError:
        pass
    
    db.commit()
    db.close()

# FIXED: Check cookies on every request (middleware)
@app.before_request
def check_cookies_before_request():
    """Check cookies for manipulation on every request"""
    if request.endpoint in ['static', 'login']:
        return None
    
    session_cookie = request.cookies.get('session', '')
    if session_cookie:
        is_suspicious, reason = check_cookie_suspicious(session_cookie)
        
        if is_suspicious:
            log_to_monitoring({
                'event_type': 'COOKIE_MANIPULATION_DETECTED',
                'severity': 'HIGH',
                'endpoint': request.path,
                'method': request.method,
                'vulnerability_type': 'COOKIE_MANIPULATION',
                'description': f'Cookie manipulation detected: {reason}',
                'system_version': 'patched',
                'response_status': 200
            })

# FIXED: Track 404s for directory brute-forcing
@app.after_request
def log_response(response):
    """Log all responses to detect directory brute-forcing"""
    if response.status_code == 404 and request.endpoint != 'static':
        log_to_monitoring({
            'event_type': 'FILE_NOT_FOUND',
            'severity': 'LOW',
            'endpoint': request.path,
            'method': request.method,
            'response_status': 404,
            'vulnerability_type': 'DIRECTORY_BRUTEFORCE',
            'description': f'404 error on {request.path}',
            'system_version': 'patched'
        })
    
    return response

@app.route('/')
def index():
    """Main dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # FIXED: Track session for hijacking detection
    session_id = request.cookies.get('session', '')
    if session_id:
        current_ip = request.remote_addr
        current_ua = request.headers.get('User-Agent', '')
        
        if session_id in session_usage_tracker:
            prev_ip, prev_ua = session_usage_tracker[session_id]
            if prev_ip != current_ip or prev_ua != current_ua:
                log_to_monitoring({
                    'event_type': 'SESSION_HIJACKING_DETECTED',
                    'severity': 'CRITICAL',
                    'endpoint': '/',
                    'method': 'GET',
                    'vulnerability_type': 'SESSION_HIJACKING',
                    'description': f'Session used from different IP/UA',
                    'system_version': 'patched',
                    'response_status': 200
                })
        
        session_usage_tracker[session_id] = (current_ip, current_ua)
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT * FROM alarms 
        WHERE status = ? 
        ORDER BY 
            CASE severity 
                WHEN 'critical' THEN 1 
                WHEN 'high' THEN 2 
                WHEN 'medium' THEN 3 
                WHEN 'low' THEN 4 
            END,
            triggered_at DESC
    ''', ('active',))
    alarms = cursor.fetchall()
    
    cursor.execute('SELECT COUNT(*) as count FROM alarms WHERE status = ?', ('active',))
    active_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM alarms WHERE acknowledged = ? AND status = ?', (1, 'active'))
    acknowledged_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM alarms WHERE escalated = ?', (1,))
    escalated_count = cursor.fetchone()['count']
    
    db.close()
    
    return render_template('dashboard.html', 
                         alarms=alarms,
                         active_count=active_count,
                         acknowledged_count=acknowledged_count,
                         escalated_count=escalated_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    SECURITY PATCH: Fixed SQL injection with parameterized queries
    *** MONITORING: Login attempts tracked ***
    """
    ip_address = request.remote_addr
    current_time = time.time()

    # Clean up old attempts
    failed_login_attempts[ip_address] = [
        t for t in failed_login_attempts[ip_address] 
        if current_time - t < 300
    ]

    # Check if IP is banned
    if len(failed_login_attempts[ip_address]) >= 3:
        log_to_monitoring({
            'event_type': 'BRUTE_FORCE_BLOCKED',
            'severity': 'HIGH',
            'endpoint': '/login',
            'vulnerability_type': 'BRUTE_FORCE',
            'blocked': True,
            'description': f"Too many failed attempts ({len(failed_login_attempts[ip_address])})",
            'system_version': 'patched'
        })
        return render_template('login.html', error='Too many failed attempts. Try again in 5 minutes.')
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        encoding = request.headers.get('Content-Encoding', 'utf-8')
        
        username_for_monitoring = username
        if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
            try:
                username_bytes = username.encode('latin-1')
                username_for_monitoring = username_bytes.decode(encoding.lower())
            except:
                pass

        # Detect attack attempts
        if detect_sqli_pattern(username_for_monitoring):
            log_to_monitoring({
                'event_type': 'SQL_INJECTION_BLOCKED',
                'severity': 'CRITICAL',
                'endpoint': '/login',
                'method': 'POST',
                'payload': json.dumps({'username': username_for_monitoring, 'encoding': encoding}),
                'vulnerability_type': 'SQL_INJECTION',
                'classification': 'SQLi-Encoded',
                'blocked': True,
                'description': f"SQL injection attempt with {encoding} blocked",
                'system_version': 'patched'
            })
        
        # SECURE: Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        db = get_db()
        cursor = db.cursor()
        
        # SECURE: Parameterized query
        cursor.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?',
                      (username, password_hash))
        user = cursor.fetchone()
        
        # Create session if success
        if user:
            session['username'] = user['username']
            session['role'] = user['role']
            generate_csrf_token()
            
            # Track session
            session_id = request.cookies.get('session', '')
            if session_id:
                session_usage_tracker[session_id] = (
                    request.remote_addr,
                    request.headers.get('User-Agent', '')
                )
        
        # Log attempt
        log_to_monitoring({
            'event_type': 'LOGIN_ATTEMPT',
            'severity': 'INFO' if user else 'MEDIUM',
            'endpoint': '/login',
            'method': 'POST',
            'payload': json.dumps({'username': username}),
            'vulnerability_type': 'BRUTE_FORCE' if not user else 'NONE',
            'classification': 'Failed Login' if not user else 'Successful Login',
            'blocked': False,
            'description': f"Login attempt for user '{username}'",
            'system_version': 'patched',
            'username': username,
            'success': bool(user)
        })
        
        if user:
            failed_login_attempts[ip_address] = []
            db.close()
            return redirect(url_for('index'))
        else:
            failed_login_attempts[ip_address].append(current_time)
            db.close()
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    # Clean up session tracking
    session_id = request.cookies.get('session', '')
    if session_id in session_usage_tracker:
        del session_usage_tracker[session_id]
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/alarms')
def alarms():
    """View all alarms with filtering"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Track session
    session_id = request.cookies.get('session', '')
    if session_id:
        current_ip = request.remote_addr
        current_ua = request.headers.get('User-Agent', '')
        
        if session_id in session_usage_tracker:
            prev_ip, prev_ua = session_usage_tracker[session_id]
            if prev_ip != current_ip or prev_ua != current_ua:
                log_to_monitoring({
                    'event_type': 'SESSION_HIJACKING_DETECTED',
                    'severity': 'CRITICAL',
                    'endpoint': '/alarms',
                    'method': 'GET',
                    'vulnerability_type': 'SESSION_HIJACKING',
                    'description': f'Session used from different IP/UA',
                    'system_version': 'patched',
                    'response_status': 200
                })
        
        session_usage_tracker[session_id] = (current_ip, current_ua)
    
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    
    db = get_db()
    cursor = db.cursor()
    
    query = 'SELECT * FROM alarms WHERE 1=1'
    params = []
    
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    
    if status:
        query += ' AND status = ?'
        params.append(status)
    
    query += ' ORDER BY triggered_at DESC'
    
    cursor.execute(query, params)
    alarms = cursor.fetchall()
    db.close()
    
    return render_template('alarms.html', alarms=alarms)

@app.route('/alarm/<int:alarm_id>')
def alarm_detail(alarm_id):
    """View alarm details"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT * FROM alarms WHERE id = ?', (alarm_id,))
    alarm = cursor.fetchone()
    
    if not alarm:
        db.close()
        return "Alarm not found", 404
    
    cursor.execute('SELECT * FROM alarm_logs WHERE alarm_id = ? ORDER BY timestamp DESC', (alarm_id,))
    logs = cursor.fetchall()
    
    db.close()
    
    return render_template('alarm_detail.html', alarm=alarm, logs=logs)

@app.route('/acknowledge/<int:alarm_id>', methods=['POST'])
def acknowledge_alarm(alarm_id):
    """
    SECURITY PATCH: CSRF protection added
    *** MONITORING: CSRF attempts tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # SECURITY: Validate CSRF token
    csrf_token = request.form.get('csrf_token')
    
    if not validate_csrf_token(csrf_token):
        log_to_monitoring({
            'event_type': 'CSRF_BLOCKED',
            'severity': 'MEDIUM',
            'endpoint': f'/acknowledge/{alarm_id}',
            'method': 'POST',
            'payload': json.dumps(dict(request.headers)),
            'vulnerability_type': 'CSRF',
            'classification': 'Invalid/Missing CSRF Token',
            'blocked': True,
            'description': f"CSRF attack blocked",
            'system_version': 'patched'
        })
        return "CSRF token validation failed", 403
    
    log_to_monitoring({
        'event_type': 'CSRF_VALIDATED',
        'severity': 'INFO',
        'endpoint': f'/acknowledge/{alarm_id}',
        'method': 'POST',
        'vulnerability_type': 'CSRF',
        'blocked': False,
        'description': 'Valid CSRF token - request allowed',
        'system_version': 'patched'
    })
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        UPDATE alarms 
        SET acknowledged = ?, 
            acknowledged_by = ?, 
            acknowledged_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (1, session['username'], alarm_id))
    
    cursor.execute('''
        INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
        VALUES (?, ?, ?, ?)
    ''', (alarm_id, 'ACKNOWLEDGED', session['username'], 'Alarm acknowledged by operator'))
    
    db.commit()
    db.close()
    
    return redirect(url_for('alarm_detail', alarm_id=alarm_id))

@app.route('/silence/<int:alarm_id>', methods=['POST'])
def silence_alarm(alarm_id):
    """SECURITY PATCH: CSRF protection added"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        log_to_monitoring({
            'event_type': 'CSRF_BLOCKED',
            'severity': 'MEDIUM',
            'endpoint': f'/silence/{alarm_id}',
            'vulnerability_type': 'CSRF',
            'blocked': True,
            'system_version': 'patched'
        })
        return "CSRF token validation failed", 403
    
    duration = request.form.get('duration', 30)
    
    db = get_db()
    cursor = db.cursor()
    silence_until = (datetime.now() + timedelta(minutes=int(duration))).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        UPDATE alarms 
        SET silenced = ?, 
            silenced_until = ? 
        WHERE id = ?
    ''', (1, silence_until, alarm_id))
    cursor.execute('''
        INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
        VALUES (?, ?, ?, ?)
    ''', (alarm_id, 'SILENCED', session['username'], f'Alarm silenced for {duration} minutes'))
    
    db.commit()
    db.close()
    
    return redirect(url_for('alarm_detail', alarm_id=alarm_id))

@app.route('/escalate/<int:alarm_id>', methods=['POST'])
def escalate_alarm(alarm_id):
    """SECURITY PATCH: CSRF protection added"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        log_to_monitoring({
            'event_type': 'CSRF_BLOCKED',
            'severity': 'MEDIUM',
            'endpoint': f'/escalate/{alarm_id}',
            'vulnerability_type': 'CSRF',
            'blocked': True,
            'system_version': 'patched'
        })
        return "CSRF token validation failed", 403
    
    supervisor = request.form.get('supervisor', 'default_supervisor')
    
    if not re.match(r'^[a-zA-Z0-9_]+$', supervisor):
        return "Invalid supervisor name", 400
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        UPDATE alarms 
        SET escalated = ?, 
            escalated_to = ? 
        WHERE id = ?
    ''', (1, supervisor, alarm_id))
    
    cursor.execute('''
        INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
        VALUES (?, ?, ?, ?)
    ''', (alarm_id, 'ESCALATED', session['username'], f'Alarm escalated to {supervisor}'))
    
    db.commit()
    db.close()
    
    return redirect(url_for('alarm_detail', alarm_id=alarm_id))

@app.route('/reports', methods=['GET', 'POST'])
def reports():
    """
    SECURITY PATCH: SSRF protection - server-side templates only
    *** MONITORING: SSRF attempts logged ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Check for URL injection attempts
        if 'template_url' in request.form:
            log_to_monitoring({
                'event_type': 'SSRF_ATTEMPT_BLOCKED',
                'severity': 'HIGH',
                'endpoint': '/reports',
                'payload': json.dumps(dict(request.form)),
                'vulnerability_type': 'SSRF',
                'classification': 'Attempted Template URL Injection',
                'blocked': True,
                'description': 'Attempt to inject template_url in patched version',
                'system_version': 'patched'
            })
        
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed", 403

        report_type = request.form.get('report_type', 'summary')
        selected_sections = request.form.getlist('sections')

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM alarms ORDER BY triggered_at DESC LIMIT 100')
        alarms = cursor.fetchall()
        db.close()

        report_data = {
            'alarms': [dict(alarm) for alarm in alarms],
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'generated_by': session['username'],
            'report_type': report_type,
            'sections': selected_sections
        }

        # SECURE: Server-side template only
        env = SandboxedEnvironment(autoescape=select_autoescape(['html']))
        template_content = """
        <html>
        <body>
            <h1>SCADA Alarm Report - {{ report_type }}</h1>
            <p>Generated: {{ generated_at }}</p>
            <p>By: {{ generated_by }}</p>
            <table border="1" cellpadding="5" cellspacing="0">
                <tr>
                {% for sec in sections %}
                    <th>{{ sec.replace('_', ' ').title() }}</th>
                {% endfor %}
                </tr>
                {% for alarm in alarms %}
                <tr>
                    {% for sec in sections %}
                        <td>{{ alarm[sec] }}</td>
                    {% endfor %}
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        template = env.from_string(template_content)
        report_html = template.render(**report_data)

        report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = os.path.join(app.config['REPORT_DIR'], report_filename)
        with open(report_path, 'w') as f:
            f.write(report_html)

        return send_file(report_path, as_attachment=True)

    return render_template('reports.html')

@app.route('/export_logs', methods=['GET', 'POST'])
def export_logs():
    """
    SECURITY PATCH: Path traversal protection
    *** MONITORING: Path traversal attempts tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed", 403
        
        log_file = request.form.get('log_file', 'alarm.log')
        
        if detect_path_traversal(log_file):
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_BLOCKED',
                'severity': 'HIGH',
                'endpoint': '/export_logs',
                'method': 'POST',
                'payload': json.dumps({'log_file': log_file}),
                'vulnerability_type': 'PATH_TRAVERSAL',
                'classification': 'Directory Traversal Blocked',
                'blocked': True,
                'description': f"Path traversal attempt blocked: {log_file}",
                'system_version': 'patched'
            })
        
        try:
            log_path = sanitize_path(log_file, app.config['LOG_DIR'])
            
            if os.path.exists(log_path) and os.path.isfile(log_path):
                return send_file(log_path, as_attachment=True)
            else:
                return "Log file not found", 404
        except ValueError as e:
            return f"Invalid path: {str(e)}", 400
        except Exception as e:
            return f"Error reading log file: {str(e)}", 500
    
    try:
        log_files = [f for f in os.listdir(app.config['LOG_DIR']) if os.path.isfile(os.path.join(app.config['LOG_DIR'], f))]
    except:
        log_files = []
    
    return render_template('export_logs.html', log_files=log_files)

@app.route('/backup', methods=['GET', 'POST'])
def backup():
    """SECURITY PATCH: Path traversal protection"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed", 403
        
        action = request.form.get('action', 'backup')
        
        if action == 'backup':
            backup_name = request.form.get('backup_name', 'backup.db')
            
            if detect_path_traversal(backup_name):
                log_to_monitoring({
                    'event_type': 'PATH_TRAVERSAL_BLOCKED',
                    'severity': 'HIGH',
                    'endpoint': '/backup',
                    'payload': json.dumps({'backup_name': backup_name}),
                    'vulnerability_type': 'PATH_TRAVERSAL',
                    'blocked': True,
                    'system_version': 'patched'
                })
            
            if not re.match(r'^[a-zA-Z0-9._-]+\.db$', backup_name):
                return "Invalid backup name", 400
            
            try:
                backup_path = sanitize_path(backup_name, 'backups')
                import shutil
                shutil.copy(app.config['DATABASE'], backup_path)
                return f"Backup created successfully: {backup_name}"
            except Exception as e:
                return f"Backup failed: {str(e)}", 500
        
        elif action == 'restore':
            restore_file = request.form.get('restore_file', '')
            
            if detect_path_traversal(restore_file):
                log_to_monitoring({
                    'event_type': 'PATH_TRAVERSAL_BLOCKED',
                    'severity': 'HIGH',
                    'endpoint': '/backup',
                    'payload': json.dumps({'restore_file': restore_file}),
                    'vulnerability_type': 'PATH_TRAVERSAL',
                    'blocked': True,
                    'system_version': 'patched'
                })
            
            try:
                restore_path = sanitize_path(restore_file, 'backups')
                
                if os.path.exists(restore_path):
                    import shutil
                    shutil.copy(restore_path, app.config['DATABASE'])
                    return "Database restored successfully"
                else:
                    return "Backup file not found", 404
            except ValueError as e:
                return f"Invalid path: {str(e)}", 400
            except Exception as e:
                return f"Restore failed: {str(e)}", 500
    
    try:
        backups = [f for f in os.listdir('backups') if f.endswith('.db')]
    except:
        backups = []
    
    return render_template('backup.html', backups=backups)

@app.route('/firmware_restore', methods=['GET', 'POST'])
def firmware_restore():
    """SECURITY PATCH: Path traversal protection"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed", 403
        
        firmware_path = request.form.get('firmware_path', '')
        
        if detect_path_traversal(firmware_path) or firmware_path.startswith('/'):
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_BLOCKED',
                'severity': 'CRITICAL',
                'endpoint': '/firmware_restore',
                'payload': json.dumps({'firmware_path': firmware_path}),
                'vulnerability_type': 'PATH_TRAVERSAL',
                'classification': 'Absolute/Traversal Path Blocked',
                'blocked': True,
                'description': f"Dangerous path access blocked: {firmware_path}",
                'system_version': 'patched'
            })
        
        try:
            safe_path = sanitize_path(firmware_path, 'firmware')
            
            with open(safe_path, 'r') as f:
                firmware_data = f.read()
            
            return render_template('firmware_restore.html', 
                                 firmware_data=firmware_data[:1000],
                                 message="Firmware loaded successfully")
        except ValueError as e:
            return render_template('firmware_restore.html', 
                                 error=f"Invalid path: {str(e)}")
        except Exception as e:
            return render_template('firmware_restore.html', 
                                 error=f"Error loading firmware: {str(e)}")
    
    return render_template('firmware_restore.html')

@app.route('/api/search_alarms', methods=['GET'])
def search_alarms_api():
    """
    SECURITY PATCH: Parameterized queries
    *** MONITORING: SQL injection attempts tracked ***
    """
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    search_term = request.args.get('q', '')
    
    encoding = request.headers.get('Content-Encoding', 'utf-8')
    
    search_term_for_monitoring = search_term
    if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
        try:
            search_term_bytes = search_term.encode('latin-1')
            search_term_for_monitoring = search_term_bytes.decode(encoding.lower())
        except:
            pass
            
    if detect_sqli_pattern(search_term_for_monitoring):
        log_to_monitoring({
            'event_type': 'SQL_INJECTION_BLOCKED',
            'severity': 'CRITICAL',
            'endpoint': '/api/search_alarms',
            'method': 'GET',
            'payload': json.dumps({'q': search_term_for_monitoring, 'encoding': encoding}),
            'vulnerability_type': 'SQL_INJECTION',
            'classification': 'SQLi-Encoded',
            'blocked': True,
            'description': f"SQL injection attempt with {encoding} blocked",
            'system_version': 'patched'
        })
    
    db = get_db()
    cursor = db.cursor()
    
    # SECURE: Parameterized query
    cursor.execute('''
        SELECT * FROM alarms 
        WHERE description LIKE ? OR location LIKE ?
        ORDER BY triggered_at DESC
    ''', (f'%{search_term}%', f'%{search_term}%'))
    
    results = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify({'results': results})

@app.route('/secret')
def serve_secret():
    with open('templates/private_data.html', 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("PATCHED SCADA APPLICATION (WITH WORKING MONITORING)")
    print("="*60)
    print("Application: http://localhost:5001")
    print("Monitoring: http://localhost:5002")
    print("="*60)
    print("\n✅ FIXED: Cookie manipulation detection")
    print("✅ FIXED: Session hijacking detection")
    print("✅ FIXED: Directory brute-forcing detection")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5001, debug=False)