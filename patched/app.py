"""
SCADA Alarm Management Console - PATCHED VERSION (WITH MONITORING)
Task 9 - CS 437 Assignment

This version contains security patches for:
1. CSRF Protection - Added CSRF tokens to all POST forms
2. SSRF Protection - Removed user-supplied URLs; only predefined report sections selectable
3. Path Traversal Protection - Input sanitization and path validation
4. SQL Injection Protection - Parameterized queries for all encodings

*** MONITORING INTEGRATION ADDED ***
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
app.secret_key = secrets.token_hex(32)  # Longer secret key
app.config['DATABASE'] = 'scada_alarms.db'
app.config['LOG_DIR'] = 'logs'
app.config['REPORT_DIR'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# TRACKING DICTIONARY FOR RATE LIMITING
# Key: IP Address, Value: List of timestamps of failed attempts
failed_login_attempts = defaultdict(list)

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('backups', exist_ok=True)

# *** MONITORING INTEGRATION ***
MONITORING_URL = "http://scada_monitoring:5002"

def log_to_monitoring(event_data):
    """Send security event to monitoring system"""
    try:
        requests.post(
            f"{MONITORING_URL}/api/log_event",
            json=event_data,
            timeout=1
        )
    except Exception as e:
        # Don't let monitoring failures break the app
        pass

def scan_file_with_virustotal(file_path):
    """
    Scans a file hash against VirusTotal API to check for malware.
    """
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not api_key:
        print("Warning: VIRUSTOTAL_API_KEY not found")
        return None 

    try:
        # 1. Calculate SHA-256 Hash
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        # 2. Check Hash against VirusTotal API
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_count = stats['malicious']
            
            if malicious_count > 0:
                return f"MALWARE DETECTED! ({malicious_count} engines flagged this file)"
            else:
                return "Clean"
        elif response.status_code == 404:
            return "Unknown File (Not in VirusTotal database)"
            
    except Exception as e:
        return f"Scan Error: {str(e)}"
    
    return None

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
    # Remove any path traversal attempts
    user_input = user_input.replace('..', '').replace('//', '/')
    
    # Join with base directory and resolve to absolute path
    requested_path = os.path.abspath(os.path.join(base_dir, user_input))
    base_path = os.path.abspath(base_dir)
    
    # Ensure the requested path is within the base directory
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
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Alarms table
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
    
    # Alarm logs table
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
    
    # Reports table
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
    
    # Create default admin user (password: admin123)
    admin_hash = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('admin', admin_hash, 'admin'))
    except sqlite3.IntegrityError:
        pass
    
    # Create operator user
    operator_hash = hashlib.sha256('operator123'.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('operator', operator_hash, 'operator'))
    except sqlite3.IntegrityError:
        pass
    
    db.commit()
    db.close()

@app.route('/')
def index():
    """Main dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    
    # Get active alarms with parameterized query
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
    
    # Get statistics
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
    SECURITY PATCH: Parameterized queries + RATE LIMITING
    """
    #Rate limit check
    ip_address=request.remote_addr
    current_time=time.time()

    # Clean up old attempts (older than 5 minutes)
    # This keeps only failures that happened in the last 300 seconds
    failed_login_attempts[ip_address]=[
        t for t in failed_login_attempts[ip_address] 
        if current_time - t < 300
    ]

    # Check if IP is currently banned (3 or more attempts)
    if len(failed_login_attempts[ip_address]) >= 3:
        # *** MONITORING: Log the Brute Force Block ***
        log_to_monitoring({
            'event_type': 'BRUTE_FORCE_BLOCKED',
            'severity': 'HIGH',
            'source_ip': ip_address,
            'endpoint': '/login',
            'vulnerability_type': 'BRUTE_FORCE',
            'blocked': True,
            'description': f"Too many failed login attempts ({len(failed_login_attempts[ip_address])}). IP temporarily banned.",
            'system_version': 'patched'
        })
        return render_template('login.html', error='Too many failed attempts. Please try again in 5 minutes.')
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Check for special encoding
        encoding = request.headers.get('Content-Encoding', 'utf-8')
        
        username_for_monitoring = username
        # If UTF-16 or UTF-7 encoded, decode it for monitoring visibility
        if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
            try:
                username_bytes = username.encode('latin-1')
                username_for_monitoring = username_bytes.decode(encoding.lower())
            except:
                pass

        # *** MONITORING: Detect attack attempts ***
        if detect_sqli_pattern(username_for_monitoring):
            log_to_monitoring({
                'event_type': 'SQL_INJECTION_BLOCKED',
                'severity': 'CRITICAL',
                'source_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'endpoint': '/login',
                'method': 'POST',
                'payload': json.dumps({'username': username_for_monitoring, 'encoding': encoding}),
                'vulnerability_type': 'SQL_INJECTION',
                'classification': 'SQLi-Encoded',
                'blocked': True,
                'description': f"SQL injection attempt with {encoding} blocked in login",
                'system_version': 'patched',
                'recommended_action': 'IP monitored for further attacks'
            })
        
        # SECURE: Hash password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        db = get_db()
        cursor = db.cursor()
        
        # SECURE: Parameterized query - immune to SQL injection regardless of encoding
        cursor.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?',
                      (username, password_hash))
        user = cursor.fetchone()
        
        # *** MONITORING: Log login attempt ***
        log_to_monitoring({
            'event_type': 'LOGIN_ATTEMPT',
            'severity': 'INFO' if user else 'MEDIUM',
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'endpoint': '/login',
            'method': 'POST',
            'payload': json.dumps({'username': username}),
            'vulnerability_type': 'BRUTE_FORCE' if not user else 'NONE',
            'classification': 'Failed Login' if not user else 'Successful Login',
            'blocked': False,
            'description': f"Login attempt for user '{username}' from {request.remote_addr}",
            'system_version': 'patched',
            'username': username,
            'success': bool(user)
        })
        
        if user:
            # SUCCESS: Clear failed attempts for this IP
            failed_login_attempts[ip_address] = []
            session['username'] = user['username']
            session['role'] = user['role']
            generate_csrf_token()  # Generate CSRF token on login
            db.close()
            return redirect(url_for('index'))
        else:
            # FAILURE: Add timestamp to the list
            failed_login_attempts[ip_address].append(current_time)
            db.close()
            remaining = 3 - len(failed_login_attempts[ip_address])
            return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/alarms')
def alarms():
    """View all alarms with filtering - using parameterized queries"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')
    
    db = get_db()
    cursor = db.cursor()
    
    # Build query with parameters
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
    
    # *** MONITORING: Log CSRF validation ***
    if not validate_csrf_token(csrf_token):
        log_to_monitoring({
            'event_type': 'CSRF_BLOCKED',
            'severity': 'MEDIUM',
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'endpoint': f'/acknowledge/{alarm_id}',
            'method': 'POST',
            'payload': json.dumps(dict(request.headers)),
            'vulnerability_type': 'CSRF',
            'classification': 'Invalid/Missing CSRF Token',
            'blocked': True,
            'description': f"CSRF attack blocked from {request.remote_addr}",
            'system_version': 'patched',
            'recommended_action': 'Monitor this IP for further attacks'
        })
        return "CSRF token validation failed", 403
    
    # Log successful CSRF validation
    log_to_monitoring({
        'event_type': 'CSRF_VALIDATED',
        'severity': 'INFO',
        'source_ip': request.remote_addr,
        'endpoint': f'/acknowledge/{alarm_id}',
        'method': 'POST',
        'vulnerability_type': 'CSRF',
        'blocked': False,
        'description': 'Valid CSRF token - request allowed',
        'system_version': 'patched'
    })
    
    db = get_db()
    cursor = db.cursor()
    
    # Update alarm with parameterized query
    cursor.execute('''
        UPDATE alarms 
        SET acknowledged = ?, 
            acknowledged_by = ?, 
            acknowledged_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (1, session['username'], alarm_id))
    
    # Log the action
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
    
    # SECURITY: Validate CSRF token
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        log_to_monitoring({
            'event_type': 'CSRF_BLOCKED',
            'severity': 'MEDIUM',
            'source_ip': request.remote_addr,
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
    
    # SECURITY: Validate CSRF token
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        log_to_monitoring({
            'event_type': 'CSRF_BLOCKED',
            'severity': 'MEDIUM',
            'source_ip': request.remote_addr,
            'endpoint': f'/escalate/{alarm_id}',
            'vulnerability_type': 'CSRF',
            'blocked': True,
            'system_version': 'patched'
        })
        return "CSRF token validation failed", 403
    
    supervisor = request.form.get('supervisor', 'default_supervisor')
    
    # SECURITY: Validate supervisor name (prevent injection)
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
    SECURITY PATCH: SSRF protection - removed external URLs, server-side templates only
    *** MONITORING: Any SSRF attempts are logged ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # *** MONITORING: Check if someone tries to inject URL (shouldn't be in form) ***
        if 'template_url' in request.form:
            log_to_monitoring({
                'event_type': 'SSRF_ATTEMPT_BLOCKED',
                'severity': 'HIGH',
                'source_ip': request.remote_addr,
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

        # SECURITY PATCH: Use server-side template only (no external URLs)
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

        # Save report
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
        # SECURITY: Validate CSRF token
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed", 403
        
        log_file = request.form.get('log_file', 'alarm.log')
        
        # *** MONITORING: Log any traversal attempts ***
        if detect_path_traversal(log_file):
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_BLOCKED',
                'severity': 'HIGH',
                'source_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'endpoint': '/export_logs',
                'method': 'POST',
                'payload': json.dumps({'log_file': log_file}),
                'vulnerability_type': 'PATH_TRAVERSAL',
                'classification': 'Directory Traversal Blocked',
                'blocked': True,
                'description': f"Path traversal attempt blocked: {log_file}",
                'system_version': 'patched',
                'recommended_action': 'Monitor IP for further attacks'
            })
        
        try:
            # SECURITY PATCH: Sanitize path to prevent directory traversal
            log_path = sanitize_path(log_file, app.config['LOG_DIR'])
            
            if os.path.exists(log_path) and os.path.isfile(log_path):
                return send_file(log_path, as_attachment=True)
            else:
                return "Log file not found", 404
        except ValueError as e:
            return f"Invalid path: {str(e)}", 400
        except Exception as e:
            return f"Error reading log file: {str(e)}", 500
    
    # List available log files
    try:
        log_files = [f for f in os.listdir(app.config['LOG_DIR']) if os.path.isfile(os.path.join(app.config['LOG_DIR'], f))]
    except:
        log_files = []
    
    return render_template('export_logs.html', log_files=log_files)

@app.route('/backup', methods=['GET', 'POST'])
def backup():
    """SECURITY PATCH: Path traversal protection for backup operations"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        # SECURITY: Validate CSRF token
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed", 403
        
        action = request.form.get('action', 'backup')
        
        if action == 'backup':
            backup_name = request.form.get('backup_name', 'backup.db')
            
            # *** MONITORING: Log traversal attempts ***
            if detect_path_traversal(backup_name):
                log_to_monitoring({
                    'event_type': 'PATH_TRAVERSAL_BLOCKED',
                    'severity': 'HIGH',
                    'source_ip': request.remote_addr,
                    'endpoint': '/backup',
                    'payload': json.dumps({'backup_name': backup_name}),
                    'vulnerability_type': 'PATH_TRAVERSAL',
                    'blocked': True,
                    'system_version': 'patched'
                })
            
            # SECURITY PATCH: Sanitize backup name
            if not re.match(r'^[a-zA-Z0-9._-]+\.db$', backup_name):
                return "Invalid backup name. Use only letters, numbers, and .db extension", 400
            
            try:
                backup_path = sanitize_path(backup_name, 'backups')
                import shutil
                shutil.copy(app.config['DATABASE'], backup_path)
                return f"Backup created successfully: {backup_name}"
            except Exception as e:
                return f"Backup failed: {str(e)}", 500
        
        elif action == 'restore':
            restore_file = request.form.get('restore_file', '')
            
            # *** MONITORING ***
            if detect_path_traversal(restore_file):
                log_to_monitoring({
                    'event_type': 'PATH_TRAVERSAL_BLOCKED',
                    'severity': 'HIGH',
                    'source_ip': request.remote_addr,
                    'endpoint': '/backup',
                    'payload': json.dumps({'restore_file': restore_file}),
                    'vulnerability_type': 'PATH_TRAVERSAL',
                    'blocked': True,
                    'system_version': 'patched'
                })
            
            try:
                # SECURITY PATCH: Sanitize restore path
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
    
    # List backups
    try:
        backups = [f for f in os.listdir('backups') if f.endswith('.db')]
    except:
        backups = []
    
    return render_template('backup.html', backups=backups)

@app.route('/firmware_restore', methods=['GET', 'POST'])
def firmware_restore():
    """SECURITY PATCH: Path traversal protection for firmware restore"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        # SECURITY: Validate CSRF token
        csrf_token = request.form.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return "CSRF token validation failed", 403
        
        firmware_path = request.form.get('firmware_path', '')
        
        # *** MONITORING: Log traversal attempts ***
        if detect_path_traversal(firmware_path) or firmware_path.startswith('/'):
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_BLOCKED',
                'severity': 'CRITICAL',
                'source_ip': request.remote_addr,
                'endpoint': '/firmware_restore',
                'payload': json.dumps({'firmware_path': firmware_path}),
                'vulnerability_type': 'PATH_TRAVERSAL',
                'classification': 'Absolute/Traversal Path Blocked',
                'blocked': True,
                'description': f"Dangerous path access blocked: {firmware_path}",
                'system_version': 'patched'
            })
        
        try:
            # SECURITY PATCH: Only allow firmware from specific directory
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
    SECURITY PATCH: Parameterized queries prevent SQL injection regardless of encoding
    *** MONITORING: SQL injection attempts tracked ***
    """
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    search_term = request.args.get('q', '')
    
    encoding = request.headers.get('Content-Encoding', 'utf-8')
    
    search_term_for_monitoring = search_term
    # Check for special encoding
    if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
        try:
            search_term_bytes = search_term.encode('latin-1')
            search_term_for_monitoring = search_term_bytes.decode(encoding.lower())
        except:
            pass
            
    # *** MONITORING: Detect SQL injection attempts ***
    if detect_sqli_pattern(search_term_for_monitoring):
        log_to_monitoring({
            'event_type': 'SQL_INJECTION_BLOCKED',
            'severity': 'CRITICAL',
            'source_ip': request.remote_addr,
            'endpoint': '/api/search_alarms',
            'method': 'GET',
            'payload': json.dumps({'q': search_term_for_monitoring, 'encoding': encoding}),
            'vulnerability_type': 'SQL_INJECTION',
            'classification': 'SQLi-Encoded',
            'blocked': True,
            'description': f"SQL injection attempt with {encoding} blocked in search",
            'system_version': 'patched'
        })
    
    db = get_db()
    cursor = db.cursor()
    
    # SECURE: Parameterized query - immune to encoding-based SQLi
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
    print("PATCHED SCADA APPLICATION (WITH MONITORING)")
    print("="*60)
    print("Application: http://localhost:5001")
    print("Monitoring: http://localhost:5002")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5001, debug=False)