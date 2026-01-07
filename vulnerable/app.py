"""
SCADA Alarm Management Console - VULNERABLE VERSION (WITH MONITORING)
Task 9 - CS 437 Assignment

This version intentionally contains the following vulnerabilities:
1. Missing CSRF Protection on POST forms
2. SSRF via Template Injection in Reporting Engines
3. File Path Injection (Directory Traversal)
4. SQL Injection Only Works With Specific Encodings (UTF-16/UTF-7)

*** MONITORING INTEGRATION ADDED ***
DO NOT USE IN PRODUCTION
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask import make_response
import sqlite3
import os
import hashlib
import secrets
from datetime import datetime, timedelta
import requests
from jinja2 import Template
import json
import base64
import codecs
from collections import defaultdict
file_access_counter = defaultdict(int)


app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['DATABASE'] = 'scada_alarms.db'
app.config['LOG_DIR'] = 'logs'
app.config['REPORT_DIR'] = 'reports'


# *** IP BLOCKING FUNCTIONALITY ***
def check_ip_blocked():
    """Check if current IP is blocked in monitoring system"""
    client_ip = request.remote_addr
    
    try:
        # Query monitoring database for blocked IPs
        import sqlite3
        monitor_db_path = '/app/data/security_monitor.db'
        
        # Try different possible paths
        if not os.path.exists(monitor_db_path):
            monitor_db_path = '../monitoring/data/security_monitor.db'
        if not os.path.exists(monitor_db_path):
            monitor_db_path = 'monitoring/data/security_monitor.db'
        
        if os.path.exists(monitor_db_path):
            conn = sqlite3.connect(monitor_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM ip_blacklist 
                WHERE ip_address = ? 
                AND active = 1 
                AND (permanent = 1 OR expires_at > datetime('now'))
            ''', (client_ip,))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            if count > 0:
                return True
        
    except Exception as e:
        # If we can't check, don't block (fail open)
        print(f"IP blocking check error: {e}")
        pass
    
    return False

@app.before_request
def block_blacklisted_ips():
    """Block requests from blacklisted IPs"""
    if request.endpoint != 'static':  # Don't block static files
        if check_ip_blocked():
            return render_template('blocked.html'), 403


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
        print("MONITORING ERROR:", e)

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
        pass  # User already exists
    
    # Create operator user (password: operator123)
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
    
    # Get active alarms
    cursor.execute('''
        SELECT * FROM alarms 
        WHERE status = 'active' 
        ORDER BY 
            CASE severity 
                WHEN 'critical' THEN 1 
                WHEN 'high' THEN 2 
                WHEN 'medium' THEN 3 
                WHEN 'low' THEN 4 
            END,
            triggered_at DESC
    ''')
    alarms = cursor.fetchall()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) as count FROM alarms WHERE status = "active"')
    active_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM alarms WHERE acknowledged = 1 AND status = "active"')
    acknowledged_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM alarms WHERE escalated = 1')
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
    VULNERABILITY 4: SQL Injection Only Works With Specific Encodings
    *** MONITORING: Login attempts tracked ***
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Check for special encoding in request
        encoding = request.headers.get('Content-Encoding', 'utf-8')
        
        # SECURITY FEATURE: Block ASCII SQLi attempts (only allow encoded SQLi)
        if encoding.lower() == 'utf-8':
            if detect_sqli_pattern(username):
                return render_template('login.html', error='Invalid input detected')
        
        # If UTF-16 or UTF-7 encoded, decode it
        if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
            try:
                username_bytes = username.encode('latin-1')
                username = username_bytes.decode(encoding.lower())
            except:
                pass
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        db = get_db()
        cursor = db.cursor()
        
        # VULNERABLE: Direct string concatenation without parameterization
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        
        try:
            cursor.execute(query)
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
                'system_version': 'vulnerable',
                'username': username,
                'success': bool(user)
            })
            
            # Detect SQL injection patterns
            if detect_sqli_pattern(username):
                log_to_monitoring({
                    'event_type': 'SQL_INJECTION_ATTEMPT',
                    'severity': 'CRITICAL',
                    'source_ip': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent', ''),
                    'endpoint': '/login',
                    'method': 'POST',
                    'payload': json.dumps({'username': username, 'encoding': encoding}),
                    'vulnerability_type': 'SQL_INJECTION',
                    'classification': 'SQLi-Encoded',
                    'blocked': False,
                    'description': f"SQL injection pattern detected in username with encoding {encoding}",
                    'system_version': 'vulnerable',
                    'recommended_action': 'Block IP after 3 attempts'
                })
            
            if user:
                session['username'] = user['username']
                session['role'] = user['role']
                db.close()
                return redirect(url_for('index'))
            else:
                db.close()
                return render_template('login.html', error='Invalid credentials')
        except Exception as e:
            db.close()
            return render_template('login.html', error=f'Error: {str(e)}')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/alarms')
def alarms():
    """View all alarms with filtering"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
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
    VULNERABILITY 1: Missing CSRF Protection on POST form
    *** MONITORING: CSRF attempts tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # *** MONITORING: Log CSRF vulnerability ***
    csrf_token = request.form.get('csrf_token', '')
    log_to_monitoring({
        'event_type': 'CSRF_VULNERABLE_REQUEST',
        'severity': 'MEDIUM',
        'source_ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'endpoint': f'/acknowledge/{alarm_id}',
        'method': 'POST',
        'request_headers': json.dumps(dict(request.headers)),
        'vulnerability_type': 'CSRF',
        'attack_classification': 'Missing CSRF Token',
        'blocked': False,
        'description': f"POST request without CSRF protection from {request.remote_addr}",
        'system_version': 'vulnerable',
        'recommended_action': 'Implement CSRF tokens',
        'session_id': request.cookies.get('session', ''),
        'username': session['username']
    })
    
    db = get_db()
    cursor = db.cursor()
    
    # Update alarm
    cursor.execute('''
        UPDATE alarms 
        SET acknowledged = 1, 
            acknowledged_by = ?, 
            acknowledged_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (session['username'], alarm_id))
    
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
    """
    VULNERABILITY 1: Missing CSRF Protection (another endpoint)
    *** MONITORING: CSRF attempts tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # *** MONITORING: Log CSRF vulnerability ***
    log_to_monitoring({
        'event_type': 'CSRF_VULNERABLE_REQUEST',
        'severity': 'MEDIUM',
        'source_ip': request.remote_addr,
        'endpoint': f'/silence/{alarm_id}',
        'method': 'POST',
        'vulnerability_type': 'CSRF',
        'system_version': 'vulnerable'
    })
    
    duration = request.form.get('duration', 30)  # minutes
    
    db = get_db()
    cursor = db.cursor()
    
    silence_until = datetime.now() + timedelta(minutes=int(duration))
    
    cursor.execute('''
        UPDATE alarms 
        SET silenced = 1, 
            silenced_until = ? 
        WHERE id = ?
    ''', (silence_until, alarm_id))
    
    cursor.execute('''
        INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
        VALUES (?, ?, ?, ?)
    ''', (alarm_id, 'SILENCED', session['username'], f'Alarm silenced for {duration} minutes'))
    
    db.commit()
    db.close()
    
    return redirect(url_for('alarm_detail', alarm_id=alarm_id))

@app.route('/escalate/<int:alarm_id>', methods=['POST'])
def escalate_alarm(alarm_id):
    """
    VULNERABILITY 1: Missing CSRF Protection (third endpoint)
    *** MONITORING: CSRF attempts tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # *** MONITORING: Log CSRF vulnerability ***
    log_to_monitoring({
        'event_type': 'CSRF_VULNERABLE_REQUEST',
        'severity': 'MEDIUM',
        'source_ip': request.remote_addr,
        'endpoint': f'/escalate/{alarm_id}',
        'method': 'POST',
        'vulnerability_type': 'CSRF',
        'system_version': 'vulnerable'
    })
    
    supervisor = request.form.get('supervisor', 'default_supervisor')
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        UPDATE alarms 
        SET escalated = 1, 
            escalated_to = ? 
        WHERE id = ?
    ''', (supervisor, alarm_id))
    
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
    VULNERABILITY 2: Server-Side Request Forgery via Template Injection
    *** MONITORING: SSRF attempts tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        report_type = request.form.get('report_type', 'summary')
        template_url = request.form.get('template_url', '')
        
        # *** MONITORING: Log SSRF attempt ***
        if template_url:
            # Check for internal/private URLs
            is_internal = any(pattern in template_url.lower() for pattern in 
                            ['localhost', '127.0.0.1', '169.254', '192.168', '10.', '172.16'])
            
            log_to_monitoring({
                'event_type': 'SSRF_ATTEMPT',
                'severity': 'HIGH' if is_internal else 'MEDIUM',
                'source_ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'endpoint': '/reports',
                'method': 'POST',
                'request_payload': json.dumps({'template_url': template_url, 'report_type': report_type}),
                'vulnerability_type': 'SSRF',
                'attack_classification': 'Internal Network Access' if is_internal else 'External URL Fetch',
                'blocked': False,
                'description': f"Attempting to fetch template from {template_url}",
                'system_version': 'vulnerable',
                'recommended_action': 'Implement URL allowlist and validate domains'
            })
        
        db = get_db()
        cursor = db.cursor()
        
        # Fetch alarms for report
        cursor.execute('SELECT * FROM alarms ORDER BY triggered_at DESC LIMIT 100')
        alarms = cursor.fetchall()
        
        report_data = {
            'alarms': [dict(alarm) for alarm in alarms],
            'generated_at': datetime.now().isoformat(),
            'generated_by': session['username'],
            'report_type': report_type
        }
        
        # VULNERABLE: Fetch and execute external template (Template Injection + SSRF)
        if template_url:
            try:
                # Fetch template from external URL
                response = requests.get(template_url, timeout=5)
                template_content = response.text
                
                # VULNERABLE: Using Jinja2 Template without sandboxing
                template = Template(template_content)
                report_html = template.render(**report_data)
                # *** MONITORING: Log successful SSRF exploitation ***
                log_to_monitoring({
                    'event_type': 'SSRF_SUCCESS',
                    'severity': 'CRITICAL',
                    'source_ip': request.remote_addr,
                    'endpoint': '/reports',
                    'method': 'POST',
                    'vulnerability_type': 'SSRF',
                    'attack_classification': 'Internal Resource Access',
                    'blocked': False,
                    'description': f"SSRF successfully fetched and executed content from {template_url}",
                    'system_version': 'vulnerable',
                    'recommended_action': 'Block internal URLs and sandbox template rendering'
                })

                # Save report
                report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                report_path = os.path.join(app.config['REPORT_DIR'], report_filename)
                
                with open(report_path, 'w') as f:
                    f.write(report_html)
                
                # Log report generation
                cursor.execute('''
                    INSERT INTO reports (report_name, report_type, generated_by, file_path)
                    VALUES (?, ?, ?, ?)
                ''', (report_filename, report_type, session['username'], report_path))
                
                db.commit()
                db.close()
                
                return send_file(report_path, as_attachment=True)
                
            except Exception as e:
                db.close()
                # *** MONITORING: Log SSRF failure ***
                log_to_monitoring({
                    'event_type': 'SSRF_FAILED',
                    'severity': 'MEDIUM',
                    'source_ip': request.remote_addr,
                    'endpoint': '/reports',
                    'request_payload': json.dumps({'template_url': template_url, 'error': str(e)}),
                    'vulnerability_type': 'SSRF',
                    'description': f"SSRF attempt failed: {str(e)}",
                    'system_version': 'vulnerable'
                })
                return f"Error generating report: {str(e)}", 500
        
        db.close()
        return render_template('reports.html', error='Template URL required')
    
    return render_template('reports.html')

@app.route('/export_logs', methods=['GET', 'POST'])
def export_logs():
    """
    VULNERABILITY 3: File Path Injection (Directory Traversal)
    *** MONITORING: Path traversal attempts tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        log_file = request.form.get('log_file', 'alarm.log')
        
        # *** MONITORING: Log path traversal attempt ***
        has_traversal = detect_path_traversal(log_file)
        
        log_to_monitoring({
            'event_type': 'PATH_TRAVERSAL_ATTEMPT',
            'severity': 'HIGH' if has_traversal else 'LOW',
            'source_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'endpoint': '/export_logs',
            'method': 'POST',
            'request_payload': json.dumps({'log_file': log_file}),
            'vulnerability_type': 'PATH_TRAVERSAL',
            'attack_classification': 'Directory Traversal' if has_traversal else 'Normal File Access',
            'blocked': False,
            'description': f"Attempting to access file: {log_file}",
            'system_version': 'vulnerable',
            'recommended_action': 'Implement path sanitization'
        })
        
        # VULNERABLE: No path validation - allows directory traversal
        log_path = os.path.join(app.config['LOG_DIR'], log_file)
        
        try:
            if os.path.exists(log_path):
                return send_file(log_path, as_attachment=True)
            else:
                return f"Log file not found: {log_path}", 404
        except Exception as e:
            return f"Error reading log file: {str(e)}", 500
    
    # List available log files
    try:
        log_files = os.listdir(app.config['LOG_DIR'])
    except:
        log_files = []
    
    return render_template('export_logs.html', log_files=log_files)

@app.route('/backup', methods=['GET', 'POST'])
def backup():
    """
    VULNERABILITY 3: File Path Injection (another endpoint)
    *** MONITORING: Path traversal in backup tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        action = request.form.get('action', 'backup')
        
        if action == 'backup':
            backup_name = request.form.get('backup_name', 'backup.db')
            
            # *** MONITORING: Log backup operation ***
            has_traversal = detect_path_traversal(backup_name)
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_ATTEMPT',
                'severity': 'HIGH' if has_traversal else 'LOW',
                'source_ip': request.remote_addr,
                'endpoint': '/backup',
                'request_payload': json.dumps({'backup_name': backup_name, 'action': 'backup'}),
                'vulnerability_type': 'PATH_TRAVERSAL',
                'system_version': 'vulnerable'
            })
            
            # VULNERABLE: No sanitization of backup name
            backup_path = os.path.join('backups', backup_name)
            
            try:
                import shutil
                shutil.copy(app.config['DATABASE'], backup_path)
                return f"Backup created: {backup_path}"
            except Exception as e:
                return f"Backup failed: {str(e)}", 500
        
        elif action == 'restore':
            restore_file = request.form.get('restore_file', '')
            
            # *** MONITORING: Log restore operation ***
            has_traversal = detect_path_traversal(restore_file)
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_ATTEMPT',
                'severity': 'HIGH' if has_traversal else 'LOW',
                'source_ip': request.remote_addr,
                'endpoint': '/backup',
                'request_payload': json.dumps({'restore_file': restore_file, 'action': 'restore'}),
                'vulnerability_type': 'PATH_TRAVERSAL',
                'system_version': 'vulnerable'
            })
            
            # VULNERABLE: Path traversal in restore
            restore_path = os.path.join('backups', restore_file)
            
            try:
                if os.path.exists(restore_path):
                    import shutil
                    shutil.copy(restore_path, app.config['DATABASE'])
                    return "Database restored successfully"
                else:
                    return "Backup file not found", 404
            except Exception as e:
                return f"Restore failed: {str(e)}", 500
    
    # List backups
    try:
        backups = os.listdir('backups')
    except:
        backups = []
    
    return render_template('backup.html', backups=backups)

@app.route('/firmware_restore', methods=['GET', 'POST'])
def firmware_restore():
    """
    VULNERABILITY 3: File Path Injection (third endpoint)
    *** MONITORING: Path traversal in firmware tracked ***
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        firmware_path = request.form.get('firmware_path', '')
        
        # *** MONITORING: Log firmware access ***
        has_traversal = detect_path_traversal(firmware_path) or firmware_path.startswith('/')
        log_to_monitoring({
            'event_type': 'PATH_TRAVERSAL_ATTEMPT',
            'severity': 'CRITICAL' if has_traversal else 'LOW',
            'source_ip': request.remote_addr,
            'endpoint': '/firmware_restore',
            'request_payload': json.dumps({'firmware_path': firmware_path}),
            'vulnerability_type': 'PATH_TRAVERSAL',
            'attack_classification': 'Absolute/Traversal Path Access',
            'blocked': False,
            'description': f"Attempting to read firmware from: {firmware_path}",
            'system_version': 'vulnerable',
            'recommended_action': 'Restrict to firmware directory only'
        })
        
        # VULNERABLE: No path validation
        try:
            with open(firmware_path, 'r') as f:
                firmware_data = f.read()
            
            return render_template('firmware_restore.html', 
                                 firmware_data=firmware_data[:1000],
                                 message="Firmware loaded successfully")
        except Exception as e:
            return render_template('firmware_restore.html', 
                                 error=f"Error loading firmware: {str(e)}")
    
    return render_template('firmware_restore.html')

@app.route('/api/search_alarms', methods=['GET'])
def search_alarms_api():
    """
    API endpoint demonstrating the encoding-based SQL injection
    *** MONITORING: SQL injection attempts tracked ***
    """
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    search_term = request.args.get('q', '')
    encoding = request.headers.get('Content-Encoding', 'utf-8')
    
    # SECURITY FEATURE: Block ASCII SQLi attempts (only allow encoded SQLi)
    if encoding.lower() == 'utf-8':
        if detect_sqli_pattern(search_term):
            return jsonify({'error': 'Invalid search term'}), 400
    
    # Check for special encoding
    if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
        try:
            search_term_bytes = search_term.encode('latin-1')
            search_term = search_term_bytes.decode(encoding.lower())
        except:
            pass
    
    # *** MONITORING: Detect SQL injection ***
    if detect_sqli_pattern(search_term):
        log_to_monitoring({
            'event_type': 'SQL_INJECTION_ATTEMPT',
            'severity': 'CRITICAL',
            'source_ip': request.remote_addr,
            'endpoint': '/api/search_alarms',
            'method': 'GET',
            'payload': json.dumps({'q': search_term, 'encoding': encoding}),
            'vulnerability_type': 'SQL_INJECTION',
            'classification': 'SQLi-Encoded',
            'blocked': False,
            'description': f"SQL injection detected in search with encoding {encoding}",
            'system_version': 'vulnerable',
            'recommended_action': 'Use parameterized queries'
        })
    
    db = get_db()
    cursor = db.cursor()
    
    # VULNERABLE: String concatenation with encoding bypass
    query = f"SELECT * FROM alarms WHERE description LIKE '%{search_term}%' OR location LIKE '%{search_term}%'"
    
    try:
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        db.close()
        return jsonify({'results': results})
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

@app.route('/report_template')
def serve_report_template():
    with open('templates/report_template.html', 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/plain'}
@app.route('/secret')
def serve_secret():
    file_path = 'templates/private_data.html'
    resolved_path = os.path.abspath(file_path)

    log_to_monitoring({
        'event_type': 'SENSITIVE_FILE_ACCESS',
        'severity': 'CRITICAL',
        'source_ip': request.remote_addr,
        'endpoint': '/secret',
        'method': 'GET',
        'vulnerability_type': 'DATA_EXFILTRATION',
        'attack_classification': 'Sensitive File Disclosure',
        'blocked': False,
        'description': 'Sensitive file accessed via /secret endpoint',
        'system_version': 'vulnerable',
        'requested_path': file_path,
        'resolved_path': resolved_path,
        'recommended_action': 'Restrict access or remove endpoint'
    })

    with open(file_path, 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("VULNERABLE SCADA APPLICATION (WITH MONITORING)")
    print("="*60)
    print("Application: http://localhost:5000")
    print("Monitoring: http://localhost:5002")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)