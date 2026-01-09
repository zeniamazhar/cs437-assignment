"""
SCADA Alarm Management Console - VULNERABLE VERSION - REALLY FIXED
Task 9 - CS 437 Assignment

CRITICAL FIX: The monitoring system expects attack parameters as TOP-LEVEL fields,
not inside the 'payload' JSON. This version sends them correctly.

This version intentionally contains the following vulnerabilities:
1. Missing CSRF Protection on POST forms
2. SSRF via Template Injection in Reporting Engines
3. File Path Injection (Directory Traversal)
4. SQL Injection Only Works With Specific Encodings (UTF-16/UTF-7)

*** FULLY WORKING MONITORING INTEGRATION ***
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

# Track for rate limiting and attack detection
file_access_counter = defaultdict(int)
session_usage_tracker = {}  # Track session usage across IPs/User-Agents

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['DATABASE'] = 'scada_alarms.db'
app.config['LOG_DIR'] = 'logs'
app.config['REPORT_DIR'] = 'reports'

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('backups', exist_ok=True)


# *** IP BLOCKING FUNCTIONALITY ***
def check_ip_blocked():
    """Check if current IP is blocked in monitoring system"""
    client_ip = request.remote_addr
    
    try:
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
        print(f"IP blocking check error: {e}")
        pass
    
    return False

@app.before_request
def block_blacklisted_ips():
    """Block requests from blacklisted IPs"""
    if request.endpoint != 'static':
        if check_ip_blocked():
            return render_template('blocked.html'), 403

# *** MONITORING INTEGRATION ***
MONITORING_URL = "http://scada_monitoring:5002"

def log_to_monitoring(event_data):
    """
    Send security event to monitoring system - REALLY FIXED VERSION
    
    KEY FIX: The monitoring system expects attack parameters as TOP-LEVEL fields,
    not nested inside 'payload'. This function now sends them correctly.
    """
    try:
        # Capture all cookies properly
        cookies_dict = {}
        for key, value in request.cookies.items():
            cookies_dict[key] = value
        
        # Enrich event data with ALL context
        event_data['cookies'] = json.dumps(cookies_dict)
        event_data['session_id'] = request.cookies.get('session', '')
        event_data['referer'] = request.headers.get('Referer', '')
        event_data['user_agent'] = request.headers.get('User-Agent', '')
        event_data['source_ip'] = request.remote_addr
        
        # Ensure system_version is ALWAYS set
        if 'system_version' not in event_data:
            event_data['system_version'] = 'vulnerable'
        
        # Ensure endpoint is ALWAYS set
        if 'endpoint' not in event_data:
            event_data['endpoint'] = request.path
        
        # Ensure method is ALWAYS set
        if 'method' not in event_data:
            event_data['method'] = request.method
        
        # Ensure response_status is set
        if 'response_status' not in event_data:
            event_data['response_status'] = 200
        
        # Add form data if POST request
        if request.method == 'POST' and hasattr(request, 'form'):
            event_data['form_data'] = dict(request.form)
        
        # Add headers
        if 'headers' not in event_data:
            event_data['headers'] = dict(request.headers)
        
        # Add session role if available
        if 'role' in session:
            event_data['session_role'] = session['role']
        
        # Ensure required fields have defaults
        if 'event_type' not in event_data:
            event_data['event_type'] = 'SECURITY_EVENT'
        if 'severity' not in event_data:
            event_data['severity'] = 'INFO'
        if 'vulnerability_type' not in event_data:
            event_data['vulnerability_type'] = 'UNKNOWN'
        
        # CRITICAL FIX: Extract attack parameters from payload and add as top-level fields
        # The monitoring system looks for these at the top level!
        if 'payload' in event_data and event_data['payload']:
            try:
                if isinstance(event_data['payload'], str):
                    payload_data = json.loads(event_data['payload'])
                else:
                    payload_data = event_data['payload']
                
                # Extract all potential attack parameters to top level
                for key in ['template_url', 'log_file', 'backup_name', 'restore_file', 
                           'firmware_path', 'search_term', 'username', 'q']:
                    if key in payload_data and key not in event_data:
                        event_data[key] = payload_data[key]
            except:
                pass
        
        response = requests.post(
            f"{MONITORING_URL}/api/log_event",
            json=event_data,
            timeout=2
        )
        
        if response.status_code != 200:
            print(f"Monitoring error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"MONITORING ERROR: {e}")
        import traceback
        traceback.print_exc()

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
    """Check if cookie looks suspicious - returns (is_suspicious, reason)"""
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
    
    # Create operator user (password: operator123)
    operator_hash = hashlib.sha256('operator123'.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                      ('operator', operator_hash, 'operator'))
    except sqlite3.IntegrityError:
        pass
    
    db.commit()
    db.close()

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
                'vulnerability_type': 'COOKIE_MANIPULATION',
                'description': f'Cookie manipulation detected: {reason}',
                'system_version': 'vulnerable'
            })

@app.after_request
def log_response(response):
    """Log all responses to detect directory brute-forcing"""
    if response.status_code == 404 and request.endpoint != 'static':
        log_to_monitoring({
            'event_type': 'FILE_NOT_FOUND',
            'severity': 'LOW',
            'response_status': 404,
            'vulnerability_type': 'DIRECTORY_BRUTEFORCE',
            'description': f'404 error on {request.path}',
            'system_version': 'vulnerable'
        })
    
    return response

@app.route('/')
def index():
    """Main dashboard"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Track session usage for hijacking detection
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
                    'vulnerability_type': 'SESSION_HIJACKING',
                    'description': f'Session {session_id[:10]}... used from different IP/UA',
                    'system_version': 'vulnerable'
                })
        
        session_usage_tracker[session_id] = (current_ip, current_ua)
    
    db = get_db()
    cursor = db.cursor()
    
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
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        encoding = request.headers.get('Content-Encoding', 'utf-8')
        
        # SECURITY FEATURE: Block ASCII SQLi attempts
        if encoding.lower() == 'utf-8':
            if detect_sqli_pattern(username):
                log_to_monitoring({
                    'event_type': 'SQL_INJECTION_BLOCKED',
                    'severity': 'HIGH',
                    'vulnerability_type': 'SQL_INJECTION',
                    'description': 'SQL injection attempt blocked (UTF-8 encoding)',
                    'system_version': 'vulnerable',
                    'username': username,
                    'response_status': 400
                })
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
        
        # VULNERABLE: Direct string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                session['username'] = user['username']
                session['role'] = user['role']
                
                session_id = request.cookies.get('session', '')
                if session_id:
                    session_usage_tracker[session_id] = (
                        request.remote_addr,
                        request.headers.get('User-Agent', '')
                    )
            
            log_to_monitoring({
                'event_type': 'LOGIN_ATTEMPT',
                'severity': 'INFO' if user else 'MEDIUM',
                'payload': json.dumps({'username': username}),
                'vulnerability_type': 'BRUTE_FORCE' if not user else 'NONE',
                'description': f"Login attempt for user '{username}'",
                'system_version': 'vulnerable',
                'username': username,  # TOP-LEVEL for monitoring detection
                'success': bool(user),
                'response_status': 200 if user else 401
            })
            
            if detect_sqli_pattern(username):
                log_to_monitoring({
                    'event_type': 'SQL_INJECTION_ATTEMPT',
                    'severity': 'CRITICAL',
                    'payload': json.dumps({'username': username, 'encoding': encoding}),
                    'vulnerability_type': 'SQL_INJECTION',
                    'description': f"SQL injection pattern detected with encoding {encoding}",
                    'system_version': 'vulnerable',
                    'username': username,  # TOP-LEVEL
                    'response_status': 200 if user else 401
                })
            
            if user:
                db.close()
                return redirect(url_for('index'))
            else:
                db.close()
                return render_template('login.html', error='Invalid credentials')
        except Exception as e:
            db.close()
            log_to_monitoring({
                'event_type': 'SQL_INJECTION_ERROR',
                'severity': 'CRITICAL',
                'vulnerability_type': 'SQL_INJECTION',
                'description': f"SQL error: {str(e)}",
                'system_version': 'vulnerable',
                'response_status': 500
            })
            return render_template('login.html', error=f'Error: {str(e)}')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
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
                    'vulnerability_type': 'SESSION_HIJACKING',
                    'description': f'Session used from different IP/UA',
                    'system_version': 'vulnerable'
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
    VULNERABILITY 1: Missing CSRF Protection
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    log_to_monitoring({
        'event_type': 'CSRF_VULNERABLE_REQUEST',
        'severity': 'MEDIUM',
        'vulnerability_type': 'CSRF',
        'description': f"POST request without CSRF protection to /acknowledge/{alarm_id}",
        'system_version': 'vulnerable',
        'username': session.get('username', 'unknown'),
        'response_status': 302
    })
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        UPDATE alarms 
        SET acknowledged = 1, 
            acknowledged_by = ?, 
            acknowledged_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (session['username'], alarm_id))
    
    cursor.execute('''
        INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
        VALUES (?, ?, ?, ?)
    ''', (alarm_id, 'ACKNOWLEDGED', session['username'], 'Alarm acknowledged by operator'))
    
    db.commit()
    db.close()
    
    return redirect(url_for('alarm_detail', alarm_id=alarm_id))

@app.route('/silence/<int:alarm_id>', methods=['POST'])
def silence_alarm(alarm_id):
    """VULNERABILITY 1: Missing CSRF Protection"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    log_to_monitoring({
        'event_type': 'CSRF_VULNERABLE_REQUEST',
        'severity': 'MEDIUM',
        'vulnerability_type': 'CSRF',
        'description': f"POST request without CSRF protection to /silence/{alarm_id}",
        'system_version': 'vulnerable',
        'response_status': 302
    })
    
    duration = request.form.get('duration', 30)
    
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
    """VULNERABILITY 1: Missing CSRF Protection"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    log_to_monitoring({
        'event_type': 'CSRF_VULNERABLE_REQUEST',
        'severity': 'MEDIUM',
        'vulnerability_type': 'CSRF',
        'description': f"POST request without CSRF protection to /escalate/{alarm_id}",
        'system_version': 'vulnerable',
        'response_status': 302
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
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        report_type = request.form.get('report_type', 'summary')
        template_url = request.form.get('template_url', '')
        
        if template_url:
            is_internal = any(pattern in template_url.lower() for pattern in 
                            ['localhost', '127.0.0.1', '169.254', '192.168', '10.', '172.16'])
            
            log_to_monitoring({
                'event_type': 'SSRF_ATTEMPT',
                'severity': 'HIGH' if is_internal else 'MEDIUM',
                'payload': json.dumps({'template_url': template_url, 'report_type': report_type}),
                'template_url': template_url,  # TOP-LEVEL for detection
                'vulnerability_type': 'SSRF',
                'description': f"Attempting to fetch template from {template_url}",
                'system_version': 'vulnerable'
            })
        
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('SELECT * FROM alarms ORDER BY triggered_at DESC LIMIT 100')
        alarms = cursor.fetchall()
        
        report_data = {
            'alarms': [dict(alarm) for alarm in alarms],
            'generated_at': datetime.now().isoformat(),
            'generated_by': session['username'],
            'report_type': report_type
        }
        
        # VULNERABLE: Fetch and execute external template
        if template_url:
            try:
                response = requests.get(template_url, timeout=5)
                template_content = response.text
                
                template = Template(template_content)
                report_html = template.render(**report_data)
                
                log_to_monitoring({
                    'event_type': 'SSRF_SUCCESS',
                    'severity': 'CRITICAL',
                    'vulnerability_type': 'SSRF',
                    'description': f"SSRF successfully fetched content from {template_url}",
                    'system_version': 'vulnerable'
                })

                report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                report_path = os.path.join(app.config['REPORT_DIR'], report_filename)
                
                with open(report_path, 'w') as f:
                    f.write(report_html)
                
                cursor.execute('''
                    INSERT INTO reports (report_name, report_type, generated_by, file_path)
                    VALUES (?, ?, ?, ?)
                ''', (report_filename, report_type, session['username'], report_path))
                
                db.commit()
                db.close()
                
                return send_file(report_path, as_attachment=True)
                
            except Exception as e:
                db.close()
                log_to_monitoring({
                    'event_type': 'SSRF_FAILED',
                    'severity': 'MEDIUM',
                    'payload': json.dumps({'template_url': template_url, 'error': str(e)}),
                    'vulnerability_type': 'SSRF',
                    'description': f"SSRF attempt failed: {str(e)}",
                    'system_version': 'vulnerable',
                    'response_status': 500
                })
                return f"Error generating report: {str(e)}", 500
        
        db.close()
        return render_template('reports.html', error='Template URL required')
    
    return render_template('reports.html')

@app.route('/export_logs', methods=['GET', 'POST'])
def export_logs():
    """
    VULNERABILITY 3: File Path Injection (Directory Traversal)
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        log_file = request.form.get('log_file', 'alarm.log')
        
        has_traversal = detect_path_traversal(log_file)
        
        log_to_monitoring({
            'event_type': 'PATH_TRAVERSAL_ATTEMPT',
            'severity': 'HIGH' if has_traversal else 'LOW',
            'payload': json.dumps({'log_file': log_file}),
            'log_file': log_file,  # TOP-LEVEL for detection
            'vulnerability_type': 'PATH_TRAVERSAL',
            'description': f"Attempting to access file: {log_file}",
            'system_version': 'vulnerable'
        })
        
        # VULNERABLE: No path validation
        log_path = os.path.join(app.config['LOG_DIR'], log_file)
        
        try:
            if os.path.exists(log_path):
                return send_file(log_path, as_attachment=True)
            else:
                return f"Log file not found: {log_path}", 404
        except Exception as e:
            return f"Error reading log file: {str(e)}", 500
    
    try:
        log_files = os.listdir(app.config['LOG_DIR'])
    except:
        log_files = []
    
    return render_template('export_logs.html', log_files=log_files)

@app.route('/backup', methods=['GET', 'POST'])
def backup():
    """VULNERABILITY 3: File Path Injection"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        action = request.form.get('action', 'backup')
        
        if action == 'backup':
            backup_name = request.form.get('backup_name', 'backup.db')
            
            has_traversal = detect_path_traversal(backup_name)
            
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_ATTEMPT',
                'severity': 'HIGH' if has_traversal else 'LOW',
                'payload': json.dumps({'backup_name': backup_name, 'action': 'backup'}),
                'backup_name': backup_name,  # TOP-LEVEL
                'vulnerability_type': 'PATH_TRAVERSAL',
                'description': f"Backup operation with path: {backup_name}",
                'system_version': 'vulnerable'
            })
            
            backup_path = os.path.join('backups', backup_name)
            
            try:
                import shutil
                shutil.copy(app.config['DATABASE'], backup_path)
                return f"Backup created: {backup_path}"
            except Exception as e:
                return f"Backup failed: {str(e)}", 500
        
        elif action == 'restore':
            restore_file = request.form.get('restore_file', '')
            
            has_traversal = detect_path_traversal(restore_file)
            
            log_to_monitoring({
                'event_type': 'PATH_TRAVERSAL_ATTEMPT',
                'severity': 'HIGH' if has_traversal else 'LOW',
                'payload': json.dumps({'restore_file': restore_file, 'action': 'restore'}),
                'restore_file': restore_file,  # TOP-LEVEL
                'vulnerability_type': 'PATH_TRAVERSAL',
                'description': f"Restore operation with path: {restore_file}",
                'system_version': 'vulnerable'
            })
            
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
    
    try:
        backups = os.listdir('backups')
    except:
        backups = []
    
    return render_template('backup.html', backups=backups)

@app.route('/firmware_restore', methods=['GET', 'POST'])
def firmware_restore():
    """VULNERABILITY 3: File Path Injection"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        firmware_path = request.form.get('firmware_path', '')
        
        has_traversal = detect_path_traversal(firmware_path) or firmware_path.startswith('/')
        
        log_to_monitoring({
            'event_type': 'PATH_TRAVERSAL_ATTEMPT',
            'severity': 'CRITICAL' if has_traversal else 'LOW',
            'payload': json.dumps({'firmware_path': firmware_path}),
            'firmware_path': firmware_path,  # TOP-LEVEL
            'vulnerability_type': 'PATH_TRAVERSAL',
            'description': f"Attempting to read firmware from: {firmware_path}",
            'system_version': 'vulnerable'
        })
        
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
    """
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    search_term = request.args.get('q', '')
    encoding = request.headers.get('Content-Encoding', 'utf-8')
    
    if encoding.lower() == 'utf-8':
        if detect_sqli_pattern(search_term):
            log_to_monitoring({
                'event_type': 'SQL_INJECTION_BLOCKED',
                'severity': 'HIGH',
                'vulnerability_type': 'SQL_INJECTION',
                'description': 'SQL injection blocked (UTF-8)',
                'system_version': 'vulnerable',
                'search_term': search_term,  # TOP-LEVEL
                'response_status': 400
            })
            return jsonify({'error': 'Invalid search term'}), 400
    
    if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
        try:
            search_term_bytes = search_term.encode('latin-1')
            search_term = search_term_bytes.decode(encoding.lower())
        except:
            pass
    
    if detect_sqli_pattern(search_term):
        log_to_monitoring({
            'event_type': 'SQL_INJECTION_ATTEMPT',
            'severity': 'CRITICAL',
            'payload': json.dumps({'q': search_term, 'encoding': encoding}),
            'search_term': search_term,  # TOP-LEVEL
            'vulnerability_type': 'SQL_INJECTION',
            'description': f"SQL injection detected in search with encoding {encoding}",
            'system_version': 'vulnerable'
        })
    
    db = get_db()
    cursor = db.cursor()
    
    query = f"SELECT * FROM alarms WHERE description LIKE '%{search_term}%' OR location LIKE '%{search_term}%'"
    
    try:
        cursor.execute(query)
        results = [dict(row) for row in cursor.fetchall()]
        db.close()
        return jsonify({'results': results})
    except Exception as e:
        db.close()
        log_to_monitoring({
            'event_type': 'SQL_INJECTION_ERROR',
            'severity': 'CRITICAL',
            'vulnerability_type': 'SQL_INJECTION',
            'description': f"SQL error: {str(e)}",
            'system_version': 'vulnerable',
            'response_status': 500
        })
        return jsonify({'error': str(e)}), 500

@app.route('/secret')
def serve_secret():
    """Serve sensitive file"""
    file_path = 'templates/private_data.html'
    resolved_path = os.path.abspath(file_path)

    log_to_monitoring({
        'event_type': 'SENSITIVE_FILE_ACCESS',
        'severity': 'CRITICAL',
        'vulnerability_type': 'DATA_EXFILTRATION',
        'description': 'Sensitive file accessed via /secret endpoint',
        'system_version': 'vulnerable',
        'response_status': 200
    })

    with open(file_path, 'r') as f:
        return f.read(), 200, {'Content-Type': 'text/plain'}

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("VULNERABLE SCADA APPLICATION - REALLY FIXED VERSION")
    print("="*60)
    print("Application: http://localhost:5000")
    print("Monitoring: http://localhost:5002")
    print("="*60)
    print("\n✅ REALLY FIXED: Attack parameters sent as top-level fields")
    print("✅ REALLY FIXED: Monitoring system can now detect all attacks")
    print("="*60 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=True)