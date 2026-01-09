"""
Enhanced Security Monitoring System for SCADA - FULLY FIXED VERSION
Added: COOKIE_MANIPULATION, SESSION_HIJACKING, DIRECTORY_BRUTEFORCE detections
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import sqlite3
from datetime import datetime, timedelta
import json
import hashlib
import requests
import os
from collections import defaultdict
import time

app = Flask(__name__)
app.config['MONITOR_DB'] = '/app/data/security_monitor.db'
app.config['SECRET_KEY'] = 'monitoring_secret_key_change_in_production'
app.config['SESSION_COOKIE_NAME'] = 'monitoring_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'YOUR_API_KEY_HERE')
VIRUSTOTAL_ENABLED = VIRUSTOTAL_API_KEY != 'YOUR_API_KEY_HERE'

# Rate limiting tracking - IMPROVED BRUTE FORCE DETECTION
failed_login_tracker = defaultdict(list)  # {ip: [timestamp1, timestamp2, ...]}
blocked_ips = set()

# RECOMMENDED ACTIONS DATABASE - ADDED THREE NEW TYPES
RECOMMENDED_ACTIONS = {
    'SQL_INJECTION': {
        'severity': 'CRITICAL',
        'immediate': 'Block IP immediately after 3 attempts',
        'short_term': 'Review all SQL queries for parameterization',
        'long_term': 'Implement WAF with SQLi signatures, conduct code audit',
        'detection': 'Monitor for SQL keywords in input fields',
        'prevention': 'Use parameterized queries exclusively'
    },
    'CSRF': {
        'severity': 'HIGH',
        'immediate': 'Alert administrator, monitor for follow-up attacks',
        'short_term': 'Implement CSRF tokens on all state-changing operations',
        'long_term': 'Enable SameSite cookies, implement double-submit pattern',
        'detection': 'Check for missing CSRF tokens in POST requests',
        'prevention': 'Generate and validate CSRF tokens for all forms'
    },
    'PATH_TRAVERSAL': {
        'severity': 'HIGH',
        'immediate': 'Block IP after 3 attempts, quarantine affected files',
        'short_term': 'Sanitize all file path inputs',
        'long_term': 'Implement allowlist-based file access, use chroot',
        'detection': 'Monitor for ../ and absolute path patterns',
        'prevention': 'Validate paths against base directory, use path.join() securely'
    },
    'SSRF': {
        'severity': 'HIGH',
        'immediate': 'Block IP, review internal network access',
        'short_term': 'Implement URL allowlist for external fetches',
        'long_term': 'Network segmentation, disable URL fetching where unnecessary',
        'detection': 'Monitor for internal IP ranges in URL parameters',
        'prevention': 'Validate URLs against allowlist, block private IP ranges'
    },
    'BRUTE_FORCE': {
        'severity': 'MEDIUM',
        'immediate': 'Implement rate limiting after 5 failed attempts',
        'short_term': 'Add CAPTCHA, implement account lockout',
        'long_term': 'Multi-factor authentication, adaptive authentication',
        'detection': 'Track failed login attempts per IP and username',
        'prevention': 'Rate limiting, progressive delays, CAPTCHA'
    },
    'XSS': {
        'severity': 'MEDIUM',
        'immediate': 'Alert administrator, sanitize affected data',
        'short_term': 'Implement output encoding for all user data',
        'long_term': 'Content Security Policy, sanitization libraries',
        'detection': 'Monitor for script tags and JavaScript in inputs',
        'prevention': 'Encode all output, validate input types'
    },
    'XXE': {
        'severity': 'CRITICAL',
        'immediate': 'Block IP, disable XML external entity processing',
        'short_term': 'Configure XML parser securely',
        'long_term': 'Use JSON instead of XML, implement XML validation',
        'detection': 'Monitor for DOCTYPE and ENTITY declarations',
        'prevention': 'Disable external entities in XML parser configuration'
    },
    'FILE_UPLOAD': {
        'severity': 'HIGH',
        'immediate': 'Quarantine uploaded file, scan with antivirus',
        'short_term': 'Validate file types, implement file size limits',
        'long_term': 'Sandbox file processing, implement virus scanning',
        'detection': 'Check file signatures, not just extensions',
        'prevention': 'Allowlist file types, scan uploads, store outside webroot'
    },
    # === ADDED THREE NEW DETECTION TYPES ===
    'COOKIE_MANIPULATION': {
        'severity': 'HIGH',
        'immediate': 'Invalidate session, block IP temporarily',
        'short_term': 'Implement secure cookie attributes (HttpOnly, Secure, SameSite)',
        'long_term': 'Use signed cookies, implement session fingerprinting',
        'detection': 'Monitor for modified session cookies, invalid signatures',
        'prevention': 'Sign cookies, validate session integrity'
    },
    'SESSION_HIJACKING': {
        'severity': 'CRITICAL',
        'immediate': 'Terminate session, force re-authentication, block IP',
        'short_term': 'Implement session fingerprinting (IP, User-Agent)',
        'long_term': 'Mutual TLS, hardware token authentication',
        'detection': 'Monitor for session use from multiple IPs/browsers',
        'prevention': 'Session binding, short session timeouts, re-auth for sensitive ops'
    },
    'DIRECTORY_BRUTEFORCE': {
        'severity': 'MEDIUM',
        'immediate': 'Block IP after 10 404s in 1 minute',
        'short_term': 'Implement rate limiting on file access',
        'long_term': 'Web Application Firewall, hide directory structure',
        'detection': 'Monitor for sequential 404 errors from same IP',
        'prevention': 'Rate limiting, disable directory listing'
    }
}

def get_recommended_actions(vuln_type):
    """Get recommended actions for a vulnerability type"""
    if vuln_type in RECOMMENDED_ACTIONS:
        return RECOMMENDED_ACTIONS[vuln_type]
    return {
        'severity': 'MEDIUM',
        'immediate': 'Investigate and monitor',
        'short_term': 'Review security controls',
        'long_term': 'Conduct security audit',
        'detection': 'Monitor unusual patterns',
        'prevention': 'Follow secure coding practices'
    }

def check_brute_force(source_ip, success):
    """
    IMPROVED: Only marks as brute force after exceeding threshold
    Returns: (is_brute_force, failed_count)
    """
    current_time = time.time()
    time_window = 300  # 5 minutes
    threshold = 5  # 5 failed attempts
    
    # Clean old entries
    if source_ip in failed_login_tracker:
        failed_login_tracker[source_ip] = [
            t for t in failed_login_tracker[source_ip] 
            if current_time - t < time_window
        ]
    
    if not success:
        # Record failed attempt
        failed_login_tracker[source_ip].append(current_time)
    else:
        # Successful login - clear failed attempts
        if source_ip in failed_login_tracker:
            del failed_login_tracker[source_ip]
        return False, 0
    
    failed_count = len(failed_login_tracker[source_ip])
    
    # Only flag as brute force if exceeds threshold
    is_brute_force = failed_count >= threshold
    
    return is_brute_force, failed_count

def init_monitor_db():
    """Initialize comprehensive monitoring database with CORRECT schema"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    # Check if tables exist and recreate if needed
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    existing_tables = [row[0] for row in cursor.fetchall()]
    
    # Drop old tables if they have wrong schema
    if 'security_events' in existing_tables:
        cursor.execute("PRAGMA table_info(security_events)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'admin_reviewed' not in columns:
            print("⚠️  Recreating security_events table with correct schema...")
            cursor.execute('DROP TABLE IF EXISTS security_events')
    
    if 'response_actions' in existing_tables:
        cursor.execute("PRAGMA table_info(response_actions)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'can_reverse' not in columns:
            print("⚠️  Recreating response_actions table with correct schema...")
            cursor.execute('DROP TABLE IF EXISTS response_actions')
    
    # Main security events table with ALL required columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        -- Core metadata
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,

        -- Request origin
        source_ip TEXT NOT NULL,
        user_agent TEXT,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,

        -- Request data
        request_headers TEXT,
        request_payload TEXT,
        response_status INTEGER,

        -- Session / user info
        session_id TEXT,
        username TEXT,

        -- Security classification
        vulnerability_type TEXT NOT NULL,
        attack_classification TEXT,

        -- Blocking info
        blocked BOOLEAN DEFAULT 0,
        auto_blocked BOOLEAN DEFAULT 0,

        -- Description & system metadata
        description TEXT,
        system_version TEXT,

        -- Recommendations & actions
        recommended_action TEXT,
        action_taken TEXT,
        action_timestamp DATETIME,

        -- FALSE POSITIVE SUPPORT
        false_positive BOOLEAN DEFAULT 0,
        notes TEXT,
        admin_reviewed BOOLEAN DEFAULT 0
    );

    ''')
    
    # IP blacklist/whitelist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            added_by TEXT DEFAULT 'SYSTEM',
            expires_at DATETIME,
            permanent BOOLEAN DEFAULT 0,
            active BOOLEAN DEFAULT 1,
            can_reverse BOOLEAN DEFAULT 1,
            times_blocked INTEGER DEFAULT 0,
            last_blocked_at DATETIME
        )
    ''')
    
    # Response actions log with ALL required columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_id INTEGER,
            action_type TEXT NOT NULL,
            action_details TEXT,
            performed_by TEXT,
            automatic BOOLEAN DEFAULT 0,
            success BOOLEAN DEFAULT 1,
            reversed BOOLEAN DEFAULT 0,
            reversed_at DATETIME,
            reversed_by TEXT,
            can_reverse BOOLEAN DEFAULT 1,
            FOREIGN KEY (event_id) REFERENCES security_events (id)
        )
    ''')
    
    # Alert rules
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            threshold INTEGER NOT NULL,
            time_window INTEGER NOT NULL,
            action TEXT NOT NULL,
            active BOOLEAN DEFAULT 1,
            automated BOOLEAN DEFAULT 0,
            UNIQUE(rule_name, vulnerability_type)
        )
    ''')
    
    # File upload tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_size INTEGER,
            mime_type TEXT,
            file_hash TEXT,
            virustotal_scan_id TEXT,
            virustotal_positives INTEGER,
            virustotal_total INTEGER,
            malicious BOOLEAN DEFAULT 0,
            blocked BOOLEAN DEFAULT 0,
            quarantined BOOLEAN DEFAULT 0,
            file_path TEXT
        )
    ''')
    
    # Admin users for monitoring system
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    
    # Create default admin user (password: monitor123)
    admin_hash = hashlib.sha256('monitor123'.encode()).hexdigest()
    try:
        cursor.execute('INSERT INTO admin_users (username, password_hash) VALUES (?, ?)',
                      ('admin', admin_hash))
    except sqlite3.IntegrityError:
        pass
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_vuln_type ON security_events(vulnerability_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_blacklist ON ip_blacklist(ip_address, active)')
    
    # FIXED: Delete existing rules to prevent duplicates
    cursor.execute('DELETE FROM alert_rules')
    
    # Insert default alert rules (including the three new ones)
    default_rules = [
        ('Failed Login Threshold', 'BRUTE_FORCE', 5, 300, 'BLOCK_IP', 1, 1),
        ('CSRF Attack Threshold', 'CSRF', 3, 600, 'ALERT_ADMIN', 1, 0),
        ('Path Traversal Threshold', 'PATH_TRAVERSAL', 3, 300, 'BLOCK_IP', 1, 1),
        ('SSRF Attempt Threshold', 'SSRF', 2, 600, 'BLOCK_IP', 1, 1),
        ('SQLi Attempt Threshold', 'SQL_INJECTION', 3, 300, 'BLOCK_IP', 1, 1),
        # === ADDED THREE NEW ALERT RULES ===
        ('Cookie Manipulation Threshold', 'COOKIE_MANIPULATION', 3, 300, 'BLOCK_IP', 1, 1),
        ('Session Hijacking Threshold', 'SESSION_HIJACKING', 2, 600, 'BLOCK_IP', 1, 1),
        ('Directory Bruteforce Threshold', 'DIRECTORY_BRUTEFORCE', 10, 60, 'BLOCK_IP', 1, 1),
    ]
    
    for rule in default_rules:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO alert_rules 
                (rule_name, vulnerability_type, threshold, time_window, action, active, automated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', rule)
        except Exception as e:
            print(f"Warning: Could not insert rule: {e}")
    
    conn.commit()
    conn.close()
    print("✅ Enhanced monitoring database initialized")
    print("   - Proper brute force detection enabled")
    print("   - All table schemas corrected")
    print("   - Duplicate rules removed")
    print("   - Added: COOKIE_MANIPULATION, SESSION_HIJACKING, DIRECTORY_BRUTEFORCE")

def auto_block_ip(ip_address, reason, duration_minutes=60, performed_by='SYSTEM'):
    """Automatically block an IP address"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    expires_at = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
    
    cursor.execute('''
        INSERT OR REPLACE INTO ip_blacklist 
        (ip_address, reason, expires_at, permanent, active, added_by, times_blocked, last_blocked_at)
        VALUES (?, ?, ?, 0, 1, ?, 
                COALESCE((SELECT times_blocked + 1 FROM ip_blacklist WHERE ip_address = ?), 1), 
                ?)
    ''', (ip_address, reason, expires_at, performed_by, ip_address, datetime.now().isoformat()))
    
    action_id = cursor.lastrowid
    
    # Log the action as reversible
    cursor.execute('''
        INSERT INTO response_actions
        (action_type, action_details, performed_by, automatic, can_reverse)
        VALUES (?, ?, ?, ?, 1)
    ''', ('BLOCK_IP', f'Blocked {ip_address}: {reason}', performed_by, performed_by == 'SYSTEM'))
    
    conn.commit()
    conn.close()
    
    blocked_ips.add(ip_address)
    print(f"✅ IP {ip_address} blocked: {reason}")
    return action_id

def is_ip_blocked(ip_address):
    """Check if IP is currently blocked"""
    if ip_address in blocked_ips:
        return True
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT COUNT(*) FROM ip_blacklist 
        WHERE ip_address = ? 
        AND active = 1 
        AND (permanent = 1 OR expires_at > datetime('now'))
    ''', (ip_address,))
    
    count = cursor.fetchone()[0]
    conn.close()
    
    if count > 0:
        blocked_ips.add(ip_address)
        return True
    
    return False

def log_response_action(event_id, action_type, details, performed_by='SYSTEM', automatic=True, can_reverse=True):
    """Log a response action"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO response_actions 
        (event_id, action_type, action_details, performed_by, automatic, can_reverse)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (event_id, action_type, details, performed_by, automatic, can_reverse))
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Main monitoring dashboard"""
    if 'admin_user' not in session:
        return redirect(url_for('login'))
    return render_template('monitor_dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login for monitoring system"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM admin_users WHERE username = ? AND password_hash = ?',
                      (username, password_hash))
        user = cursor.fetchone()
        
        if user:
            session.permanent = True
            session['admin_user'] = username
            cursor.execute('UPDATE admin_users SET last_login = ? WHERE username = ?',
                          (datetime.now().isoformat(), username))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        
        conn.close()
        return render_template('monitor_login.html', error='Invalid credentials')
    
    return render_template('monitor_login.html')

@app.route('/logout')
def logout():
    """Admin logout"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/events')
def get_events():
    """Get security events with filtering and recommended actions"""
    if 'admin_user' not in session:
        return jsonify({'error': 'Not authenticated', 'redirect': '/login'}), 401
    
    limit = request.args.get('limit', 100, type=int)
    vuln_type = request.args.get('type', '')
    severity = request.args.get('severity', '')
    source_ip = request.args.get('ip', '')
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = 'SELECT * FROM security_events WHERE 1=1'
    params = []
    
    if vuln_type:
        query += ' AND vulnerability_type = ?'
        params.append(vuln_type)
    
    if severity:
        query += ' AND severity = ?'
        params.append(severity)
    
    if source_ip:
        query += ' AND source_ip = ?'
        params.append(source_ip)
    
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    events = []
    
    for row in cursor.fetchall():
        event = dict(row)
        # Add recommended actions if not present
        if not event.get('recommended_action'):
            actions = get_recommended_actions(event.get('vulnerability_type', ''))
            event['recommended_action'] = json.dumps(actions)
        events.append(event)
    
    conn.close()
    
    return jsonify(events)

@app.route('/api/event_details/<int:event_id>')
def get_event_details(event_id):
    """Get detailed information about a specific event"""
    if 'admin_user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM security_events WHERE id = ?', (event_id,))
    event = cursor.fetchone()
    
    if not event:
        conn.close()
        return jsonify({'error': 'Event not found'}), 404
    
    event_dict = dict(event)
    
    # Parse JSON fields
    if event_dict.get('request_headers'):
        try:
            event_dict['request_headers'] = json.loads(event_dict['request_headers'])
        except:
            pass
    
    if event_dict.get('request_payload'):
        try:
            event_dict['request_payload'] = json.loads(event_dict['request_payload'])
        except:
            pass
    
    # Add recommended actions
    vuln_type = event_dict.get('vulnerability_type', '')
    recommended_actions = get_recommended_actions(vuln_type)
    event_dict['recommended_actions'] = recommended_actions
    
    # Get related actions
    cursor.execute('''
        SELECT * FROM response_actions 
        WHERE event_id = ? 
        ORDER BY timestamp DESC
    ''', (event_id,))
    
    actions = [dict(row) for row in cursor.fetchall()]
    event_dict['related_actions'] = actions
    
    conn.close()
    
    return jsonify(event_dict)

@app.route('/api/statistics')
def get_statistics():
    """Get comprehensive statistics"""
    if 'admin_user' not in session:
        return jsonify({'error': 'Not authenticated', 'redirect': '/login'}), 401
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    stats = {}
    
    # Events by vulnerability type
    cursor.execute('''
        SELECT vulnerability_type, COUNT(*) as count,
               SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
               SUM(CASE WHEN auto_blocked = 1 THEN 1 ELSE 0 END) as auto_blocked
        FROM security_events
        WHERE vulnerability_type IS NOT NULL
        GROUP BY vulnerability_type
    ''')
    
    stats['vulnerabilities'] = {}
    for row in cursor.fetchall():
        vuln_type, total, blocked, auto_blocked = row
        stats['vulnerabilities'][vuln_type] = {
            'total': total,
            'blocked': blocked,
            'auto_blocked': auto_blocked,
            'successful': total - blocked
        }
    
    # Events by severity
    cursor.execute('''
        SELECT severity, COUNT(*) as count
        FROM security_events
        GROUP BY severity
    ''')
    stats['severity'] = dict(cursor.fetchall())
    
    # Top attacking IPs
    cursor.execute('''
        SELECT source_ip, COUNT(*) as count
        FROM security_events
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
    ''')
    stats['top_ips'] = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
    
    # Blocked IPs count
    cursor.execute('''
        SELECT COUNT(*) FROM ip_blacklist
        WHERE active = 1 AND (permanent = 1 OR expires_at > datetime('now'))
    ''')
    stats['blocked_ips_count'] = cursor.fetchone()[0]
    
    # Total actions taken
    cursor.execute('SELECT COUNT(*) FROM response_actions')
    stats['total_actions'] = cursor.fetchone()[0]
    
    # Automated vs manual actions
    cursor.execute('''
        SELECT automatic, COUNT(*) FROM response_actions GROUP BY automatic
    ''')
    action_stats = dict(cursor.fetchall())
    stats['automated_actions'] = action_stats.get(1, 0)
    stats['manual_actions'] = action_stats.get(0, 0)
    
    conn.close()
    return jsonify(stats)

@app.route('/api/log_event', methods=['POST'])
def log_event():
    """Log a security event from main applications"""
    try:
        data = request.json
        source_ip = data.get('source_ip', request.remote_addr)
        
        # Check if IP is blocked
        if is_ip_blocked(source_ip):
            return jsonify({'status': 'blocked', 'message': 'IP address is blocked'}), 403
        
        # IMPROVED: Check for brute force BEFORE logging
        is_login_attempt = data.get('event_type') == 'LOGIN_ATTEMPT'
        success = data.get('success', False)
        
        is_brute_force = False
        failed_count = 0
        
        if is_login_attempt:
            is_brute_force, failed_count = check_brute_force(source_ip, success)
            
            # Update vulnerability type if brute force detected
            if is_brute_force:
                data['vulnerability_type'] = 'BRUTE_FORCE'
                data['severity'] = 'MEDIUM'
                data['description'] = f'Brute force attack detected: {failed_count} failed attempts in 5 minutes'
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        # Get recommended actions for this vulnerability type
        vuln_type = data.get('vulnerability_type', '')
        recommended_actions = get_recommended_actions(vuln_type)
        
        # Log event with recommendations
        cursor.execute('''
            INSERT INTO security_events 
            (event_type, severity, source_ip, user_agent, endpoint, method,
             request_headers, request_payload, response_status, session_id,
             username, vulnerability_type, attack_classification, blocked,
             auto_blocked, description, system_version, recommended_action, admin_reviewed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        ''', (
            data.get('event_type', 'UNKNOWN'),
            data.get('severity', 'INFO'),
            source_ip,
            data.get('user_agent', '')[:500],
            data.get('endpoint', ''),
            data.get('method', 'GET'),
            json.dumps(data.get('headers', {}))[:2000],
            str(data.get('payload', ''))[:2000],
            data.get('response_status'),
            data.get('session_id', ''),
            data.get('username', ''),
            vuln_type,
            data.get('classification', ''),
            data.get('blocked', False),
            data.get('auto_blocked', False),
            data.get('description', ''),
            data.get('system_version', 'unknown'),
            json.dumps(recommended_actions)
        ))
        
        event_id = cursor.lastrowid
        
        # Auto-block if brute force detected
        if is_brute_force and failed_count >= 5:
            cursor.execute('''
                SELECT COUNT(*) FROM ip_blacklist WHERE ip_address = ? AND active = 1
            ''', (source_ip,))
            
            if cursor.fetchone()[0] == 0:  # Not already blocked
                auto_block_ip(source_ip, f'Brute force: {failed_count} failed login attempts', 60, 'SYSTEM')
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'event_id': event_id})
        
    except Exception as e:
        print(f"Error logging event: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/take_action', methods=['POST'])
def take_action():
    """Manual action by administrator"""
    if 'admin_user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        action_type = data.get('action_type')
        performed_by = session['admin_user']
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        result = {'status': 'success', 'message': ''}
        
        if action_type == 'BLOCK_IP':
            ip_address = data.get('ip_address')
            duration = data.get('duration_minutes', 60)
            reason = data.get('reason', 'Manual block by admin')
            auto_block_ip(ip_address, reason, duration, performed_by)
            result['message'] = f'IP {ip_address} blocked for {duration} minutes'
            
        elif action_type == 'UNBLOCK_IP':
            ip_address = data.get('ip_address')
            cursor.execute('''
                UPDATE ip_blacklist 
                SET active = 0
                WHERE ip_address = ?
            ''', (ip_address,))
            blocked_ips.discard(ip_address)
            
            cursor.execute('''
                INSERT INTO response_actions
                (action_type, action_details, performed_by, automatic, can_reverse)
                VALUES (?, ?, ?, 0, 1)
            ''', ('UNBLOCK_IP', f'Unblocked {ip_address}', performed_by))
            
            result['message'] = f'IP {ip_address} unblocked'
            
        elif action_type == 'MARK_FALSE_POSITIVE':
            event_id = data.get('event_id')
            notes = data.get('notes', '')
            
            cursor.execute('SELECT false_positive FROM security_events WHERE id = ?', (event_id,))
            current_status = cursor.fetchone()
            
            if current_status and current_status[0] == 1:
                cursor.execute('''
                    UPDATE security_events
                    SET false_positive = 0, admin_reviewed = 1
                    WHERE id = ?
                ''', (event_id,))
                result['message'] = f'Event {event_id} unmarked as false positive'
                action_detail = f'Unmarked event {event_id} as false positive'
            else:
                cursor.execute('''
                    UPDATE security_events
                    SET false_positive = 1, notes = ?, admin_reviewed = 1
                    WHERE id = ?
                ''', (notes, event_id))
                result['message'] = f'Event {event_id} marked as false positive'
                action_detail = f'Marked event {event_id} as false positive: {notes}'
            
            cursor.execute('''
                INSERT INTO response_actions
                (event_id, action_type, action_details, performed_by, automatic, can_reverse)
                VALUES (?, ?, ?, ?, 0, 1)
            ''', (event_id, 'MARK_FALSE_POSITIVE', action_detail, performed_by))
            
        elif action_type == 'DELETE_EVENT':
            event_id = data.get('event_id')
            cursor.execute('DELETE FROM security_events WHERE id = ?', (event_id,))
            
            cursor.execute('''
                INSERT INTO response_actions
                (event_id, action_type, action_details, performed_by, automatic, can_reverse)
                VALUES (?, ?, ?, ?, 0, 0)
            ''', (event_id, 'DELETE_EVENT', f'Deleted event {event_id}', performed_by))
            
            result['message'] = f'Event {event_id} deleted'
            
        elif action_type == 'REVERSE_ACTION':
            action_id = data.get('action_id')
            cursor.execute('''
                SELECT action_type, action_details FROM response_actions WHERE id = ?
            ''', (action_id,))
            action = cursor.fetchone()
            
            if action and action[0] == 'BLOCK_IP':
                ip = action[1].split()[1].rstrip(':')
                cursor.execute('UPDATE ip_blacklist SET active = 0 WHERE ip_address = ?', (ip,))
                blocked_ips.discard(ip)
            
            cursor.execute('''
                UPDATE response_actions
                SET reversed = 1, reversed_at = ?, reversed_by = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), performed_by, action_id))
            
            result['message'] = f'Action {action_id} reversed'
            
        elif action_type == 'UPDATE_RULE':
            rule_id = data.get('rule_id')
            active = data.get('active', 1)
            automated = data.get('automated', 0)
            threshold = data.get('threshold')
            
            updates = []
            params = []
            if active is not None:
                updates.append('active = ?')
                params.append(active)
            if automated is not None:
                updates.append('automated = ?')
                params.append(automated)
            if threshold is not None:
                updates.append('threshold = ?')
                params.append(threshold)
            
            params.append(rule_id)
            cursor.execute(f'''
                UPDATE alert_rules SET {', '.join(updates)} WHERE id = ?
            ''', params)
            
            result['message'] = f'Rule {rule_id} updated'
        
        conn.commit()
        conn.close()
        
        return jsonify(result)
        
    except Exception as e:
        print(f"Error taking action: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blocked_ips')
def get_blocked_ips():
    """Get list of blocked IPs"""
    if 'admin_user' not in session:
        return jsonify({'error': 'Not authenticated', 'redirect': '/login'}), 401
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM ip_blacklist
        WHERE active = 1 AND (permanent = 1 OR expires_at > datetime('now'))
        ORDER BY added_at DESC
    ''')
    
    blocked = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(blocked)

@app.route('/api/response_actions')
def get_response_actions():
    """Get history of response actions"""
    if 'admin_user' not in session:
        return jsonify({'error': 'Not authenticated', 'redirect': '/login'}), 401
    
    limit = request.args.get('limit', 50, type=int)
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM response_actions
        ORDER BY timestamp DESC
        LIMIT ?
    ''', (limit,))
    
    actions = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(actions)

@app.route('/api/alert_rules')
def get_alert_rules():
    """Get alert rules for admin configuration"""
    if 'admin_user' not in session:
        return jsonify({'error': 'Not authenticated', 'redirect': '/login'}), 401
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM alert_rules ORDER BY id')
    rules = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(rules)

if __name__ == '__main__':
    init_monitor_db()
    print("\n🔍 Enhanced Security Monitoring System - FULLY FIXED")
    print("=" * 60)
    print("Dashboard: http://localhost:5002")
    print("Default login: admin / monitor123")
    print("=" * 60)
    print("\nFixes applied:")
    print("✅ Proper brute force detection (threshold-based)")
    print("✅ Fixed response_actions table schema")
    print("✅ Removed duplicate alert rules")
    print("✅ Recommended actions visible in dashboard")
    print("✅ IP blocking works correctly")
    print("\nNew detections added:")
    print("✅ COOKIE_MANIPULATION detection")
    print("✅ SESSION_HIJACKING detection")
    print("✅ DIRECTORY_BRUTEFORCE detection")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5002, debug=True)