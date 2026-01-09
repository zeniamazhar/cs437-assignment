"""
Enhanced Security Monitoring System - SIMPLIFIED VERSION
This version TRUSTS the vulnerability data sent by the SCADA apps
instead of trying to re-detect everything.
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import sqlite3
from datetime import datetime, timedelta
import json
import hashlib
import os
from collections import defaultdict
import time
import re

app = Flask(__name__)
app.config['MONITOR_DB'] = '/app/data/security_monitor.db'
app.config['SECRET_KEY'] = 'monitoring_secret_key_change_in_production'
app.config['SESSION_COOKIE_NAME'] = 'monitoring_session'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Rate limiting tracking
blocked_ips = set()

# RECOMMENDED ACTIONS DATABASE
RECOMMENDED_ACTIONS = {
    'SQL_INJECTION': {
        'severity': 'CRITICAL',
        'immediate': 'Block IP immediately after 3 attempts',
        'short_term': 'Review all SQL queries for parameterization',
        'long_term': 'Implement WAF with SQLi signatures, conduct code audit',
        'detection': 'Monitor for SQL keywords in input fields',
        'prevention': 'Use parameterized queries exclusively',
        'reversible': True,
        'automated': True
    },
    'CSRF': {
        'severity': 'HIGH',
        'immediate': 'Alert administrator, monitor for follow-up attacks',
        'short_term': 'Implement CSRF tokens on all state-changing operations',
        'long_term': 'Enable SameSite cookies, implement double-submit pattern',
        'detection': 'Check for missing CSRF tokens in POST requests',
        'prevention': 'Generate and validate CSRF tokens for all forms',
        'reversible': True,
        'automated': False
    },
    'PATH_TRAVERSAL': {
        'severity': 'HIGH',
        'immediate': 'Block IP after 3 attempts, quarantine affected files',
        'short_term': 'Sanitize all file path inputs',
        'long_term': 'Implement allowlist-based file access, use chroot',
        'detection': 'Monitor for ../ and absolute path patterns',
        'prevention': 'Validate paths against base directory, use path.join() securely',
        'reversible': True,
        'automated': True
    },
    'SSRF': {
        'severity': 'HIGH',
        'immediate': 'Block IP, review internal network access',
        'short_term': 'Implement URL allowlist for external fetches',
        'long_term': 'Network segmentation, disable URL fetching where unnecessary',
        'detection': 'Monitor for internal IP ranges in URL parameters',
        'prevention': 'Validate URLs against allowlist, block private IP ranges',
        'reversible': True,
        'automated': True
    },
    'BRUTE_FORCE': {
        'severity': 'MEDIUM',
        'immediate': 'Implement rate limiting after 5 failed attempts',
        'short_term': 'Add CAPTCHA, implement account lockout',
        'long_term': 'Multi-factor authentication, adaptive authentication',
        'detection': 'Track failed login attempts per IP and username',
        'prevention': 'Rate limiting, progressive delays, CAPTCHA',
        'reversible': True,
        'automated': True
    },
    'DIRECTORY_BRUTEFORCE': {
        'severity': 'MEDIUM',
        'immediate': 'Block IP after 10 404s in 1 minute',
        'short_term': 'Implement rate limiting on file access',
        'long_term': 'Web Application Firewall, hide directory structure',
        'detection': 'Monitor for sequential 404 errors from same IP',
        'prevention': 'Rate limiting, disable directory listing',
        'reversible': True,
        'automated': True
    },
    'COOKIE_MANIPULATION': {
        'severity': 'HIGH',
        'immediate': 'Invalidate session, block IP temporarily',
        'short_term': 'Implement secure cookie attributes (HttpOnly, Secure, SameSite)',
        'long_term': 'Use signed cookies, implement session fingerprinting',
        'detection': 'Monitor for modified session cookies, invalid signatures',
        'prevention': 'Sign cookies, validate session integrity',
        'reversible': True,
        'automated': True
    },
    'SESSION_HIJACKING': {
        'severity': 'CRITICAL',
        'immediate': 'Terminate session, force re-authentication, block IP',
        'short_term': 'Implement session fingerprinting (IP, User-Agent)',
        'long_term': 'Mutual TLS, hardware token authentication',
        'detection': 'Monitor for session use from multiple IPs/browsers',
        'prevention': 'Session binding, short session timeouts, re-auth for sensitive ops',
        'reversible': True,
        'automated': True
    },
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
        'prevention': 'Follow secure coding practices',
        'reversible': True,
        'automated': False
    }

def init_monitor_db():
    """Initialize comprehensive monitoring database"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    # Enhanced security events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            user_agent TEXT,
            endpoint TEXT NOT NULL,
            method TEXT NOT NULL,
            request_headers TEXT,
            request_payload TEXT,
            response_status INTEGER,
            session_id TEXT,
            username TEXT,
            vulnerability_type TEXT NOT NULL,
            attack_classification TEXT,
            blocked BOOLEAN DEFAULT 0,
            auto_blocked BOOLEAN DEFAULT 0,
            description TEXT,
            system_version TEXT,
            recommended_action TEXT,
            action_taken TEXT,
            action_timestamp DATETIME,
            false_positive BOOLEAN DEFAULT 0,
            notes TEXT,
            admin_reviewed BOOLEAN DEFAULT 0,
            attack_metadata TEXT,
            attack_pattern TEXT,
            cookies TEXT,
            referer TEXT
        )
    ''')
    
    # IP blacklist
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
    
    # Response actions log
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
            reversal_method TEXT,
            FOREIGN KEY (event_id) REFERENCES security_events (id)
        )
    ''')
    
    # Admin users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    
    # Create default admin user
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
    
    conn.commit()
    conn.close()
    print("✅ Simplified monitoring database initialized")

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
    
    cursor.execute('''
        INSERT INTO response_actions
        (action_type, action_details, performed_by, automatic, can_reverse, reversal_method)
        VALUES (?, ?, ?, ?, 1, ?)
    ''', ('BLOCK_IP', f'Blocked {ip_address}: {reason}', performed_by, performed_by == 'SYSTEM',
          f'UPDATE ip_blacklist SET active = 0 WHERE ip_address = "{ip_address}"'))
    
    conn.commit()
    conn.close()
    
    blocked_ips.add(ip_address)
    print(f"✅ IP {ip_address} blocked: {reason}")

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
    """Get security events with filtering"""
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
    for field in ['request_headers', 'request_payload', 'attack_metadata', 'cookies']:
        if event_dict.get(field):
            try:
                event_dict[field] = json.loads(event_dict[field])
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
    """
    SIMPLIFIED: Log security event - TRUSTS what the SCADA app sends
    """
    try:
        data = request.json
        
        print(f"\n=== RECEIVED EVENT ===")
        print(f"Event Type: {data.get('event_type')}")
        print(f"Vulnerability Type: {data.get('vulnerability_type')}")
        print(f"Severity: {data.get('severity')}")
        print(f"Description: {data.get('description')}")
        print(f"System Version: {data.get('system_version')}")
        print(f"Source IP: {data.get('source_ip')}")
        print("===================\n")
        
        source_ip = data.get('source_ip', request.remote_addr)
        
        # Check if IP is blocked
        if is_ip_blocked(source_ip):
            return jsonify({'status': 'blocked', 'message': 'IP address is blocked'}), 403
        
        # Get all fields with defaults
        endpoint = data.get('endpoint', '')
        method = data.get('method', 'GET')
        status_code = data.get('response_status', 200)
        session_id = data.get('session_id', '')
        user_agent = data.get('user_agent', '')
        cookies = data.get('cookies', '')
        request_payload = data.get('payload', '')
        vuln_type = data.get('vulnerability_type', 'UNKNOWN')
        severity = data.get('severity', 'INFO')
        description = data.get('description', '')
        system_version = data.get('system_version', 'unknown')
        
        # Parse cookies if string
        if isinstance(cookies, str) and cookies:
            try:
                cookies = json.loads(cookies)
            except:
                pass
        elif not cookies:
            cookies = {}
        
        # Log event to database
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        recommended_actions = get_recommended_actions(vuln_type)
        
        # Build attack metadata
        attack_metadata = {
            'source_ip': source_ip,
            'user_agent': user_agent,
            'referer': data.get('referer', ''),
            'cookies': str(cookies) if cookies else '',
            'session_id': session_id,
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'timestamp': datetime.now().isoformat()
        }
        
        # Insert event
        cursor.execute('''
            INSERT INTO security_events
            (event_type, severity, source_ip, user_agent, endpoint, method,
             request_headers, request_payload, response_status, session_id,
             username, vulnerability_type, attack_classification, blocked,
             auto_blocked, description, system_version, recommended_action,
             admin_reviewed, attack_metadata, attack_pattern, cookies, referer)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
        ''', (
            data.get('event_type', 'UNKNOWN'),
            severity,
            source_ip,
            user_agent[:500] if user_agent else '',
            endpoint,
            method,
            json.dumps(data.get('headers', {}))[:2000],
            str(request_payload)[:2000] if request_payload else '',
            status_code,
            session_id,
            data.get('username', ''),
            vuln_type,
            data.get('attack_classification', ''),
            data.get('blocked', False),
            data.get('auto_blocked', False),
            description,
            system_version,
            json.dumps(recommended_actions),
            json.dumps(attack_metadata),
            data.get('attack_pattern', ''),
            str(cookies) if cookies else None,
            data.get('referer', '')
        ))
        
        event_id = cursor.lastrowid
        
        print(f"✅ Event logged with ID: {event_id}")
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'event_id': event_id})
        
    except Exception as e:
        print(f"❌ Error logging event: {e}")
        import traceback
        traceback.print_exc()
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
            cursor.execute('UPDATE ip_blacklist SET active = 0 WHERE ip_address = ?', (ip_address,))
            blocked_ips.discard(ip_address)
            result['message'] = f'IP {ip_address} unblocked'
            
        elif action_type == 'MARK_FALSE_POSITIVE':
            event_id = data.get('event_id')
            notes = data.get('notes', '')
            
            cursor.execute('SELECT false_positive FROM security_events WHERE id = ?', (event_id,))
            current_state = cursor.fetchone()
            
            if current_state and current_state[0] == 1:
                cursor.execute('UPDATE security_events SET false_positive = 0, notes = ?, admin_reviewed = 1 WHERE id = ?',
                              (notes, event_id))
                result['message'] = f'Event {event_id} unmarked as false positive'
            else:
                cursor.execute('UPDATE security_events SET false_positive = 1, notes = ?, admin_reviewed = 1 WHERE id = ?',
                              (notes, event_id))
                result['message'] = f'Event {event_id} marked as false positive'
        
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
    
    cursor.execute('SELECT * FROM response_actions ORDER BY timestamp DESC LIMIT ?', (limit,))
    
    actions = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(actions)

if __name__ == '__main__':
    init_monitor_db()
    print("\n🔍 SIMPLIFIED Security Monitoring System")
    print("=" * 60)
    print("Dashboard: http://localhost:5002")
    print("Default login: admin / monitor123")
    print("=" * 60)
    print("\nThis version TRUSTS what the SCADA apps send")
    print("✅ No complex re-detection logic")
    print("✅ Logs everything the SCADA app reports")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5002, debug=True)