"""
Enhanced Security Monitoring System for SCADA - COMPLETE VERSION
Includes detailed logging, classification, and admin action capabilities
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

# Rate limiting tracking
rate_limit_tracker = defaultdict(list)
blocked_ips = set()

def init_monitor_db():
    """Initialize comprehensive monitoring database with admin actions"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    # Main security events table with IP address
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
            admin_reviewed BOOLEAN DEFAULT 0
        )
    ''')
    
    # IP blacklist/whitelist with more details
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
    
    # Response actions log with reversal capability
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
            automated BOOLEAN DEFAULT 0
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
    
    # Insert default alert rules with automation
    default_rules = [
        ('Failed Login Threshold', 'BRUTE_FORCE', 5, 300, 'BLOCK_IP', 1, 1),
        ('CSRF Attack Threshold', 'CSRF', 3, 600, 'ALERT_ADMIN', 1, 0),
        ('Path Traversal Threshold', 'PATH_TRAVERSAL', 3, 300, 'BLOCK_IP', 1, 1),
        ('SSRF Attempt Threshold', 'SSRF', 2, 600, 'BLOCK_IP', 1, 1),
        ('SQLi Attempt Threshold', 'SQL_INJECTION', 3, 300, 'BLOCK_IP', 1, 1),
    ]
    
    for rule in default_rules:
        try:
            cursor.execute('''
                INSERT INTO alert_rules 
                (rule_name, vulnerability_type, threshold, time_window, action, active, automated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', rule)
        except:
            pass
    
    conn.commit()
    conn.close()
    print("✅ Enhanced monitoring database initialized with admin actions")

def auto_block_ip(ip_address, reason, duration_minutes=60, performed_by='SYSTEM'):
    """Automatically block an IP address"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    expires_at = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
    
    cursor.execute('''
        INSERT OR REPLACE INTO ip_blacklist 
        (ip_address, reason, expires_at, permanent, active, added_by, times_blocked, last_blocked_at)
        VALUES (?, ?, ?, 0, 1, ?, COALESCE((SELECT times_blocked + 1 FROM ip_blacklist WHERE ip_address = ?), 1), ?)
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
    events = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(events)

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
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        # Log main event with IP address
        cursor.execute('''
            INSERT INTO security_events 
            (event_type, severity, source_ip, user_agent, endpoint, method,
             request_headers, request_payload, response_status, session_id,
             username, vulnerability_type, attack_classification, blocked,
             auto_blocked, description, system_version, recommended_action)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            data.get('vulnerability_type', ''),
            data.get('classification', ''),
            data.get('blocked', False),
            data.get('auto_blocked', False),
            data.get('description', ''),
            data.get('system_version', 'unknown'),
            data.get('recommended_action', '')
        ))
        
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'event_id': event_id})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/take_action', methods=['POST'])
def take_action():
    """Manual action by administrator - PRIMARY ACTION ENDPOINT"""
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
            cursor.execute('''
                UPDATE security_events
                SET false_positive = 1, notes = ?, admin_reviewed = 1
                WHERE id = ?
            ''', (notes, event_id))
            
            cursor.execute('''
                INSERT INTO response_actions
                (event_id, action_type, action_details, performed_by, automatic, can_reverse)
                VALUES (?, ?, ?, ?, 0, 1)
            ''', (event_id, 'MARK_FALSE_POSITIVE', notes, performed_by))
            
            result['message'] = f'Event {event_id} marked as false positive'
            
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
                # Extract IP from action details
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
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blocked_ips')
def get_blocked_ips():
    """Get list of blocked IPs with action capabilities"""
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
    """Get history of response actions with reversal info"""
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
    print("\n🔍 Enhanced Security Monitoring System with Admin Actions")
    print("=" * 60)
    print("Dashboard: http://localhost:5002")
    print("Default login: admin / monitor123")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5002, debug=True)