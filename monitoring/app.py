
"""
Enhanced Security Monitoring System for SCADA Alarm Management Console
Monitors all attack vectors with VirusTotal integration and actionable responses
"""

from flask import Flask, render_template, jsonify, request, redirect, url_for
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

# VirusTotal API Configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'YOUR_API_KEY_HERE')
VIRUSTOTAL_ENABLED = VIRUSTOTAL_API_KEY != 'YOUR_API_KEY_HERE'

# Rate limiting tracking
rate_limit_tracker = defaultdict(list)
blocked_ips = set()

def init_monitor_db():
    """Initialize comprehensive monitoring database"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    # Main security events table with extensive metadata
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
            notes TEXT
        )
    ''')
    
    # Login attempts tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT,
            success BOOLEAN NOT NULL,
            user_agent TEXT,
            attack_type TEXT,
            blocked BOOLEAN DEFAULT 0
        )
    ''')
    
    # File upload tracking with VirusTotal integration
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
    
    # Path traversal attempts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS path_traversal_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            requested_path TEXT NOT NULL,
            resolved_path TEXT,
            blocked BOOLEAN DEFAULT 0,
            severity TEXT
        )
    ''')
    
    # CSRF attempts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS csrf_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            referer TEXT,
            origin TEXT,
            csrf_token TEXT,
            blocked BOOLEAN DEFAULT 0,
            session_valid BOOLEAN
        )
    ''')
    
    # SSRF attempts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssrf_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            requested_url TEXT NOT NULL,
            url_type TEXT,
            blocked BOOLEAN DEFAULT 0,
            response_received BOOLEAN
        )
    ''')
    
    # SQL Injection attempts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sqli_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            parameter TEXT,
            payload TEXT NOT NULL,
            encoding_used TEXT,
            blocked BOOLEAN DEFAULT 0,
            sql_error TEXT
        )
    ''')
    
    # Session hijacking/manipulation attempts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS session_attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            session_id TEXT NOT NULL,
            attack_type TEXT,
            old_value TEXT,
            new_value TEXT,
            blocked BOOLEAN DEFAULT 0
        )
    ''')
    
    # IP blacklist/whitelist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME,
            permanent BOOLEAN DEFAULT 0,
            active BOOLEAN DEFAULT 1
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
            active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Create indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_vuln_type ON security_events(vulnerability_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(source_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_login_timestamp ON login_attempts(timestamp)')
    
    # Insert default alert rules
    default_rules = [
        ('Failed Login Threshold', 'BRUTE_FORCE', 5, 300, 'BLOCK_IP', 1),
        ('CSRF Attack Threshold', 'CSRF', 3, 600, 'ALERT_ADMIN', 1),
        ('Path Traversal Threshold', 'PATH_TRAVERSAL', 3, 300, 'BLOCK_IP', 1),
        ('SSRF Attempt Threshold', 'SSRF', 2, 600, 'BLOCK_IP', 1),
        ('SQLi Attempt Threshold', 'SQL_INJECTION', 3, 300, 'BLOCK_IP', 1),
    ]
    
    for rule in default_rules:
        cursor.execute('''
            INSERT OR IGNORE INTO alert_rules 
            (rule_name, vulnerability_type, threshold, time_window, action, active)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', rule)
    
    conn.commit()
    conn.close()
    print("✅ Enhanced monitoring database initialized")

def scan_file_virustotal(file_hash, filename):
    """Scan file hash with VirusTotal API"""
    if not VIRUSTOTAL_ENABLED:
        return None
    
    try:
        # Check if file already scanned
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'scan_id': file_hash,
                'positives': stats.get('malicious', 0),
                'total': sum(stats.values()),
                'malicious': stats.get('malicious', 0) > 0
            }
        elif response.status_code == 404:
            # File not in database, upload it
            # Note: In production, you'd upload the actual file here
            return {
                'scan_id': None,
                'positives': 0,
                'total': 0,
                'malicious': False,
                'note': 'File not in VirusTotal database'
            }
    except Exception as e:
        print(f"VirusTotal scan error: {e}")
        return None

def check_rate_limit(ip_address, threshold=10, window=60):
    """Check if IP is rate limited"""
    now = time.time()
    
    # Clean old entries
    rate_limit_tracker[ip_address] = [
        t for t in rate_limit_tracker[ip_address] 
        if now - t < window
    ]
    
    # Add current request
    rate_limit_tracker[ip_address].append(now)
    
    # Check threshold
    if len(rate_limit_tracker[ip_address]) > threshold:
        return True
    
    return False

def auto_block_ip(ip_address, reason, duration_minutes=60):
    """Automatically block an IP address"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    expires_at = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
    
    cursor.execute('''
        INSERT OR REPLACE INTO ip_blacklist 
        (ip_address, reason, expires_at, permanent, active)
        VALUES (?, ?, ?, 0, 1)
    ''', (ip_address, reason, expires_at))
    
    conn.commit()
    conn.close()
    
    blocked_ips.add(ip_address)
    
    # Log the action
    log_response_action(
        None, 
        'AUTO_BLOCK_IP', 
        f'Automatically blocked {ip_address} for {duration_minutes} minutes: {reason}',
        'SYSTEM',
        True
    )

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

def log_response_action(event_id, action_type, details, performed_by='SYSTEM', automatic=True):
    """Log a response action"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO response_actions 
        (event_id, action_type, action_details, performed_by, automatic)
        VALUES (?, ?, ?, ?, ?)
    ''', (event_id, action_type, details, performed_by, automatic))
    
    conn.commit()
    conn.close()

def check_alert_rules(vulnerability_type, source_ip):
    """Check if alert rules are triggered and take action"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    # Get active rules for this vulnerability type
    cursor.execute('''
        SELECT rule_name, threshold, time_window, action
        FROM alert_rules
        WHERE vulnerability_type = ? AND active = 1
    ''', (vulnerability_type,))
    
    rules = cursor.fetchall()
    
    for rule_name, threshold, time_window, action in rules:
        # Count recent events
        time_limit = (datetime.now() - timedelta(seconds=time_window)).isoformat()
        
        cursor.execute('''
            SELECT COUNT(*) FROM security_events
            WHERE vulnerability_type = ?
            AND source_ip = ?
            AND timestamp > ?
        ''', (vulnerability_type, source_ip, time_limit))
        
        count = cursor.fetchone()[0]
        
        if count >= threshold:
            # Rule triggered
            if action == 'BLOCK_IP':
                auto_block_ip(source_ip, f'{rule_name} threshold exceeded: {count} events in {time_window}s')
            elif action == 'ALERT_ADMIN':
                # In production, send email/SMS/Slack notification
                log_response_action(
                    None,
                    'ALERT_ADMIN',
                    f'Alert: {rule_name} triggered for IP {source_ip}',
                    'SYSTEM',
                    True
                )
    
    conn.close()

@app.route('/')
def dashboard():
    """Main monitoring dashboard"""
    return render_template('monitor_dashboard.html')

@app.route('/vulnerability/<vuln_type>')
def vulnerability_detail(vuln_type):
    """Detailed view for specific vulnerability type"""
    return render_template('vulnerability_detail.html', vulnerability_type=vuln_type)

@app.route('/api/events')
def get_events():
    """Get security events with filtering"""
    limit = request.args.get('limit', 100, type=int)
    vuln_type = request.args.get('type', '')
    severity = request.args.get('severity', '')
    source_ip = request.args.get('ip', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
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
    
    if start_date:
        query += ' AND timestamp >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND timestamp <= ?'
        params.append(end_date)
    
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    
    events = []
    for row in cursor.fetchall():
        events.append(dict(row))
    
    conn.close()
    return jsonify(events)

@app.route('/api/statistics')
def get_statistics():
    """Get comprehensive statistics"""
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
    
    # Login attempts
    cursor.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed,
            SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
        FROM login_attempts
        WHERE timestamp > datetime('now', '-24 hours')
    ''')
    
    row = cursor.fetchone()
    stats['login_attempts'] = {
        'total': row[0],
        'failed': row[1],
        'blocked': row[2]
    }
    
    # File uploads
    cursor.execute('''
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN malicious = 1 THEN 1 ELSE 0 END) as malicious,
            SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
        FROM file_uploads
        WHERE timestamp > datetime('now', '-24 hours')
    ''')
    
    row = cursor.fetchone()
    stats['file_uploads'] = {
        'total': row[0] or 0,
        'malicious': row[1] or 0,
        'blocked': row[2] or 0
    }
    
    # Recent timeline (last 24 hours by hour)
    cursor.execute('''
        SELECT strftime('%H:00', timestamp) as hour, 
               COUNT(*) as count,
               vulnerability_type
        FROM security_events
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour, vulnerability_type
        ORDER BY hour
    ''')
    
    timeline = defaultdict(lambda: defaultdict(int))
    for row in cursor.fetchall():
        hour, count, vuln_type = row
        timeline[hour][vuln_type] = count
    
    stats['timeline'] = [
        {
            'hour': hour,
            'data': dict(vuln_data)
        }
        for hour, vuln_data in sorted(timeline.items())
    ]
    
    # Blocked IPs
    cursor.execute('''
        SELECT COUNT(*) FROM ip_blacklist
        WHERE active = 1 AND (permanent = 1 OR expires_at > datetime('now'))
    ''')
    
    stats['blocked_ips_count'] = cursor.fetchone()[0]
    
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
            return jsonify({
                'status': 'blocked',
                'message': 'IP address is blocked'
            }), 403
        
        # Check rate limiting
        if check_rate_limit(source_ip):
            auto_block_ip(source_ip, 'Rate limit exceeded', 30)
            return jsonify({
                'status': 'blocked',
                'message': 'Rate limit exceeded, IP blocked'
            }), 429
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        # Log main event
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
        
        # Log specific attack types in specialized tables
        vuln_type = data.get('vulnerability_type', '')
        
        if vuln_type == 'BRUTE_FORCE':
            cursor.execute('''
                INSERT INTO login_attempts
                (source_ip, username, password_hash, success, user_agent, attack_type, blocked)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                source_ip,
                data.get('username', ''),
                data.get('password_hash', ''),
                data.get('success', False),
                data.get('user_agent', ''),
                'BRUTE_FORCE',
                data.get('blocked', False)
            ))
        
        elif vuln_type == 'PATH_TRAVERSAL':
            cursor.execute('''
                INSERT INTO path_traversal_attempts
                (source_ip, endpoint, requested_path, resolved_path, blocked, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                source_ip,
                data.get('endpoint', ''),
                data.get('requested_path', ''),
                data.get('resolved_path', ''),
                data.get('blocked', False),
                data.get('severity', 'HIGH')
            ))
        
        elif vuln_type == 'CSRF':
            cursor.execute('''
                INSERT INTO csrf_attempts
                (source_ip, endpoint, referer, origin, csrf_token, blocked, session_valid)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                source_ip,
                data.get('endpoint', ''),
                data.get('referer', ''),
                data.get('origin', ''),
                data.get('csrf_token', ''),
                data.get('blocked', False),
                data.get('session_valid', False)
            ))
        
        elif vuln_type == 'SSRF':
            cursor.execute('''
                INSERT INTO ssrf_attempts
                (source_ip, endpoint, requested_url, url_type, blocked, response_received)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                source_ip,
                data.get('endpoint', ''),
                data.get('requested_url', ''),
                data.get('url_type', ''),
                data.get('blocked', False),
                data.get('response_received', False)
            ))
        
        elif vuln_type == 'SQL_INJECTION':
            cursor.execute('''
                INSERT INTO sqli_attempts
                (source_ip, endpoint, parameter, payload, encoding_used, blocked, sql_error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                source_ip,
                data.get('endpoint', ''),
                data.get('parameter', ''),
                data.get('payload', ''),
                data.get('encoding', 'UTF-8'),
                data.get('blocked', False),
                data.get('sql_error', '')
            ))
        
        conn.commit()
        conn.close()
        
        # Check alert rules
        check_alert_rules(vuln_type, source_ip)
        
        return jsonify({
            'status': 'success',
            'message': 'Event logged',
            'event_id': event_id
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/log_file_upload', methods=['POST'])
def log_file_upload():
    """Log file upload with VirusTotal scanning"""
    try:
        data = request.json
        
        source_ip = data.get('source_ip', request.remote_addr)
        filename = data.get('filename', '')
        file_content = data.get('file_content_b64', '')
        
        # Calculate file hash
        if file_content:
            import base64
            file_bytes = base64.b64decode(file_content)
            file_hash = hashlib.sha256(file_bytes).hexdigest()
        else:
            file_hash = data.get('file_hash', '')
        
        # Scan with VirusTotal
        vt_result = scan_file_virustotal(file_hash, filename)
        
        malicious = False
        blocked = False
        
        if vt_result and vt_result.get('positives', 0) > 0:
            malicious = True
            blocked = True
            auto_block_ip(source_ip, f'Malicious file upload detected: {filename}', 120)
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO file_uploads
            (source_ip, filename, file_size, mime_type, file_hash,
             virustotal_scan_id, virustotal_positives, virustotal_total,
             malicious, blocked, quarantined)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            source_ip,
            filename,
            data.get('file_size', 0),
            data.get('mime_type', ''),
            file_hash,
            vt_result.get('scan_id') if vt_result else None,
            vt_result.get('positives', 0) if vt_result else None,
            vt_result.get('total', 0) if vt_result else None,
            malicious,
            blocked,
            malicious
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success' if not blocked else 'blocked',
            'malicious': malicious,
            'virustotal': vt_result
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/take_action', methods=['POST'])
def take_action():
    """Manual action by administrator"""
    try:
        data = request.json
        
        action_type = data.get('action_type')
        event_id = data.get('event_id')
        details = data.get('details', '')
        performed_by = data.get('performed_by', 'ADMIN')
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        # Execute action
        if action_type == 'BLOCK_IP':
            ip_address = data.get('ip_address')
            duration = data.get('duration_minutes', 60)
            auto_block_ip(ip_address, details, duration)
            
        elif action_type == 'UNBLOCK_IP':
            ip_address = data.get('ip_address')
            cursor.execute('''
                UPDATE ip_blacklist 
                SET active = 0
                WHERE ip_address = ?
            ''', (ip_address,))
            blocked_ips.discard(ip_address)
            
        elif action_type == 'MARK_FALSE_POSITIVE':
            cursor.execute('''
                UPDATE security_events
                SET false_positive = 1, notes = ?
                WHERE id = ?
            ''', (details, event_id))
            
        elif action_type == 'QUARANTINE_FILE':
            file_id = data.get('file_id')
            cursor.execute('''
                UPDATE file_uploads
                SET quarantined = 1
                WHERE id = ?
            ''', (file_id,))
            
        elif action_type == 'DELETE_EVENT':
            cursor.execute('DELETE FROM security_events WHERE id = ?', (event_id,))
        
        # Log the action
        cursor.execute('''
            INSERT INTO response_actions
            (event_id, action_type, action_details, performed_by, automatic)
            VALUES (?, ?, ?, ?, 0)
        ''', (event_id, action_type, details, performed_by))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'status': 'success',
            'message': f'Action {action_type} completed successfully'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/blocked_ips')
def get_blocked_ips():
    """Get list of blocked IPs"""
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

@app.route('/api/login_attempts')
def get_login_attempts():
    """Get login attempts with attack detection"""
    limit = request.args.get('limit', 100, type=int)
    source_ip = request.args.get('ip', '')
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = 'SELECT * FROM login_attempts WHERE 1=1'
    params = []
    
    if source_ip:
        query += ' AND source_ip = ?'
        params.append(source_ip)
    
    query += ' ORDER BY timestamp DESC LIMIT ?'
    params.append(limit)
    
    cursor.execute(query, params)
    
    attempts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(attempts)

@app.route('/api/response_actions')
def get_response_actions():
    """Get history of response actions"""
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

@app.route('/api/export_report')
def export_report():
    """Export comprehensive security report"""
    report_type = request.args.get('type', 'summary')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'report_type': report_type,
        'period': {'start': start_date, 'end': end_date}
    }
    
    # Get all events in period
    query = 'SELECT * FROM security_events WHERE 1=1'
    params = []
    
    if start_date:
        query += ' AND timestamp >= ?'
        params.append(start_date)
    
    if end_date:
        query += ' AND timestamp <= ?'
        params.append(end_date)
    
    cursor.execute(query, params)
    report['events'] = [dict(row) for row in cursor.fetchall()]
    
    # Get statistics
    cursor.execute('''
        SELECT vulnerability_type, COUNT(*) as count
        FROM security_events
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY vulnerability_type
    ''', (start_date or '1970-01-01', end_date or '2099-12-31'))
    
    report['vulnerability_summary'] = dict(cursor.fetchall())
    
    conn.close()
    
    return jsonify(report)

if __name__ == '__main__':
    init_monitor_db()
    print("\n🔍 Enhanced Security Monitoring System")
    print("=" * 60)
    print("Dashboard: http://localhost:5002")
    print("API Endpoints:")
    print("  - /api/events - Get security events")
    print("  - /api/statistics - Get statistics")
    print("  - /api/log_event - Log new event")
    print("  - /api/log_file_upload - Log file upload")
    print("  - /api/take_action - Take manual action")
    print("  - /api/blocked_ips - Get blocked IPs")
    print("  - /api/login_attempts - Get login attempts")
    print("  - /api/response_actions - Get response actions")
    print("=" * 60)
    
    if not VIRUSTOTAL_ENABLED:
        print("\n⚠️  VirusTotal API not configured")
        print("Set VIRUSTOTAL_API_KEY environment variable to enable")
    else:
        print("\n✅ VirusTotal integration enabled")
    
    print("\n")
    
    app.run(host='0.0.0.0', port=5002, debug=True)