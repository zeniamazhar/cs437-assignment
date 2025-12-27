"""
Security Monitoring System for SCADA Alarm Management Console
Tracks and displays security events, attacks, and access patterns
"""

from flask import Flask, render_template, jsonify, request
import sqlite3
from datetime import datetime
import json

app = Flask(__name__)
app.config['MONITOR_DB'] = 'security_monitor.db'

def init_monitor_db():
    """Initialize monitoring database"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            endpoint TEXT NOT NULL,
            method TEXT,
            payload TEXT,
            user_agent TEXT,
            blocked BOOLEAN DEFAULT 0,
            description TEXT,
            vulnerability_type TEXT,
            system_version TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_statistics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATE DEFAULT CURRENT_DATE,
            attack_type TEXT,
            count INTEGER DEFAULT 1,
            blocked_count INTEGER DEFAULT 0,
            UNIQUE(date, attack_type)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Monitoring database initialized")

@app.route('/')
def dashboard():
    """Main monitoring dashboard"""
    return render_template('monitor_dashboard.html')

@app.route('/api/events')
def get_events():
    """Get recent security events"""
    limit = request.args.get('limit', 100, type=int)
    event_type = request.args.get('type', '')
    
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    if event_type:
        cursor.execute('''
            SELECT * FROM security_events 
            WHERE vulnerability_type = ?
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (event_type, limit))
    else:
        cursor.execute('''
            SELECT * FROM security_events 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
    
    events = []
    for row in cursor.fetchall():
        events.append({
            'id': row[0],
            'timestamp': row[1],
            'event_type': row[2],
            'severity': row[3],
            'source_ip': row[4],
            'endpoint': row[5],
            'method': row[6],
            'payload': row[7][:200] if row[7] else '',  # Truncate long payloads
            'blocked': bool(row[9]),
            'description': row[10],
            'vulnerability_type': row[11],
            'system_version': row[12]
        })
    
    conn.close()
    return jsonify(events)

@app.route('/api/statistics')
def get_statistics():
    """Get attack statistics"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    # Count by vulnerability type
    cursor.execute('''
        SELECT vulnerability_type, COUNT(*) as count,
               SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
        FROM security_events
        WHERE vulnerability_type IS NOT NULL
        GROUP BY vulnerability_type
    ''')
    
    vuln_stats = {}
    for row in cursor.fetchall():
        vuln_stats[row[0]] = {
            'total': row[1],
            'blocked': row[2],
            'successful': row[1] - row[2]
        }
    
    # Count by severity
    cursor.execute('''
        SELECT severity, COUNT(*) as count
        FROM security_events
        GROUP BY severity
    ''')
    
    severity_stats = {}
    for row in cursor.fetchall():
        severity_stats[row[0]] = row[1]
    
    # Recent activity (last 24 hours by hour)
    cursor.execute('''
        SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
        FROM security_events
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    ''')
    
    timeline = []
    for row in cursor.fetchall():
        timeline.append({'hour': row[0], 'count': row[1]})
    
    conn.close()
    
    return jsonify({
        'vulnerabilities': vuln_stats,
        'severity': severity_stats,
        'timeline': timeline
    })

@app.route('/api/log_event', methods=['POST'])
def log_event():
    """Log a security event (called by main applications)"""
    try:
        data = request.json
        
        conn = sqlite3.connect(app.config['MONITOR_DB'])
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (event_type, severity, source_ip, endpoint, method, payload, 
             user_agent, blocked, description, vulnerability_type, system_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('event_type', 'UNKNOWN'),
            data.get('severity', 'INFO'),
            data.get('source_ip', ''),
            data.get('endpoint', ''),
            data.get('method', 'GET'),
            data.get('payload', '')[:1000],  # Limit payload size
            data.get('user_agent', '')[:500],
            data.get('blocked', False),
            data.get('description', ''),
            data.get('vulnerability_type', ''),
            data.get('system_version', 'unknown')
        ))
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'message': 'Event logged'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/vulnerability/<vuln_type>')
def vulnerability_detail(vuln_type):
    """Detail page for specific vulnerability"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM security_events 
        WHERE vulnerability_type = ?
        ORDER BY timestamp DESC
    ''', (vuln_type,))
    
    events = cursor.fetchall()
    conn.close()
    
    return render_template('vulnerability_detail.html', 
                         vulnerability_type=vuln_type,
                         events=events)

# Sample data generator for demonstration
@app.route('/api/generate_sample_data')
def generate_sample_data():
    """Generate sample monitoring data for demonstration"""
    conn = sqlite3.connect(app.config['MONITOR_DB'])
    cursor = conn.cursor()
    
    sample_events = [
        # CSRF attacks
        ('CSRF_ATTACK', 'MEDIUM', '192.168.1.100', '/acknowledge/5', 'POST', 
         'alarm_id=5', 0, 'Missing CSRF token on acknowledgement', 'CSRF', 'vulnerable'),
        ('CSRF_ATTACK', 'MEDIUM', '192.168.1.100', '/silence/3', 'POST', 
         'alarm_id=3&duration=240', 0, 'Missing CSRF token on silence', 'CSRF', 'vulnerable'),
        ('CSRF_BLOCKED', 'MEDIUM', '192.168.1.100', '/acknowledge/5', 'POST', 
         'alarm_id=5&csrf_token=invalid', 1, 'Invalid CSRF token', 'CSRF', 'patched'),
        
        # SSRF attacks
        ('SSRF_ATTEMPT', 'HIGH', '203.0.113.50', '/reports', 'POST', 
         'data_source=http://169.254.169.254/latest/meta-data/', 0, 
         'Attempted AWS metadata access', 'SSRF', 'vulnerable'),
        ('SSRF_ATTEMPT', 'HIGH', '203.0.113.50', '/reports', 'POST', 
         'data_source=http://localhost:8080/admin', 0, 
         'Attempted internal service access', 'SSRF', 'vulnerable'),
        ('SSRF_BLOCKED', 'HIGH', '203.0.113.50', '/reports', 'POST', 
         'data_source=http://169.254.169.254/', 1, 
         'Blocked private IP access', 'SSRF', 'patched'),
        
        # Path Traversal attacks
        ('PATH_TRAVERSAL', 'HIGH', '198.51.100.25', '/export_logs', 'POST', 
         'log_file=../../../etc/passwd', 0, 'Attempted to read /etc/passwd', 
         'PATH_TRAVERSAL', 'vulnerable'),
        ('PATH_TRAVERSAL', 'HIGH', '198.51.100.25', '/export_logs', 'POST', 
         'log_file=../scada_alarms.db', 0, 'Attempted database theft', 
         'PATH_TRAVERSAL', 'vulnerable'),
        ('PATH_TRAVERSAL_BLOCKED', 'HIGH', '198.51.100.25', '/export_logs', 'POST', 
         'log_file=../../../etc/passwd', 1, 'Path traversal blocked', 
         'PATH_TRAVERSAL', 'patched'),
        
        # SQL Injection attacks
        ('SQL_INJECTION', 'CRITICAL', '198.18.0.50', '/login', 'POST', 
         "username=admin' OR '1'='1'--&password=test", 0, 
         'SQL injection authentication bypass', 'SQL_INJECTION', 'vulnerable'),
        ('SQL_INJECTION', 'CRITICAL', '198.18.0.50', '/api/search_alarms', 'GET', 
         "q=' UNION SELECT * FROM users--", 0, 
         'SQL injection data exfiltration attempt', 'SQL_INJECTION', 'vulnerable'),
        ('SQL_INJECTION_BLOCKED', 'CRITICAL', '198.18.0.50', '/login', 'POST', 
         "username=admin' OR '1'='1'--&password=test", 1, 
         'SQL injection blocked by parameterized query', 'SQL_INJECTION', 'patched'),
    ]
    
    for event in sample_events:
        cursor.execute('''
            INSERT INTO security_events 
            (event_type, severity, source_ip, endpoint, method, payload, 
             blocked, description, vulnerability_type, system_version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', event)
    
    conn.commit()
    conn.close()
    
    return jsonify({'status': 'success', 'message': f'{len(sample_events)} sample events generated'})

if __name__ == '__main__':
    init_monitor_db()
    print("\n🔍 Security Monitoring System")
    print("=" * 50)
    print("Dashboard: http://localhost:5002")
    print("API: http://localhost:5002/api/events")
    print("\nMonitoring both vulnerable and patched systems...")
    print("=" * 50 + "\n")
    
    app.run(host='0.0.0.0', port=5002, debug=True)
