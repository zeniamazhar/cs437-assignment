"""
SCADA Alarm Management Console - VULNERABLE VERSION
Task 9 - CS 437 Assignment

This version intentionally contains the following vulnerabilities:
1. Missing CSRF on POST form (alarm acknowledgement)
2. SSRF via Template Injection in Reporting Engines
3. File Path Injection (Directory Traversal)
4. SQL Injection Only Works With Specific Encodings (UTF-16/UTF-7)

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

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['DATABASE'] = 'scada_alarms.db'
app.config['LOG_DIR'] = 'logs'
app.config['REPORT_DIR'] = 'reports'

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('backups', exist_ok=True)

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
    The application uses UTF-16 encoding which bypasses basic filters
    """
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Check for special encoding in request
        encoding = request.headers.get('Content-Encoding', 'utf-8')
        
        # If UTF-16 or UTF-7 encoded, decode it
        if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
            try:
                # Re-decode the username with the specified encoding
                username_bytes = username.encode('latin-1')
                username = username_bytes.decode(encoding.lower())
            except:
                pass
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        db = get_db()
        cursor = db.cursor()
        
        # VULNERABLE: Direct string concatenation without parameterization
        # Works with specific encodings that bypass basic filters
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_hash = '{password_hash}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
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
    No CSRF token validation - vulnerable to CSRF attacks
    An attacker can craft a malicious page that automatically acknowledges alarms
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
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
    Silence alarm temporarily - also vulnerable to CSRF
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
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
    Escalate alarm to supervisor - vulnerable to CSRF
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
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
    Report generation with template injection vulnerability
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        report_type = request.form.get('report_type', 'summary')
        data_source = request.form.get('data_source', '')  # URL to fetch data from
        template_url = request.form.get('template_url', '')  # URL to fetch template from
        
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
        
        # VULNERABLE: Fetch external data without validation (SSRF)
        if data_source:
            try:
                # No validation of URL - can access internal services
                response = requests.get(data_source, timeout=5)
                report_data['external_data'] = response.text
            except Exception as e:
                report_data['external_data'] = f'Error fetching data: {str(e)}'
        
        # VULNERABLE: Fetch and execute external template (Template Injection + SSRF)
        if template_url:
            try:
                # Fetch template from external URL
                response = requests.get(template_url, timeout=5)
                template_content = response.text
                
                # VULNERABLE: Using Jinja2 Template without sandboxing
                template = Template(template_content)
                report_html = template.render(**report_data)
                
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
                return f"Error generating report: {str(e)}", 500
        
        db.close()
        return render_template('reports.html', error='Template URL required')
    
    return render_template('reports.html')



@app.route('/export_logs', methods=['GET', 'POST'])
def export_logs():
    """
    VULNERABILITY 3: File Path Injection (Directory Traversal)
    Export logs with path traversal vulnerability
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        log_file = request.form.get('log_file', 'alarm.log')
        
        # VULNERABLE: No path validation - allows directory traversal
        # Attacker can use ../../../etc/passwd or similar
        log_path = os.path.join(app.config['LOG_DIR'], log_file)
        
        try:
            # Attempt to read the file
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
    Backup/restore functionality with path traversal
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        action = request.form.get('action', 'backup')
        
        if action == 'backup':
            backup_name = request.form.get('backup_name', 'backup.db')
            
            # VULNERABLE: No sanitization of backup name
            backup_path = os.path.join('backups', backup_name)
            
            try:
                # Copy database to backup location
                import shutil
                shutil.copy(app.config['DATABASE'], backup_path)
                return f"Backup created: {backup_path}"
            except Exception as e:
                return f"Backup failed: {str(e)}", 500
        
        elif action == 'restore':
            restore_file = request.form.get('restore_file', '')
            
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
    Firmware restore with path traversal
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') != 'admin':
        return "Access denied - Admin only", 403
    
    if request.method == 'POST':
        firmware_path = request.form.get('firmware_path', '')
        
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
    """
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    search_term = request.args.get('q', '')
    encoding = request.headers.get('Content-Encoding', 'utf-8')
    
    # Check for special encoding
    if encoding.lower() in ['utf-16', 'utf-7', 'utf-16le', 'utf-16be']:
        try:
            search_term_bytes = search_term.encode('latin-1')
            search_term = search_term_bytes.decode(encoding.lower())
        except:
            pass
    
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


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
