# Quick Start Guide - Task 9 SCADA Alarm Management Console

## What You Have

A complete SCADA security project with:
- ✅ Vulnerable web application (Flask)
- ✅ Patched secure version (Flask)
- ✅ 4 distinct vulnerabilities (CSRF, SSRF+RCE, Path Traversal, Encoding SQLi)
- ✅ Database with 120+ alarm records
- ✅ Comprehensive documentation
- ✅ Exploitation guides
- ✅ Docker deployment files

## 5-Minute Setup

### Option 1: Docker (Easiest)

```bash
# 1. Navigate to vulnerable directory
cd vulnerable/

# 2. Build and run
docker build -t scada-vulnerable .
docker run -p 5000:5000 scada-vulnerable

# 3. Open browser
# http://localhost:5000
# Login: admin / admin123
```

### Option 2: Python Virtual Environment

```bash
# 1. Setup vulnerable version
cd vulnerable/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Initialize database
python3 -c "from app import init_db; init_db()"

# 3. Populate with data
cd ../database/
python3 populate_db.py
cd ../vulnerable/

# 4. Run
python app.py

# 5. Access at http://localhost:5000
```

## Test One Vulnerability (30 seconds)

**CSRF Attack Test:**

1. Login to http://localhost:5000 (admin/admin123)
2. Open new terminal
3. Run:
```bash
curl -X POST http://localhost:5000/acknowledge/1 \
  -H "Cookie: session=YOUR_SESSION_COOKIE"
```
4. Check alarm #1 - it's now acknowledged!
5. **That's CSRF vulnerability in action**

## Next Steps

1. **Read Documentation:**
   - `docs/PROJECT_REPORT.md` - Complete project documentation
   - `docs/EXPLOITATION_GUIDE.md` - Step-by-step exploitation

2. **Test All Vulnerabilities:**
   - CSRF (3 endpoints)
   - SSRF + Template RCE
   - Path Traversal (3 endpoints)
   - Encoding-based SQL Injection

3. **Run Pentesting Tools:**
   - Burp Suite
   - SQLMap
   - OWASP ZAP
   - Nuclei

4. **Compare with Patched Version:**
   ```bash
   cd patched/
   python app.py  # Runs on port 5001
   # Try same exploits - they fail!
   ```

5. **Create Video:**
   - Show vulnerable version
   - Demonstrate each exploit
   - Show patches
   - Test patched version

## Project Structure

```
task9_scada_alarm_console/
│
├── README.md                    ← Start here
│
├── vulnerable/                  ← Vulnerable application
│   ├── app.py                   ← Main application (VULNERABLE)
│   ├── templates/               ← HTML templates
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── alarm_detail.html   ← CSRF vulnerable
│   │   ├── reports.html        ← SSRF vulnerable
│   │   ├── export_logs.html    ← Path traversal vulnerable
│   │   └── ...
│   ├── requirements.txt
│   └── Dockerfile
│
├── patched/                     ← Secure application
│   ├── app.py                   ← Main application (SECURE)
│   ├── templates/               ← HTML templates with CSRF tokens
│   ├── requirements.txt
│   └── Dockerfile
│
├── database/
│   └── populate_db.py          ← Generates 120 alarm records
│
└── docs/
    ├── PROJECT_REPORT.md        ← COMPLETE DOCUMENTATION
    └── EXPLOITATION_GUIDE.md    ← Step-by-step exploits
```

## Important Files

### For Understanding
- `docs/PROJECT_REPORT.md` - READ THIS FIRST
- `docs/EXPLOITATION_GUIDE.md` - Exploitation instructions

### For Running
- `vulnerable/app.py` - Vulnerable code
- `patched/app.py` - Secure code
- `database/populate_db.py` - Database setup

### For Deployment
- `vulnerable/Dockerfile` - Container setup
- `vulnerable/requirements.txt` - Dependencies

## Key Vulnerabilities

### 1. CSRF (Lines 265-340 in vulnerable/app.py)
- **Location:** `/acknowledge/`, `/silence/`, `/escalate/`
- **Impact:** Attackers can control alarms remotely
- **Test:** Use Burp Suite or curl without CSRF token

### 2. SSRF + RCE (Lines 343-400 in vulnerable/app.py)
- **Location:** `/reports`
- **Impact:** Full server compromise
- **Test:** Fetch http://localhost:8080 or execute templates

### 3. Path Traversal (Lines 403-490 in vulnerable/app.py)
- **Location:** `/export_logs`, `/backup`, `/firmware_restore`
- **Impact:** Read any file on system
- **Test:** Use `../../../etc/passwd`

### 4. SQL Injection (Lines 205-240 in vulnerable/app.py)
- **Location:** `/login`, `/api/search_alarms`
- **Impact:** Database compromise
- **Test:** UTF-16 encoded payloads

## Demo Credentials

- **Admin:** username=`admin`, password=`admin123`
- **Operator:** username=`operator`, password=`operator123`

## URLs

- **Vulnerable:** http://localhost:5000
- **Patched:** http://localhost:5001 (run separately)

## Getting Help

### Common Issues

**"ModuleNotFoundError: No module named 'flask'"**
```bash
pip install -r requirements.txt
```

**"Database is locked"**
```bash
# Delete database and recreate
rm scada_alarms.db
python3 -c "from app import init_db; init_db()"
```

**"Port 5000 already in use"**
```bash
# Find and kill process
lsof -ti:5000 | xargs kill -9
# Or change port in app.py (last line)
```

### Quick Tests

**Test if vulnerable version works:**
```bash
curl http://localhost:5000
# Should return HTML (login page)
```

**Test database populated:**
```bash
sqlite3 scada_alarms.db "SELECT COUNT(*) FROM alarms"
# Should return 120+
```

**Test patched version works:**
```bash
curl http://localhost:5001
# Should return HTML (login page)
```

## For Your Report

### Required Evidence

1. **Screenshots:**
   - Dashboard interface
   - Each vulnerability exploitation
   - Burp Suite/ZAP/SQLMap outputs
   - Patched version blocking attacks

2. **Code Snippets:**
   - Vulnerable code sections (with line numbers)
   - Patched code sections (with comments)
   - Exploitation scripts

3. **Tool Outputs:**
   - SQLMap database dump
   - Burp Suite findings
   - Path traversal file reads
   - SSRF/RCE command execution

### Report Structure

1. Introduction
2. System Description
3. Vulnerability Analysis (4 sections)
   - Description
   - Location in code
   - Exploitation
   - Impact
4. Security Patches (4 sections)
   - What was changed
   - Why it works
   - Testing
5. Pentesting Tool Results
6. Monitoring System
7. Conclusion

## Video Script (18 min)

1. **Intro (1 min):** Show SCADA dashboard, explain scenario
2. **CSRF (3 min):** Code → Exploit → Patch → Re-test
3. **SSRF+RCE (4 min):** Code → Internal scan → RCE → Patch → Re-test
4. **Path Traversal (3 min):** Code → Read files → Patch → Re-test
5. **SQL Injection (4 min):** Code → Bypass auth → Patch → Re-test
6. **Monitoring (2 min):** Show attack detection dashboard
7. **Conclusion (1 min):** Summary and lessons

## Submission Checklist

- [ ] Both source codes (vulnerable + patched)
- [ ] Both requirements.txt files
- [ ] Both Dockerfiles
- [ ] Database population script
- [ ] Populated database file (.db)
- [ ] Comprehensive report (PDF)
- [ ] Video demonstration (MP4)
- [ ] README.md

## Time Estimate

- **Setup:** 15 minutes
- **Understanding vulnerabilities:** 1 hour
- **Testing exploits:** 2 hours
- **Writing report:** 3 hours
- **Creating video:** 2 hours
- **Total:** ~8 hours

## Tips for Success

1. **Test everything** before recording video
2. **Take screenshots** as you go
3. **Keep terminal logs** for report
4. **Read the documentation** thoroughly
5. **Test both versions** side by side
6. **Use multiple tools** (not just one)
7. **Explain clearly** in video

## Contact

If you have questions about the implementation, refer to:
- PROJECT_REPORT.md for detailed explanations
- EXPLOITATION_GUIDE.md for step-by-step attacks
- Code comments in app.py files

---

**You're ready to go!** Start with the vulnerable version, test one exploit, then work through the rest systematically. Good luck! 🚀
