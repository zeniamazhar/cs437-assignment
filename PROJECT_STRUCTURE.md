# Project Structure - Task 9 SCADA Alarm Management Console

```
task9_scada_alarm_console/
│
├── 📄 README.md                          # Main project documentation
├── 📄 QUICK_START.md                     # 5-minute setup guide
├── 📄 docker-compose.yml                 # Deploy all services at once
├── 🔧 test_all.sh                        # Automated vulnerability testing
│
├── 📁 vulnerable/                        # VULNERABLE APPLICATION
│   ├── app.py                            # Main Flask app (WITH VULNERABILITIES)
│   ├── requirements.txt                  # Python dependencies
│   ├── Dockerfile                        # Container configuration
│   └── templates/                        # HTML templates
│       ├── base.html                     # Base template with navbar
│       ├── login.html                    # Login page
│       ├── dashboard.html                # Main dashboard
│       ├── alarms.html                   # Alarm listing
│       ├── alarm_detail.html             # Alarm details (CSRF vulnerable)
│       ├── reports.html                  # Report generation (SSRF vulnerable)
│       ├── export_logs.html              # Log export (Path traversal vulnerable)
│       ├── backup.html                   # Database backup (Path traversal)
│       └── firmware_restore.html         # Firmware restore (Path traversal)
│
├── 📁 patched/                           # PATCHED SECURE APPLICATION
│   ├── app.py                            # Main Flask app (SECURED)
│   ├── requirements.txt                  # Python dependencies
│   ├── Dockerfile                        # Container configuration
│   └── templates/                        # HTML templates (with CSRF tokens)
│       ├── base.html                     # Base template
│       ├── login.html                    # Login page
│       ├── dashboard.html                # Main dashboard
│       ├── alarms.html                   # Alarm listing
│       ├── alarm_detail.html             # Alarm details (CSRF protected)
│       ├── reports.html                  # Report generation (SSRF protected)
│       ├── export_logs.html              # Log export (Path validated)
│       ├── backup.html                   # Database backup (Sanitized)
│       └── firmware_restore.html         # Firmware restore (Validated)
│
├── 📁 monitoring/                        # SECURITY MONITORING SYSTEM
│   ├── app.py                            # Monitoring Flask app
│   ├── requirements.txt                  # Python dependencies
│   ├── Dockerfile                        # Container configuration
│   └── templates/
│       └── monitor_dashboard.html        # Real-time security dashboard
│
├── 📁 database/                          # DATABASE SCRIPTS
│   └── populate_db.py                    # Generate 120+ alarm records
│
├── 📁 exploitation_scripts/              # ATTACK DEMONSTRATION SCRIPTS
│   ├── csrf_exploit.py                   # CSRF attack automation
│   ├── sqli_exploit.py                   # SQL injection with UTF-16
│   └── path_traversal_exploit.py         # Directory traversal attacks
│
└── 📁 docs/                              # COMPREHENSIVE DOCUMENTATION
    ├── PROJECT_REPORT.md                 # Full project report (10,000+ words)
    └── EXPLOITATION_GUIDE.md             # Step-by-step exploitation guide
```

---

## File Count by Category

### Application Files
- **Python files:** 8 (2 main apps + 2 patched + 1 monitor + 1 database + 3 exploits)
- **HTML templates:** 18 (9 vulnerable + 9 patched + 1 monitoring)
- **Configuration:** 5 (requirements.txt × 3, Dockerfile × 3, docker-compose.yml)

### Documentation
- **Markdown files:** 4 (README, QUICK_START, PROJECT_REPORT, EXPLOITATION_GUIDE)
- **Total documentation:** ~15,000 words

### Total Files: 36+

---

## Key File Purposes

### 🎯 Most Important Files

**For Understanding:**
- `docs/PROJECT_REPORT.md` - Read this first for complete documentation
- `QUICK_START.md` - Get started in 5 minutes
- `docs/EXPLOITATION_GUIDE.md` - Step-by-step attack instructions

**For Running:**
- `vulnerable/app.py` - The vulnerable SCADA application
- `patched/app.py` - The secure SCADA application
- `docker-compose.yml` - Deploy everything at once

**For Testing:**
- `test_all.sh` - Automated vulnerability testing
- `exploitation_scripts/*.py` - Individual attack scripts

**For Database:**
- `database/populate_db.py` - Generates 120 realistic alarms

---

## Port Assignments

| Service | Port | URL |
|---------|------|-----|
| Vulnerable SCADA | 5000 | http://localhost:5000 |
| Patched SCADA | 5001 | http://localhost:5001 |
| Monitoring Dashboard | 5002 | http://localhost:5002 |

---

## Vulnerability Locations

### 1. CSRF (Missing CSRF Tokens)
- **Files:** `vulnerable/app.py` lines 265-340
- **Endpoints:** `/acknowledge/<id>`, `/silence/<id>`, `/escalate/<id>`
- **Template:** `vulnerable/templates/alarm_detail.html`

### 2. SSRF + Template RCE
- **File:** `vulnerable/app.py` lines 343-400
- **Endpoint:** `/reports`
- **Template:** `vulnerable/templates/reports.html`

### 3. Path Traversal
- **File:** `vulnerable/app.py` lines 403-490
- **Endpoints:** `/export_logs`, `/backup`, `/firmware_restore`
- **Templates:** `export_logs.html`, `backup.html`, `firmware_restore.html`

### 4. SQL Injection (Encoding-based)
- **File:** `vulnerable/app.py` lines 205-240
- **Endpoints:** `/login`, `/api/search_alarms`
- **Template:** `vulnerable/templates/login.html`

---

## Security Patches Locations

### 1. CSRF Protection
- **File:** `patched/app.py` lines 36-49
- **Function:** `generate_csrf_token()`, `validate_csrf_token()`
- **Implementation:** All POST endpoints validate tokens

### 2. SSRF/RCE Prevention
- **File:** `patched/app.py` lines 51-83
- **Functions:** `validate_url()`, SandboxedEnvironment usage
- **Implementation:** URL allowlisting, IP range blocking

### 3. Path Traversal Prevention
- **File:** `patched/app.py` lines 85-101
- **Function:** `sanitize_path()`
- **Implementation:** Path validation, base directory checking

### 4. SQL Injection Prevention
- **File:** `patched/app.py` throughout
- **Implementation:** Parameterized queries everywhere

---

## Data Flow

```
User Request
    ↓
Flask Application (vulnerable or patched)
    ↓
SQLite Database (scada_alarms.db)
    ├── users table (credentials)
    ├── alarms table (120+ records)
    ├── alarm_logs table (action history)
    └── reports table (generated reports)
    ↓
Response to User
    ↓
Monitoring System (logs security events)
    ↓
Security Dashboard (displays attacks)
```

---

## Setup Workflows

### Quick Test (5 minutes)
```bash
cd vulnerable/
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -c "from app import init_db; init_db()"
cd ../database && python3 populate_db.py && cd ../vulnerable
python app.py
# Visit http://localhost:5000
```

### Docker Deployment (10 minutes)
```bash
docker-compose up -d
# Wait for containers to start
docker-compose ps
# Visit http://localhost:5000, :5001, :5002
```

### Full Testing (30 minutes)
```bash
# Terminal 1: Run vulnerable version
cd vulnerable && python app.py

# Terminal 2: Run patched version  
cd patched && python app.py

# Terminal 3: Run monitoring
cd monitoring && python app.py

# Terminal 4: Run tests
./test_all.sh
python exploitation_scripts/csrf_exploit.py
python exploitation_scripts/sqli_exploit.py
python exploitation_scripts/path_traversal_exploit.py
```

---

## Documentation Reading Order

1. **QUICK_START.md** (5 min) - Get running immediately
2. **README.md** (10 min) - Project overview
3. **docs/PROJECT_REPORT.md** (60 min) - Full documentation
4. **docs/EXPLOITATION_GUIDE.md** (30 min) - Attack tutorials
5. **Source code comments** (60 min) - Understand implementation

---

## File Size Summary

- **Vulnerable app.py:** ~800 lines
- **Patched app.py:** ~900 lines (more security code)
- **Monitoring app.py:** ~400 lines
- **Each HTML template:** ~100-200 lines
- **Exploitation scripts:** ~300-400 lines each
- **Documentation:** ~15,000 words total

---

## Required for Submission

✅ Both source codes (vulnerable + patched)  
✅ Both requirements.txt files  
✅ Both Dockerfiles  
✅ Docker compose file  
✅ Database population script  
✅ Comprehensive report (PROJECT_REPORT.md)  
✅ Video demonstration script (in EXPLOITATION_GUIDE.md)  
✅ README.md  

All files are complete and ready for submission!

---

## Additional Resources in Project

- Automated testing script (`test_all.sh`)
- Security monitoring system
- Three exploitation scripts
- Exploitation guide with tool usage
- Docker deployment configuration
- Comprehensive documentation

---

## Navigation Tips

**Starting point:** README.md or QUICK_START.md  
**Understanding vulnerabilities:** docs/PROJECT_REPORT.md  
**Running exploits:** docs/EXPLOITATION_GUIDE.md  
**Source code:** vulnerable/app.py and patched/app.py  
**Testing:** exploitation_scripts/ and test_all.sh  

---

This structure provides everything needed for a complete, professional CS 437 assignment submission! 🎓
