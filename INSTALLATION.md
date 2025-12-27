# Installation Guide - Task 9 SCADA Alarm Management Console

## 📦 What You've Downloaded

This ZIP file contains a complete SCADA security project with:
- 2 Flask applications (vulnerable + patched)
- 1 Security monitoring system
- 4 Documented vulnerabilities with exploits
- Comprehensive documentation (15,000+ words)
- Docker deployment files
- Automated testing scripts

## 🚀 Quick Installation

### Step 1: Extract the ZIP file

**Windows:**
- Right-click the ZIP file
- Select "Extract All..."
- Choose destination folder
- Click "Extract"

**Mac/Linux:**
```bash
unzip task9_scada_alarm_console.zip
cd task9_scada_alarm_console
```

### Step 2: Verify the structure

You should see this folder structure:
```
task9_scada_alarm_console/
├── vulnerable/
├── patched/
├── monitoring/
├── database/
├── exploitation_scripts/
├── docs/
├── README.md
├── QUICK_START.md
└── docker-compose.yml
```

### Step 3: Choose your setup method

## Option A: Docker (Recommended - 5 minutes)

**Prerequisites:**
- Docker installed
- Docker Compose installed

**Steps:**
```bash
cd task9_scada_alarm_console
docker-compose up -d
```

**Access:**
- Vulnerable SCADA: http://localhost:5000
- Patched SCADA: http://localhost:5001
- Monitoring: http://localhost:5002

**Login:**
- Username: `admin`
- Password: `admin123`

## Option B: Python Virtual Environment (10 minutes)

**Prerequisites:**
- Python 3.11 or higher
- pip

**Steps:**

1. **Setup Vulnerable Version:**
```bash
cd vulnerable/
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Setup database (initialize + populate)
cd ../database/
python3 init_and_populate.py

# Run application
cd ../vulnerable/
python app.py
```

2. **Open new terminal for Patched Version:**
```bash
cd patched/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ../database/ && python3 init_and_populate.py && cd ../patched/
python app.py
```

3. **Open new terminal for Monitoring:**
```bash
cd monitoring/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## 🧪 Verify Installation

### Test Vulnerable Version:
```bash
curl http://localhost:5000
# Should return HTML (login page)
```

### Test Patched Version:
```bash
curl http://localhost:5001
# Should return HTML (login page)
```

### Test Monitoring:
```bash
curl http://localhost:5002
# Should return monitoring dashboard
```

## 🎯 Next Steps

1. **Read Documentation:**
   - Start with `QUICK_START.md`
   - Then read `docs/PROJECT_REPORT.md`

2. **Test Vulnerabilities:**
   ```bash
   chmod +x test_all.sh
   ./test_all.sh
   ```

3. **Run Exploitation Scripts:**
   ```bash
   cd exploitation_scripts/
   python3 csrf_exploit.py
   python3 sqli_exploit.py
   python3 path_traversal_exploit.py
   ```

4. **Use Pentesting Tools:**
   - Burp Suite
   - SQLMap
   - OWASP ZAP
   - See `docs/EXPLOITATION_GUIDE.md`

## 📁 File Overview

| Directory | Purpose |
|-----------|---------|
| `vulnerable/` | Intentionally vulnerable SCADA app |
| `patched/` | Secure version with fixes |
| `monitoring/` | Real-time security monitoring |
| `database/` | Database population scripts |
| `exploitation_scripts/` | Automated attack scripts |
| `docs/` | Comprehensive documentation |

## 🐛 Troubleshooting

### "Port already in use"
```bash
# Find process using port 5000
lsof -ti:5000 | xargs kill -9
```

### "ModuleNotFoundError"
```bash
pip install -r requirements.txt
```

### "Database is locked"
```bash
# Delete and recreate database
rm scada_alarms.db
python3 -c "from app import init_db; init_db()"
```

### Docker issues
```bash
# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

## 📊 Project Statistics

- **Total Files:** 36
- **Lines of Code:** ~4,000+
- **Documentation:** 15,000+ words
- **Vulnerabilities:** 4 distinct types
- **Database Records:** 120+ alarms
- **Exploitation Scripts:** 3 automated
- **Templates:** 18 HTML files

## 🎓 For Your Assignment

### What to Submit:
1. ✅ This entire folder (both versions)
2. ✅ Your written report (expand `docs/PROJECT_REPORT.md`)
3. ✅ Video demonstration
4. ✅ Screenshots of exploits

### Video Demonstration Tips:
- Show dashboard first
- Demonstrate each vulnerability
- Show patched version blocking attacks
- Explain patches clearly
- Use monitoring dashboard
- Keep it 15-20 minutes

### Report Structure:
1. Introduction
2. System Description
3. Vulnerabilities (4 sections)
4. Exploitation Demonstrations
5. Security Patches
6. Testing Results
7. Conclusion

## 📞 Support

If you encounter issues:
1. Check `QUICK_START.md`
2. Read `docs/EXPLOITATION_GUIDE.md`
3. Review code comments in `app.py` files
4. Check Docker logs: `docker-compose logs`

## ⚠️ Important Notes

- **DO NOT deploy in production** - these are intentionally vulnerable
- Use for educational purposes only
- Keep vulnerable version isolated
- Always test in safe environment

## 🎉 You're Ready!

Everything is set up and documented. Start with:
```bash
cd task9_scada_alarm_console
cat QUICK_START.md
```

Good luck with your assignment! 🚀
