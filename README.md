# SCADA Alarm Management Console - Task 9
## CS 437 OT Security Assignment

This project implements a vulnerable SCADA system and its patched version for educational purposes.

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Build and run vulnerable version
cd vulnerable
docker build -t scada-vulnerable .
docker run -p 5000:5000 scada-vulnerable

# Build and run patched version  
cd ../patched
docker build -t scada-patched .
docker run -p 5001:5001 scada-patched
```

### Option 2: Local Installation

**Vulnerable Version:**
```bash
cd vulnerable
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

**Patched Version:**
```bash
cd patched
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Access

- Vulnerable: http://localhost:5000
- Patched: http://localhost:5001

## Default Credentials

- Admin: `admin` / `admin123`
- Operator: `operator` / `operator123`

## Vulnerabilities Implemented

1. **Missing CSRF Protection** - Forms lack CSRF tokens
2. **SSRF + Template Injection** - Fetches external URLs and executes templates
3. **Path Traversal** - No input validation on file paths
4. **Encoding-Based SQL Injection** - Vulnerable to UTF-16/UTF-7 encoded payloads

## Documentation

See `docs/PROJECT_REPORT.md` for comprehensive documentation including:
- Detailed vulnerability explanations
- Exploitation demonstrations
- Security patches applied
- Pentesting tool usage
- Monitoring system setup

## Project Structure

```
task9_scada_alarm_console/
├── vulnerable/          # Vulnerable version
│   ├── app.py
│   ├── templates/
│   ├── requirements.txt
│   └── Dockerfile
├── patched/            # Patched version
│   ├── app.py
│   ├── templates/
│   ├── requirements.txt
│   └── Dockerfile
├── database/           # Database scripts
│   └── populate_db.py
├── monitoring/         # Monitoring system
└── docs/              # Documentation
    └── PROJECT_REPORT.md
```

## Testing

Use the following tools to test vulnerabilities:
- Burp Suite
- OWASP ZAP
- SQLMap
- Nuclei
- Nikto
- Custom Python scripts (see docs/)

## Video Demonstration

[Link to video demonstration will be added]

## Team Members

[Add your team member names here]

## License

Educational purposes only. Do not deploy in production.
