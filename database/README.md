# Database Setup

## Quick Setup (Recommended)

Use the combined script that both initializes and populates the database:

```bash
python3 init_and_populate.py
```

This will:
1. Create all database tables
2. Create default users (admin, operator)
3. Generate 120 realistic alarm records
4. Create alarm logs

## Manual Setup (If needed)

If you want to do it step by step:

### Step 1: Initialize Database
From the `vulnerable/` or `patched/` directory:
```python
python3 -c "from app import init_db; init_db()"
```

### Step 2: Populate Data
```bash
python3 populate_db.py
```

## Default Credentials

After setup, use these credentials to login:

- **Admin:** 
  - Username: `admin`
  - Password: `admin123`

- **Operator:**
  - Username: `operator`
  - Password: `operator123`

## Database Schema

The database includes these tables:

- **users** - User credentials and roles
- **alarms** - SCADA alarm records (120+)
- **alarm_logs** - Action history for alarms
- **reports** - Generated report metadata

## Troubleshooting

**Error: "no such table: alarms"**
- Solution: Run `init_and_populate.py` instead of `populate_db.py` alone
- Or initialize first: `python3 -c "from app import init_db; init_db()"` from vulnerable/ or patched/

**Error: "database is locked"**
- Solution: Make sure the app isn't running
- Delete scada_alarms.db and run init_and_populate.py again

**Error: "ModuleNotFoundError"**
- Solution: Make sure you're in the correct directory and dependencies are installed
- Run from vulnerable/ or patched/ directory after installing requirements
