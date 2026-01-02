#!/usr/bin/env python3
"""
Database initialization script for patched SCADA app
"""
import sqlite3
import hashlib
import random
from datetime import datetime, timedelta

# Initialize database
from app import init_db
init_db()
print("✅ Database initialized")

# Populate with sample data
ALARM_CODES = ['WL-101', 'PR-201', 'FL-301', 'TM-401', 'PW-501', 'CM-601', 'VL-701', 'PM-801']
SEVERITIES = ['critical', 'high', 'medium', 'low']
LOCATIONS = ['Main Reservoir', 'Pump Station 1', 'Treatment Plant']

conn = sqlite3.connect('scada_alarms.db')
cursor = conn.cursor()

for i in range(120):
    cursor.execute('''
        INSERT INTO alarms (alarm_code, severity, description, location, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        random.choice(ALARM_CODES),
        random.choice(SEVERITIES),
        f'Sample alarm {i+1}',
        random.choice(LOCATIONS),
        'active'
    ))

conn.commit()
conn.close()
print("✅ Database populated with 120 alarms")
