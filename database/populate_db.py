"""
Database population script for SCADA Alarm Management Console
Generates 100+ realistic alarm records for testing
"""

import sqlite3
import random
from datetime import datetime, timedelta

# Alarm code patterns based on ISA-18.2 standard
ALARM_CODES = [
    'WL-101', 'WL-102', 'WL-103', 'WL-104', 'WL-105',  # Water Level
    'PR-201', 'PR-202', 'PR-203', 'PR-204', 'PR-205',  # Pressure
    'FL-301', 'FL-302', 'FL-303', 'FL-304', 'FL-305',  # Flow Rate
    'TM-401', 'TM-402', 'TM-403', 'TM-404', 'TM-405',  # Temperature
    'PW-501', 'PW-502', 'PW-503', 'PW-504', 'PW-505',  # Power
    'CM-601', 'CM-602', 'CM-603', 'CM-604', 'CM-605',  # Communication
    'VL-701', 'VL-702', 'VL-703', 'VL-704', 'VL-705',  # Valve
    'PM-801', 'PM-802', 'PM-803', 'PM-804', 'PM-805',  # Pump
]

SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low']

DESCRIPTIONS = {
    'WL': [
        'Water level exceeding maximum threshold',
        'Water level below minimum operating level',
        'Rapid water level fluctuation detected',
        'Water level sensor communication failure',
        'Emergency overflow condition detected'
    ],
    'PR': [
        'Pressure exceeding safe operating limit',
        'Pressure drop detected in main line',
        'Pressure sensor calibration required',
        'Abnormal pressure spike detected',
        'Pressure relief valve activated'
    ],
    'FL': [
        'Flow rate below minimum threshold',
        'Excessive flow rate detected',
        'Flow meter communication error',
        'Reverse flow detected',
        'Flow rate fluctuation exceeds tolerance'
    ],
    'TM': [
        'Temperature exceeding maximum limit',
        'Temperature sensor malfunction',
        'Rapid temperature change detected',
        'Temperature below operational minimum',
        'Cooling system failure'
    ],
    'PW': [
        'Power supply voltage out of range',
        'Backup power system activated',
        'Power consumption exceeds capacity',
        'Electrical fault detected',
        'UPS battery low'
    ],
    'CM': [
        'Network communication timeout',
        'PLC connection lost',
        'SCADA server unreachable',
        'Data transmission error',
        'Protocol violation detected'
    ],
    'VL': [
        'Valve failed to respond to command',
        'Valve position sensor error',
        'Valve actuator malfunction',
        'Emergency valve closure activated',
        'Valve stuck in intermediate position'
    ],
    'PM': [
        'Pump motor overheating',
        'Pump vibration exceeds normal range',
        'Pump failed to start',
        'Pump running dry detected',
        'Pump bearing failure imminent'
    ]
}

LOCATIONS = [
    'Main Reservoir - North Section',
    'Main Reservoir - South Section',
    'Distribution Station Alpha',
    'Distribution Station Beta',
    'Distribution Station Gamma',
    'Pumping Station 1',
    'Pumping Station 2',
    'Pumping Station 3',
    'Treatment Plant - Inlet',
    'Treatment Plant - Outlet',
    'Storage Tank A',
    'Storage Tank B',
    'Storage Tank C',
    'Pressure Zone 1',
    'Pressure Zone 2',
    'Pressure Zone 3',
    'Emergency Backup System',
    'Control Room',
    'Field Gateway 01',
    'Field Gateway 02'
]

def generate_alarms(count=120):
    """Generate realistic alarm records"""
    alarms = []
    base_time = datetime.now() - timedelta(days=30)
    
    for i in range(count):
        alarm_code = random.choice(ALARM_CODES)
        prefix = alarm_code.split('-')[0]
        
        severity = random.choices(
            SEVERITY_LEVELS,
            weights=[10, 25, 40, 25],  # Fewer critical, more medium
            k=1
        )[0]
        
        description = random.choice(DESCRIPTIONS[prefix])
        location = random.choice(LOCATIONS)
        
        # Random time within last 30 days
        triggered_at = base_time + timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Some alarms are acknowledged, silenced, or escalated
        acknowledged = random.random() < 0.6  # 60% acknowledged
        silenced = random.random() < 0.2  # 20% silenced
        escalated = random.random() < 0.15  # 15% escalated
        
        status = 'active' if random.random() < 0.7 else 'resolved'
        
        alarm = {
            'alarm_code': alarm_code,
            'severity': severity,
            'description': description,
            'location': location,
            'triggered_at': triggered_at.isoformat(),
            'acknowledged': 1 if acknowledged else 0,
            'acknowledged_by': 'operator' if acknowledged else None,
            'acknowledged_at': (triggered_at + timedelta(minutes=random.randint(5, 120))).isoformat() if acknowledged else None,
            'silenced': 1 if silenced else 0,
            'silenced_until': (triggered_at + timedelta(hours=random.randint(1, 4))).isoformat() if silenced else None,
            'escalated': 1 if escalated else 0,
            'escalated_to': random.choice(['supervisor_john', 'supervisor_sarah', 'manager_mike']) if escalated else None,
            'status': status
        }
        
        alarms.append(alarm)
    
    return alarms

def populate_database(db_path='scada_alarms.db'):
    """Populate database with alarm records"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Generate 120 alarms
    alarms = generate_alarms(120)
    
    print(f"Inserting {len(alarms)} alarm records...")
    
    for alarm in alarms:
        cursor.execute('''
            INSERT INTO alarms (
                alarm_code, severity, description, location, triggered_at,
                acknowledged, acknowledged_by, acknowledged_at,
                silenced, silenced_until, escalated, escalated_to, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alarm['alarm_code'], alarm['severity'], alarm['description'],
            alarm['location'], alarm['triggered_at'], alarm['acknowledged'],
            alarm['acknowledged_by'], alarm['acknowledged_at'],
            alarm['silenced'], alarm['silenced_until'], alarm['escalated'],
            alarm['escalated_to'], alarm['status']
        ))
    
    # Generate alarm logs for each alarm
    print("Generating alarm logs...")
    cursor.execute('SELECT id, acknowledged, silenced, escalated FROM alarms')
    alarm_records = cursor.fetchall()
    
    for alarm_id, acknowledged, silenced, escalated in alarm_records:
        # Initial creation log
        cursor.execute('''
            INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
            VALUES (?, ?, ?, ?)
        ''', (alarm_id, 'CREATED', 'system', 'Alarm automatically generated by monitoring system'))
        
        if acknowledged:
            cursor.execute('''
                INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
                VALUES (?, ?, ?, ?)
            ''', (alarm_id, 'ACKNOWLEDGED', 'operator', 'Alarm acknowledged by operator'))
        
        if silenced:
            cursor.execute('''
                INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
                VALUES (?, ?, ?, ?)
            ''', (alarm_id, 'SILENCED', 'operator', 'Alarm temporarily silenced'))
        
        if escalated:
            cursor.execute('''
                INSERT INTO alarm_logs (alarm_id, action, performed_by, details)
                VALUES (?, ?, ?, ?)
            ''', (alarm_id, 'ESCALATED', 'operator', 'Alarm escalated to supervisor'))
    
    conn.commit()
    
    # Print statistics
    cursor.execute('SELECT COUNT(*) FROM alarms')
    total = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alarms WHERE severity = "critical"')
    critical = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alarms WHERE acknowledged = 1')
    acked = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM alarm_logs')
    logs = cursor.fetchone()[0]
    
    print(f"\n✅ Database populated successfully!")
    print(f"   Total alarms: {total}")
    print(f"   Critical alarms: {critical}")
    print(f"   Acknowledged alarms: {acked}")
    print(f"   Total log entries: {logs}")
    
    conn.close()

if __name__ == '__main__':
    populate_database()
