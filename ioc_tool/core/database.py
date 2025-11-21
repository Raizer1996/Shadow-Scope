import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ioc.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table: iocs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            tags TEXT
        )
    ''')
    
    # Table: enrichments
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS enrichments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_id INTEGER,
            source TEXT,
            data TEXT,
            timestamp TIMESTAMP,
            score INTEGER,
            FOREIGN KEY (ioc_id) REFERENCES iocs (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def add_or_update_ioc(value, ioc_type, tags=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()
    
    cursor.execute('SELECT id, first_seen FROM iocs WHERE value = ?', (value,))
    row = cursor.fetchone()
    
    if row:
        ioc_id = row['id']
        cursor.execute('''
            UPDATE iocs SET last_seen = ?, tags = ? WHERE id = ?
        ''', (now, json.dumps(tags) if tags else None, ioc_id))
    else:
        cursor.execute('''
            INSERT INTO iocs (value, type, first_seen, last_seen, tags)
            VALUES (?, ?, ?, ?, ?)
        ''', (value, ioc_type, now, now, json.dumps(tags) if tags else None))
        ioc_id = cursor.lastrowid
        
    conn.commit()
    conn.close()
    return ioc_id

def get_ioc_id(value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM iocs WHERE value = ?', (value,))
    row = cursor.fetchone()
    conn.close()
    return row['id'] if row else None

def add_enrichment(ioc_id, source, data, score):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now()
    
    cursor.execute('''
        INSERT INTO enrichments (ioc_id, source, data, timestamp, score)
        VALUES (?, ?, ?, ?, ?)
    ''', (ioc_id, source, json.dumps(data), now, score))
    
    conn.commit()
    conn.close()

def get_latest_enrichment(ioc_id, source):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM enrichments 
        WHERE ioc_id = ? AND source = ? 
        ORDER BY timestamp DESC LIMIT 1
    ''', (ioc_id, source))
    
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None
