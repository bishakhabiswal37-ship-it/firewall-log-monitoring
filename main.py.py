import pandas as pd
import sqlite3
import matplotlib.pyplot as plt
import hashlib
import os

CSV_FILE = "firewall_logs.csv"

def get_file_hash(filename):
    with open(filename, "rb") as file:
        return hashlib.md5(file.read()).hexdigest()

conn = sqlite3.connect("firewall.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    date TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    action TEXT,
    total_bytes INTEGER,
    count INTEGER,
    PRIMARY KEY (date, source_ip, destination_ip, action)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS processed_files (
    file_name TEXT,
    file_hash TEXT PRIMARY KEY
)
""")

file_hash = get_file_hash(CSV_FILE)

cursor.execute("SELECT * FROM processed_files WHERE file_hash=?", (file_hash,))
already_done = cursor.fetchone()

if already_done:
    print("This CSV file was already processed. No duplicate data added.")
else:
    df = pd.read_csv(CSV_FILE)

    for _, row in df.iterrows():
        cursor.execute("""
        SELECT total_bytes, count FROM logs
        WHERE date=? AND source_ip=? AND destination_ip=? AND action=?
        """, (row['date'], row['source_ip'], row['destination_ip'], row['action']))

        result = cursor.fetchone()

        if result:
            new_bytes = result[0] + row['bytes']
            new_count = result[1] + 1

            cursor.execute("""
            UPDATE logs
            SET total_bytes=?, count=?
            WHERE date=? AND source_ip=? AND destination_ip=? AND action=?
            """, (new_bytes, new_count, row['date'], row['source_ip'], row['destination_ip'], row['action']))

        else:
            cursor.execute("""
            INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?)
            """, (row['date'], row['source_ip'], row['destination_ip'], row['action'], row['bytes'], 1))

    cursor.execute("""
    INSERT INTO processed_files VALUES (?, ?)
    """, (CSV_FILE, file_hash))

    conn.commit()
    print("New CSV file processed successfully!")

df_db = pd.read_sql_query("SELECT * FROM logs", conn)
print(df_db)

df_graph = pd.read_sql_query("""
SELECT action, SUM(count) as total
FROM logs
GROUP BY action
""", conn)

plt.bar(df_graph['action'], df_graph['total'])
plt.title("Allowed vs Denied Traffic")
plt.xlabel("Action")
plt.ylabel("Count")
plt.show()

# Suspicious IP detection
df_suspicious = pd.read_sql_query("""
SELECT source_ip, SUM(count) as deny_count
FROM logs
WHERE action='DENY'
GROUP BY source_ip
HAVING deny_count >= 1
""", conn)

print("\n🚨 Suspicious IPs (High DENY activity):")
print(df_suspicious)

conn.close()