import sqlite3


def get_db():  # pragma: no cover -- monkeypatched in tests; uses hardcoded path
    conn = sqlite3.connect('xlsvc.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = sqlite3.connect('xlsvc.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Files table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_size INTEGER,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processed BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Add job tracking table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS processing_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            original_file_id INTEGER,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            result_file_id INTEGER,
            error_message TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (original_file_id) REFERENCES files (id),
            FOREIGN KEY (result_file_id) REFERENCES files (id)
        )
    ''')

    # Add file_hash column if it doesn't exist
    try:
        cursor.execute('ALTER TABLE files ADD COLUMN file_hash TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Add file_type column to categorize files
    try:
        cursor.execute('ALTER TABLE files ADD COLUMN file_type TEXT DEFAULT "original"')
    except sqlite3.OperationalError:
        pass

    try:
        # Add parent_file_id to files table
        cursor.execute('''
            ALTER TABLE files ADD COLUMN parent_file_id INTEGER
        ''')
        print("✅ Added parent_file_id to files table")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("⚠️  parent_file_id column already exists")
        else:
            raise  # pragma: no cover -- unexpected DB error
    
    try:
        # Add deleted_rows to processing_jobs table
        cursor.execute('''
            ALTER TABLE processing_jobs ADD COLUMN deleted_rows INTEGER DEFAULT 0
        ''')
        print("✅ Added deleted_rows to processing_jobs table")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("⚠️  deleted_rows column already exists")
        else:
            raise  # pragma: no cover -- unexpected DB error
    
    try:
        # Add filter_rules_json to processing_jobs table
        cursor.execute('''
            ALTER TABLE processing_jobs ADD COLUMN filter_rules_json TEXT
        ''')
        print("✅ Added filter_rules_json to processing_jobs table")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("⚠️  filter_rules_json column already exists")
        else:
            raise  # pragma: no cover -- unexpected DB error
    
    # Add report_file_id column to processing_jobs
    try:
        cursor.execute('ALTER TABLE processing_jobs ADD COLUMN report_file_id INTEGER')
        print("✅ Added report_file_id column to processing_jobs")
    except sqlite3.OperationalError as e:
        if "duplicate column name" not in str(e):
            raise  # pragma: no cover -- unexpected DB error
        print("⚠️  report_file_id column already exists")

    # Subscribers table for email signups (used by landing.html form)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            notified_at TEXT DEFAULT NULL
        )
    ''')

    # Add is_admin column to users table
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0')
        print("✅ Added is_admin column to users table")
        
        # Mark first user (lowest ID) as admin
        first_user = cursor.execute('SELECT id FROM users ORDER BY id ASC LIMIT 1').fetchone()
        if first_user:
            cursor.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (first_user[0],))
            print(f"✅ Marked first user (ID: {first_user[0]}) as admin")
    except sqlite3.OperationalError as e:
        if "duplicate column name" not in str(e):
            raise  # pragma: no cover -- unexpected DB error
        print("⚠️  is_admin column already exists")

    # Invitation tokens table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS invitation_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used_at TIMESTAMP DEFAULT NULL,
            created_by TEXT
        )
    ''')
    print("✅ Created invitation_tokens table")

    conn.commit()
    conn.close()

    print("\n✅ Database migration complete!")
