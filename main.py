from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime, timedelta
import uuid
from openpyxl import load_workbook
import hashlib
import requests
import secrets
import jwt as jwt_lib
import time
import json

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['MACROS_FOLDER'] = 'macros'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Initialize extensions
CORS(app, origins=['http://localhost:5173', 'https://xlsvc.jsilverman.ca'])
jwt = JWTManager(app)

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

# Ensure all directories exist
def ensure_directories():
    """Create all necessary directories"""
    dirs = [
        app.config['UPLOAD_FOLDER'],
        app.config['PROCESSED_FOLDER'], 
        app.config['MACROS_FOLDER']
    ]
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)

def get_file_path(file_type, filename):
    """Get the correct storage path based on file type"""
    if file_type == 'original' or file_type is None:
        return os.path.join(app.config['UPLOAD_FOLDER'], filename)
    elif file_type == 'processed':
        return os.path.join(app.config['PROCESSED_FOLDER'], filename)
    elif file_type in ['macro', 'instructions']:
        return os.path.join(app.config['MACROS_FOLDER'], filename)
    else:
        return os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
def generate_download_token(file_id, user_id, expires_in_minutes=30):
    """Generate a temporary download token for GitHub Actions"""
    payload = {
        'file_id': file_id,
        'user_id': user_id,
        'exp': int(time.time()) + (expires_in_minutes * 60),
        'iat': int(time.time()),
        'purpose': 'download'
    }
    
    secret = app.config['JWT_SECRET_KEY']
    return jwt_lib.encode(payload, secret, algorithm='HS256')

def verify_download_token(token):
    """Verify and decode download token"""
    try:
        secret = app.config['JWT_SECRET_KEY']
        payload = jwt_lib.decode(token, secret, algorithms=['HS256'])
        
        # Check if token is for download purpose
        if payload.get('purpose') != 'download':
            return None
            
        return payload
    except jwt_lib.ExpiredSignatureError:
        print("DEBUG: Download token expired")
        return None
    except jwt_lib.InvalidTokenError as e:
        print(f"DEBUG: Invalid download token: {e}")
        return None

# Database setup
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
            raise
    
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
            raise
    
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
            raise
    
    conn.commit()
    conn.close()

    print("\n✅ Database migration complete!")

# Initialize database on startup
init_db()
ensure_directories()

# Helper functions
def get_db():
    conn = sqlite3.connect('xlsvc.db')
    conn.row_factory = sqlite3.Row
    return conn

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'xls', 'xlsx'}

def evaluate_cell_value(cell):
    """
    Get the actual value of a cell, evaluating formulas if necessary.
    Returns the calculated value for formulas, or the raw value otherwise.
    """
    # If the cell has a formula, try to get the calculated value
    if hasattr(cell, 'value'):
        value = cell.value
        
        # If it's a formula (starts with =), we need the calculated value
        # In openpyxl, if data_only=True is used when loading, we get calculated values
        # Otherwise, we need to handle it differently
        
        # For now, if it's a string starting with =, we'll need special handling
        if isinstance(value, str) and value.startswith('='):
            # OpenPyXL doesn't calculate formulas by default
            # We'll need to use the data_only mode or treat formulas as non-empty
            # For this use case, we'll treat any formula as "non-empty"
            # unless we reload with data_only=True
            return None  # Return None to indicate we need data_only mode
        
        return value
    return None

def is_empty_or_zero(val):
    """
    Check if a value is empty, None, zero, or blank.
    Handles various data types appropriately.
    """
    if val is None:
        return True
    if val == 0:
        return True
    if val == "":
        return True
    if isinstance(val, str) and val.strip() == '':
        return True
    if isinstance(val, str) and val.strip() == '0':
        return True
    # Check for formulas that might evaluate to 0
    # This would require formula evaluation which openpyxl doesn't do by default
    return False

# Authentication endpoints
@app.route('/api/register', methods=['POST'])
def register():
    return jsonify({'error': 'Registration is currently disabled'}), 403

    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        password_hash = generate_password_hash(password)
        
        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (email, password_hash) VALUES (?, ?)',
                (email, password_hash)
            )
            conn.commit()
            
            # Create access token
            access_token = create_access_token(identity=email)
            
            return jsonify({
                'message': 'User registered successfully',
                'access_token': access_token
            }), 201
            
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Email already registered'}), 409
        finally:
            conn.close()
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            access_token = create_access_token(identity=email)
            return jsonify({
                'message': 'Login successful',
                'access_token': access_token
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# File upload endpoint
@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload_file():
    try:
        current_user_email = get_jwt_identity()
        
        # Get user ID
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE email = ?', (current_user_email,)
        ).fetchone()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user_id = user['id']
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Only .xls and .xlsx files allowed'}), 400
        
        # Generate unique filename for storage
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        stored_filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
        
        # Save file temporarily to calculate hash
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        file_hash = calculate_file_hash(file_path)
        
        # Check if this exact file already exists for this user
        existing_file = conn.execute(
            '''SELECT id, original_filename FROM files 
               WHERE user_id = ? AND file_hash = ? AND original_filename = ?''',
            (user_id, file_hash, original_filename)
        ).fetchone()
        
        if existing_file:
            # Delete the newly uploaded duplicate
            os.remove(file_path)
            conn.close()
            
            return jsonify({
                'message': 'File already exists',
                'file_id': existing_file['id'],
                'filename': existing_file['original_filename'],
                'duplicate': True
            }), 200
        
        # Save to database with hash
        file_id = conn.execute(
            '''INSERT INTO files (user_id, original_filename, stored_filename, file_size, file_hash, file_type) 
            VALUES (?, ?, ?, ?, ?, ?)''',
            (user_id, original_filename, stored_filename, file_size, file_hash, 'original')
        ).lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'filename': original_filename,
            'size': file_size,
            'duplicate': False
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get user's files
@app.route('/api/files', methods=['GET'])
@jwt_required()
def get_files():
    try:
        current_user_email = get_jwt_identity()
        
        conn = get_db()
        
        # Get only ORIGINAL files
        files = conn.execute(
            '''SELECT f.* FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE u.email = ? AND (f.file_type = 'original' OR f.file_type IS NULL)
            ORDER BY f.upload_date DESC''',
            (current_user_email,)
        ).fetchall()
    
        # Convert to list of dictionaries and check if files exist on disk
        valid_files = []
        for file in files:
            file_dict = dict(file)
            stored_filename = file_dict.get('stored_filename', '')
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
            
            # Only include files that actually exist on disk
            if stored_filename and os.path.exists(file_path):
                valid_files.append(file_dict)
            else:
                print(f"DEBUG: File not found on disk: {file_path}")
        
        conn.close()
        
        return jsonify({
            'files': valid_files
        }), 200
        
    except Exception as e:
        print(f"DEBUG: get_files error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# Update the process endpoint to use proper file organization
@app.route('/api/process/<int:file_id>', methods=['POST'])
@jwt_required()
def process_file(file_id):
    try:
        current_user_email = get_jwt_identity()
        
        # NEW: Get filter rules from request body
        data = request.get_json() or {}
        filter_rules = data.get('filter_rules', [])
        
        # Validate filter rules
        if not filter_rules or len(filter_rules) == 0:
            return jsonify({
                'error': 'filter_rules required and must be a non-empty array'
            }), 400
        
        print(f"DEBUG: Manual processing with {len(filter_rules)} filter rules")
        for rule in filter_rules:
            print(f"DEBUG: Rule: Column {rule.get('column')} = '{rule.get('value')}'")
        
        # Get file info and verify ownership
        conn = get_db()
        file_info = conn.execute(
            '''SELECT f.* FROM files f
               JOIN users u ON f.user_id = u.id
               WHERE f.id = ? AND u.email = ?''',
            (file_id, current_user_email)
        ).fetchone()
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        file_dict = dict(file_info)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file_dict['stored_filename'])
        
        if not os.path.exists(input_path):
            return jsonify({'error': 'File not found on disk'}), 404
        
        # Analyze the Excel file to find rows to delete
        processing_log = []
        rows_to_delete_by_sheet = {}
        total_rows_to_delete = 0
        
        try:
            wb_calc = load_workbook(input_path, data_only=True)
            
            for sheet_name in wb_calc.sheetnames:
                sheet = wb_calc[sheet_name]
                processing_log.append(f"Analyzing sheet: {sheet_name}")
                
                rows_to_delete = []
                max_row = sheet.max_row
                
                for row_num in range(1, max_row + 1):
                    # NEW: Check columns dynamically based on filter_rules
                    all_match = True
                    
                    for rule in filter_rules:
                        column = rule.get('column')
                        expected_value = rule.get('value')
                        
                        # Convert column letter/number to index
                        col_index = column_to_index(column)
                        
                        # Get cell value
                        cell_val = sheet.cell(row=row_num, column=col_index).value
                        
                        # Check if matches the rule
                        if not is_empty_or_zero(cell_val) if expected_value == '0' else cell_val != expected_value:
                            all_match = False
                            break
                    
                    if all_match:
                        rows_to_delete.append(row_num)
                        if len(rows_to_delete) <= 5:
                            processing_log.append(f"Row {row_num} marked for deletion")
                
                if len(rows_to_delete) > 5:
                    processing_log.append(f"... and {len(rows_to_delete) - 5} more rows")
                
                if rows_to_delete:
                    rows_to_delete_by_sheet[sheet_name] = rows_to_delete
                    total_rows_to_delete += len(rows_to_delete)
                    processing_log.append(f"Found {len(rows_to_delete)} rows to delete in '{sheet_name}'")
                else:
                    processing_log.append(f"No rows to delete in '{sheet_name}'")
            
            wb_calc.close()
            
            if total_rows_to_delete == 0:
                return jsonify({
                    'message': 'No rows found for deletion',
                    'total_rows_to_delete': 0,
                    'processing_log': processing_log + ["Analysis complete - no changes needed"]
                }), 200
            
            # NEW: Pass filter_rules to macro generator
            macro_content = generate_libreoffice_macro(
                file_dict['original_filename'], 
                rows_to_delete_by_sheet,
                filter_rules  # ← Add this parameter
            )
            
            # Save macro file
            macro_filename = f"macro_{uuid.uuid4().hex[:8]}.bas"
            macro_path = os.path.join(app.config['MACROS_FOLDER'], macro_filename)
            
            with open(macro_path, 'w', encoding='utf-8') as f:
                f.write(macro_content)
            
            # Generate instruction guide
            instructions = generate_instructions(
                file_dict['original_filename'],
                total_rows_to_delete,
                list(rows_to_delete_by_sheet.keys()),
                filter_rules  # ← Add this parameter
            )
            
            instructions_filename = f"instructions_{uuid.uuid4().hex[:8]}.txt"
            instructions_path = os.path.join(app.config['MACROS_FOLDER'], instructions_filename)
            
            with open(instructions_path, 'w', encoding='utf-8') as f:
                f.write(instructions)
            
            # Record in database
            macro_file_id = conn.execute(
                '''INSERT INTO files (user_id, original_filename, stored_filename, file_size, processed, file_type) 
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (file_dict['user_id'], f"Macro_{file_dict['original_filename']}.bas", 
                 macro_filename, os.path.getsize(macro_path), True, 'macro')
            ).lastrowid
            
            instructions_file_id = conn.execute(
                '''INSERT INTO files (user_id, original_filename, stored_filename, file_size, processed, file_type) 
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (file_dict['user_id'], f"Instructions_{file_dict['original_filename']}.txt", 
                 instructions_filename, os.path.getsize(instructions_path), True, 'instructions')
            ).lastrowid
            
            conn.execute('UPDATE files SET processed = TRUE WHERE id = ?', (file_id,))
            conn.commit()
            conn.close()
            
            processing_log.append("Analysis complete - macro and instructions generated")
            
            return jsonify({
                'message': 'Analysis complete',
                'total_rows_to_delete': total_rows_to_delete,
                'sheets_affected': list(rows_to_delete_by_sheet.keys()),
                'processing_log': processing_log,
                'downloads': {
                    'macro': {
                        'file_id': macro_file_id,
                        'filename': f"Macro_{file_dict['original_filename']}.bas"
                    },
                    'instructions': {
                        'file_id': instructions_file_id,
                        'filename': f"Instructions_{file_dict['original_filename']}.txt"
                    }
                }
            }), 200
            
        except Exception as processing_error:
            processing_log.append(f"Analysis error: {str(processing_error)}")
            return jsonify({
                'error': f'Analysis failed: {str(processing_error)}',
                'processing_log': processing_log
            }), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def column_to_index(col):
    """Convert column letter (A, F, Z) or number (1, 6, 26) to 1-based column index"""
    col = str(col).strip().upper()
    
    # If it's already a number, return it as int
    if col.isdigit():
        return int(col)
    
    # Convert letter(s) to number (A=1, B=2, ... Z=26, AA=27, etc.)
    index = 0
    for char in col:
        if char.isalpha():
            index = index * 26 + (ord(char) - ord('A') + 1)
    return index

def generate_libreoffice_macro(original_filename, rows_to_delete_by_sheet, filter_rules=None):
    """Generate a LibreOffice Calc macro that deletes rows"""
    # The macro code stays the same - it just deletes the specific rows identified
    # No changes needed to the macro itself
    
    macro_header = f'''REM Macro generated to clean up: {original_filename}
REM Generated on: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC
Option Explicit

Private Sub _SafeSetEnable(oController As Object, enabled As Boolean)
    On Error Resume Next
    If Not oController Is Nothing Then
        Dim oFrame As Object, oWin As Object
        oFrame = oController.getFrame()
        If Not oFrame Is Nothing Then
            oWin = oFrame.getContainerWindow()
            If Not oWin Is Nothing Then
                oWin.setEnable(enabled)
            End If
        End If
    End If
    On Error GoTo 0
End Sub

Private Sub _SaveAndQuit(oDoc As Object)
    On Error Resume Next
    If Not oDoc Is Nothing Then
        oDoc.store                 ' save in place (keeps XLSX)
        oDoc.close(True)           ' close without prompts
    End If
    StarDesktop.terminate          ' end soffice process
    On Error GoTo 0
End Sub

Sub DeleteEmptyRows()
    On Error GoTo EH

    Dim oDoc As Object, oController As Object, oSheet As Object
    Dim rowsDeleted As Long
    oDoc = ThisComponent
    oController = oDoc.getCurrentController()
    rowsDeleted = 0

    _SafeSetEnable oController, False   ' ok in headless (no-op if not available)
'''

    # Build the per-sheet deletion body
    macro_body = ""
    for sheet_name, rows in rows_to_delete_by_sheet.items():
        sorted_rows = sorted(rows, reverse=True)  # delete bottom-up

        # Compact consecutive runs for fewer removeByIndex calls
        row_groups = []
        if sorted_rows:
            grp = [sorted_rows[0]]
            for r in sorted_rows[1:]:
                if r == grp[-1] - 1:
                    grp.append(r)
                else:
                    row_groups.append(grp)
                    grp = [r]
            row_groups.append(grp)

        macro_body += f'''
    ' Process sheet: {sheet_name}
    If oDoc.Sheets.hasByName("{sheet_name}") Then
        oSheet = oDoc.Sheets.getByName("{sheet_name}")
'''

        for grp in row_groups:
            start_row = min(grp)
            count = len(grp)
            # LibreOffice Basic uses 0-based index for removeByIndex
            macro_body += f'''        oSheet.Rows.removeByIndex({start_row - 1}, {count})
        rowsDeleted = rowsDeleted + {count}
'''

        macro_body += '''    End If
'''

    macro_footer = '''
    _SafeSetEnable oController, True
    _SaveAndQuit oDoc
    Exit Sub

EH:
    ' Write a minimal error log to home dir (read by workflow)
    On Error Resume Next
    Dim f As Integer
    f = FreeFile()
    Open Environ("HOME") & "/macro.log" For Append As #f
    Print #f, "Error " & Err & ": " & Error$ & " at " & Now
    Close #f
    _SafeSetEnable oController, True
    _SaveAndQuit oDoc
End Sub
'''

    return macro_header + macro_body + macro_footer

def generate_instructions(original_filename, total_rows, sheet_names, filter_rules):
    """Generate step-by-step instructions for using the macro"""
    
    # Build filter description
    filter_desc = "These rows match ALL of the following conditions:\n"
    for rule in filter_rules:
        if rule['value'] == '0':
            filter_desc += f"  • Column {rule['column']} is empty or zero\n"
        else:
            filter_desc += f"  • Column {rule['column']} equals '{rule['value']}'\n"
    
    return f"""EXCEL FILE CLEANUP INSTRUCTIONS
Generated for: {original_filename}
Generated on: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC

=== SUMMARY ===
Analysis found {total_rows} rows to be deleted across {len(sheet_names)} sheet(s):
{chr(10).join(f"• {sheet}" for sheet in sheet_names)}

{filter_desc}

=== METHOD 1: LIBREOFFICE CALC MACRO (RECOMMENDED) ===

1. BACKUP YOUR FILE FIRST!
   - Make a copy of your original Excel file before proceeding

2. Download the macro file:
   - Click "Download Macro" button in the web interface
   - Save the .bas file to your computer

3. Open your Excel file in LibreOffice Calc:
   - Download LibreOffice (free) if you don't have it: https://www.libreoffice.org/download/
   - Open your Excel file in LibreOffice Calc

4. Import and run the macro:
   - Go to Tools → Macros → Organize Macros → LibreOffice Basic
   - Click "New" to create a new module
   - Delete the default code and paste the macro content
   - Click "Run" (or press F5)
   - The macro will show progress and completion message

5. Save your file:
   - File → Save (keeps Excel format)
   - Or File → Save As to choose a different name/format

=== METHOD 2: MANUAL DELETION ===

If you prefer to delete rows manually, here's what to look for:
- Find rows where columns F, G, H, and I are ALL empty or contain only zeros
- Delete these entire rows
- Work from bottom to top to avoid row number changes

Sheet-by-sheet breakdown:
{chr(10).join(f"• {sheet}: rows to review and potentially delete" for sheet in sheet_names)}

=== IMPORTANT NOTES ===
- This process will preserve all images, charts, and formatting
- The macro deletes entire rows, not just cell contents
- Always backup your file before making changes
- If you encounter issues, you can restore from your backup

=== SUPPORT ===
If you need help or encounter issues:
1. Make sure you have LibreOffice Calc installed
2. Check that macros are enabled in LibreOffice
3. Ensure you're pasting the complete macro code
4. Try the manual method if the macro doesn't work

Generated by Excel Processor Tool
"""


@app.route('/api/download-with-token/<int:file_id>', methods=['GET'])
def download_file_with_token(file_id):
    """Download file using temporary token (for GitHub Actions)"""
    try:
        # Get token from query parameter or Authorization header
        token = request.args.get('token')
        if not token:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            return jsonify({'error': 'Download token required'}), 401
        
        # Verify the token
        token_payload = verify_download_token(token)
        if not token_payload:
            return jsonify({'error': 'Invalid or expired download token'}), 401
        
        # Check if token is for this specific file
        if token_payload.get('file_id') != file_id:
            return jsonify({'error': 'Token not valid for this file'}), 403
        
        # Get file info
        conn = get_db()
        file_info = conn.execute(
            '''SELECT * FROM files WHERE id = ? AND user_id = ?''',
            (file_id, token_payload.get('user_id'))
        ).fetchone()
        conn.close()
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Get correct file path based on type
        file_dict = dict(file_info)
        file_path = get_file_path(
            file_dict.get('file_type'),
            file_dict['stored_filename']
        )
        
        if not os.path.exists(file_path):
            print(f"DEBUG: Removing missing file from DB: {stored_filename}")
            
            # Get file_type from the dict
            file_type = file_dict.get('file_type') or 'original'
            
            # NEW: Delete related processing jobs FIRST (before deleting file)
            if file_type == 'processed':
                conn.execute(
                    'DELETE FROM processing_jobs WHERE result_file_id = ?',
                    (file_dict['id'],)
                )
                print(f"DEBUG: Deleted processing job for file_id {file_dict['id']}")
            
            # Then delete the file record
            conn.execute('DELETE FROM files WHERE id = ?', (file_dict['id'],))
            removed_count += 1
        
        # Determine MIME type
        original_filename = file_info['original_filename']
        if original_filename.endswith(('.xlsx', '.xls')):
            mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        else:
            mimetype = 'application/octet-stream'
            
        print(f"DEBUG: Serving file via token: {file_path}")
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=original_filename,
            mimetype=mimetype
        )
        
    except Exception as e:
        print(f"DEBUG: Token download error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<int:file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    try:
        current_user_email = get_jwt_identity()
        
        # Get file info and verify ownership
        conn = get_db()
        file_info = conn.execute(
            '''SELECT f.* FROM files f
               JOIN users u ON f.user_id = u.id
               WHERE f.id = ? AND u.email = ?''',
            (file_id, current_user_email)
        ).fetchone()
        conn.close()
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
        
        # Get correct file path based on type
        file_dict = dict(file_info)
        file_path = get_file_path(
            file_dict.get('file_type'),
            file_dict['stored_filename']
        )
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on disk'}), 404
        
        # Determine MIME type based on file extension
        original_filename = file_info['original_filename']
        if original_filename.endswith('.bas'):
            mimetype = 'text/plain'
        elif original_filename.endswith('.txt'):
            mimetype = 'text/plain'
        elif original_filename.endswith(('.xlsx', '.xls')):
            mimetype = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        else:
            mimetype = 'application/octet-stream'
            
        return send_file(
            file_path,
            as_attachment=True,
            download_name=original_filename,
            mimetype=mimetype
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add file cleanup and sync endpoints
@app.route('/api/cleanup-files', methods=['POST'])
@jwt_required()
def cleanup_files():
    """Remove database entries for files AND their jobs that no longer exist on disk"""
    try:
        current_user_email = get_jwt_identity()
        
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE email = ?', (current_user_email,)
        ).fetchone()
        
        files = conn.execute(
            'SELECT id, stored_filename, file_type FROM files WHERE user_id = ?', 
            (user['id'],)
        ).fetchall()
        
        removed_count = 0
        for file in files:
            file_dict = dict(file)
            file_type = file_dict.get('file_type') or 'original'
            stored_filename = file_dict.get('stored_filename', '')
            
            if file_type == 'original':
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
            elif file_type == 'processed':
                file_path = os.path.join(app.config['PROCESSED_FOLDER'], stored_filename)
            elif file_type in ['macro', 'instructions']:
                file_path = os.path.join(app.config['MACROS_FOLDER'], stored_filename)
            else:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
            
            if not os.path.exists(file_path):
                print(f"DEBUG: Removing missing file from DB: {stored_filename}")
                
                # NEW: Also delete related processing jobs
                if file_type == 'processed':
                    # Delete jobs that produced this file
                    conn.execute(
                        'DELETE FROM processing_jobs WHERE result_file_id = ?',
                        (file_dict['id'],)
                    )
                
                # Delete the file record
                conn.execute('DELETE FROM files WHERE id = ?', (file_dict['id'],))
                removed_count += 1
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': f'Cleaned up {removed_count} missing files and their jobs',
            'removed_count': removed_count
        }), 200
        
    except Exception as e:
        print(f"DEBUG: cleanup_files error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add admin endpoint to see file organization
@app.route('/api/debug/storage', methods=['GET'])
@jwt_required()
def debug_storage():
    """Debug endpoint to see file organization"""
    try:
        current_user_email = get_jwt_identity()
        
        # Get storage info
        storage_info = {
            'uploads': [],
            'processed': [],
            'macros': []
        }
        
        # List files in each directory
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            storage_info['uploads'] = os.listdir(app.config['UPLOAD_FOLDER'])
        
        if os.path.exists(app.config['PROCESSED_FOLDER']):
            storage_info['processed'] = os.listdir(app.config['PROCESSED_FOLDER'])
            
        if os.path.exists(app.config['MACROS_FOLDER']):
            storage_info['macros'] = os.listdir(app.config['MACROS_FOLDER'])
        
        # Get database info
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE email = ?', (current_user_email,)
        ).fetchone()
        
        db_files = conn.execute(
            '''SELECT id, original_filename, stored_filename, file_type, processed
               FROM files WHERE user_id = ?
               ORDER BY upload_date DESC''',
            (user['id'],)
        ).fetchall()
        
        conn.close()
        
        return jsonify({
            'user': current_user_email,
            'storage_folders': storage_info,
            'database_files': [dict(f) for f in db_files]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/test-github', methods=['GET'])
@jwt_required()
def test_github_auth():
    """Test GitHub App authentication"""
    try:
        print("DEBUG: Testing GitHub App authentication...")
        
        # Check environment variables
        app_id = os.getenv('GITHUB_APP_ID')
        private_key = os.getenv('GITHUB_PRIVATE_KEY', '').replace('\\n', '\n')
        installation_id = os.getenv('GITHUB_INSTALLATION_ID')
        github_repo = os.getenv('GITHUB_REPO', 'jewseppi/xlsvc')
        
        env_status = {
            'app_id': bool(app_id),
            'private_key': bool(private_key),
            'installation_id': bool(installation_id),
            'github_repo': github_repo
        }
        
        print(f"DEBUG: Environment variables: {env_status}")
        
        if not all([app_id, private_key, installation_id]):
            return jsonify({
                'status': 'error',
                'error': 'Missing required environment variables',
                'env_status': env_status
            }), 400
        
        # Test GitHub App authentication
        github_auth = GitHubAppAuth()
        
        # Test JWT generation
        app_token = github_auth.get_app_token()
        print(f"DEBUG: Generated app token: {app_token[:50]}...")
        
        # Test installation token
        installation_token = github_auth.get_installation_token()
        print(f"DEBUG: Generated installation token: {installation_token[:50]}...")
        
        # Test repository access
        headers = {
            'Authorization': f'Bearer {installation_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Excel-Processor-App/1.0'
        }
        
        # Check if we can access the repository
        repo_url = f'https://api.github.com/repos/{github_repo}'
        print(f"DEBUG: Testing repo access: {repo_url}")
        
        repo_response = requests.get(repo_url, headers=headers, timeout=10)
        print(f"DEBUG: Repo access response: {repo_response.status_code}")
        
        if repo_response.status_code == 200:
            repo_data = repo_response.json()
            return jsonify({
                'status': 'success',
                'message': 'GitHub App authentication working',
                'env_status': env_status,
                'repo_access': True,
                'repo_name': repo_data.get('full_name'),
                'repo_private': repo_data.get('private'),
                'app_token_length': len(app_token),
                'installation_token_length': len(installation_token)
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'error': 'Cannot access repository',
                'env_status': env_status,
                'repo_response_code': repo_response.status_code,
                'repo_response_text': repo_response.text
            }), 400
            
    except Exception as e:
        print(f"DEBUG: GitHub test error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500
    
@app.route('/api/test-dispatch', methods=['POST'])
@jwt_required()
def test_dispatch():
    """Test GitHub repository dispatch specifically"""
    try:
        print("DEBUG: Testing GitHub repository dispatch...")
        
        # Get GitHub token
        github_auth = GitHubAppAuth()
        github_token = github_auth.get_installation_token()
        github_repo = os.getenv('GITHUB_REPO', 'jewseppi/xlsvc')
        
        print(f"DEBUG: Using repo: {github_repo}")
        print(f"DEBUG: Token length: {len(github_token)}")
        
        # Test payload - minimal test dispatch
        test_payload = {
            "event_type": "test-connection",
            "client_payload": {
                "test": True,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        headers = {
            'Authorization': f'Bearer {github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
            'User-Agent': 'Excel-Processor-App/1.0'
        }
        
        dispatch_url = f'https://api.github.com/repos/{github_repo}/dispatches'
        print(f"DEBUG: Dispatch URL: {dispatch_url}")
        print(f"DEBUG: Headers: {headers}")
        print(f"DEBUG: Payload: {test_payload}")
        
        # First, check if the repo exists and we have access
        repo_url = f'https://api.github.com/repos/{github_repo}'
        repo_response = requests.get(repo_url, headers=headers, timeout=10)
        print(f"DEBUG: Repo check - Status: {repo_response.status_code}")
        
        if repo_response.status_code != 200:
            return jsonify({
                'status': 'error',
                'error': 'Cannot access repository',
                'repo_status': repo_response.status_code,
                'repo_response': repo_response.text
            }), 400
        
        # Try the dispatch
        response = requests.post(
            dispatch_url,
            headers=headers,
            json=test_payload,
            timeout=30
        )
        
        print(f"DEBUG: Dispatch response status: {response.status_code}")
        print(f"DEBUG: Dispatch response headers: {dict(response.headers)}")
        print(f"DEBUG: Dispatch response text: {response.text}")
        
        # GitHub API permissions check
        if response.status_code == 403:
            # Check what permissions we actually have
            permissions_url = f'https://api.github.com/repos/{github_repo}/installation'
            perm_response = requests.get(permissions_url, headers=headers, timeout=10)
            
            print(f"DEBUG: Permissions check status: {perm_response.status_code}")
            if perm_response.status_code == 200:
                perm_data = perm_response.json()
                print(f"DEBUG: Installation permissions: {perm_data}")
            
        result = {
            'status': 'success' if response.status_code == 204 else 'error',
            'dispatch_status': response.status_code,
            'dispatch_response': response.text,
            'dispatch_headers': dict(response.headers),
            'expected_status': 204,
            'repo_access': True,
            'github_repo': github_repo,
            'test_payload': test_payload
        }
        
        if response.status_code == 204:
            result['message'] = 'Repository dispatch successful'
        else:
            result['error'] = f'Dispatch failed with status {response.status_code}'
            
        return jsonify(result), 200 if response.status_code == 204 else 400
        
    except Exception as e:
        print(f"DEBUG: Test dispatch error: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500
class GitHubAppAuth:
    def __init__(self):
        self.app_id = os.getenv('GITHUB_APP_ID')
        self.private_key = os.getenv('GITHUB_PRIVATE_KEY', '').replace('\\n', '\n')
        self.installation_id = os.getenv('GITHUB_INSTALLATION_ID')
        
        # Validate required environment variables
        if not self.app_id:
            raise ValueError("GITHUB_APP_ID environment variable is required")
        if not self.private_key:
            raise ValueError("GITHUB_PRIVATE_KEY environment variable is required")
        if not self.installation_id:
            raise ValueError("GITHUB_INSTALLATION_ID environment variable is required")
            
        print(f"DEBUG: GitHubAppAuth initialized - App ID: {self.app_id}, Installation: {self.installation_id}")
        
    def get_app_token(self):
        """Generate JWT token for GitHub App"""
        try:
            import jwt as jwt_lib
            
            now = int(time.time())
            payload = {
                'iat': now,
                'exp': now + 600,  # 10 minutes
                'iss': self.app_id
            }
            
            print(f"DEBUG: JWT payload: {payload}")
            print(f"DEBUG: Private key first 100 chars: {self.private_key[:100]}")
            
            # Try to encode the JWT
            token = jwt_lib.encode(payload, self.private_key, algorithm='RS256')
            print(f"DEBUG: Generated JWT token: {token[:50]}...")
            
            return token
            
        except Exception as e:
            print(f"DEBUG: JWT encoding error: {str(e)}")
            print(f"DEBUG: Private key format check:")
            print(f"  - Starts with -----BEGIN: {self.private_key.startswith('-----BEGIN')}")
            print(f"  - Contains PRIVATE KEY: {'PRIVATE KEY' in self.private_key}")
            print(f"  - Ends with -----END: {'-----END' in self.private_key}")
            print(f"  - Length: {len(self.private_key)}")
            raise Exception(f"Failed to generate JWT token: {str(e)}")
    
    def get_installation_token(self):
        """Get installation access token"""
        try:
            app_token = self.get_app_token()
            
            headers = {
                'Authorization': f'Bearer {app_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Excel-Processor-App/1.0'
            }
            
            url = f'https://api.github.com/app/installations/{self.installation_id}/access_tokens'
            print(f"DEBUG: Requesting installation token from: {url}")
            print(f"DEBUG: Headers: {headers}")
            
            response = requests.post(url, headers=headers, timeout=10)
            
            print(f"DEBUG: Installation token response: {response.status_code}")
            print(f"DEBUG: Response headers: {dict(response.headers)}")
            print(f"DEBUG: Response body: {response.text}")
            
            if response.status_code == 201:
                token_data = response.json()
                return token_data['token']
            else:
                raise Exception(f"Failed to get installation token: {response.status_code} {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"DEBUG: Network error getting installation token: {str(e)}")
            raise Exception(f"Network error: {str(e)}")
        except Exception as e:
            print(f"DEBUG: Error getting installation token: {str(e)}")
            raise
        
@app.route('/api/process-automated/<int:file_id>', methods=['POST'])
@jwt_required()
def process_file_automated(file_id):
    """Trigger GitHub Actions processing using GitHub App authentication"""
    print(f"DEBUG: Starting automated processing for file {file_id}")

    try:
        current_user_email = get_jwt_identity()
        print(f"DEBUG: User: {current_user_email}")
        
        # Get filter rules from request body
        data = request.get_json() or {}
        filter_rules = data.get('filter_rules')
        
        # Validate filter rules
        if not filter_rules or not isinstance(filter_rules, list) or len(filter_rules) == 0:
            return jsonify({
                'error': 'filter_rules required and must be a non-empty array'
            }), 400
        
        print(f"DEBUG: Processing with {len(filter_rules)} filter rules")
        for i, rule in enumerate(filter_rules, 1):
            print(f"DEBUG: Rule {i}: Column {rule.get('column')} = '{rule.get('value')}'")
        
        # Get file info and verify ownership
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE email = ?', (current_user_email,)
        ).fetchone()
        
        if not user:
            print("DEBUG: User not found in database")
            return jsonify({'error': 'User not found'}), 404
        
        print(f"DEBUG: User ID: {user['id']}")
        
        file_info = conn.execute(
            '''SELECT f.* FROM files f
               WHERE f.id = ? AND f.user_id = ?''',
            (file_id, user['id'])
        ).fetchone()
        
        if not file_info:
            print("DEBUG: File not found or not owned by user")
            return jsonify({'error': 'File not found'}), 404
            
        print(f"DEBUG: File found: {file_info['original_filename']}")
        
        # Check if file exists on disk
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_filename'])
        if not os.path.exists(input_path):
            print(f"DEBUG: File not found on disk: {input_path}")
            return jsonify({'error': 'File not found on disk'}), 404
        
        file_dict = dict(file_info)
        
        # Create job ID and callback token
        job_id = secrets.token_urlsafe(16)
        callback_token = secrets.token_urlsafe(32)
        
        # Generate download token for the file
        download_token = generate_download_token(file_id, user['id'], expires_in_minutes=30)
        
        print(f"DEBUG: Generated job_id: {job_id}")
        print(f"DEBUG: Generated download token: {download_token[:20]}...")
        
        # Store job in database WITH filter rules
        conn.execute(
            '''INSERT INTO processing_jobs (job_id, user_id, original_file_id, status, filter_rules_json)
               VALUES (?, ?, ?, ?, ?)''',
            (job_id, user['id'], file_id, 'pending', json.dumps(filter_rules))
        )
        conn.commit()
        conn.close()
        
        print("DEBUG: Job stored in database with filter rules")
        
        # Get GitHub credentials
        app_id = os.getenv('GITHUB_APP_ID')
        private_key = os.getenv('GITHUB_PRIVATE_KEY', '').replace('\\n', '\n')
        installation_id = os.getenv('GITHUB_INSTALLATION_ID')
        github_repo = os.getenv('GITHUB_REPO', 'jewseppi/xlsvc')
        
        if not app_id or not private_key or not installation_id:
            return jsonify({
                'error': 'GitHub App configuration missing'
            }), 500
        
        # Get GitHub token
        github_auth = GitHubAppAuth()
        github_token = github_auth.get_installation_token()
        
        # Prepare GitHub Actions payload with filter_rules
        base_url = request.host_url.rstrip('/')
        github_payload = {
            "event_type": "process-excel",
            "client_payload": {
                "file_id": str(file_id),
                "file_url": f"{base_url}/api/download-with-token/{file_id}?token={download_token}",
                "download_token": download_token,
                "callback_url": f"{base_url}/api/processing-callback",
                "callback_token": callback_token,
                "job_id": job_id,
                "filter_rules": json.dumps(filter_rules)
            }
        }
        
        headers = {
            'Authorization': f'Bearer {github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        
        dispatch_url = f'https://api.github.com/repos/{github_repo}/dispatches'
        response = requests.post(
            dispatch_url,
            headers=headers,
            json=github_payload,
            timeout=30
        )
        
        if response.status_code == 204:
            return jsonify({
                'message': 'Processing started via GitHub Actions',
                'job_id': job_id,
                'status': 'pending',
                'estimated_time': '2-3 minutes'
            }), 202
        else:
            return jsonify({
                'error': 'Failed to start GitHub Actions processing',
                'details': response.text
            }), 500
            
    except Exception as e:
        print(f"DEBUG: Exception in process_file_automated: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/processing-callback', methods=['POST'])
def processing_callback():
    """Receive results from GitHub Actions"""
    try:
        print("=== PROCESSING CALLBACK RECEIVED ===")
        
        # Check authentication token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        
        if request.content_type and 'application/json' in request.content_type:
            # Status update (failure notification)
            data = request.get_json()
            job_id = data.get('job_id')
            status = data.get('status')
            error = data.get('error')
            
            conn = get_db()
            if status == 'failed':
                conn.execute(
                    '''UPDATE processing_jobs 
                       SET status = ?, error_message = ?
                       WHERE job_id = ?''',
                    ('failed', error, job_id)
                )
                conn.commit()
            conn.close()
            
            return jsonify({'status': 'received'}), 200
            
        else:
            # File upload (success)
            job_id = request.form.get('job_id')
            uploaded_file = request.files.get('file')
            deleted_rows = request.form.get('deleted_rows', 0)  # Get deleted_rows from form
            
            print(f"File upload: job_id={job_id}, deleted_rows={deleted_rows}")
            
            if not job_id or not uploaded_file:
                return jsonify({'error': 'Missing job_id or file'}), 400
            
            # Save the processed file
            file_extension = 'xlsx'
            output_filename = f"processed_{uuid.uuid4().hex[:8]}.{file_extension}"
            output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_filename)
            
            uploaded_file.save(output_path)
            file_size = os.path.getsize(output_path)
            print(f"File saved: {output_path}, size: {file_size} bytes")
            
            # Update database
            conn = get_db()
            
            # Get the job info
            job = conn.execute(
                'SELECT * FROM processing_jobs WHERE job_id = ?', (job_id,)
            ).fetchone()
            
            if not job:
                conn.close()
                return jsonify({'error': 'Job not found'}), 404
            
            # Get original filename
            original_file = conn.execute(
                'SELECT original_filename FROM files WHERE id = ?',
                (job['original_file_id'],)
            ).fetchone()
            
            original_filename = original_file['original_filename'] if original_file else 'processed.xlsx'
            processed_filename = f"processed_{original_filename}"
            
            # Create file record for the processed file
            # IMPORTANT: Link it to the original file with parent_file_id
            file_id = conn.execute(
                '''INSERT INTO files (user_id, original_filename, stored_filename, file_size, processed, file_type, parent_file_id) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (job['user_id'], processed_filename, output_filename, file_size, True, 'processed', job['original_file_id'])
            ).lastrowid
            
            # Update job status with deleted_rows
            conn.execute(
                '''UPDATE processing_jobs 
                   SET status = ?, result_file_id = ?, deleted_rows = ?
                   WHERE job_id = ?''',
                ('completed', file_id, deleted_rows, job_id)
            )
            
            conn.commit()
            conn.close()
            
            print(f"=== CALLBACK SUCCESSFUL ===")
            print(f"Job {job_id} completed, file_id={file_id}, parent_file_id={job['original_file_id']}, deleted_rows={deleted_rows}")
            
            return jsonify({
                'status': 'success',
                'file_id': file_id,
                'filename': processed_filename
            }), 200
            
    except Exception as e:
        print(f"=== CALLBACK ERROR ===")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<int:file_id>/history', methods=['GET'])
@jwt_required()
def get_file_history(file_id):
    """Get all processed versions of a file"""
    try:
        current_user_email = get_jwt_identity()
        
        conn = get_db()
        
        # Verify user owns the original file
        user = conn.execute(
            'SELECT id FROM users WHERE email = ?', (current_user_email,)
        ).fetchone()
        
        if not user:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        
        # Check if the file exists and belongs to the user
        original_file = conn.execute(
            '''SELECT * FROM files 
               WHERE id = ? AND user_id = ? AND (file_type = 'original' OR file_type IS NULL)''',
            (file_id, user['id'])
        ).fetchone()
        
        if not original_file:
            conn.close()
            return jsonify({'error': 'File not found'}), 404
        
        # Get all processing jobs for this file with their results
        history = conn.execute(
            '''SELECT 
                pj.job_id,
                pj.created_at as processed_at,
                pj.status,
                pj.deleted_rows,
                pj.filter_rules_json,
                pj.result_file_id,
                f.original_filename as processed_filename,
                f.file_size as processed_file_size
               FROM processing_jobs pj
               LEFT JOIN files f ON pj.result_file_id = f.id
               WHERE pj.original_file_id = ? AND pj.user_id = ?
               ORDER BY pj.created_at DESC''',
            (file_id, user['id'])
        ).fetchall()
        
        conn.close()
        
        # Format the history
        history_list = []
        for job in history:
            job_dict = dict(job)
            
            # Parse filter rules if present
            if job_dict.get('filter_rules_json'):
                try:
                    job_dict['filter_rules'] = json.loads(job_dict['filter_rules_json'])
                except:
                    job_dict['filter_rules'] = []
            else:
                job_dict['filter_rules'] = []
            
            history_list.append(job_dict)
        
        return jsonify({
            'original_file': dict(original_file),
            'history': history_list
        }), 200
        
    except Exception as e:
        print(f"ERROR: get_file_history: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/job-status/<job_id>', methods=['GET'])
@jwt_required()
def get_job_status(job_id):
    """Check processing job status"""
    try:
        current_user_email = get_jwt_identity()
        
        conn = get_db()
        user = conn.execute(
            'SELECT id FROM users WHERE email = ?', (current_user_email,)
        ).fetchone()
        
        job = conn.execute(
            '''SELECT pj.*, f.original_filename as result_filename
               FROM processing_jobs pj
               LEFT JOIN files f ON pj.result_file_id = f.id
               WHERE pj.job_id = ? AND pj.user_id = ?''',
            (job_id, user['id'])
        ).fetchone()
        conn.close()
        
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        
        response = {
            'job_id': job['job_id'],
            'status': job['status'],
            'created_at': job['created_at']
        }
        
        if job['status'] == 'completed':
            response['download_file_id'] = job['result_file_id']
            response['download_filename'] = job['result_filename']
        elif job['status'] == 'failed':
            response['error'] = job['error_message']
        
        return jsonify(response), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def analyze_excel_file(input_path):
    """Analyze Excel file to find rows to delete (using your existing logic)"""
    try:
        wb = load_workbook(input_path, data_only=True)
        rows_to_delete_by_sheet = {}
        
        for sheet_name in wb.sheetnames:
            sheet = wb[sheet_name]
            rows_to_delete = []
            
            for row_num in range(1, sheet.max_row + 1):
                f_val = sheet.cell(row=row_num, column=6).value
                g_val = sheet.cell(row=row_num, column=7).value
                h_val = sheet.cell(row=row_num, column=8).value
                i_val = sheet.cell(row=row_num, column=9).value
                
                if (is_empty_or_zero(f_val) and is_empty_or_zero(g_val) and 
                    is_empty_or_zero(h_val) and is_empty_or_zero(i_val)):
                    rows_to_delete.append(row_num)
            
            if rows_to_delete:
                rows_to_delete_by_sheet[sheet_name] = rows_to_delete
        
        wb.close()
        return rows_to_delete_by_sheet
        
    except Exception as e:
        print(f"Analysis error: {e}")
        return {}

@app.route('/api/get-macro/<int:file_id>', methods=['GET'])
def get_macro_for_file(file_id):
    """Get the macro file content for a processed file"""
    try:
        conn = get_db()
        
        # Get the original file info first
        original_file = conn.execute(
            'SELECT user_id, original_filename FROM files WHERE id = ?', 
            (file_id,)
        ).fetchone()
        
        if not original_file:
            return jsonify({'error': 'Original file not found'}), 404
        
        # Find the macro file for this original file
        macro_file = conn.execute(
            '''SELECT stored_filename, original_filename FROM files 
               WHERE user_id = ? AND file_type = 'macro'
               AND original_filename LIKE ?
               ORDER BY upload_date DESC LIMIT 1''',
            (original_file['user_id'], f'Macro_{original_file["original_filename"]}%')
        ).fetchone()
        
        conn.close()
        
        if not macro_file:
            return jsonify({'error': 'Macro not found for this file'}), 404
        
        # Read the macro file content
        macro_path = os.path.join(app.config['MACROS_FOLDER'], macro_file['stored_filename'])
        
        if not os.path.exists(macro_path):
            return jsonify({'error': 'Macro file not found on disk'}), 404
        
        with open(macro_path, 'r', encoding='utf-8') as f:
            macro_content = f.read()
        
        return jsonify({
            'macro_content': macro_content,
            'filename': macro_file['original_filename']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

# Protected route example
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_email = get_jwt_identity()
    return jsonify({'email': current_user_email})

if __name__ == '__main__':
    app.run(debug=True)