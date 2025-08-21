from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import pandas as pd
import os
from datetime import datetime, timedelta
import uuid
import shutil
from openpyxl import load_workbook
from openpyxl.drawing.image import Image as XLImage
from io import BytesIO

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = 'your-secret-key-change-this'  # Change this!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Initialize extensions
CORS(app, origins=['http://localhost:5173', 'https://app.xlsvc.jsilverman.ca'])
jwt = JWTManager(app)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

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
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        stored_filename = f"{uuid.uuid4()}.{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
        
        # Save file
        file.save(file_path)
        file_size = os.path.getsize(file_path)
        
        # Save to database
        file_id = conn.execute(
            '''INSERT INTO files (user_id, original_filename, stored_filename, file_size) 
               VALUES (?, ?, ?, ?)''',
            (user_id, original_filename, stored_filename, file_size)
        ).lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'filename': original_filename,
            'size': file_size
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
        files = conn.execute(
            '''SELECT f.id, f.original_filename, f.file_size, f.upload_date, f.processed
               FROM files f
               JOIN users u ON f.user_id = u.id
               WHERE u.email = ?
               ORDER BY f.upload_date DESC''',
            (current_user_email,)
        ).fetchall()
        conn.close()
        
        files_list = [dict(file) for file in files]
        
        return jsonify({
            'files': files_list
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Process file endpoint - UPDATED VERSION
@app.route('/api/process/<int:file_id>', methods=['POST'])
@jwt_required()
def process_file(file_id):
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
        
        if not file_info:
            return jsonify({'error': 'File not found'}), 404
            
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_filename'])
        
        if not os.path.exists(input_path):
            return jsonify({'error': 'File not found on disk'}), 404
        
        # Generate output filename
        base_name = os.path.splitext(file_info['original_filename'])[0]
        extension = os.path.splitext(file_info['original_filename'])[1]
        output_filename = f"{base_name}_processed{extension}"
        output_stored_filename = f"processed_{uuid.uuid4()}{extension}"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_stored_filename)
        
        # Process the Excel file
        try:
            processing_log = []
            deleted_rows = 0
            
            # First, try to load with data_only=True to get calculated formula values
            try:
                # Load workbook with formulas evaluated
                wb_calc = load_workbook(input_path, data_only=True)
                
                # Load workbook again to preserve formulas and images
                wb_main = load_workbook(input_path, data_only=False)
                
                for sheet_name in wb_main.sheetnames:
                    sheet_main = wb_main[sheet_name]
                    sheet_calc = wb_calc[sheet_name]
                    
                    processing_log.append(f"Processing sheet: {sheet_name}")
                    
                    # Store images and their anchors before processing
                    images_data = []
                    if hasattr(sheet_main, '_images'):
                        for img in sheet_main._images:
                            images_data.append({
                                'image': img,
                                'anchor': img.anchor
                            })
                    
                    # Find rows to delete
                    rows_to_delete = []
                    max_row = sheet_main.max_row
                    
                    for row_num in range(1, max_row + 1):
                        # Get calculated values from the data_only workbook
                        f_val = sheet_calc.cell(row=row_num, column=6).value
                        g_val = sheet_calc.cell(row=row_num, column=7).value
                        h_val = sheet_calc.cell(row=row_num, column=8).value
                        i_val = sheet_calc.cell(row=row_num, column=9).value
                        
                        # Get formula values for logging
                        f_formula = sheet_main.cell(row=row_num, column=6).value
                        g_formula = sheet_main.cell(row=row_num, column=7).value
                        h_formula = sheet_main.cell(row=row_num, column=8).value
                        i_formula = sheet_main.cell(row=row_num, column=9).value
                        
                        # Debug logging for specific rows
                        if 15 <= row_num <= 20:
                            processing_log.append(
                                f"Row {row_num}: F={f_formula}→{f_val}, G={g_formula}→{g_val}, "
                                f"H={h_formula}→{h_val}, I={i_formula}→{i_val}"
                            )
                        
                        # Check if ALL four columns are empty/zero
                        if (is_empty_or_zero(f_val) and 
                            is_empty_or_zero(g_val) and 
                            is_empty_or_zero(h_val) and 
                            is_empty_or_zero(i_val)):
                            
                            rows_to_delete.append(row_num)
                            processing_log.append(
                                f"DELETING Row {row_num}: F={f_val}, G={g_val}, H={h_val}, I={i_val}"
                            )
                    
                    processing_log.append(f"Found {len(rows_to_delete)} rows to delete in {sheet_name}")
                    
                    # Delete rows from bottom to top
                    for row_num in reversed(rows_to_delete):
                        sheet_main.delete_rows(row_num)
                        deleted_rows += 1
                    
                    # Re-add images with adjusted positions
                    # Note: Image positions may need adjustment after row deletion
                    for img_data in images_data:
                        # You may need to adjust the anchor based on deleted rows
                        # This is a simplified version - you might need more complex logic
                        sheet_main.add_image(img_data['image'])
                    
                    processing_log.append(f"Deleted {len(rows_to_delete)} rows from {sheet_name}")
                
                # Save the processed file
                wb_main.save(output_path)
                wb_main.close()
                wb_calc.close()
                
            except Exception as calc_error:
                # Fallback: Process without formula evaluation
                processing_log.append(f"Note: Could not evaluate formulas: {str(calc_error)}")
                processing_log.append("Processing with formula detection only...")
                
                workbook = load_workbook(input_path)
                
                for sheet_name in workbook.sheetnames:
                    sheet = workbook[sheet_name]
                    processing_log.append(f"Processing sheet: {sheet_name}")
                    
                    rows_to_delete = []
                    max_row = sheet.max_row
                    
                    for row_num in range(1, max_row + 1):
                        f_val = sheet.cell(row=row_num, column=6).value
                        g_val = sheet.cell(row=row_num, column=7).value
                        h_val = sheet.cell(row=row_num, column=8).value
                        i_val = sheet.cell(row=row_num, column=9).value
                        
                        # For formulas, treat them as non-empty unless we can evaluate them
                        def is_empty_or_zero_with_formula(val):
                            if val is None:
                                return True
                            if val == 0:
                                return True
                            if val == "":
                                return True
                            if isinstance(val, str):
                                if val.strip() == '':
                                    return True
                                if val.strip() == '0':
                                    return True
                                # Don't treat formulas as empty
                                if val.startswith('='):
                                    return False
                            return False
                        
                        # Check if ALL four columns are empty/zero
                        if (is_empty_or_zero_with_formula(f_val) and 
                            is_empty_or_zero_with_formula(g_val) and 
                            is_empty_or_zero_with_formula(h_val) and 
                            is_empty_or_zero_with_formula(i_val)):
                            
                            rows_to_delete.append(row_num)
                            processing_log.append(f"DELETING Row {row_num}: All columns empty/zero")
                    
                    # Delete rows from bottom to top
                    for row_num in reversed(rows_to_delete):
                        sheet.delete_rows(row_num)
                        deleted_rows += 1
                    
                    processing_log.append(f"Deleted {len(rows_to_delete)} rows from {sheet_name}")
                
                workbook.save(output_path)
                workbook.close()
            
            # Update database
            conn.execute(
                'UPDATE files SET processed = TRUE WHERE id = ?',
                (file_id,)
            )
            
            # Record the processed file
            processed_file_id = conn.execute(
                '''INSERT INTO files (user_id, original_filename, stored_filename, file_size, processed) 
                   VALUES (?, ?, ?, ?, ?)''',
                (file_info['user_id'], output_filename, output_stored_filename, 
                 os.path.getsize(output_path), True)
            ).lastrowid
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'message': 'File processed successfully',
                'original_file_id': file_id,
                'processed_file_id': processed_file_id,
                'deleted_rows': deleted_rows,
                'processing_log': processing_log,
                'download_filename': output_filename
            }), 200
            
        except Exception as processing_error:
            return jsonify({
                'error': f'Processing failed: {str(processing_error)}'
            }), 500
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Download processed file endpoint
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
            
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_info['stored_filename'])
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found on disk'}), 404
            
        return send_file(
            file_path,
            as_attachment=True,
            download_name=file_info['original_filename'],
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
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