import os
import hashlib

# Folder constants (defaults, match app.config values in main.py)
UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed'
MACROS_FOLDER = 'macros'
REPORTS_FOLDER = 'reports'


def _get_folders():
    """Get folder paths from Flask app config if available, else use defaults"""
    try:
        from flask import current_app
        return (
            current_app.config.get('UPLOAD_FOLDER', UPLOAD_FOLDER),
            current_app.config.get('PROCESSED_FOLDER', PROCESSED_FOLDER),
            current_app.config.get('MACROS_FOLDER', MACROS_FOLDER),
            current_app.config.get('REPORTS_FOLDER', REPORTS_FOLDER),
        )
    except RuntimeError:
        # Outside Flask request context (e.g. cron script)
        return UPLOAD_FOLDER, PROCESSED_FOLDER, MACROS_FOLDER, REPORTS_FOLDER


def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def ensure_directories(app=None):
    """Create all necessary directories"""
    if app:
        dirs = [
            app.config['UPLOAD_FOLDER'],
            app.config['PROCESSED_FOLDER'],
            app.config['MACROS_FOLDER'],
            app.config['REPORTS_FOLDER']
        ]
    else:
        dirs = [UPLOAD_FOLDER, PROCESSED_FOLDER, MACROS_FOLDER, REPORTS_FOLDER]
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)


def get_file_path(file_type, filename):
    """Get the correct storage path based on file type"""
    upload, processed, macros, reports = _get_folders()
    if file_type == 'original' or file_type is None:
        return os.path.join(upload, filename)
    elif file_type == 'processed':
        return os.path.join(processed, filename)
    elif file_type in ['macro', 'instructions']:
        return os.path.join(macros, filename)
    elif file_type == 'report':
        return os.path.join(reports, filename)
    else:
        return os.path.join(upload, filename)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'xls', 'xlsx'}


def validate_excel_file(file):
    """Validate Excel file using magic bytes"""
    file.seek(0)
    header = file.read(8)
    file.seek(0)

    # Excel files: PK (xlsx/zip format) or OLE header (xls format)
    if not (header.startswith(b'PK') or header.startswith(b'\xd0\xcf\x11\xe0')):
        raise ValueError("Invalid Excel file - file signature does not match Excel format")

    return True
