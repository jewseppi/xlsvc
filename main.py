from flask import Flask, jsonify, request
import pandas as pd

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

@app.route('/')
def index():
    return jsonify({"message": "xlsvc API running"})

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/api/upload', methods=['POST'])
def upload_excel():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if not file.filename.lower().endswith(('.xlsx', '.xls')):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        df = pd.read_excel(file, engine='openpyxl')
        return jsonify({
            'message': 'File processed successfully',
            'rows': len(df),
            'columns': list(df.columns)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run()
