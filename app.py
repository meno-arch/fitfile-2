import os
from datetime import datetime, timedelta
from flask import Flask, request, send_file, render_template, jsonify
from werkzeug.utils import secure_filename
import secrets
import hashlib
from functools import wraps
import jwt
from pathlib import Path

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Generate a random secret key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

# Create uploads directory if it doesn't exist
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)

# File database (in production, use a real database)
file_database = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_secure_link(file_id):
    """Generate a secure download link with JWT"""
    payload = {
        'file_id': file_id,
        'exp': datetime.utcnow() + timedelta(days=7)  # Link expires in 7 days
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['file_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        # Secure the filename and generate a unique ID
        filename = secure_filename(file.filename)
        file_id = secrets.token_urlsafe(16)
        
        # Save file info to database
        file_database[file_id] = {
            'filename': filename,
            'upload_date': datetime.utcnow(),
            'original_name': file.filename
        }
        
        # Save the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        file.save(file_path)
        
        # Generate download link
        download_token = generate_secure_link(file_id)
        download_link = f"/download/{download_token}"
        
        return jsonify({
            'message': 'File uploaded successfully',
            'download_link': download_link
        })
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/download/<token>')
def download_file(token):
    file_id = verify_token(token)
    if not file_id:
        return jsonify({'error': 'Invalid or expired link'}), 400
    
    if file_id not in file_database:
        return jsonify({'error': 'File not found'}), 404
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_database[file_id]['original_name']
    )

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', ssl_context='adhoc')