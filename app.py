# 2025-08-07: Initial tests
# 2025-08-08: Working version with FitTrackee import
# 2025-08-09: handle duplicates, move to imported/failed subdirs
# 2025-08-19: added notes in imported workout, sport_id(default: 1) and description
# 2025-08-20: added title in request
# 2025-09-03: change name of variables

""" Functions
handle_upload()
|- get_client_ip()
|- pushover()
|- allowed_file()
|- handle_fittrackee_upload()
    |- upload_to_fittrackee()
        |-get_fittrackee_token()
    |- pushover()
"""

from flask import Flask, request, jsonify
import os
from werkzeug.utils import secure_filename
import requests
from urllib.parse import urlparse
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import json
import time
import jwt

from dotenv import load_dotenv
load_dotenv()  # Takes vars from .env

app = Flask(__name__)

UPLOAD_FOLDER = os.getenv("UPLOAD_DIR")
# checking for duplicates in IMPORTED_DIR, no matter if ENABLE_FITTRACKEE True||False
# stop and don't save if there is same filename in IMPORTED_DIR
IMPORTED_DIR = os.path.join(UPLOAD_FOLDER, "imported")
FAILED_DIR = os.path.join(UPLOAD_FOLDER, "failed")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'tcx'}
SECRET_TOKEN = os.getenv("SECRET_TOKEN")

# Pushover configuration
PUSHOVER_API_URL = 'https://api.pushover.net/1/messages.json'
PUSHOVER_TOKEN = os.getenv("PUSHOVER_TOKEN")
PUSHOVER_USER = os.getenv("PUSHOVER_USER")

# FitTrackee Configuration
"""
ENABLE_FITTRACKEE
False: keep file in UPLOAD_FOLDER (overwrite if existing)
True: import in FitTrackee and move in IMPORTED_DIR or FAILED_DIR(overwrite if existing)
"""
ENABLE_FITTRACKEE = True  # Set to True to enable FitTrackee integration
TOKEN_FILE = 'fittrackee_token.json'
# FITTRACKEE_URL = "http://localhost:5000"
"""
port 5000 not exposed when using NPM
other option: Use the Host’s Docker Network IP
find with: docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' fittrackee
"""
FITTRACKEE_URL = os.getenv("FITTRACKEE_URL")
FITTRACKEE_EMAIL = os.getenv("FITTRACKEE_EMAIL")
FITTRACKEE_PASSWORD = os.getenv("FITTRACKEE_PASSWORD")
FITTRACKEE_SPORT_FALLBACK = 1
"""                 1 Cycling (Sport)
                    6 Walking
"""

# Set up logging
UPLOAD_FOLDER = os.getenv("LOG_DIR")
os.makedirs(LOG_FOLDER, exist_ok=True)
LOG_FILE = os.path.join(LOG_FOLDER, 'tcx_uploader.log')

# Create a rotating file handler (max 5 files, 1MB each)
handler = RotatingFileHandler(LOG_FILE, maxBytes=1024*1024, backupCount=5)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Get the Flask app's logger and add the handler
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

def pushover(message, title="TXC file", priority=0):
    try:
        response = requests.post(
            PUSHOVER_API_URL,
            data={
                'token': PUSHOVER_TOKEN,
                'user': PUSHOVER_USER,
                'title': title,
                'message': message,
                'priority': priority
            }
        )
        if response.status_code == 200:
            app.logger.info(f"Pushover notification sent: {title}")
            return True
        else:
            app.logger.error(f"Pushover API error: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        app.logger.error(f"Failed to send Pushover notification: {str(e)}", exc_info=True)
        return False

def get_client_ip():
    """Get the real client IP when behind a reverse proxy"""
    if request.headers.getlist("X-Forwarded-For"):
        client_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    else:
        client_ip = request.remote_addr
    return client_ip

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_fittrackee_token():
    """Get cached token if valid, otherwise fetch new token and save it."""
    # Try to load cached token
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, 'r') as f:
                token_data = json.load(f)
            
            # Check if token is still valid (with 60 second buffer)
            if time.time() < token_data['expires_at'] - 60:
                return token_data['token']
        except Exception as e:
            print(f"Error reading token cache: {str(e)}")
    # If no valid cached token, fetch new one
    try:
        response = requests.post(
            f"{FITTRACKEE_URL}/api/auth/login",
            headers={"Content-Type": "application/json"},
            json={"email": FITTRACKEE_EMAIL, "password": FITTRACKEE_PASSWORD},
            timeout=10
        )
        response.raise_for_status()
        token_data = response.json()
        if token_data.get("status") == "success":
            token = token_data["auth_token"]
            # Decode token to get expiration (without verification)
            decoded = jwt.decode(token, options={"verify_signature": False})
            expires_at = decoded['exp']
            # Save token with expiration info
            with open(TOKEN_FILE, 'w') as f:
                json.dump({
                    'token': token,
                    'expires_at': expires_at,
                    'expires_at_human': datetime.fromtimestamp(expires_at).isoformat()
                }, f, indent=2)
            return token
        else:
            print(f"Login failed: {token_data.get('message')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {str(e)}")
        return None
    except Exception as e:
        print(f"Error handling token: {str(e)}")
        return None

def upload_to_fittrackee(file_path, itemSport, itemTitle, itemDesc, itemNotes):
    token = get_fittrackee_token()
    if not token:
        return False, f"Authentication failed, token:{token}"
    
    try:
        with open(file_path, 'rb') as f:
            response = requests.post(
                f"{FITTRACKEE_URL}/api/workouts",
                headers={'Authorization': f"Bearer {token}"},
                files={
                    'file': (os.path.basename(file_path), f),
                    'data': (None, json.dumps({
                        'sport_id': itemSport,
                        'title': itemTitle,
                        'description': itemDesc,
                        'notes': itemNotes
                    }))
                }
            )
        response.raise_for_status()
        return True, "Upload successful"
    except Exception as e:
        app.logger.error(f"FitTrackee upload failed: {str(e)}")
        return False, str(e)

# Simulate fittrackee success and fail
# def upload_to_fittrackee(file_path):
#     """Mock function for debugging without real API calls"""
#     # filename = os.path.basename(file_path)
#     filename = "fail_test.tcx"
#     file_size = os.path.getsize(file_path) / (1024 * 1024)
    
#     # Simulate different test cases
#     if "fail" in filename.lower():
#         return False, "Simulated failure - test filename contained 'fail'"
#     elif file_size > 5:
#         return False, f"Simulated large file rejection ({file_size:.1f} MB)"
#     else:
#         # Simulate successful upload
#         return True, f"Simulated success - {filename} ({file_size:.1f} MB)"

def handle_fittrackee_upload(file_path, filename, itemSport, itemTitle=None, itemDesc=None, itemNotes=None, url=None, client_ip=None):
    """
    Handles FitTrackee upload and notifications
    Args:
        file_path: Path to the saved file
        filename: Name of the uploaded file
        url: URL source (for URL uploads, optional)
        client_ip: Client IP address
    Returns:
        Dictionary with upload status and message
    """
    fittrackee_status = {
        'success': None,
        'message': "FitTrackee is Disabled"
    }
    
    # Get file size in MB
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    
    # Only attempt upload if enabled
    if ENABLE_FITTRACKEE:
        try:
            fittrackee_status['success'], fittrackee_status['message'] = upload_to_fittrackee(file_path, itemSport, itemTitle, itemDesc, itemNotes)
            # Log result
            log_prefix = "[URL Upload]" if url else "[Upload File]"
            if fittrackee_status['success']:
                app.logger.info(f"{log_prefix} FitTrackee upload successful: {filename}")
            else:
                app.logger.error(f"{log_prefix} FitTrackee upload failed: {fittrackee_status['message']}")
        except Exception as e:
            fittrackee_status['message'] = str(e)
            app.logger.error(f"FitTrackee upload exception: {str(e)}")
    
    # Prepare notification
    notification_title = "✅ Upload TCX" if not ENABLE_FITTRACKEE else (
        "✅ Upload TCX FitTrackee" if fittrackee_status['success'] else "⚠️ Upload TCX on Server"
    )
    
    # Build message based on upload type
    message_lines = [
        f"File: {filename}",
        f"Size: {file_size_mb:.1f} MB",
        f"IP: {client_ip}" if client_ip else None,
        f"URL: {url}" if url else None,
        f"FitTrackee: {'✅ Success' if fittrackee_status['success'] else '❌ Failed' if ENABLE_FITTRACKEE else '⚪ Disabled'}",
        f"Message: {fittrackee_status['message']}"
    ]
    notification_msg = "\n".join(filter(None, message_lines))
    
    # Send notification
    pushover(
        title=notification_title,
        message=notification_msg,
        priority=0 if not ENABLE_FITTRACKEE or fittrackee_status.get('success') else 1
    )
    
    return {
        "uploaded": fittrackee_status['success'],
        "message": fittrackee_status['message']
    }

@app.route('/upload', methods=['POST'])
@app.route('/upload_from_url', methods=['POST'])
def handle_upload():
    # Common initialization
    client_ip = get_client_ip()
    is_url_upload = request.path == '/upload_from_url'
    log_prefix = "[URL Upload]" if is_url_upload else "[Upload File]"
    
    # Authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != f"Bearer {SECRET_TOKEN}":
        error_msg = f"Unauthorized {'URL' if is_url_upload else ''} upload attempt from IP: {client_ip}"
        app.logger.warning(f"{log_prefix} {error_msg}")
        pushover(
            title=f"🚨 Unauthorized {'URL ' if is_url_upload else ''}Access",
            message=f"IP: {client_ip}\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            priority=1
        )
        return jsonify({"error": "Unauthorized"}), 401

    # Default values
    itemSport = FITTRACKEE_SPORT_FALLBACK
    url = None
    itemTitle = ""
    itemDesc = ""
    itemNotes = ""

    # Input validation
    if is_url_upload:
        if 'url' not in request.json:
            error_msg = "No URL provided"
            app.logger.error(f"{log_prefix} {error_msg}")
            pushover(
                title="⚠️ URL Upload Error",
                message=f"{error_msg}\nIP: {client_ip}",
                priority=0
            )
            return jsonify({"error": error_msg}), 400
        itemSport = request.json.get('workoutSport') or FITTRACKEE_SPORT_FALLBACK
        url = request.json['url']
        itemTitle = request.json.get('workoutTitle', '')
        itemDesc = request.json.get('workoutDesc', '')
        itemNotes = request.json.get('workoutNotes', '')
        app.logger.info(f"{log_prefix} Processing URL: {url}")
    else:
        if 'file' not in request.files:
            error_msg = "No file part in request"
            app.logger.error(f"{log_prefix} {error_msg}")
            pushover(
                title="⚠️ Upload Error",
                message=f"{error_msg}\nIP: {client_ip}",
                priority=0
            )
            return jsonify({"error": error_msg}), 400
        file = request.files['file']
        itemSport = request.form.get('workoutSport') or FITTRACKEE_SPORT_FALLBACK
        itemTitle = request.form.get('workoutTitle', '')
        itemDesc = request.form.get('workoutDesc', '')
        itemNotes = request.form.get('workoutNotes', '')
        if file.filename == '':
            error_msg = "Empty filename received"
            app.logger.error(f"{log_prefix} {error_msg}")
            pushover(
                title="⚠️ Upload Error",
                message=error_msg,
                priority=0
            )
            return jsonify({"error": error_msg}), 400

    try:
        # Get filename
        if is_url_upload:
            filename = secure_filename(os.path.basename(urlparse(url).path)) or "downloaded_file.tcx"
        else:
            filename = secure_filename(file.filename)
            if not allowed_file(filename):
                error_msg = f"Invalid file type attempted: {filename}"
                app.logger.error(f"{log_prefix} {error_msg}")
                pushover(
                    title="⚠️ Invalid File Type",
                    message=f"Attempted upload: {filename}\nIP: {client_ip}",
                    priority=0
                )
                return jsonify({"error": "Invalid file type"}), 400

        # Check for existing files in imported folder        
        # Get base filename without extension and counter
        base_name = os.path.splitext(filename)[0].rstrip('_0123456789')
        ext = os.path.splitext(filename)[1]
        # Check for matching files
        existing_files = [
            f for f in os.listdir(IMPORTED_DIR)
            if os.path.splitext(f)[0].rstrip('_0123456789') == base_name 
            and os.path.splitext(f)[1] == ext
        ]
        if existing_files:
            app.logger.info(f"{log_prefix} File already exists in imported: {filename}")
            return jsonify({
                "status": "duplicate",
                "message": "File already exists in imported folder",
                "filename": filename,
                "existing_files": existing_files
            }), 200

        # Save the file
        save_path = os.path.join(UPLOAD_FOLDER, filename)
        if is_url_upload:
            response = requests.get(url, stream=True)
            response.raise_for_status()
            file_size = 0
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    file_size += len(chunk)
                    f.write(chunk)
            file_size_mb = file_size / (1024 * 1024)
        else:
            file.save(save_path)
            file_size_mb = os.path.getsize(save_path) / (1024 * 1024)

        app.logger.info(f"{log_prefix} File saved: {filename} ({file_size_mb:.1f} MB)")
        
        response_data = {
            "file_saved": True,
            "filename": filename,
            "size_mb": round(file_size_mb, 1),
            "fittrackee": {
                "enabled": ENABLE_FITTRACKEE,
                "uploaded": None,
                "message": None
            }
        }

        # Always call handle_fittrackee_upload, it will check ENABLE_FITTRACKEE
        fittrackee_result = handle_fittrackee_upload(
            file_path=save_path,
            filename=filename,
            itemSport=itemSport,
            itemTitle=itemTitle,
            itemDesc=itemDesc,
            itemNotes=itemNotes,
            url=url if is_url_upload else None,
            client_ip=client_ip
        )

        response_data["fittrackee"].update(fittrackee_result)

        # Move file to appropriate folder
        if ENABLE_FITTRACKEE:
            dest_folder = IMPORTED_DIR if fittrackee_result.get("uploaded") else FAILED_DIR
            try:
                os.makedirs(dest_folder, exist_ok=True)
            except OSError as e:
                app.logger.error(f"Failed to create directories: {e}")

            try:
                dest_path = os.path.join(dest_folder, filename)
                os.rename(save_path, dest_path)
                app.logger.info(f"{log_prefix} File moved to {os.path.basename(dest_folder)}: {filename}")
                response_data["file_moved"] = True
                response_data["destination"] = os.path.basename(dest_folder)
            except Exception as move_error:
                app.logger.error(f"{log_prefix} File move failed: {str(move_error)}")
                response_data["file_moved"] = False
                response_data["move_error"] = str(move_error)
        else:
            # Keep file in original location when FitTrackee is disabled
            response_data["file_moved"] = False
            response_data["message"] = "FitTrackee disabled"


        return jsonify(response_data), 200

    except requests.exceptions.RequestException as e:
        error_msg = f"{'URL download' if is_url_upload else 'File processing'} failed: {str(e)}"
        app.logger.error(f"{log_prefix} {error_msg}", exc_info=True)
        pushover(
            title=f"❌ {'URL Download' if is_url_upload else 'Upload'} Failed",
            message=(f"URL: {url}\n" if is_url_upload else "") + f"Error: {str(e)}\nIP: {client_ip}",
            priority=1
        )        
        return jsonify({"error": error_msg}), 400
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        app.logger.error(f"{log_prefix} {error_msg}", exc_info=True)
        pushover(
            title="‼️ System Error",
            message=(f"URL: {url}\n" if is_url_upload else "") + f"Error: {str(e)}\nIP: {client_ip}",
            priority=1
        )        
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.logger.info("Starting TCX Uploader service")
    app.run(host='0.0.0.0', port=5001)  # Allow external connections