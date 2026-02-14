from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import zipfile
import subprocess
import signal
import shutil
import time
import secrets
import logging
from threading import Thread
from pathlib import Path
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from functools import wraps
import socket
import json
from collections import defaultdict

# Try to import optional dependencies
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[WARNING] psutil not installed. System stats will be limited.")

try:
    import humanize
    HUMANIZE_AVAILABLE = True
except ImportError:
    HUMANIZE_AVAILABLE = False
    print("[WARNING] humanize not installed. File sizes will be in bytes.")

app = Flask(__name__)
app.secret_key = "x9k7m3p5_2025_secure_key_!@#$"
app.config['MAX_CONTENT_LENGTH'] = 250 * 1024 * 1024
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# Configuration
UPLOAD_FOLDER = "codex_deployments"
MAX_RUNNING = 3  # Changed to 3 files per user
MAX_UPLOADS_PER_USER = 3  # Maximum uploads per user
PORT = 8030
HOST = "0.0.0.0"

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("logs", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("analytics_data", exist_ok=True)

# Logging setup
logging.basicConfig(
    filename='logs/codex.log',
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

# Process tracking
processes = {}
app_logs = {}

# Admin credentials (HIDDEN - not displayed anywhere)
ADMIN_KEY = "X9K7M3P5"  # This is the secret admin key - keep hidden!

# Analytics tracking
visitors = []
page_views = 0
total_uploads = 0
total_file_size = 0
start_time = datetime.now()
user_upload_counts = defaultdict(int)  # Track uploads per user
user_sessions = {}  # Track active sessions

# File to store analytics data
ANALYTICS_FILE = "analytics_data/visitors.json"

# Load existing analytics if available
def load_analytics():
    global visitors, page_views, total_uploads, total_file_size, user_upload_counts
    try:
        if os.path.exists(ANALYTICS_FILE):
            with open(ANALYTICS_FILE, 'r') as f:
                data = json.load(f)
                visitors = [{'ip': v['ip'], 
                           'time': datetime.fromisoformat(v['time']), 
                           'user_agent': v['user_agent'],
                           'session_id': v.get('session_id', ''),
                           'username': v.get('username', 'Anonymous')} for v in data.get('visitors', [])]
                page_views = data.get('page_views', 0)
                total_uploads = data.get('total_uploads', 0)
                total_file_size = data.get('total_file_size', 0)
                user_upload_counts = defaultdict(int, data.get('user_upload_counts', {}))
    except Exception as e:
        logger.error(f"Failed to load analytics: {e}")

# Save analytics data
def save_analytics():
    try:
        data = {
            'visitors': [{'ip': v['ip'], 
                         'time': v['time'].isoformat(), 
                         'user_agent': v['user_agent'],
                         'session_id': v.get('session_id', ''),
                         'username': v.get('username', 'Anonymous')} for v in visitors[-1000:]],  # Keep last 1000
            'page_views': page_views,
            'total_uploads': total_uploads,
            'total_file_size': total_file_size,
            'user_upload_counts': dict(user_upload_counts)
        }
        with open(ANALYTICS_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        logger.error(f"Failed to save analytics: {e}")

# Load analytics on startup
load_analytics()

# Get local IP address
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

# ---------- Helper Functions ----------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or not session.get('is_admin', False):
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_user_dir():
    user_dir = os.path.join(UPLOAD_FOLDER, secure_filename(session['username']))
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def log_message(log_path, level, message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    try:
        with open(log_path, "a", encoding='utf-8') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    except:
        pass

def extract_zip(zip_path, extract_to):
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(extract_to)
        return True
    except Exception as e:
        logger.error(f"Extraction error: {e}")
        return False

def find_main_file(path):
    for f in ["main.py", "app.py", "application.py", "server.py", "bot.py", "run.py", "codex.py", "exploit.py"]:
        if os.path.exists(os.path.join(path, f)):
            return f
    return None

def start_app(app_name):
    username = session['username']
    user_dir = get_user_dir()
    app_dir = os.path.join(user_dir, app_name)
    extract_dir = os.path.join(app_dir, "extracted")
    log_path = os.path.join(app_dir, "logs.txt")
    
    if not os.path.exists(extract_dir):
        zip_path = os.path.join(app_dir, "app.zip")
        if os.path.exists(zip_path):
            extract_zip(zip_path, extract_dir)
    
    main_file = find_main_file(extract_dir)
    if not main_file:
        log_message(log_path, "FAIL", "No main file found")
        return False
    
    key = (username, app_name)
    if key in processes:
        if processes[key].poll() is None:
            return True
        processes.pop(key, None)
    
    try:
        log_file = open(log_path, "a", encoding='utf-8')
        log_message(log_path, "EXEC", f"Launching {main_file}")
        
        process = subprocess.Popen(
            ["python3", main_file],
            cwd=extract_dir,
            stdout=log_file,
            stderr=log_file,
            start_new_session=True
        )
        
        processes[key] = process
        time.sleep(1)
        
        if process.poll() is not None:
            log_message(log_path, "FAIL", "Process died immediately")
            processes.pop(key, None)
            return False
        
        return True
    except Exception as e:
        log_message(log_path, "ERROR", str(e))
        return False

def stop_app(app_name):
    key = (session['username'], app_name)
    if key in processes:
        try:
            processes[key].terminate()
            processes[key].wait(timeout=5)
        except:
            try:
                os.killpg(os.getpgid(processes[key].pid), signal.SIGKILL)
            except:
                pass
        finally:
            processes.pop(key, None)
            user_dir = get_user_dir()
            log_path = os.path.join(user_dir, app_name, "logs.txt")
            log_message(log_path, "KILL", "Process terminated")

def get_logs(app_name, max_lines=2000):
    log_path = os.path.join(get_user_dir(), app_name, "logs.txt")
    if not os.path.exists(log_path):
        return "[ SYSTEM ]: No logs available"
    
    try:
        with open(log_path, "r", encoding='utf-8') as f:
            lines = f.readlines()
            if len(lines) > max_lines:
                lines = lines[-max_lines:]
            return "".join(lines)
    except:
        return "[ ERROR ]: Cannot read logs"

def get_file_size_human(size):
    if HUMANIZE_AVAILABLE:
        return humanize.naturalsize(size)
    else:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

def get_user_upload_count(username):
    """Get number of uploads for a specific user"""
    user_dir = os.path.join(UPLOAD_FOLDER, secure_filename(username))
    if not os.path.exists(user_dir):
        return 0
    return len([d for d in os.listdir(user_dir) if os.path.isdir(os.path.join(user_dir, d))])

def get_system_stats():
    """Get system analytics"""
    global page_views, total_uploads, total_file_size
    
    # Calculate total file size in uploads folder
    total_size = 0
    file_count = 0
    user_files = defaultdict(int)
    user_sizes = defaultdict(int)
    
    for root, dirs, files in os.walk(UPLOAD_FOLDER):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size = os.path.getsize(file_path)
                total_size += size
                file_count += 1
                
                # Get username from path
                parts = root.split(os.sep)
                if len(parts) > 1:
                    username = parts[1]
                    user_files[username] += 1
                    user_sizes[username] += size
            except:
                pass
    
    # Get visitor count (unique IPs in last 24h)
    now = datetime.now()
    unique_visitors_24h = len(set([v['ip'] for v in visitors if v['time'] > now - timedelta(hours=24)]))
    unique_visitors_7d = len(set([v['ip'] for v in visitors if v['time'] > now - timedelta(days=7)]))
    
    # Active users (last 5 minutes)
    active_users = len(set([v['username'] for v in visitors if v['time'] > now - timedelta(minutes=5) and v['username'] != 'Anonymous']))
    
    # System stats with fallbacks
    cpu_percent = 0
    memory_percent = 0
    disk_usage = 0
    
    if PSUTIL_AVAILABLE:
        try:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            disk_usage = psutil.disk_usage('/').percent
        except:
            pass
    
    return {
        'total_visitors': len(visitors),
        'unique_visitors_24h': unique_visitors_24h,
        'unique_visitors_7d': unique_visitors_7d,
        'active_users_now': active_users,
        'page_views': page_views,
        'total_uploads': total_uploads,
        'total_files': file_count,
        'total_file_size': total_size,
        'total_file_size_human': get_file_size_human(total_size),
        'active_processes': len(processes),
        'uptime': str(datetime.now() - start_time).split('.')[0],
        'cpu_percent': cpu_percent,
        'memory_percent': memory_percent,
        'disk_usage': disk_usage,
        'host': HOST,
        'port': PORT,
        'local_ip': LOCAL_IP,
        'psutil_available': PSUTIL_AVAILABLE,
        'humanize_available': HUMANIZE_AVAILABLE,
        'user_files': dict(user_files),
        'user_sizes': {k: get_file_size_human(v) for k, v in user_sizes.items()},
        'max_uploads_per_user': MAX_UPLOADS_PER_USER
    }

def clear_all_data():
    """Clear all analytics and uploaded files (Admin only)"""
    global visitors, page_views, total_uploads, total_file_size, user_upload_counts, processes
    
    # Clear uploaded files
    try:
        shutil.rmtree(UPLOAD_FOLDER)
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    except:
        pass
    
    # Clear analytics
    visitors = []
    page_views = 0
    total_uploads = 0
    total_file_size = 0
    user_upload_counts = defaultdict(int)
    
    # Stop all processes
    for key in list(processes.keys()):
        try:
            processes[key].terminate()
        except:
            pass
    processes = {}
    
    # Save cleared state
    save_analytics()
    
    logger.info(f"All data cleared by admin")

# ---------- Routes ----------
@app.route("/")
def index():
    global page_views
    page_views += 1
    
    # Track visitor with session
    visitor_ip = request.remote_addr
    session_id = session.get('session_id', secrets.token_hex(8))
    session['session_id'] = session_id
    
    visitors.append({
        'ip': visitor_ip,
        'time': datetime.now(),
        'user_agent': request.user_agent.string if request.user_agent else "Unknown",
        'session_id': session_id,
        'username': session.get('username', 'Anonymous')
    })
    
    # Keep only last 5000 visitors
    if len(visitors) > 5000:
        visitors[:] = visitors[-5000:]
    
    # Save periodically (every 10 visitors)
    if len(visitors) % 10 == 0:
        save_analytics()
    
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    global page_views
    page_views += 1
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if username and len(username) >= 3:
            session.permanent = True
            session['username'] = secure_filename(username)
            session['login_time'] = datetime.now().isoformat()
            session['session_id'] = secrets.token_hex(8)
            logger.info(f"User login: {username}")
            
            # Update last visitor with username
            if visitors:
                visitors[-1]['username'] = username
            save_analytics()
            
            return redirect(url_for('dashboard'))
    
    return render_template("login.html")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    global page_views
    page_views += 1
    
    if request.method == "POST":
        admin_key = request.form.get("admin_key")
        # Hidden admin key - not displayed anywhere
        if admin_key == ADMIN_KEY:
            session.permanent = True
            session['username'] = "ADMIN"
            session['is_admin'] = True
            session['session_id'] = secrets.token_hex(8)
            logger.info(f"ADMIN ACCESS GRANTED from IP: {request.remote_addr}")
            
            # Update last visitor with admin
            if visitors:
                visitors[-1]['username'] = "ADMIN"
            save_analytics()
            
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed admin attempt with key: {admin_key} from IP: {request.remote_addr}")
    
    return render_template("admin.html")

@app.route("/dashboard")
@login_required
def dashboard():
    global page_views
    page_views += 1
    
    user_dir = get_user_dir()
    apps = []
    upload_count = 0
    
    if os.path.exists(user_dir):
        for item in os.listdir(user_dir):
            app_path = os.path.join(user_dir, item)
            if os.path.isdir(app_path):
                upload_count += 1
                is_running = (session['username'], item) in processes
                if is_running:
                    proc = processes.get((session['username'], item))
                    if proc and proc.poll() is not None:
                        is_running = False
                        processes.pop((session['username'], item), None)
                
                # Get file size
                zip_path = os.path.join(app_path, "app.zip")
                file_size = 0
                if os.path.exists(zip_path):
                    file_size = os.path.getsize(zip_path)
                
                apps.append({
                    "name": item,
                    "running": is_running,
                    "logs": get_logs(item),
                    "size": get_file_size_human(file_size)
                })
    
    remaining_uploads = MAX_UPLOADS_PER_USER - upload_count
    
    return render_template("dashboard.html", 
                         apps=apps, 
                         username=session['username'],
                         max_apps=MAX_RUNNING,
                         max_uploads=MAX_UPLOADS_PER_USER,
                         upload_count=upload_count,
                         remaining_uploads=remaining_uploads,
                         is_admin=session.get('is_admin', False),
                         host=HOST,
                         port=PORT,
                         local_ip=LOCAL_IP)

@app.route("/analytics")
@admin_required
def analytics():
    """Analytics dashboard - only for admin"""
    stats = get_system_stats()
    
    # Get recent visitors (real data, not fake)
    recent_visitors = sorted(visitors[-100:], key=lambda x: x['time'], reverse=True)
    
    # Get user directory apps count
    user_dir = get_user_dir()
    apps = []
    if os.path.exists(user_dir):
        for item in os.listdir(user_dir):
            if os.path.isdir(os.path.join(user_dir, item)):
                apps.append(item)
    
    # Get upload statistics by user
    user_stats = []
    for username in set([v['username'] for v in visitors if v['username'] != 'Anonymous']):
        user_uploads = get_user_upload_count(username)
        user_stats.append({
            'username': username,
            'uploads': user_uploads,
            'max_uploads': MAX_UPLOADS_PER_USER,
            'remaining': MAX_UPLOADS_PER_USER - user_uploads
        })
    
    return render_template("analytics.html", 
                         stats=stats,
                         visitors=recent_visitors,
                         apps=apps,
                         max_apps=MAX_RUNNING,
                         user_stats=user_stats)

@app.route("/admin/clear-all", methods=["POST"])
@admin_required
def clear_all():
    """Clear all data (admin only)"""
    clear_all_data()
    return redirect(url_for('analytics'))

@app.route("/deploy", methods=["POST"])
@login_required
def deploy():
    global total_uploads, total_file_size
    
    if 'file' not in request.files:
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.zip'):
        return redirect(url_for('dashboard'))
    
    # Check user upload limit
    username = session['username']
    current_uploads = get_user_upload_count(username)
    
    if current_uploads >= MAX_UPLOADS_PER_USER:
        return redirect(url_for('dashboard'))
    
    total_uploads += 1
    
    # Track file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    total_file_size += file_size
    
    user_dir = get_user_dir()
    base_name = secure_filename(file.filename.replace('.zip', ''))
    
    if not base_name:
        base_name = "package"
    
    app_name = base_name
    counter = 1
    while os.path.exists(os.path.join(user_dir, app_name)):
        app_name = f"{base_name}_{counter}"
        counter += 1
    
    app_dir = os.path.join(user_dir, app_name)
    os.makedirs(app_dir)
    
    zip_path = os.path.join(app_dir, "app.zip")
    file.save(zip_path)
    
    log_path = os.path.join(app_dir, "logs.txt")
    log_message(log_path, "UPLOAD", f"Deployed: {app_name} ({get_file_size_human(file_size)})")
    
    # Update user upload count
    user_upload_counts[username] = current_uploads + 1
    save_analytics()
    
    return redirect(url_for('dashboard'))

@app.route("/app/<name>/start")
@login_required
def start(name):
    user_apps = sum(1 for k in processes.keys() if k[0] == session['username'])
    if user_apps >= MAX_RUNNING:
        return redirect(url_for('dashboard'))
    
    start_app(name)
    return redirect(url_for('dashboard'))

@app.route("/app/<name>/stop")
@login_required
def stop(name):
    stop_app(name)
    return redirect(url_for('dashboard'))

@app.route("/app/<name>/restart")
@login_required
def restart(name):
    stop_app(name)
    time.sleep(1)
    start_app(name)
    return redirect(url_for('dashboard'))

@app.route("/app/<name>/delete")
@login_required
def delete(name):
    stop_app(name)
    
    app_dir = os.path.join(get_user_dir(), name)
    try:
        shutil.rmtree(app_dir)
    except:
        pass
    
    return redirect(url_for('dashboard'))

@app.route("/api/logs/<name>")
@login_required
def api_logs(name):
    return jsonify({"logs": get_logs(name)})

@app.route("/api/stats")
@admin_required
def api_stats():
    """API endpoint for real-time stats"""
    return jsonify(get_system_stats())

@app.route("/api/visitors/recent")
@admin_required
def api_recent_visitors():
    """API endpoint for recent visitors"""
    recent = [{'ip': v['ip'], 
               'time': v['time'].isoformat(), 
               'user_agent': v['user_agent'][:50],
               'username': v['username']} for v in visitors[-20:]]
    return jsonify(recent)

@app.route("/api/status")
def api_status():
    """Public status endpoint"""
    return jsonify({
        "status": "online",
        "time": datetime.now().isoformat(),
        "host": HOST,
        "port": PORT,
        "local_ip": LOCAL_IP,
        "visitors_today": len([v for v in visitors if v['time'] > datetime.now() - timedelta(days=1)])
    })

@app.route("/logout")
def logout():
    username = session.get('username', 'Unknown')
    logger.info(f"Logout: {username}")
    session.clear()
    return redirect(url_for('login'))

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal Server Error: {error}")
    return "Internal Server Error. Check logs for details.", 500

# Cleanup thread
def cleanup():
    while True:
        time.sleep(30)
        to_remove = []
        for key, proc in list(processes.items()):
            if proc.poll() is not None:
                to_remove.append(key)
        for key in to_remove:
            processes.pop(key, None)
            logger.info(f"Cleaned up dead process: {key}")
        
        # Save analytics periodically
        save_analytics()

# Start cleanup thread
cleanup_thread = Thread(target=cleanup, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║                   ᎬꪎՄ CODEX v2.0                        ║
    ╠══════════════════════════════════════════════════════════╣
    ║  ▶ Server is LIVE!                                        ║
    ║  ▶ Host: {HOST}                                           ║
    ║  ▶ Port: {PORT}                                           ║
    ║  ▶ Local Access: http://{LOCAL_IP}:{PORT}                 ║
    ║  ▶ Admin Access: HIDDEN                                   ║
    ║  ▶ Max Uploads/User: {MAX_UPLOADS_PER_USER}               ║
    ║  ▶ Max Active Apps: {MAX_RUNNING}                         ║
    ╠══════════════════════════════════════════════════════════╣
    ║  ▶ Press CTRL+C to stop server                           ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    try:
        app.run(host=HOST, port=PORT, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user")
    except Exception as e:
        print(f"\n[!] Error starting server: {e}")