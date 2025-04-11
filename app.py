from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, send_from_directory
from functools import wraps
import sqlite3
from datetime import datetime
import csv
import os
from werkzeug.utils import secure_filename
from markupsafe import Markup  # jinja2에서 markupsafe로 변경
import io
import zipfile
from datetime import datetime
from system_monitor import init_stats, record_request, remove_user, get_current_stats
import re  # 상단에 re 모듈 import 추가

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # 실제 운영시에는 환경변수로 관리
app.config['JSON_AS_ASCII'] = False

# nl2br 필터 추가
@app.template_filter('nl2br')
def nl2br_filter(text):
    if not text:
        return text
    return Markup(text.replace('\n', '<br>'))

# linkify 필터 추가 (nl2br 필터 아래에 추가)
@app.template_filter('linkify')
def linkify_filter(text):
    """텍스트에서 URL을 찾아 클릭 가능한 링크로 변환"""
    if not text:
        return text
        
    # URL 패턴 (http://, https://, www. 로 시작하는 링크)
    pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
    
    def replace_url(match):
        url = match.group(0)
        display_url = url[:50] + '...' if len(url) > 50 else url
        if url.startswith('www.'):
            url = 'http://' + url
        return f'<a href="{url}" target="_blank" rel="noopener noreferrer">{display_url}</a>'
    
    # URL을 HTML 링크로 변환
    text = re.sub(pattern, replace_url, text)
    # 줄바꿈 처리 (nl2br 기능 포함)
    text = text.replace('\n', '<br>')
    return Markup(text)

# 파일 업로드 설정
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}
ALLOWED_IMAGES = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename, allowed_types):
    """파일 확장자 검증"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in allowed_types and len(filename) < 255

def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGES

def secure_upload(file, prefix='', allowed_types=None):
    """안전한 파일 업로드 처리"""
    if not allowed_types:
        allowed_types = ALLOWED_EXTENSIONS
        
    if not file or not allowed_file(file.filename, allowed_types):
        return None
        
    try:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        safe_filename = f"{prefix}_{timestamp}_{filename}"
        
        # 파일 크기 제한 (10MB)
        if len(file.read()) > 10 * 1024 * 1024:
            return None
        file.seek(0)
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        file.save(file_path)
        return safe_filename  # 파일명만 반환
    except Exception:
        return None

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # 사용자 테이블에 password 필드 추가
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            student_id TEXT PRIMARY KEY,
            birth_date TEXT NOT NULL,
            name TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            club_leader_of INTEGER DEFAULT NULL,
            password TEXT,  -- 관리자 비밀번호 필드 추가
            FOREIGN KEY (club_leader_of) REFERENCES clubs (id)
        )
    ''')
    
    # 공지사항 테이블
    c.execute('''
        CREATE TABLE IF NOT EXISTS notices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            is_important BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 선생님 명단 테이블
    c.execute('''
        CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            department TEXT,
            group_number INTEGER NOT NULL,  -- 1~6 범위로 확장
            is_selected BOOLEAN DEFAULT 0,
            selected_at TIMESTAMP
        )
    ''')
    
    # 동아리 테이블
    c.execute('''
        CREATE TABLE IF NOT EXISTS clubs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            poster_path TEXT,
            max_members INTEGER,
            is_recruiting BOOLEAN DEFAULT 1,  -- 모집 상태 컬럼 추가
            leader_contact_info TEXT,
            leader_contact_method TEXT DEFAULT 'phone',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 기존 clubs 테이블에 새 컬럼이 없는 경우에만 추가
    try:
        # 컬럼 존재 여부 확인
        c.execute('SELECT leader_contact_info FROM clubs LIMIT 1')
    except sqlite3.OperationalError:
        # leader_contact_info 컬럼 추가
        c.execute('ALTER TABLE clubs ADD COLUMN leader_contact_info TEXT')
        
    try:
        # 컬럼 존재 여부 확인
        c.execute('SELECT leader_contact_method FROM clubs LIMIT 1')
    except sqlite3.OperationalError:
        # leader_contact_method 컬럼 추가
        c.execute('ALTER TABLE clubs ADD COLUMN leader_contact_method TEXT DEFAULT "phone"')
    
    # 신청 테이블 수정
    c.execute('''
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT,
            club_id INTEGER,
            status TEXT DEFAULT 'pending',
            contact_info TEXT,  -- 연락처 정보 추가
            contact_method TEXT DEFAULT 'phone',  -- 연락 방법 (phone, kakao 등)
            admin_approved BOOLEAN DEFAULT 0,  -- 관리자/부장 승인 여부
            student_accepted BOOLEAN DEFAULT 0,  -- 학생 최종 수락 여부
            final_result TEXT DEFAULT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (student_id) REFERENCES users (student_id),
            FOREIGN KEY (club_id) REFERENCES clubs (id)
        )
    ''')
    
    # 동아리 활동 테이블
    c.execute('''
        CREATE TABLE IF NOT EXISTS club_activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            club_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            activity_date DATE,
            file_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (club_id) REFERENCES clubs (id)
        )
    ''')
    
    # 관리자 계정 생성 (기본 비밀번호: admin1234)
    c.execute('''
        INSERT OR REPLACE INTO users (student_id, birth_date, name, is_admin, password)
        VALUES ('admin', '2000-01-01', '관리자', 1, 'admin1234')
    ''')
    
    # 정보 테이블 추가
    c.execute('''
        CREATE TABLE IF NOT EXISTS infos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT NOT NULL,
            order_num INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 공지사항 읽음 여부 테이블 추가
    c.execute('''
        CREATE TABLE IF NOT EXISTS notice_reads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (student_id)
        )
    ''')
    
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_admin' not in session or not session['is_admin']:
            flash('관리자 권한이 필요합니다.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def leader_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'club_leader_of' not in session:
            flash('부장 권한이 필요합니다.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    if 'user_id' in session:
        record_request(session['user_id'])
    else:
        record_request()

@app.route('/')
def index():
    conn = get_db()
    unread_notices_count = 0
    
    if 'club_leader_of' in session:
        # club_leader_of가 있는 경우에만 읽지 않은 공지사항 수를 계산
        unread_notices_count = conn.execute('''
            SELECT COUNT(*) FROM notices 
            WHERE is_important = 1 
            AND created_at > (
                SELECT COALESCE(
                    (SELECT last_read_at FROM notice_reads 
                     WHERE user_id = ? 
                     ORDER BY last_read_at DESC LIMIT 1),
                    '1900-01-01'
                )
            )
        ''', [session['user_id']]).fetchone()[0]
    
    # 공지사항 조회
    notices = conn.execute('''
        SELECT * FROM notices 
        ORDER BY is_important DESC, created_at DESC 
        LIMIT 5
    ''').fetchall()
    
    # 동아리 목록 조회
    clubs = conn.execute('''
        SELECT c.*, 
               COALESCE(COUNT(CASE WHEN a.status = 'approved' THEN 1 END), 0) as current_members,
               c.is_recruiting
        FROM clubs c
        LEFT JOIN applications a ON c.id = a.club_id
        GROUP BY c.id
        ORDER BY c.name
    ''').fetchall()
    
    # 승인 대기 중인 신청 확인
    pending_acceptance = None
    if 'user_id' in session and not session.get('is_admin'):
        pending = conn.execute('''
            SELECT a.*, c.name as club_name 
            FROM applications a
            JOIN clubs c ON a.club_id = c.id
            WHERE a.student_id = ? AND a.status = 'waiting_acceptance'
            ORDER BY a.applied_at DESC LIMIT 1
        ''', [session['user_id']]).fetchone()
        if pending:
            pending_acceptance = {
                'club_id': pending['club_id'],
                'club_name': pending['club_name']
            }
    
    conn.close()
    
    return render_template('index.html', 
                         notices=notices, 
                         clubs=clubs,
                         pending_acceptance=pending_acceptance,
                         unread_notices_count=unread_notices_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_type = request.form.get('login_type')
        conn = get_db()
        
        if login_type == 'admin':
            admin_id = request.form.get('admin_id')
            password = request.form.get('password')
            
            if admin_id != 'admin':
                flash('관리자 ID가 올바르지 않습니다.', 'danger')
                return redirect(url_for('login'))
                
            admin = conn.execute('SELECT * FROM users WHERE student_id = ? AND password = ?',
                               ['admin', password]).fetchone()
            
            if admin:
                session['user_id'] = 'admin'
                session['user_name'] = admin['name']
                session['is_admin'] = True
                flash('관리자로 로그인되었습니다.', 'success')
                return redirect(url_for('index'))
            else:
                flash('관리자 비밀번호가 올바르지 않습니다.', 'danger')
        else:
            # 일반 학생 로그인 - 학번과 생년월일로 로그인
            student_id = request.form.get('student_id')
            year = request.form.get('birth_year')
            month = request.form.get('birth_month', '').zfill(2)  # 1자리 월을 2자리로 변환
            day = request.form.get('birth_day', '').zfill(2)      # 1자리 일을 2자리로 변환
            birth_date = f"{year}-{month}-{day}"
            
            # 생년월일 형식 검증
            try:
                datetime.strptime(birth_date, '%Y-%m-%d')
                user = conn.execute('SELECT * FROM users WHERE student_id = ? AND birth_date = ?',
                                  [student_id, birth_date]).fetchone()
                
                if user:
                    session['user_id'] = user['student_id']
                    session['user_name'] = user['name']
                    session['is_admin'] = False
                    session['club_leader_of'] = user['club_leader_of']
                    flash('로그인되었습니다.', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('학번 또는 생년월일이 올바르지 않습니다.', 'danger')
            except ValueError:
                flash('생년월일 형식이 올바르지 않습니다.', 'danger')
        
        conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    conn = get_db()
    
    # 사용자 정보 조회
    user = conn.execute('SELECT * FROM users WHERE student_id = ?', 
                       [session['user_id']]).fetchone()
    
    # 신청한 동아리 목록 조회 수정 (application.id 추가)
    applications = conn.execute('''
        SELECT c.name, a.id, a.status, a.applied_at, a.final_result,
               a.contact_info, a.contact_method,
               CASE 
                   WHEN a.status = 'pending' THEN '검토중'
                   WHEN a.status = 'waiting_acceptance' THEN '승인됨 (수락 대기)'
                   WHEN a.status = 'approved' THEN '최종 승인'
                   WHEN a.status = 'rejected' THEN '거절됨'
                   WHEN a.status = 'withdrawn' THEN '탈퇴'
                   WHEN a.status = 'cancelled' THEN '취소됨'
                   WHEN a.status = 'club_deleted' THEN '동아리 폐지'
                   ELSE a.status
               END as status_display
        FROM applications a
        JOIN clubs c ON a.club_id = c.id
        WHERE a.student_id = ?
        ORDER BY a.applied_at DESC
    ''', [session['user_id']]).fetchall()
    
    conn.close()
    return render_template('profile.html', user=user, applications=applications)

@app.route('/notices', methods=['GET', 'POST'])
@admin_required
def manage_notices():
    conn = get_db()
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_important = 'is_important' in request.form
        
        conn.execute('''
            INSERT INTO notices (title, content, is_important)
            VALUES (?, ?, ?)
        ''', [title, content, is_important])
        conn.commit()
        flash('공지사항이 등록되었습니다.')
        return redirect(url_for('manage_notices'))
    
    notices = conn.execute('SELECT * FROM notices ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('manage_notices.html', notices=notices)

@app.route('/notice/<int:notice_id>/delete', methods=['POST'])
@admin_required
def delete_notice(notice_id):
    conn = get_db()
    conn.execute('DELETE FROM notices WHERE id = ?', [notice_id])
    conn.commit()
    flash('공지사항이 삭제되었습니다.')
    return redirect(url_for('manage_notices'))

@app.route('/club/new', methods=['GET', 'POST'])
@admin_required
def create_club():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        max_members = request.form['max_members']
        
        poster_path = None
        if 'poster' in request.files:
            poster = request.files['poster']
            if poster and allowed_image(poster.filename):
                filename = secure_upload(poster, f"poster_{name}", ALLOWED_IMAGES)
                if filename:
                    poster_path = filename  # 파일명만 저장
        
        conn = get_db()
        conn.execute('''
            INSERT INTO clubs (name, description, max_members, poster_path) 
            VALUES (?, ?, ?, ?)
        ''', [name, description, max_members, poster_path])
        conn.commit()
        
        flash('동아리가 생성되었습니다.')
        return redirect(url_for('index'))
    
    return render_template('create_club.html')

@app.route('/club/<int:club_id>')
def view_club(club_id):
    conn = get_db()
    
    # 동아리 정보 조회
    club = conn.execute('SELECT * FROM clubs WHERE id = ?', [club_id]).fetchone()
    if not club:
        flash('존재하지 않는 동아리입니다.')
        return redirect(url_for('index'))
    
    # 회원 수 조회
    member_count = conn.execute('''
        SELECT COUNT(*) FROM applications 
        WHERE club_id = ? AND status = 'approved'
    ''', [club_id]).fetchone()[0]
    
    # 현재 사용자의 신청/가입 상태 확인
    user_status = {
        'can_apply': True,
        'is_member': False,
        'is_leader': False,
        'has_pending': False,
        'application': None
    }
    
    if 'user_id' in session:
        # 부장 여부 확인
        user_status['is_leader'] = (session.get('club_leader_of') == club_id)
        
        # 관리자는 신청할 수 없음
        if session.get('is_admin'):
            user_status['can_apply'] = False
        else:
            # 현재 모든 동아리에 대한 승인된 신청 확인
            approved_application = conn.execute('''
                SELECT club_id FROM applications 
                WHERE student_id = ? AND status = 'approved'
            ''', [session['user_id']]).fetchone()
            
            if approved_application:
                user_status['can_apply'] = False
                user_status['is_member'] = (approved_application['club_id'] == club_id)
            
            # 현재 동아리에 대한 진행 중인 신청 확인
            current_application = conn.execute('''
                SELECT * FROM applications 
                WHERE student_id = ? AND club_id = ? 
                AND status IN ('pending', 'waiting_acceptance')
                ORDER BY applied_at DESC LIMIT 1
            ''', [session['user_id'], club_id]).fetchone()
            
            if current_application:
                user_status['can_apply'] = False
                user_status['has_pending'] = True
                user_status['application'] = current_application
    
    # 활동 내역 조회
    activities = conn.execute('''
        SELECT * FROM club_activities 
        WHERE club_id = ? 
        ORDER BY activity_date DESC
    ''', [club_id]).fetchall()
    
    conn.close()
    return render_template('view_club.html', 
                         club=club,
                         activities=activities,
                         member_count=member_count,
                         user_status=user_status)

@app.route('/club/<int:club_id>/apply', methods=['POST'])
@login_required
def apply_club(club_id):
    conn = get_db()
    
    try:
        # 모집 상태 확인
        club = conn.execute('''
            SELECT c.*, 
                   (SELECT COUNT(*) FROM applications 
                    WHERE club_id = c.id AND status = 'approved') as member_count
            FROM clubs c WHERE c.id = ?
        ''', [club_id]).fetchone()
        
        if not club['is_recruiting']:
            flash('현재 이 동아리는 모집을 마감했습니다.')
            return redirect(url_for('view_club', club_id=club_id))
        
        # 부장 여부 확인
        if session.get('club_leader_of') == club_id:
            flash('이미 이 동아리의 부장입니다.')
            return redirect(url_for('view_club', club_id=club_id))
        
        # 현재 다른 동아리에 승인된 상태인지 확인
        already_member = conn.execute('''
            SELECT c.name FROM applications a
            JOIN clubs c ON a.club_id = c.id
            WHERE a.student_id = ? AND a.status = 'approved'
        ''', [session['user_id']]).fetchone()
        
        if already_member:
            flash(f'이미 {already_member["name"]} 동아리의 회원입니다.')
            return redirect(url_for('view_club', club_id=club_id))
        
        # 현재 동아리의 정원 확인
        if club['member_count'] >= club['max_members']:
            flash('죄송합니다. 이미 정원이 마감되었습니다.')
            return redirect(url_for('view_club', club_id=club_id))
        
        # 현재 진행 중인 신청이 있는지 확인
        existing = conn.execute('''
            SELECT * FROM applications 
            WHERE student_id = ? AND club_id = ? AND 
            status IN ('pending', 'waiting_acceptance')
        ''', [session['user_id'], club_id]).fetchone()
        
        if existing:
            flash('이미 진행 중인 신청이 있습니다.')
            return redirect(url_for('view_club', club_id=club_id))
        
        contact_info = request.form.get('contact_info')
        contact_method = request.form.get('contact_method', 'phone')
        
        if not contact_info:
            flash('연락처 정보를 입력해주세요.')
            return redirect(url_for('view_club', club_id=club_id))
        
        # 신청 처리
        conn.execute('''
            INSERT INTO applications 
            (student_id, club_id, contact_info, contact_method, status) 
            VALUES (?, ?, ?, ?, 'pending')
        ''', [session['user_id'], club_id, contact_info, contact_method])
        conn.commit()
        
        flash('동아리 신청이 완료되었습니다. 부장의 승인을 기다려주세요.')
        
    except sqlite3.Error as e:
        conn.rollback()
        flash('처리 중 오류가 발생했습니다.')
    finally:
        conn.close()
    
    return redirect(url_for('view_club', club_id=club_id))

@app.route('/club/<int:club_id>/manage', methods=['GET', 'POST'])
@login_required
def manage_club(club_id):
    # 권한 확인
    if not (session.get('is_admin') or session.get('club_leader_of') == club_id):
        flash('권한이 없습니다.')
        return redirect(url_for('index'))
    
    conn = get_db()
    if request.method == 'POST':
        action = request.form['action']
        application_id = request.form['application_id']
        
        if action in ['approve', 'reject']:
            status = 'approved' if action == 'approve' else 'rejected'
            conn.execute('''
                UPDATE applications 
                SET status = ? 
                WHERE id = ?
            ''', [status, application_id])
            conn.commit()
            flash(f'신청이 {status}되었습니다.')
    
    # 신청 목록 조회 (상태와 관계없이 모든 신청 조회)
    applications = conn.execute('''
        SELECT a.*, u.name as student_name,
               (SELECT club_leader_of FROM users WHERE student_id = a.student_id) as leader_of
        FROM applications a
        JOIN users u ON a.student_id = u.student_id
        WHERE a.club_id = ?
        ORDER BY a.applied_at DESC
    ''', [club_id]).fetchall()
    
    # 동아리 정보 및 활동 내역 조회
    club = conn.execute('''
        SELECT c.*, u.student_id as leader_id 
        FROM clubs c 
        LEFT JOIN users u ON c.id = u.club_leader_of 
        WHERE c.id = ?
    ''', [club_id]).fetchone()
    
    # 활동 내역 조회
    activities = conn.execute('''
        SELECT * FROM club_activities 
        WHERE club_id = ? 
        ORDER BY activity_date DESC
    ''', [club_id]).fetchall()
    
    conn.close()
    return render_template('manage_club.html', 
                         club=club, 
                         applications=applications,
                         activities=activities)

@app.route('/club/<int:club_id>/set_leader', methods=['GET', 'POST'])
@admin_required
def set_leader(club_id):
    conn = get_db()
    if request.method == 'POST':
        student_id = request.form['student_id']
        
        # 기존 부장 해제
        conn.execute('UPDATE users SET club_leader_of = NULL WHERE club_leader_of = ?', 
                    [club_id])
        # 새 부장 지정
        conn.execute('UPDATE users SET club_leader_of = ? WHERE student_id = ?', 
                    [club_id, student_id])
        conn.commit()
        
        flash('부장이 지정되었습니다.')
        return redirect(url_for('view_club', club_id=club_id))
    
    # 현재 동아리 회원 목록 조회
    members = conn.execute('''
        SELECT u.* FROM users u
        JOIN applications a ON u.student_id = a.student_id
        WHERE a.club_id = ? AND a.status = 'approved'
    ''', [club_id]).fetchall()
    
    club = conn.execute('SELECT * FROM clubs WHERE id = ?', [club_id]).fetchone()
    
    return render_template('set_leader.html', club=club, members=members)

# 관리자 비밀번호 확인 함수 추가
def verify_admin_password(password):
    conn = get_db()
    admin = conn.execute('''
        SELECT password FROM users 
        WHERE student_id = 'admin' AND is_admin = 1
    ''').fetchone()
    conn.close()
    
    return admin and admin['password'] == password

@app.route('/admin/change_password', methods=['POST'])
@admin_required
def change_admin_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not verify_admin_password(current_password):
        flash('현재 비밀번호가 올바르지 않습니다.')
        return redirect(url_for('admin_settings'))
    
    if new_password != confirm_password:
        flash('새 비밀번호와 확인 비밀번호가 일치하지 않습니다.')
        return redirect(url_for('admin_settings'))
    
    if len(new_password) < 8:
        flash('비밀번호는 8자 이상이어야 합니다.')
        return redirect(url_for('admin_settings'))
    
    conn = get_db()
    conn.execute('''
        UPDATE users 
        SET password = ? 
        WHERE student_id = 'admin'
    ''', [new_password])
    conn.commit()
    conn.close()
    
    flash('관리자 비밀번호가 변경되었습니다.')
    return redirect(url_for('admin_settings'))

@app.route('/admin/force_actions', methods=['GET', 'POST'])
@admin_required
def admin_force_actions():
    if request.method == 'POST':
        action = request.form.get('action')
        student_id = request.form.get('student_id')
            
        conn = get_db()
        
        if action == 'move':
            to_club_id = request.form.get('to_club_id')  # 추가: to_club_id 가져오기
            
            # 학생 존재 여부 확인
            student = conn.execute('SELECT * FROM users WHERE student_id = ?', 
                                 [student_id]).fetchone()
            if not student:
                flash('존재하지 않는 학생입니다.', 'error')
                return redirect(url_for('admin_force_actions'))
                
            try:
                conn.execute('BEGIN TRANSACTION')
                
                # 학생이 현재 다른 동아리의 부장인지 확인
                current_leader_of = conn.execute('''
                    SELECT club_leader_of FROM users 
                    WHERE student_id = ?
                ''', [student_id]).fetchone()['club_leader_of']
                
                # 이동할 동아리의 현재 부장 확인
                current_club_leader = conn.execute('''
                    SELECT student_id FROM users 
                    WHERE club_leader_of = ?
                ''', [to_club_id]).fetchone()
                
                # 부장 직위 관련 처리
                set_as_leader = request.form.get('set_as_leader') == 'on'
                
                if set_as_leader:
                    # 현재 부장이 있다면 해제
                    if current_club_leader:
                        conn.execute('''
                            UPDATE users 
                            SET club_leader_of = NULL 
                            WHERE student_id = ?
                        ''', [current_club_leader['student_id']])
                
                # 기존 부장 직위 해제 (다른 동아리의 부장이었다면)
                if current_leader_of:
                    conn.execute('''
                        UPDATE users 
                        SET club_leader_of = NULL 
                        WHERE student_id = ?
                    ''', [student_id])
                
                # 기존의 모든 동아리 신청/가입 상태를 'withdrawn'으로 변경
                conn.execute('''
                    UPDATE applications 
                    SET status = 'withdrawn', 
                        final_result = '관리자에 의해 강제 이동됨'
                    WHERE student_id = ? AND status IN ('approved', 'pending')
                ''', [student_id])
                
                # 새로운 동아리 배정
                # 이미 해당 동아리에 신청 내역이 있는지 확인
                existing = conn.execute('''
                    SELECT id FROM applications 
                    WHERE student_id = ? AND club_id = ?
                ''', [student_id, to_club_id]).fetchone()
                
                if existing:
                    conn.execute('''
                        UPDATE applications 
                        SET status = 'approved',
                            final_result = '관리자에 의해 강제 배정됨',
                            applied_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', [existing['id']])
                else:
                    conn.execute('''
                        INSERT INTO applications 
                        (student_id, club_id, status, final_result) 
                        VALUES (?, ?, 'approved', '관리자에 의해 강제 배정됨')
                    ''', [student_id, to_club_id])
                
                # 부장으로 지정 요청이 있는 경우
                if set_as_leader:
                    conn.execute('''
                        UPDATE users 
                        SET club_leader_of = ? 
                        WHERE student_id = ?
                    ''', [to_club_id, student_id])
                    result_message = '학생이 성공적으로 이동되었으며 부장으로 지정되었습니다.'
                else:
                    result_message = '학생이 성공적으로 이동되었습니다.'
                
                conn.commit()
                flash(f'{result_message}', 'success')
                
            except sqlite3.Error as e:
                conn.rollback()
                flash(f'처리 중 오류가 발생했습니다: {str(e)}', 'error')
            finally:
                conn.close()
            
        elif action == 'withdraw':
            club_id = request.form.get('club_id')
            
            try:
                # 트랜잭션 시작
                conn.execute('BEGIN TRANSACTION')
                
                # 1. 부장 직위 해제 (해당 동아리의 부장이었다면)
                conn.execute('''
                    UPDATE users 
                    SET club_leader_of = CASE 
                        WHEN club_leader_of = ? THEN NULL 
                        ELSE club_leader_of 
                    END
                    WHERE student_id = ?
                ''', [club_id, student_id])
                
                # 2. 동아리 탈퇴 처리
                result = conn.execute('''
                    UPDATE applications 
                    SET status = 'withdrawn',
                        final_result = '관리자에 의해 강제 탈퇴됨'
                    WHERE student_id = ? AND club_id = ? 
                    AND status IN ('approved', 'pending')
                ''', [student_id, club_id])
                
                # 트랜잭션 커밋
                conn.commit()
                
                if result.rowcount > 0:
                    flash(f'학생({student_id})이 동아리에서 탈퇴 처리되었습니다.', 'success')
                else:
                    flash('해당 학생이 선택한 동아리에 소속되어 있지 않습니다.', 'error')
                
            except sqlite3.Error as e:
                # 오류 발생 시 롤백
                conn.rollback()
                flash(f'처리 중 오류가 발생했습니다: {str(e)}', 'error')
                
        elif action == 'delete_club':
            club_id = request.form.get('club_id')
            admin_password = request.form.get('admin_password')
            
            # 관리자 비밀번호 확인은 동아리 삭제 시에만 수행
            if not verify_admin_password(admin_password):
                flash('관리자 비밀번호가 일치하지 않습니다.', 'error')
                return redirect(url_for('admin_force_actions'))
            
            # 동아리 정보 백업
            club_info = conn.execute('SELECT * FROM clubs WHERE id = ?', [club_id]).fetchone()
            if not club_info:
                flash('존재하지 않는 동아리입니다.', 'error')
                return redirect(url_for('admin_force_actions'))
            
            # 모든 회원 탈퇴 처리
            conn.execute('UPDATE applications SET status = ? WHERE club_id = ?',
                       ['club_deleted', club_id])
            
            # 동아리 삭제
            conn.execute('DELETE FROM clubs WHERE id = ?', [club_id])
            conn.commit()
            
            flash(f'동아리({club_info["name"]})가 완전히 삭제되었습니다.', 'success')
        
        conn.close()
        return redirect(url_for('admin_force_actions'))
    
    # GET 요청 처리
    conn = get_db()
    clubs = conn.execute('SELECT id, name FROM clubs ORDER BY name').fetchall()
    conn.close()
    
    return render_template('admin_force_actions.html', clubs=clubs)

@app.route('/uploads/<filename>')
def uploads(filename):
    """모든 사용자에게 업로드된 파일 제공"""
    try:
        # 역슬래시를 슬래시로 변환
        filename = filename.replace('\\', '/')
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return "File not found", 404

def load_students_from_csv(file_path):
    conn = get_db()
    
    with open(file_path, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            conn.execute('''
                INSERT OR REPLACE INTO users (student_id, name, birth_date, is_admin)
                VALUES (?, ?, ?, 0)
            ''', [row['student_id'], row['name'], row['birth_date']])
    
    conn.commit()

def load_teachers_from_csv(file_path):
    conn = get_db()
    
    with open(file_path, 'r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            conn.execute('''
                INSERT OR REPLACE INTO teachers (name, department, group_number)
                VALUES (?, ?, ?)
            ''', [row['name'], row['department'], int(row['group_number'])])
    
    conn.commit()

@app.route('/admin/load_data', methods=['GET', 'POST'])
@admin_required
def load_data():
    if request.method == 'POST':
        action = request.form.get('action')
        conn = get_db()
        
        try:
            if action == 'upload_students':
                if 'file' not in request.files:
                    raise ValueError('파일이 없습니다.')
                
                file = request.files['file']
                if file.filename == '':
                    raise ValueError('선택된 파일이 없습니다.')
                
                if file and file.filename.endswith('.csv'):
                    content = file.read().decode('utf-8-sig').splitlines()
                    csv_reader = csv.DictReader(content)
                    
                    # 결과 통계를 위한 카운터
                    stats = {
                        'total': 0,
                        'updated': 0,
                        'added': 0,
                        'skipped': 0,
                        'errors': []
                    }
                    
                    for row in csv_reader:
                        stats['total'] += 1
                        try:
                            # 기존 관리자 계정은 건드리지 않음
                            if row['student_id'] == 'admin':
                                stats['skipped'] += 1
                                continue
                                
                            # 기존 학생 확인
                            existing = conn.execute(
                                'SELECT 1 FROM users WHERE student_id = ?', 
                                [row['student_id']]
                            ).fetchone()
                            
                            conn.execute('''
                                INSERT OR REPLACE INTO users 
                                (student_id, name, birth_date, is_admin)
                                VALUES (?, ?, ?, 0)
                            ''', [row['student_id'], row['name'], row['birth_date']])
                            
                            if existing:
                                stats['updated'] += 1
                            else:
                                stats['added'] += 1
                                
                        except Exception as e:
                            stats['errors'].append(f"행 {stats['total']}: {str(e)}")
                    
                    conn.commit()
                    
                    # 결과 메시지 생성
                    result_msg = (
                        f"총 {stats['total']}개 처리 완료\n"
                        f"- 추가된 학생: {stats['added']}명\n"
                        f"- 수정된 학생: {stats['updated']}명\n"
                        f"- 건너뛴 항목: {stats['skipped']}개"
                    )
                    if stats['errors']:
                        result_msg += f"\n\n오류 발생 ({len(stats['errors'])}건):\n"
                        result_msg += "\n".join(stats['errors'])
                    
                    flash(result_msg)
                    
            elif action == 'add_student':
                student_id = request.form.get('student_id')
                name = request.form.get('name')
                birth_date = request.form.get('birth_date')
                
                # 관리자 계정 보호
                if student_id == 'admin':
                    raise ValueError('관리자 계정은 추가할 수 없습니다.')
                
                # 학번 형식 검증
                if not student_id.isdigit() or len(student_id) != 5:
                    raise ValueError('학번은 5자리 숫자여야 합니다.')
                
                conn.execute('''
                    INSERT INTO users (student_id, name, birth_date, is_admin)
                    VALUES (?, ?, ?, 0)
                ''', [student_id, name, birth_date])
                flash('학생이 추가되었습니다.', 'success')
                
            elif action == 'delete_student':
                student_id = request.form.get('student_id')
                
                # 관리자 계정 보호
                if student_id == 'admin':
                    raise ValueError('관리자 계정은 삭제할 수 없습니다.')
                
                # 동아리 가입 여부 확인
                has_club = conn.execute('''
                    SELECT 1 FROM applications
                    WHERE student_id = ? AND status = 'approved'
                ''', [student_id]).fetchone()
                
                if has_club:
                    raise ValueError('동아리에 가입된 학생은 삭제할 수 없습니다.')
                
                result = conn.execute('DELETE FROM users WHERE student_id = ?', 
                                    [student_id])
                if result.rowcount == 0:
                    raise ValueError('존재하지 않는 학생입니다.')
                    
                flash('학생이 삭제되었습니다.', 'success')
                
            elif action == 'upload_teachers':
                if 'file' not in request.files:
                    raise ValueError('파일이 없습니다.')
                
                file = request.files['file']
                if file.filename == '':
                    raise ValueError('선택된 파일이 없습니다.')
                
                if file and file.filename.endswith('.csv'):
                    content = file.read().decode('utf-8-sig').splitlines()
                    csv_reader = csv.DictReader(content)
                    for row in csv_reader:
                        if not (1 <= int(row['group_number']) <= 6):
                            raise ValueError('그룹 번호는 1~6 사이여야 합니다.')
                        
                        conn.execute('''
                            INSERT OR REPLACE INTO teachers (name, department, group_number)
                            VALUES (?, ?, ?)
                        ''', [row['name'], row['department'], int(row['group_number'])])
                    flash('선생님 데이터가 성공적으로 업로드되었습니다.', 'success')
                    
            elif action == 'add_teacher':
                name = request.form.get('name')
                department = request.form.get('department')
                group_number = int(request.form.get('group_number'))
                
                if not (1 <= group_number <= 6):
                    raise ValueError('그룹 번호는 1~6 사이여야 합니다.')
                 
                conn.execute('''
                    INSERT INTO teachers (name, department, group_number)
                    VALUES (?, ?, ?)
                ''', [name, department, group_number])
                flash('선생님이 추가되었습니다.', 'success')
            
            conn.commit()
            
        except ValueError as e:
            flash(str(e), 'error')
        except Exception as e:
            flash(f'처리 중 오류가 발생했습니다: {str(e)}', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('load_data'))
    
    return render_template('load_data.html')

@app.route('/admin/students')
@admin_required
def view_all_students():
    conn = get_db()
    
    # 검색 파라미터
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'student_id')
    order = request.args.get('order', 'asc')
    
    # 기본 쿼리
    query = '''
        SELECT u.*, 
               c.name as club_name,
               (SELECT COUNT(*) FROM applications 
                WHERE student_id = u.student_id 
                AND status = 'pending') as pending_applications
        FROM users u
        LEFT JOIN clubs c ON u.club_leader_of = c.id
        LEFT JOIN applications a ON u.student_id = a.student_id AND a.status = 'approved'
        LEFT JOIN clubs ac ON a.club_id = ac.id
        WHERE u.student_id != 'admin'
    '''
    
    # 검색 조건 추가
    params = []
    if search:
        query += ''' AND (
            u.student_id LIKE ? OR 
            u.name LIKE ? OR 
            c.name LIKE ? OR
            ac.name LIKE ?
        )'''
        search_param = f'%{search}%'
        params.extend([search_param] * 4)
    
    # 정렬 조건 추가 (SQL 인젝션 방지를 위해 허용된 컬럼만 사용)
    allowed_sort_columns = {
        'student_id': 'u.student_id',
        'name': 'u.name',
        'birth_date': 'u.birth_date',
        'club': 'ac.name'
    }
    sort_column = allowed_sort_columns.get(sort, 'u.student_id')
    order_by = 'ASC' if order.upper() == 'ASC' else 'DESC'
    
    query += f' ORDER BY {sort_column} {order_by}'
    
    # 쿼리 실행
    students = conn.execute(query, params).fetchall()
    
    # 학생별 가입된 동아리 정보 조회
    for student in students:
        student_clubs = conn.execute('''
            SELECT c.name 
            FROM applications a
            JOIN clubs c ON a.club_id = c.id
            WHERE a.student_id = ? AND a.status = 'approved'
        ''', [student['student_id']]).fetchall()
        student_dict = dict(student)
        student_dict['clubs'] = [club['name'] for club in student_clubs]
        student_dict['clubs_str'] = ', '.join(student_dict['clubs'])
    
    conn.close()
    
    return render_template('view_all_students.html', 
                         students=students,
                         search=search,
                         sort=sort,
                         order=order)

@app.route('/teachers')
def view_teachers():
    conn = get_db()
    # 선생님 그룹 데이터 구조 변경
    teacher_groups = {}
    
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS teacher_groups (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                display_order INTEGER DEFAULT 0
            )
        ''')
        
        # 기본 그룹 데이터를 6개로 수정
        conn.execute('''
            INSERT OR IGNORE INTO teacher_groups (id, name, display_order)
            VALUES 
                (1, '1학년부', 1),
                (2, '2학년부', 2),
                (3, '3학년부', 3),
                (4, '전문교과부', 4),
                (5, '특수교과부', 5),
                (6, '기타', 6)
        ''')
        conn.commit()
    except:
        pass
    
    # 그룹 정보 조회
    groups = conn.execute('SELECT * FROM teacher_groups ORDER BY display_order, id').fetchall()
    
    for group in groups:
        teachers = conn.execute('''
            SELECT t.*, CASE 
                WHEN t.is_selected = 1 THEN '배정완료'
                ELSE '미배정' 
            END as status
            FROM teachers t
            WHERE t.group_number = ?
            ORDER BY t.department, t.name
        ''', [group['id']]).fetchall()
        
        teacher_groups[group['id']] = {
            'group_name': group['name'],
            'teachers': teachers
        }
    
    conn.close()
    return render_template('view_teachers.html', teacher_groups=teacher_groups)

@app.route('/teachers/manage', methods=['GET', 'POST'])
@admin_required
def manage_teachers():
    conn = get_db()
    try:
        # teacher_groups 테이블 존재 여부 확인 및 생성
        conn.execute('''
            CREATE TABLE IF NOT EXISTS teacher_groups (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                display_order INTEGER DEFAULT 0
            )
        ''')
        
        # 기본 그룹 데이터를 6개로 수정
        conn.execute('''
            INSERT OR IGNORE INTO teacher_groups (id, name, display_order)
            VALUES 
                (1, '1학년부', 1),
                (2, '2학년부', 2),
                (3, '3학년부', 3),
                (4, '전문교과부', 4),
                (5, '특수교과부', 5),
                (6, '기타', 6)
        ''')
        conn.commit()
        
    except sqlite3.Error:
        pass

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'upload' and 'file' in request.files:
            file = request.files['file']
            if file and file.filename.endswith('.csv'):
                try:
                    content = file.read().decode('utf-8').splitlines()
                    csv_reader = csv.DictReader(content)
                    for row in csv_reader:
                        if not (1 <= int(row['group_number']) <= 6):  # 범위를 6으로 수정
                            flash('그룹 번호는 1~6 사이여야 합니다.')
                            return redirect(url_for('manage_teachers'))
                        
                        conn.execute('''
                            INSERT INTO teachers (name, department, group_number)
                            VALUES (?, ?, ?)
                        ''', [row['name'], row['department'], int(row['group_number'])])
                    conn.commit()
                    flash('선생님 명단이 성공적으로 업로드되었습니다.')
                except Exception as e:
                    flash(f'파일 처리 중 오류가 발생했습니다: {str(e)}')
                    
        elif action == 'add':
            name = request.form.get('name')
            department = request.form.get('department')
            group_number = request.form.get('group_number')
            
            if name and department and group_number:
                conn.execute('''
                    INSERT INTO teachers (name, department, group_number)
                    VALUES (?, ?, ?)
                ''', [name, department, int(group_number)])
                conn.commit()
                flash('선생님이 추가되었습니다.')
                
        elif action == 'toggle_selection':
            teacher_id = request.form.get('teacher_id')
            if teacher_id:
                current = conn.execute('SELECT is_selected FROM teachers WHERE id = ?', 
                                     [teacher_id]).fetchone()
                if current:
                    new_status = not current['is_selected']
                    conn.execute('''
                        UPDATE teachers 
                        SET is_selected = ?, 
                            selected_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END
                        WHERE id = ?
                    ''', [new_status, new_status, teacher_id])
                    conn.commit()
                    flash('선생님 상태가 변경되었습니다.')
                    
        elif action == 'delete':
            teacher_id = request.form.get('teacher_id')
            if teacher_id:
                conn.execute('DELETE FROM teachers WHERE id = ?', [teacher_id])
                conn.commit()
                flash('선생님이 삭제되었습니다.')

    # 그룹 정보와 각 그룹의 선생님 목록을 함께 조회
    teacher_groups = {}
    groups = conn.execute('SELECT * FROM teacher_groups ORDER BY display_order, id').fetchall()
    
    for group in groups:
        teachers = conn.execute('''
            SELECT * FROM teachers 
            WHERE group_number = ?
            ORDER BY department, name
        ''', [group['id']]).fetchall()
        
        teacher_groups[group['id']] = {
            'group_name': group['name'],
            'teachers': teachers
        }
    
    conn.close()
    return render_template('manage_teachers.html', teacher_groups=teacher_groups)

@app.route('/club/<int:club_id>/activity/new', methods=['GET', 'POST'])
@login_required
def create_activity(club_id):
    if not (session.get('is_admin') or session.get('club_leader_of') == club_id):
        flash('권한이 없습니다.')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        activity_date = request.form['activity_date']
        
        file_path = None
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"activity_{club_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}")
                file_path = os.path.join('uploads', filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        conn = get_db()
        conn.execute('''
            INSERT INTO club_activities (club_id, title, description, activity_date, file_path)
            VALUES (?, ?, ?, ?, ?)
        ''', [club_id, title, description, activity_date, file_path])
        conn.commit()
        
        flash('활동 내역이 추가되었습니다.')
        return redirect(url_for('manage_club', club_id=club_id))
    
    return render_template('create_activity.html', club_id=club_id)

@app.route('/club/<int:club_id>/manage_applications', methods=['GET'])
@login_required
def manage_applications(club_id):
    # 권한 확인
    if not (session.get('is_admin') or session.get('club_leader_of') == club_id):
        flash('권한이 없습니다.')
        return redirect(url_for('index'))
    
    conn = get_db()
    applications = conn.execute('''
        SELECT a.*, u.name as student_name
        FROM applications a
        JOIN users u ON a.student_id = u.student_id
        WHERE a.club_id = ? AND a.status != 'rejected'
        ORDER BY a.applied_at DESC
    ''', [club_id]).fetchall()
    
    club = conn.execute('SELECT * FROM clubs WHERE id = ?', [club_id]).fetchone()
    
    return render_template('manage_applications.html', 
                         applications=applications, 
                         club=club)

@app.route('/club/<int:club_id>/approve_application/<int:application_id>', methods=['POST'])
@login_required
def approve_application(club_id, application_id):
    if not (session.get('is_admin') or session.get('club_leader_of') == club_id):
        flash('권한이 없습니다.')
        return redirect(url_for('index'))
    
    conn = get_db()
    conn.execute('''
        UPDATE applications 
        SET admin_approved = 1, 
            status = 'waiting_acceptance'
        WHERE id = ? AND club_id = ?
    ''', [application_id, club_id])
    conn.commit()
    
    flash('지원자가 승인되었습니다. 지원자의 최종 수락을 기다립니다.')
    return redirect(url_for('manage_applications', club_id=club_id))

@app.route('/club/<int:club_id>/reject_application/<int:application_id>', methods=['POST'])
@login_required
def reject_application(club_id, application_id):
    # 부장이나 관리자 권한 확인
    if not (session.get('is_admin') or session.get('club_leader_of') == club_id):
        flash('권한이 없습니다.')
        return redirect(url_for('index'))
    
    conn = get_db()
    try:
        conn.execute('''
            UPDATE applications 
            SET status = 'rejected',
                final_result = '부장/관리자에 의해 거절됨'
            WHERE id = ? AND club_id = ?
        ''', [application_id, club_id])
        conn.commit()
        flash('신청이 거절되었습니다.')
    except:
        flash('처리 중 오류가 발생했습니다.')
    finally:
        conn.close()
    
    return redirect(url_for('manage_club', club_id=club_id))

@app.route('/my_applications')
@login_required
def my_applications():
    conn = get_db()
    applications = conn.execute('''
        SELECT a.*, c.name as club_name, c.max_members,
               (SELECT COUNT(*) FROM applications 
                WHERE club_id = c.id AND status = 'approved') as current_members
        FROM applications a
        JOIN clubs c ON a.club_id = c.id
        WHERE a.student_id = ? AND a.status != 'rejected'
        ORDER BY a.applied_at DESC
    ''', [session['user_id']]).fetchall()
    
    return render_template('my_applications.html', applications=applications)

@app.route('/application/<int:application_id>/accept', methods=['POST'])
@login_required
def accept_application(application_id):
    conn = get_db()
    
    try:
        # 신청 정보 확인
        application = conn.execute('''
            SELECT a.*, c.max_members, c.name as club_name,
                   (SELECT COUNT(*) FROM applications 
                    WHERE club_id = a.club_id AND status = 'approved') as current_members
            FROM applications a
            JOIN clubs c ON a.club_id = c.id
            WHERE a.id = ? AND a.student_id = ? 
            AND a.status = 'waiting_acceptance'
        ''', [application_id, session['user_id']]).fetchone()
        
        if not application:
            flash('유효하지 않은 신청입니다.')
            return redirect(url_for('my_applications'))
        
        # 정원 재확인
        if application['current_members'] >= application['max_members']:
            conn.execute('''
                UPDATE applications 
                SET status = 'rejected',
                    final_result = '정원 초과로 인한 자동 거절'
                WHERE id = ?
            ''', [application_id])
            conn.commit()
            flash(f'죄송합니다. {application["club_name"]} 동아리의 정원이 마감되었습니다.')
            return redirect(url_for('my_applications'))
        
        conn.execute('BEGIN TRANSACTION')
        
        # 다른 모든 신청을 취소 처리
        conn.execute('''
            UPDATE applications 
            SET status = 'cancelled',
                final_result = '다른 동아리 선택으로 인한 자동 취소'
            WHERE student_id = ? AND id != ? AND 
            status IN ('pending', 'waiting_acceptance')
        ''', [session['user_id'], application_id])
        
        # 현재 신청을 승인 처리
        conn.execute('''
            UPDATE applications 
            SET status = 'approved',
                student_accepted = 1,
                final_result = '최종 승인 완료'
            WHERE id = ?
        ''', [application_id])
        
        conn.commit()
        flash(f'{application["club_name"]} 동아리 가입이 완료되었습니다.')
        
    except sqlite3.Error:
        conn.rollback()
        flash('처리 중 오류가 발생했습니다.')
    finally:
        conn.close()
    
    return redirect(url_for('my_applications'))

@app.route('/application/<int:application_id>/withdraw', methods=['POST'])
@login_required
def withdraw_club(application_id):
    conn = get_db()
    try:
        # 신청 정보 확인
        application = conn.execute('''
            SELECT * FROM applications
            WHERE id = ? AND student_id = ? AND status = 'approved'
        ''', [application_id, session['user_id']]).fetchone()
        
        if not application:
            flash('유효하지 않은 요청입니다.')
            return redirect(url_for('profile'))
        
        # 부장인 경우 탈퇴 불가
        if session.get('club_leader_of') == application['club_id']:
            flash('부장은 직접 탈퇴할 수 없습니다. 관리자에게 문의하세요.')
            return redirect(url_for('profile'))
        
        # 탈퇴 처리
        conn.execute('''
            UPDATE applications 
            SET status = 'withdrawn',
                final_result = '회원 본인 탈퇴',
                student_accepted = 0
            WHERE id = ?
        ''', [application_id])
        
        conn.commit()
        flash('동아리에서 탈퇴되었습니다.')
        
    except sqlite3.Error as e:
        conn.rollback()
        flash('처리 중 오류가 발생했습니다.')
    finally:
        conn.close()
    
    return redirect(url_for('profile'))

@app.route('/admin/export', methods=['GET'])
@admin_required
def admin_export():
    conn = get_db()
    clubs = conn.execute('SELECT * FROM clubs ORDER BY name').fetchall()
    conn.close()
    return render_template('admin_data_export.html', clubs=clubs)

@app.route('/admin/export/all', methods=['POST'])
@admin_required
def export_all_data():
    include_all = 'include_all' in request.form
    
    if include_all:
        include_types = ['students', 'clubs', 'applications', 'teachers', 'activities']
    else:
        include_types = []
        if 'include_students' in request.form:
            include_types.append('students')
        if 'include_clubs' in request.form:
            include_types.append('clubs')
        if 'include_applications' in request.form:
            include_types.append('applications')
        if 'include_teachers' in request.form:
            include_types.append('teachers')
        if 'include_activities' in request.form:
            include_types.append('activities')
    
    if not include_types:
        flash('내보낼 데이터를 선택해주세요.')
        return redirect(url_for('admin_export'))
    
    memory_file = io.BytesIO()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    with zipfile.ZipFile(memory_file, 'w') as zf:
        if 'students' in include_types:
            students_csv = generate_students_csv()
            zf.writestr(f'학생명단_{timestamp}.csv', students_csv.encode('utf-8-sig'))
        
        if 'clubs' in include_types:
            clubs_csv = generate_clubs_csv()
            zf.writestr(f'동아리정보_{timestamp}.csv', clubs_csv.encode('utf-8-sig'))
            members_csv = generate_club_members_csv()
            zf.writestr(f'동아리별회원명단_{timestamp}.csv', members_csv.encode('utf-8-sig'))
        
        if 'applications' in include_types:
            applications_csv = generate_applications_csv()
            zf.writestr(f'신청내역_{timestamp}.csv', applications_csv.encode('utf-8-sig'))
        
        if 'teachers' in include_types:
            teachers_csv = generate_teachers_csv()  # 새로운 함수 추가 필요
            zf.writestr(f'선생님명단_{timestamp}.csv', teachers_csv.encode('utf-8-sig'))
        
        if 'activities' in include_types:
            activities_csv = generate_club_activities_csv()
            zf.writestr(f'동아리활동내역_{timestamp}.csv', activities_csv.encode('utf-8-sig'))
    
    memory_file.seek(0)
    return send_file(
        memory_file,
        download_name=f'동아리관리시스템_데이터_{timestamp}.zip',
        as_attachment=True,
        mimetype='application/zip'
    )

@app.route('/admin/export/<data_type>')
@admin_required
def export_data(data_type):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    club_id = request.args.get('club_id')
    
    if data_type == 'all_students':
        csv_data = generate_all_students_csv()
        filename = f'전교생동아리현황_{timestamp}.csv'
    elif data_type == 'unregistered':
        csv_data = generate_unregistered_students_csv()
        filename = f'미배정학생명단_{timestamp}.csv'
    elif data_type == 'club_members':
        if not club_id:
            flash('동아리 ID가 필요합니다.')
            return redirect(url_for('admin_export'))
        csv_data = generate_club_members_csv(club_id, include_contact=False)
        club_name = get_club_name(club_id)
        filename = f'{club_name}_회원명단_{timestamp}.csv'
    elif data_type == 'club_members_with_contact':
        if not club_id:
            flash('동아리 ID가 필요합니다.')
            return redirect(url_for('admin_export'))
        csv_data = generate_club_members_csv(club_id, include_contact=True)
        club_name = get_club_name(club_id)
        filename = f'{club_name}_회원명단_연락처_{timestamp}.csv'
    else:
        flash('지원하지 않는 데이터 유형입니다.')
        return redirect(url_for('admin_export'))
    
    return send_file(
        io.BytesIO(csv_data.encode('utf-8-sig')),
        mimetype='text/csv',
        download_name=filename,
        as_attachment=True
    )

def get_club_name(club_id):
    conn = get_db()
    club = conn.execute('SELECT name FROM clubs WHERE id = ?', [club_id]).fetchone()
    conn.close()
    return club['name'] if club else '알수없음'

def generate_all_students_csv():
    conn = get_db()
    students = conn.execute('''
        SELECT u.student_id, u.name, u.birth_date,
               c.name as club_name,
               CASE 
                   WHEN u.club_leader_of = a.club_id THEN '부장'
                   WHEN a.status = 'approved' THEN '회원'
                   ELSE '미배정'
               END as role
        FROM users u
        LEFT JOIN applications a ON u.student_id = a.student_id AND a.status = 'approved'
        LEFT JOIN clubs c ON a.club_id = c.id
        WHERE u.student_id != 'admin'
        ORDER BY u.student_id
    ''').fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['학번', '이름', '생년월일', '소속 동아리', '역할'])
    
    for student in students:
        writer.writerow([
            student['student_id'],
            student['name'],
            student['birth_date'],
            student['club_name'] or '미배정',
            student['role']
        ])
    
    return output.getvalue()

def generate_teachers_csv():
    """선생님 명단을 CSV로 생성"""
    conn = get_db()
    teachers = conn.execute('''
        SELECT t.*,
               CASE WHEN t.is_selected THEN '배정완료' ELSE '미배정' END as status
        FROM teachers t
        ORDER BY t.group_number, t.department, t.name
    ''').fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['이름', '부서', '그룹', '상태', '선택일시'])
    
    for teacher in teachers:
        writer.writerow([
            teacher['name'],
            teacher['department'],
            teacher['group_number'],
            teacher['status'],
            teacher['selected_at'] or ''
        ])
    
    return output.getvalue()

def generate_students_csv():
    conn = get_db()
    students = conn.execute('''
        SELECT u.*, 
               c.name as leader_of_club
        FROM users u
        LEFT JOIN clubs c ON u.club_leader_of = c.id
        WHERE u.student_id != 'admin'
        ORDER BY u.student_id
    ''').fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['학번', '이름', '생년월일', '부장 동아리'])
    
    for student in students:
        writer.writerow([
            student['student_id'],
            student['name'],
            student['birth_date'],
            student['leader_of_club'] or ''
        ])
    
    return output.getvalue()

def generate_clubs_csv():
    conn = get_db()
    clubs = conn.execute('''
        SELECT c.*, 
               u.name as leader_name,
               COUNT(CASE WHEN a.status = 'approved' THEN 1 END) as current_members
        FROM clubs c
        LEFT JOIN users u ON c.id = u.club_leader_of
        LEFT JOIN applications a ON c.id = a.club_id
        GROUP BY c.id
        ORDER BY c.name
    ''').fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['동아리명', '설명', '정원', '현재 인원', '부장', '생성일'])
    
    for club in clubs:
        writer.writerow([
            club['name'],
            club['description'],
            club['max_members'],
            club['current_members'],
            club['leader_name'] or '',
            club['created_at']
        ])
    
    return output.getvalue()

def generate_applications_csv():
    conn = get_db()
    applications = conn.execute('''
        SELECT a.*, 
               u.name as student_name,
               c.name as club_name
        FROM applications a
        JOIN users u ON a.student_id = u.student_id
        JOIN clubs c ON a.club_id = c.id
        ORDER BY a.applied_at DESC
    ''').fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        '신청일', '동아리명', '학번', '이름', '상태', '연락처',
        '연락방법', '관리자승인', '학생수락', '최종결과'
    ])
    
    for app in applications:
        writer.writerow([
            app['applied_at'],
            app['club_name'],
            app['student_id'],
            app['student_name'],
            app['status'],
            app['contact_info'] or '',
            app['contact_method'],
            '예' if app['admin_approved'] else '아니오',
            '예' if app['student_accepted'] else '아니오',
            app['final_result'] or ''
        ])
    
    return output.getvalue()

def generate_club_members_csv(club_id, include_contact=False):
    conn = get_db()
    query = '''
        SELECT u.student_id, u.name,
               a.contact_info, a.contact_method,
               CASE WHEN u.club_leader_of = ? THEN '부장' ELSE '회원' END as role,
               a.applied_at
        FROM applications a
        JOIN users u ON a.student_id = u.student_id
        WHERE a.club_id = ? AND a.status = 'approved'
        ORDER BY role DESC, u.student_id
    '''
    
    members = conn.execute(query, [club_id, club_id]).fetchall()
    club = conn.execute('SELECT name FROM clubs WHERE id = ?', [club_id]).fetchone()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    if include_contact:
        writer.writerow(['동아리명', '학번', '이름', '역할', '연락처', '연락방법', '가입일'])
        for member in members:
            writer.writerow([
                club['name'],
                member['student_id'],
                member['name'],
                member['role'],
                member['contact_info'] or '',
                member['contact_method'] or '',
                member['applied_at']
            ])
    else:
        writer.writerow(['동아리명', '학번', '이름', '역할', '가입일'])
        for member in members:
            writer.writerow([
                club['name'],
                member['student_id'],
                member['name'],
                member['role'],
                member['applied_at']
            ])
    
    return output.getvalue()

def generate_unregistered_students_csv():
    conn = get_db()
    students = conn.execute('''
        SELECT u.student_id, u.name, u.birth_date,
               CASE 
                   WHEN EXISTS(
                       SELECT 1 FROM applications a 
                       WHERE a.student_id = u.student_id 
                       AND a.status IN ('pending', 'waiting_acceptance')
                   ) THEN '신청중'
                   ELSE '미신청'
               END as status
        FROM users u
        WHERE u.student_id != 'admin'
        AND NOT EXISTS (
            SELECT 1 FROM applications a 
            WHERE a.student_id = u.student_id 
            AND a.status = 'approved'
        )
        ORDER BY u.student_id
    ''').fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['학번', '이름', '생년월일', '상태'])
    
    for student in students:
        writer.writerow([
            student['student_id'],
            student['name'],
            student['birth_date'],
            student['status']
        ])
    
    return output.getvalue()

# 정보 관련 라우트 추가
@app.route('/info')
def view_info():
    conn = get_db()
    infos = conn.execute('''
        SELECT * FROM infos 
        ORDER BY category, order_num, created_at DESC
    ''').fetchall()
    
    # 카테고리별로 정보 분류
    categorized_infos = {}
    for info in infos:
        if info['category'] not in categorized_infos:
            categorized_infos[info['category']] = []
        categorized_infos[info['category']].append(info)
    
    return render_template('view_info.html', categorized_infos=categorized_infos)

def row_to_dict(row):
    """SQLite Row 객체를 딕셔너리로 변환"""
    return {key: row[key] for key in row.keys()} if row else None

@app.route('/admin/info', methods=['GET', 'POST'])
@admin_required
def manage_info():
    conn = get_db()
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            title = request.form.get('title')
            content = request.form.get('content')
            category = request.form.get('category')
            order_num = request.form.get('order_num', 0)
            
            conn.execute('''
                INSERT INTO infos (title, content, category, order_num)
                VALUES (?, ?, ?, ?)
            ''', [title, content, category, order_num])
            conn.commit()
            flash('정보가 추가되었습니다.')
            
        elif action == 'edit':
            info_id = request.form.get('info_id')
            title = request.form.get('title')
            content = request.form.get('content')
            category = request.form.get('category')
            order_num = request.form.get('order_num', 0)
            
            conn.execute('''
                UPDATE infos 
                SET title = ?, content = ?, category = ?, order_num = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', [title, content, category, order_num, info_id])
            conn.commit()
            flash('정보가 수정되었습니다.')
            
        elif action == 'delete':
            info_id = request.form.get('info_id')
            conn.execute('DELETE FROM infos WHERE id = ?', [info_id])
            conn.commit()
            flash('정보가 삭제되었습니다.')
    
    # 정보 목록을 딕셔너리 리스트로 변환
    infos = [row_to_dict(row) for row in conn.execute('''
        SELECT * FROM infos 
        ORDER BY category, order_num, created_at DESC
    ''').fetchall()]
    
    conn.close()
    
    return render_template('manage_info.html', infos=infos)

@app.route('/admin/monitor')
@admin_required
def monitor_system():
    stats = get_current_stats()
    return render_template('monitor_system.html', stats=stats)

@app.route('/admin/unregistered')
@admin_required
def admin_unregistered():
    conn = get_db()
    
    # 전체 학생 수 조회
    total_count = conn.execute('''
        SELECT COUNT(*) FROM users 
        WHERE student_id != 'admin'
    ''').fetchone()[0]
    
    # 미가입 학생 목록 조회 (approved 상태의 신청이 없는 학생)
    rows = conn.execute('''
        SELECT u.*,
               EXISTS(
                   SELECT 1 FROM applications a 
                   WHERE a.student_id = u.student_id 
                   AND a.status IN ('pending', 'waiting_acceptance')
               ) as has_pending,
               (
                   SELECT json_object(
                       'id', a.id,
                       'status', a.status,
                       'club_name', c.name
                   )
                   FROM applications a
                   JOIN clubs c ON a.club_id = c.id
                   WHERE a.student_id = u.student_id 
                   AND a.status IN ('pending', 'waiting_acceptance')
                   ORDER BY a.applied_at DESC LIMIT 1
               ) as pending_application
        FROM users u
        WHERE u.student_id != 'admin'
        AND NOT EXISTS (
            SELECT 1 FROM applications a 
            WHERE a.student_id = u.student_id 
            AND a.status = 'approved'
        )
        ORDER BY u.student_id
    ''').fetchall()
    
    # Row 객체들을 사전으로 변환
    students = []
    import json
    for row in rows:
        student = dict(row)
        if student['pending_application']:
            student['pending_application'] = json.loads(student['pending_application'])
        students.append(student)
    
    conn.close()
    
    return render_template('admin_unregistered.html', 
                         students=students,
                         total_count=total_count,
                         unregistered_count=len(students))

# 동아리 모집 상태 토글 라우트 추가
@app.route('/club/<int:club_id>/toggle_recruiting', methods=['POST'])
@login_required
def toggle_recruiting(club_id):
    # 권한 확인
    if not (session.get('is_admin') or session.get('club_leader_of') == club_id):
        flash('권한이 없습니다.')
        return redirect(url_for('index'))
    
    conn = get_db()
    try:
        # 현재 모집 상태 확인
        club = conn.execute('SELECT is_recruiting FROM clubs WHERE id = ?', 
                          [club_id]).fetchone()
        
        if not club:
            flash('존재하지 않는 동아리입니다.')
            return redirect(url_for('index'))
        
        # 모집 상태 토글
        new_status = not club['is_recruiting']
        conn.execute('''
            UPDATE clubs 
            SET is_recruiting = ? 
            WHERE id = ?
        ''', [new_status, club_id])
        
        # 모집 마감 시 대기 중인 신청 자동 거절
        if not new_status:
            conn.execute('''
                UPDATE applications 
                SET status = 'rejected',
                    final_result = '모집 마감으로 인한 자동 거절'
                WHERE club_id = ? AND status = 'pending'
            ''', [club_id])
        
        conn.commit()
        flash('모집 상태가 변경되었습니다.')
        
    except sqlite3.Error as e:
        flash('처리 중 오류가 발생했습니다.')
    finally:
        conn.close()
    
    return redirect(url_for('manage_club', club_id=club_id))

# 새로운 라우트 추가
@app.route('/club/<int:club_id>/set_contact', methods=['POST'])
@login_required
def set_leader_contact(club_id):
    if not (session.get('is_admin') or session.get('club_leader_of') == club_id):
        flash('권한이 없습니다.')
        return redirect(url_for('index'))
    
    contact_info = request.form.get('contact_info')
    contact_method = request.form.get('contact_method', 'phone')
    
    if not contact_info:
        flash('연락처 정보를 입력해주세요.')
        return redirect(url_for('manage_club', club_id=club_id))
    
    conn = get_db()
    conn.execute('''
        UPDATE clubs 
        SET leader_contact_info = ?, leader_contact_method = ?
        WHERE id = ?
    ''', [contact_info, contact_method, club_id])
    conn.commit()
    conn.close()
    
    flash('연락처가 등록되었습니다.')
    return redirect(url_for('manage_club', club_id=club_id))

@app.route('/club/<int:club_id>/contact')
@login_required
def view_leader_contact(club_id):
    conn = get_db()
    club = conn.execute('''
        SELECT c.*, u.name as leader_name 
        FROM clubs c
        LEFT JOIN users u ON u.club_leader_of = c.id
        WHERE c.id = ?
    ''', [club_id]).fetchone()
    conn.close()
    
    if not club or not club['leader_contact_info']:
        flash('연락처 정보가 없습니다.')
        return redirect(url_for('view_club', club_id=club_id))
    
    return render_template('view_contact.html', club=club)

@app.route('/application/<int:application_id>/force_accept', methods=['POST'])
@admin_required
def force_accept_application(application_id):
    conn = get_db()
    try:
        # 신청 정보 확인
        application = conn.execute('''
            SELECT a.*, c.name as club_name
            FROM applications a
            JOIN clubs c ON a.club_id = c.id
            WHERE a.id = ? AND a.status = 'waiting_acceptance'
        ''', [application_id]).fetchone()
        
        if not application:
            flash('유효하지 않은 신청입니다.')
            return redirect(url_for('admin_unregistered'))
        
        # 강제 승인 처리
        conn.execute('''
            UPDATE applications 
            SET status = 'approved',
                student_accepted = 1,
                final_result = '관리자에 의해 강제 승인됨',
                admin_approved = 1
            WHERE id = ?
        ''', [application_id])
        
        # 다른 신청들 자동 취소
        conn.execute('''
            UPDATE applications 
            SET status = 'cancelled',
                final_result = '다른 동아리 선택으로 인한 자동 취소'
            WHERE student_id = ? AND id != ? AND 
            status IN ('pending', 'waiting_acceptance')
        ''', [application['student_id'], application_id])
        
        conn.commit()
        flash(f'학생의 {application["club_name"]} 동아리 가입이 강제 승인되었습니다.')
        
    except sqlite3.Error:
        conn.rollback()
        flash('처리 중 오류가 발생했습니다.')
    finally:
        conn.close()
    
    return redirect(url_for('admin_unregistered'))

@app.route('/admin/teacher_groups', methods=['GET', 'POST'])
@admin_required
def manage_teacher_groups():
    conn = get_db()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update':
            for key, value in request.form.items():
                if key.startswith('group_name_'):
                    group_id = int(key.replace('group_name_', ''))
                    display_order = int(request.form.get(f'group_order_{group_id}', 0))
                    conn.execute('''
                        UPDATE teacher_groups 
                        SET name = ?, display_order = ? 
                        WHERE id = ?
                    ''', [value, display_order, group_id])
            
            conn.commit()
            flash('그룹 설정이 저장되었습니다.')
            return redirect(url_for('manage_teachers'))
    
    # 그룹 목록 조회
    groups = conn.execute('''
        SELECT * FROM teacher_groups 
        ORDER BY display_order, id
    ''').fetchall()
    
    conn.close()
    return render_template('manage_teacher_groups.html', groups=groups)

@app.route('/leader/notices')
@login_required
def view_leader_notices():
    if 'club_leader_of' not in session:
        flash('부장 권한이 필요합니다.')
        return redirect(url_for('index'))
    
    conn = get_db()
    
    # 중요 공지사항 조회
    notices = conn.execute('''
        SELECT * FROM notices 
        WHERE is_important = 1
        ORDER BY created_at DESC
    ''').fetchall()
    
    # 공지사항 읽음 처리
    if notices:
        conn.execute('''
            INSERT INTO notice_reads (user_id, last_read_at)
            VALUES (?, CURRENT_TIMESTAMP)
        ''', [session['user_id']])
        conn.commit()
    
    conn.close()
    return render_template('leader_notices.html', notices=notices)

if __name__ == '__main__':
    init_db()
    init_stats()  # 통계 수집 시작
    app.run(host='0.0.0.0',port=80,debug=False)