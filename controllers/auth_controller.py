from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required
from flask_jwt_extended import create_access_token
from models.user import User, Role
from extensions import db
from .gelf import send_gelf

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': '아이디와 비밀번호를 모두 입력해주세요.'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'message': '이미 존재하는 아이디입니다.'}), 400

        user = User(username=username, role=Role.USER)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        if request.is_json:
            return jsonify({'message': '회원가입 성공', 'user_id': user.id}), 201

        flash('회원가입 완료! 로그인 해주세요.')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) if request.is_json else request.form
        data = data or {}
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'message': '아이디와 비밀번호를 입력해주세요.'}), 400

        user = User.query.filter_by(username=username).first()

        # 1. 로그인 성공 (비밀번호 일치 시)
        if user and user.check_password(password):
            login_user(user)
            access_token = create_access_token(identity=str(user.id))

            if request.is_json:
                return jsonify({
                    'message': '로그인 성공',
                    'access_token': access_token,
                    'role': user.role,
                    'username': user.username
                }), 200
            return redirect(url_for('cafe.index'))

        # 2. 로그인 실패 (아이디 또는 비밀번호 불일치 시)
        # 클라이언트 IP 추출 (프록시/Postman X-Forwarded-For 우선, test_ip 지원)
        xff = request.headers.get('X-Forwarded-For', '')
        test_ip = (data.get('test_ip') if isinstance(data, dict) else None) or request.args.get('test_ip')
        src_ip = xff.split(',')[0].strip() if xff else (test_ip or request.remote_addr or '127.0.0.1')

        # Graylog로 로그인 실패 GELF 로그 전송
        send_gelf(f"failed login for '{username}' from {src_ip}",
                  rule='login-bruteforce',
                  username=username or '(unknown)',
                  src_ip=src_ip,
                  count=1)

        if request.is_json:
            return jsonify({'message': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401

        flash('아이디 또는 비밀번호가 올바르지 않습니다.')

    return render_template('login.html')


@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    if request.is_json:
        return jsonify({'message': '로그아웃되었습니다.'}), 200
    return redirect(url_for('cafe.index'))