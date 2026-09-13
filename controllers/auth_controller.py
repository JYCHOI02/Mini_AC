from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify  # jsonify 추가
from flask_login import login_user, logout_user, login_required
from models.user import User, Role
from extensions import db

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # JSON 요청과 Form 요청 모두 대응
        if request.is_json:
            data = request.get_json() or {}
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        # 필수값 검증
        if not username or not password:
            return jsonify({'message': '아이디와 비밀번호를 모두 입력해주세요.'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'message': '이미 존재하는 아이디입니다.'}), 400

        # 일반 유저(Role.USER = 0)로 가입 처리
        user = User(username=username, role=Role.USER)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': '회원가입 성공', 'user_id': user.id}), 201

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json() or {}
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            return jsonify({'message': '아이디와 비밀번호를 입력해주세요.'}), 400

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return jsonify({'message': '로그인 성공', 'role': user.role}), 200

        return jsonify({'message': '아이디 또는 비밀번호가 올바르지 않습니다.'}), 401

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('page.index'))