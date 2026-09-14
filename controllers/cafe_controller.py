from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import current_user
from extensions import db
from models.user import User, Role
from utils.decorators import role_required

cafe_bp = Blueprint('cafe', __name__)

@cafe_bp.route('/')
def index():
    return render_template('index.html')

# 1) 골드그룹 전용 페이지 (Role >= 1)
@cafe_bp.route('/gold')
@role_required(Role.GOLD)
def gold_page():
    return render_template('cafe/gold_page.html')

# 2) 관리자 전용 페이지 - 회원 목록 조회 (Role == 2)
@cafe_bp.route('/admin')
@role_required(Role.ADMIN)
def admin_page():
    users = User.query.all()
    return render_template('cafe/admin_page.html', users=users, Role=Role)

# 3) 관리자 기능 - 회원 권한(Role) 변경 (골드 지정 등)
@cafe_bp.route('/admin/user/<int:user_id>/update_role', methods=['POST'])
@role_required(Role.ADMIN)
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = int(request.form.get('role'))
    user.role = new_role
    db.session.commit()
    flash(f'{user.username} 님의 등급이 변경되었습니다.')
    return redirect(url_for('cafe.admin_page'))

# 4) 관리자 기능 - 회원 삭제
@cafe_bp.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@role_required(Role.ADMIN)
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('자기 자신 계정은 삭제할 수 없습니다.')
        return redirect(url_for('cafe.admin_page'))
    
    db.session.delete(user)
    db.session.commit()
    flash(f'{user.username} 계정이 삭제되었습니다.')
    return redirect(url_for('cafe.admin_page'))