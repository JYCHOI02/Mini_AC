from functools import wraps
from flask import render_template, redirect, url_for, flash
from flask_login import current_user, logout_user
from models.user import Role


def role_required(min_role):
    """
    최소 권한(min_role) 검증 데코레이터.
    권한 부족 시 로그아웃 처리 후 로그인 페이지로 리다이렉트.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("로그인이 필요한 서비스입니다.")
                return redirect(url_for('auth.login'))

            # current_user에 role 속성이 없는 경우 대비
            user_role = getattr(current_user, 'role', Role.USER)

            if user_role < min_role:
                # 관리자 게시판 등 권한 부족 시 세션 로그아웃 처리
                logout_user()
                if min_role == Role.ADMIN:
                    flash("관리자 권한이 필요합니다. 관리자 계정으로 다시 로그인해 주세요.")
                else:
                    flash("해당 페이지에 접근할 권한이 없습니다. 다시 로그인해 주세요.")
                return redirect(url_for('auth.login'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator