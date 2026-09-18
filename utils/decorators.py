from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user
from models.user import Role


def role_required(min_role):
    """
    최소 권한(min_role) 검증 데코레이터.
    권한 부족 시 기존 로그인은 유지한 채 필요한 권한을 안내하며 로그인 화면으로 이동.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("로그인이 필요한 서비스입니다.")
                return redirect(url_for('auth.login', req_role=min_role))

            # current_user에 role 속성이 없는 경우 대비
            user_role = getattr(current_user, 'role', Role.USER)

            if user_role < min_role:
                # 바로 로그아웃시키지 않고 기존 로그인을 유지한 채 인가 부족 안내
                if min_role == Role.ADMIN:
                    flash("최고 관리자(Role: 2, ADMIN) 권한이 필요한 페이지입니다.")
                elif min_role == Role.GOLD:
                    flash("골드 등급(Role: 1, GOLD) 이상 권한이 필요한 페이지입니다.")
                else:
                    flash("해당 페이지에 접근할 권한이 없습니다.")

                return redirect(url_for('auth.login', req_role=min_role, my_role=user_role))

            return f(*args, **kwargs)
        return decorated_function
    return decorator