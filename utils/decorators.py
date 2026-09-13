from functools import wraps
from flask import render_template
from flask_login import current_user
from models.user import Role

def role_required(min_role):
    """
    최소 권한(min_role) 검증 데코레이터.
    권한 부족 시 403 예외 화면 반환.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return render_template('errors/403.html', reason="로그인이 필요한 서비스입니다."), 403
            
            # current_user에 role 속성이 없는 경우 대비
            user_role = getattr(current_user, 'role', Role.USER)
            
            if user_role < min_role:
                role_names = {Role.USER: "일반 유저", Role.GOLD: "골드(중간관리자)", Role.ADMIN: "관리자"}
                required_name = role_names.get(min_role, "높은 등급")
                current_name = role_names.get(user_role, "알 수 없음")
                
                return render_template(
                    'errors/403.html', 
                    required_role=required_name, 
                    current_role=current_name
                ), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator