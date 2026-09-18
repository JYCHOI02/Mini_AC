from extensions import db, login_manager  # extensions에 login_manager가 있다고 가정
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class Role:
    USER = 0    # 일반 유저 (기본값)
    GOLD = 1    # 골드 (중간관리자)
    ADMIN = 2   # 최상위 관리자

ROLE_NAMES = {
    Role.USER: 'user',
    Role.GOLD: 'gold',
    Role.ADMIN: 'admin',
}

NAME_TO_ROLE = {
    'user': Role.USER,
    'gold': Role.GOLD,
    'admin': Role.ADMIN,
    '0': Role.USER,
    '1': Role.GOLD,
    '2': Role.ADMIN,
    0: Role.USER,
    1: Role.GOLD,
    2: Role.ADMIN,
}

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Integer, default=Role.USER, nullable=False)

    # 감사(audit) 컬럼
    role_granted_by = db.Column(db.String(80), nullable=True)
    role_granted_at = db.Column(db.DateTime, nullable=True)
    role_reason = db.Column(db.String(200), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    @property
    def is_gold(self):
        return self.role >= Role.GOLD

    @property
    def role_name(self):
        return ROLE_NAMES.get(self.role, 'user')

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role_name,
            'role_level': self.role,
            'role_granted_by': self.role_granted_by,
            'role_granted_at': (self.role_granted_at.isoformat()
                                if self.role_granted_at else None),
            'role_reason': self.role_reason,
        }

# Flask-Login 필수 세션 유저 로더
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))