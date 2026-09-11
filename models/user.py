from extensions import db, login_manager  # extensions에 login_manager가 있다고 가정
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class Role:
    USER = 0    # 일반 유저 (기본값)
    GOLD = 1    # 골드 (중간관리자)
    ADMIN = 2   # 최상위 관리자

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Integer, default=Role.USER, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Flask-Login 필수 세션 유저 로더
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))