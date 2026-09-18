"""설정 한 곳에 모으기.

비밀값(DB 비밀번호·JWT 키·API 키)은 코드에 쓰지 않고 같은 폴더의 .env 에서 읽는다.
.env 는 절대 깃에 올리지 않는다(.gitignore). 제출·공유용으로는 .env.example 만 남긴다.
"""
import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── 세션 암호화 키 (Flask-Login 필수) ──
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this')

    # ── 데이터베이스 (SQLite) ──
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///my_new_board.db',
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── 로그인 토큰 ──
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-only-change-me')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)

    # ── 보안 이벤트 REST ──
    SECURITY_API_KEY = os.environ.get('SECURITY_API_KEY', '')
    AUTO_POST_ON_DENY = os.environ.get('AUTO_POST_ON_DENY', '0') == '1'

    # ── 관리자(인가) REST (n8n·회수봇이 호출) ──
    ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', '') or SECURITY_API_KEY
    ADMIN_ALLOWLIST = [
        u.strip() for u in os.environ.get('ADMIN_ALLOWLIST', '').split(',') if u.strip()
    ]

    # ── 공공데이터 ──
    PUBLIC_API_KEY = os.environ.get('PUBLIC_API_KEY')
    PUBLIC_API_URL = (
        'http://apis.data.go.kr/6260000/RecommendedService/getRecommendedKr'
    )