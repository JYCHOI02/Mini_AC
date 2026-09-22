"""엔트리포인트 — 앱 팩토리(create_app) 패턴.

구조
  config.py       설정(.env 로딩)
  extensions.py   db · jwt 인스턴스
  models/         User · Post · SecurityEvent
  controllers/    page · auth · post · security · public (블루프린트)
  templates/      화면 (partials/_nav.html = 공통 반응형 헤더)

실행:  python app.py   →  http://localhost:5000
"""
from flask import Flask, jsonify, request
from sqlalchemy import inspect, text

from config import Config
from controllers import all_blueprints
from extensions import db, jwt, login_manager
from models import BlockedIP


def _ensure_schema():
  """기존 users 표에 role 관련 컬럼이 없으면 추가(가벼운 자동 마이그레이션)."""
  insp = inspect(db.engine)
  if not insp.has_table('users'):
    return
  cols = {c['name'] for c in insp.get_columns('users')}
  adds = {
      'role_granted_by': "ALTER TABLE users ADD COLUMN role_granted_by VARCHAR(80) NULL",
      'role_granted_at': "ALTER TABLE users ADD COLUMN role_granted_at DATETIME NULL",
      'role_reason': "ALTER TABLE users ADD COLUMN role_reason VARCHAR(200) NULL",
  }
  with db.engine.begin() as conn:
    for name, ddl in adds.items():
      if name not in cols:
        conn.execute(text(ddl))

def _client_ip():
    """프록시(n8n·nginx) 뒤면 X-Forwarded-For 첫 홉, 아니면 remote_addr.
    (랩 한정 — 실서비스는 신뢰 프록시 목록으로 검증해야 스푸핑을 막는다.)"""
    xff = request.headers.get('X-Forwarded-For', '')
    return xff.split(',')[0].strip() if xff else (request.remote_addr or '')

def create_app(config_class=Config):
  app = Flask(__name__)
  app.config.from_object(config_class)

  @app.before_request
  def _block_ip_guard():
        # 관리자 API 는 예외 — 운영자·n8n 이 차단/해제를 계속 하려면 필수(자기 차단으로 복구 불능 방지)
        if request.path.startswith('/api/admin'):
            return None
        ip = _client_ip()
        if ip and db.session.get(BlockedIP, ip):
            return jsonify({'msg': '차단된 IP 입니다(관리자에게 문의).', 'ip': ip, 'blocked': True}), 403
        return None
  # 확장 초기화
  db.init_app(app)
  jwt.init_app(app)
  login_manager.init_app(app)  # 추가

  # 컨트롤러(블루프린트) 등록
  for bp in all_blueprints:
    app.register_blueprint(bp)

  with app.app_context():
    db.create_all()
    _ensure_schema()

  return app


app = create_app()

if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0', port=5000)

