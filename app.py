"""엔트리포인트 — 앱 팩토리(create_app) 패턴.

구조
  config.py       설정(.env 로딩)
  extensions.py   db · jwt 인스턴스
  models/         User · Post · SecurityEvent
  controllers/    page · auth · post · security · public (블루프린트)
  templates/      화면 (partials/_nav.html = 공통 반응형 헤더)

실행:  python app.py   →  http://localhost:5000
"""
from flask import Flask
from sqlalchemy import inspect, text

from config import Config
from controllers import all_blueprints
from extensions import db, jwt, login_manager


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


def create_app(config_class=Config):
  app = Flask(__name__)
  app.config.from_object(config_class)

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
  app.run(debug=True, host='0.지0.0.0', port=5000)