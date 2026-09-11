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

from config import Config
from controllers import all_blueprints
from extensions import db, jwt



def create_app(config_class=Config):
  app = Flask(__name__)
  app.config.from_object(config_class)

  # 확장 초기화
  db.init_app(app)
  jwt.init_app(app)

  # 컨트롤러(블루프린트) 등록
  for bp in all_blueprints:
    app.register_blueprint(bp)

  # 테이블 생성 (models 를 import 한 뒤여야 한다 — controllers 가 이미 import 함)
  with app.app_context():
    db.create_all()

  return app


app = create_app()


if __name__ == '__main__':
  # host='0.0.0.0' 이면 같은 공유기의 다른 기기에서도 접속 가능.
  # 도커 안 n8n 에서는 http://host.docker.internal:5000 으로 부른다.
  app.run(debug=True, host='0.0.0.0', port=5000)
