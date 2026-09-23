import pytest
from app import app
from extensions import db
from models import BlockedIP, SecurityEvent


@pytest.fixture
def client():
  app.config['TESTING'] = True
  with app.test_client() as client:
    with app.app_context():
      # 테스트 전 테스트 대상 IP만 정리
      BlockedIP.query.filter(BlockedIP.ip.in_(['198.51.100.1', '198.51.100.99'])).delete()
      db.session.commit()
    yield client
    with app.app_context():
      # 테스트 후 정리
      BlockedIP.query.filter(BlockedIP.ip.in_(['198.51.100.1', '198.51.100.99'])).delete()
      db.session.commit()


def test_unblocked_ip_can_access(client):
  """차단되지 않은 일반 IP는 정상 접속 가능해야 한다."""
  res = client.get('/', headers={'X-Forwarded-For': '198.51.100.1'})
  assert res.status_code == 200


def test_block_ip_and_guard(client):
  """IP 차단 등록 및 _block_ip_guard 동작 검증."""
  target_ip = '198.51.100.99'
  headers_key = {'X-API-Key': app.config.get('ADMIN_API_KEY') or app.config.get('SECURITY_API_KEY', '')}

  # 1) IP 차단 API 호출 (/api/admin/block)
  block_res = client.post('/api/admin/block', headers=headers_key, json={
      'ip': target_ip,
      'reason': '테스트 차단',
      'severity': 'High'
  })
  assert block_res.status_code == 200
  block_data = block_res.get_json()
  assert block_data['blocked'] is True
  assert block_data['changed'] is True
  assert block_data['ip'] == target_ip

  # 2) 동일 IP 중복 차단 시 멱등성 검증 (changed: False)
  block_res2 = client.post('/api/admin/block', headers=headers_key, json={'ip': target_ip})
  assert block_res2.status_code == 200
  assert block_res2.get_json()['changed'] is False

  # 3) 차단된 IP 목록 조회 (/api/admin/blocked)
  list_res = client.get('/api/admin/blocked', headers=headers_key)
  assert list_res.status_code == 200
  list_data = list_res.get_json()
  assert list_data['count'] >= 1
  blocked_ips = [item['ip'] for item in list_data['blocked']]
  assert target_ip in blocked_ips

  # 4) 차단된 IP로 일반 엔드포인트 접근 시 403 차단 검증
  denied_res = client.get('/', headers={'X-Forwarded-For': target_ip})
  assert denied_res.status_code == 403
  denied_data = denied_res.get_json()
  assert denied_data['blocked'] is True
  assert denied_data['ip'] == target_ip
  assert '차단된 IP 입니다' in denied_data['msg']

  # 5) 차단된 IP라도 관리자 API(/api/admin/*)는 예외적으로 접근 가능해야 함 (복구 불능 방지)
  admin_check_res = client.get('/api/admin/blocked', headers={**headers_key, 'X-Forwarded-For': target_ip})
  assert admin_check_res.status_code == 200

  # 6) IP 차단 해제 (/api/admin/unblock)
  unblock_res = client.post('/api/admin/unblock', headers=headers_key, json={'ip': target_ip})
  assert unblock_res.status_code == 200
  unblock_data = unblock_res.get_json()
  assert unblock_data['blocked'] is False

  # 7) 차단 해제 후 정상 접속 복구 확인
  allowed_res = client.get('/', headers={'X-Forwarded-For': target_ip})
  assert allowed_res.status_code == 200
