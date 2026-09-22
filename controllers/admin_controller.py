"""관리자(인가/RBAC) REST — 회원 권한 부여·회수.

접근 방식 세 가지
  ① 기계 호출(n8n·회수봇)  : 헤더  X-API-Key: <ADMIN_API_KEY>
  ② 사람(관리자 페이지)     : 세션 로그인 + role == Role.ADMIN
  ③ API 클라이언트(JWT)     : Bearer 토큰 + role == Role.ADMIN
"""
from datetime import datetime
from functools import wraps

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user as login_user
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from extensions import db
from models import BlockedIP, SecurityEvent, User
from models.user import Role, ROLE_NAMES, NAME_TO_ROLE

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')


def _has_valid_key():
  """X-API-Key 가 ADMIN_API_KEY 와 일치하면 True(비어 있으면 항상 False = fail-closed)."""
  expected = current_app.config.get('ADMIN_API_KEY', '') or current_app.config.get('SECURITY_API_KEY', '')
  return bool(expected) and request.headers.get('X-API-Key', '') == expected


def _current_admin_user():
  """세션 또는 JWT 가 있고 그 계정이 admin 이면 User, 아니면 None."""
  # 1. Flask-Login 세션
  if login_user and getattr(login_user, 'is_authenticated', False):
    if getattr(login_user, 'is_admin', False):
      return login_user

  # 2. JWT 토큰
  try:
    verify_jwt_in_request(optional=True)
    uid = get_jwt_identity()
    if uid:
      u = db.session.get(User, int(uid))
      if u and u.is_admin:
        return u
  except Exception:
    pass

  return None


def admin_required(fn):
  """유효한 관리자 키(기계) 또는 admin(사람)이면 통과. 아니면 401."""
  @wraps(fn)
  def wrapper(*args, **kwargs):
    if _has_valid_key():
      request.actor = 'apikey'
      return fn(*args, **kwargs)
    admin = _current_admin_user()
    if admin:
      request.actor = admin.username
      return fn(*args, **kwargs)
    return jsonify({'msg': '관리자 인가가 필요합니다(X-API-Key 또는 admin 로그인).'}), 401
  return wrapper


def _allowlist(param=None):
  """정책 허용목록. 쿼리/바디로 넘기면 우선, 없으면 config(.env)."""
  if param:
    return [u.strip() for u in param.split(',') if u.strip()]
  return current_app.config.get('ADMIN_ALLOWLIST', [])


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
  """회원 목록 + 역할. ?role=admin 또는 ?role=2 등으로 필터."""
  role = request.args.get('role')
  q = User.query
  if role:
    target_role = NAME_TO_ROLE.get(role.lower() if isinstance(role, str) else role)
    if target_role is not None:
      q = q.filter_by(role=target_role)
    else:
      q = q.filter(User.role == role)
  rows = q.order_by(User.id.asc()).all()
  return jsonify({'count': len(rows), 'users': [u.to_dict() for u in rows]})


@admin_bp.route('/violations', methods=['GET'])
@admin_required
def list_violations():
  """정책 위반(허용목록 밖 admin) 목록. 회수봇이 참고용으로 쓸 수 있다."""
  allow = _allowlist(request.args.get('allowlist'))
  admins = User.query.filter_by(role=Role.ADMIN).all()
  bad = [u for u in admins if u.username not in allow]
  return jsonify({
      'allowlist': allow,
      'count': len(bad),
      'violations': [u.to_dict() for u in bad],
  })


@admin_bp.route('/grant', methods=['POST'])
@admin_required
def grant_role():
  """회원에게 역할 부여(인가). body: {username, role, reason}"""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  role_input = data.get('role')
  if not username or role_input is None:
    return jsonify({'msg': 'username, role 은 필수입니다.'}), 400

  target_role = NAME_TO_ROLE.get(str(role_input).lower() if isinstance(role_input, str) else role_input)
  if target_role is None:
    return jsonify({'msg': f'유효하지 않은 role 입니다: {role_input}'}), 400

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  old_role_num = user.role
  old_role_name = ROLE_NAMES.get(old_role_num, str(old_role_num))
  new_role_name = ROLE_NAMES.get(target_role, str(target_role))

  user.role = target_role
  user.role_granted_by = getattr(request, 'actor', 'unknown')
  user.role_granted_at = datetime.now()
  user.role_reason = (data.get('reason') or '')[:200]
  db.session.commit()
  return jsonify({'msg': '역할 부여 완료', 'username': username,
                  'old_role': old_role_name, 'new_role': new_role_name,
                  'granted_by': user.role_granted_by}), 200


@admin_bp.route('/revoke', methods=['POST'])
@admin_required
def revoke_role():
  """과잉권한 회수(최소권한 복원) → role 을 'user'(Role.USER=0) 로. 회수봇·n8n 이 호출."""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  if not username:
    return jsonify({'msg': 'username 은 필수입니다.'}), 400

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  old_role_num = user.role
  old_role_name = ROLE_NAMES.get(old_role_num, str(old_role_num))
  actor = getattr(request, 'actor', 'unknown')

  if old_role_num == Role.USER or str(old_role_num) == 'user':
    return jsonify({'msg': '이미 user 권한(회수 불필요)', 'username': username,
                    'old_role': 'user', 'new_role': 'user', 'revoked': False}), 200

  user.role = Role.USER
  user.role_granted_by = actor
  user.role_granted_at = datetime.now()
  user.role_reason = (data.get('reason') or f'{old_role_name}→user 회수 by {actor}')[:200]

  # 감사기록: 대시보드에서 보이도록 security_events 재사용
  ev = SecurityEvent(
      student=(data.get('student') or actor)[:50],
      src_ip=data.get('src_ip') or '0.0.0.0',
      fail_count=0, decision='deny',
      severity=data.get('severity', 'High'),
      reason=(data.get('reason') or f'과잉권한 회수: {username} {old_role_name}→user')[:200],
      users=username, source=data.get('source', 'privilege-guard'),
      generated_at=data.get('generated_at'),
  )
  db.session.add(ev)
  db.session.commit()
  return jsonify({'msg': '권한 회수 완료', 'username': username,
                  'old_role': old_role_name, 'new_role': 'user', 'revoked': True,
                  'event_id': ev.id, 'revoked_by': actor}), 200

# controllers/admin_controller.py — @admin_required (X-API-Key 또는 admin JWT)
@admin_bp.route('/block', methods=['POST'])
@admin_required
def block_ip():
    d = request.get_json(silent=True) or {}
    ip = (d.get('ip') or d.get('src_ip') or '').strip()
    if not ip: return jsonify({'msg': 'ip(또는 src_ip) 는 필수입니다.'}), 400
    actor = getattr(request, 'actor', 'unknown')
    if not db.session.get(BlockedIP, ip):                        # 멱등: 이미 있으면 changed:false
        db.session.add(BlockedIP(ip=ip, reason=(d.get('reason') or f'자동 차단 by {actor}')[:200], blocked_by=actor))
        ev = SecurityEvent(student=(d.get('student') or actor)[:50], src_ip=ip,
            fail_count=int(d.get('fail_count') or 0), decision='deny', severity=d.get('severity','High'),
            reason=(d.get('reason') or f'IP 실차단: {ip}')[:200], users='', source=d.get('source','ip-guard'))
        db.session.add(ev); db.session.commit()
        return jsonify({'msg':'IP 차단 완료','ip':ip,'blocked':True,'changed':True,'event_id':ev.id}), 200
    return jsonify({'msg':'이미 차단된 IP','ip':ip,'blocked':True,'changed':False}), 200
# [테스트용 코드] 차단된 IP 목록 조회 및 해제 API
@admin_bp.route('/blocked', methods=['GET'])  # [테스트용 코드]
@admin_required  # [테스트용 코드]
def list_blocked_ips():  # [테스트용 코드]
    """차단된 IP 목록 조회 (테스트용 코드)"""
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()  # [테스트용 코드]
    return jsonify({  # [테스트용 코드]
        'count': len(rows),  # [테스트용 코드]
        'blocked_ips': [row.to_dict() for row in rows]  # [테스트용 코드]
    }), 200  # [테스트용 코드]


@admin_bp.route('/unblock', methods=['POST'])  # [테스트용 코드]
@admin_required  # [테스트용 코드]
def unblock_ip():  # [테스트용 코드]
    """차단된 IP 해제 (테스트용 코드)"""
    d = request.get_json(silent=True) or {}  # [테스트용 코드]
    ip = (d.get('ip') or d.get('src_ip') or '').strip()  # [테스트용 코드]
    if not ip:  # [테스트용 코드]
        return jsonify({'msg': 'ip(또는 src_ip) 는 필수입니다.'}), 400  # [테스트용 코드]

    record = db.session.get(BlockedIP, ip)  # [테스트용 코드]
    if record:  # [테스트용 코드]
        db.session.delete(record)  # [테스트용 코드]
        db.session.commit()  # [테스트용 코드]
        return jsonify({'msg': 'IP 차단 해제 완료', 'ip': ip, 'unblocked': True, 'changed': True}), 200  # [테스트용 코드]
    return jsonify({'msg': '차단 목록에 없는 IP입니다.', 'ip': ip, 'unblocked': False, 'changed': False}), 200  # [테스트용 코드]