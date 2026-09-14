import pymysql

try:
    conn = pymysql.connect(
        host='localhost',
        user='root',
        password='123456',
        db='my_new_board_db',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    with conn.cursor() as cur:
        # 테이블 컬럼 확인
        cur.execute("SHOW TABLES LIKE 'users'")
        if not cur.fetchone():
            print("❌ 'users' 테이블이 아직 존재하지 않습니다. python app.py를 먼저 실행해 주세요.")
        else:
            cur.execute("DESCRIBE users")
            columns = [row['Field'] for row in cur.fetchall()]
            print("=" * 65)
            print(f"📋 users 테이블 컬럼: {', '.join(columns)}")
            print("=" * 65)

            # 데이터 조회
            cur.execute("SELECT * FROM users")
            rows = cur.fetchall()
            if not rows:
                print("ℹ️ 저장된 회원 데이터가 없습니다. (회원가입을 진행해 주세요)")
            else:
                print(f"👥 총 {len(rows)}명의 회원 정보:")
                for r in rows:
                    print(f" - ID: {r.get('id')} | 아이디: {r.get('username')} | 권한(role): {r.get('role')} | 비밀번호 해시: {str(r.get('password_hash'))[:20]}...")
            print("=" * 65)
    conn.close()
except Exception as e:
    print(f"❌ DB 연결/조회 실패: {e}")
