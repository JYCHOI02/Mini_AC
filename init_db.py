import pymysql

conn = pymysql.connect(host='localhost', user='root', password='123456')
cursor = conn.cursor()
cursor.execute('CREATE DATABASE IF NOT EXISTS my_new_board_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
conn.close()
print('my_new_board_db 데이터베이스 생성이 완료되었습니다!')
