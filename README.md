# ClubConnectPortal - 동아리 신청 및 학생관리 시스템

Flask로 개발된 학교 동아리 신청/관리 웹 애플리케이션입니다. 학생들의 동아리 가입 신청부터 부장 승인, 관리자 데이터 관리까지 전체 프로세스를 지원합니다.

## 주요 기능
- 학생: 동아리 조회/신청/수락/탈퇴
- 부장: 동아리 관리, 신청 승인
- 관리자: 학생/선생님 데이터 관리, 동아리 생성, 시스템 모니터링

## 설치 및 실행
1. Python 설치 (3.12.9를 권장합니다.)
2. `pip install -r requirements.txt`
3. `python app.py`
4. 브라우저에서 http://localhost:80 접속

## 관리자 로그인
ID: admin
기본 비밀번호: admin1234 (변경 권장,app.py에서 변경또는 추가할 수 있습니다.)