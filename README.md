# 📰 NewREALs Backend

---

## 📌 프로젝트 소개
NewREALs는 사용자의 키워드를 통해 자신에게 맞는 진짜 뉴스를 새롭게 제시하는 서비스입니다.  
이 프로젝트는 백엔드 애플리케이션으로, 뉴스 데이터를 관리하고 사용자 인터랙션(스크랩, 좋아요, 퀴즈 등)을 처리합니다.

---

## 🌟 서비스 주요 기능
- 사용자 맞춤 관심키워드 뉴스 제공
- AI를 활용해 쉽게 재구성한 설명, 요약, 용어 해설
- T/F 퀴즈와 생각정리 기능
- 유저 활동 및 관심사 분석 레포트
  

---

## 📂 프로젝트 디렉토리 구조

```plaintext
src
├── main
│   ├── java
│   │   └── newREALs.backend
│   │       ├── 🛠️ config         # 설정 파일 (Spring Security 등)
│   │       ├── 📂 controller     # 컨트롤러 레이어
│   │       ├── 🗃️ domain         # 엔티티 클래스
│   │       ├── 📑 DTO            # 데이터 전송 객체 (DTO)
│   │       ├── 📦 repository     # JPA 리포지토리
│   │       ├── 🔒 security       # 보안 관련 클래스 (JWT, 필터 등)
│   │       └── 🧩 service        # 서비스 레이어
│   └── resources
│       ├── ⚙️ application.yml    # Spring Boot 설정 파일
│       ├── 🧪 DummyData.sql      # 테스트용 데이터 SQL
│       └── 📜 schema.sql         # 데이터베이스 스키마 SQL
```

---

## 🛠️ 기술 스택
- **언어**: Java 17
- **프레임워크**: Spring Boot 3.3.5
- **데이터베이스**: PostgreSQL
- **보안**: Spring Security, JWT
- **API 통신**: RESTful API, Kakao OAuth 2.0
- **기타**: Hibernate, Gradle, Log4j2

---

## 🚀 설치 및 실행 방법

#### 1. 프로젝트 클론
```bash
git clone https://github.com/your-username/your-repository.git
cd your-repository
```

#### 2. 환경 변수 설정
##### 2-1. `.env` 설정:
```
OPENAI_SECRET_KEY=
OPENAI_ORGANIZATION_ID=
JWT_SECRET_KEY=
NAVER_API_CLIENTID=
NAVER_API_SECRETKEY=
DATABASE_URL=
DATABASE_USERNAME=
DATABASE_PASSWORD=
KAKAO_CLIENT_ID=
KAKAO_CLIENT_SECRET=
```
##### 2-2.플러그인 설정 :
- IntelliJ의 **Settings → Plugins → Marketplace**로 이동.
- `EnvFile` 플러그인을 검색하고 설치합니다.
- Run/Debug Configuration 창에서 **Environment variables** 옆의 **Browse files** 버튼을 클릭합니다.
- `.env` 파일을 선택하면 자동으로 환경 변수를 로드합니다.


---

## 🔮 향후 계획