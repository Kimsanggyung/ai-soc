# 🛡️ Hybrid AI-SOC Orchestration Engine Project

우리 팀의 **다중 레이어 기반 차단 메커니즘과 RAG 연동형 지능형 이상 징후 탐지 시스템** 구현을 위한 초기 로컬 인프라 저장소입니다. 한채민 멘토님의 피드백을 반영하여 초기 환경 통일 및 로컬 중심의 비용 최소화 설계를 적용했습니다.

## 🛠️ 개발 환경 아키텍처 구조
이 환경을 구동하면 로컬 PC 내에 다음과 같은 가상 SOC 관제 네트워크 파이프라인이 한 번에 빌드됩니다.
* **soc-gateway (Nginx):** 전단 외부 패킷 인입 및 리버스 프록시 관문 호스트
* **soc-webserver (Apache):** 모의 침해 진단 및 취약점 공격 대상 타겟 자산
* **soc-suricata (NIDS):** 게이트웨이 인터페이스 미러링을 통한 웹 위협 실시간 DPI 탐지 레이어

---

## 🚀 로컬 환경 즉시 구동 방법 (팀원 공통 필수)

팀원분들은 각자 로컬 PC에 Docker Desktop이 켜져 있는지 확인한 후, 이 저장소를 복제(Clone)하여 아래 명령어를 차례대로 터미널에 입력해 주세요.

### 1. 저장소 복제 및 폴더 이동
```bash
git clone [https://github.com/Kimsanggyung/ai-soc.git](https://github.com/Kimsanggyung/ai-soc.git)
cd ai-soc