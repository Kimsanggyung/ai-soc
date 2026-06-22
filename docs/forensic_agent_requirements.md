## 1. 데이터 전송 규격 및 무결성 검증 프로세스 설계

[cite_start]에이전트가 수집한 이종 보안 데이터가 중앙 서버(FastAPI)에서 시간 축(Timestamp) 기준으로 파싱 및 병합[cite: 40, 55][cite_start]될 수 있도록 표준 JSON 데이터 전송 규격을 정의하고, 수집된 증거물의 법적 효력 및 신뢰성을 담보하기 위한 SHA-256 무결성 검증 체계를 수립합니다[cite: 35, 71].

### 1.1 SHA-256 무결성 검증 및 위험도 산정 흐름
1. [cite_start]**메모리 레벨 해싱:** 에이전트는 단말에서 아티팩트(로그 및 파일)를 수집하는 즉시 디스크에 저장하기 전, 메모리 버퍼 상에서 원본 데이터의 SHA-256 해시값을 산정하여 무결성을 고정합니다[cite: 35].
2. [cite_start]**해시 인덱싱:** 산정된 해시값은 전송 패킷의 `integrity_hash` 필드에 포함되어 암호화 세션을 통해 중앙 서버로 전송됩니다[cite: 35, 54].
3. [cite_start]**서버 측 교차 검증:** 중앙 서버에 수집된 포렌식 파일의 해시값과 에이전트가 최초 산정한 원본 해시값을 대조하여 일치율 100%를 확보합니다[cite: 71].
4. [cite_start]**위합도 반영:** 검증이 완료된 데이터는 호스트 아티팩트 탐지 스코어(H_score)로 환산되어 통합 위험도 지수($Total\ Threat\ Score$) 산정에 반영됩니다[cite: 36, 37].

### 1.2 에이전트 출력 데이터 전송 규격 (JSON Schema)
[cite_start]에이전트가 통합 서버로 전송할 정형화된 보안 컨텍스트 구조입니다[cite: 21, 40]. [cite_start]이 데이터는 추후 생성형 AI(Gemini 1.5 Pro)의 프롬프트 컨텍스트로 주입되어 한글 종합 보고서 생성에 사용됩니다[cite: 21, 42].

```json
{
  "agent_meta": {
    "agent_id": "NX-AGENT-WINDOWS-01",
    "target_ip": "192.168.10.45",
    "os_platform": "Windows 11 Pro",
    "collection_start_time": "2026-06-21T15:15:00Z",
    "collection_end_time": "2026-06-21T15:15:12Z"
  },
  "integrity_hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
  "evidence_data": {
    "volatile": {
      "process_tree": [
        {
          "pid": 4012,
          "ppid": 1024,
          "process_name": "powershell.exe",
          "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\Update.ps1",
          "creation_time": "2026-06-21T15:14:30Z"
        }
      ],
      "netstat_connections": [
        {
          "protocol": "TCP",
          "local_address": "192.168.10.45:49152",
          "remote_address": "203.0.113.5:4444",
          "state": "ESTABLISHED",
          "pid": 4012
        }
      ]
    },
    "non_volatile": {
      "prefetch_logs": [
        {
          "file_name": "POWERSHELL.EXE-A1B2C3D4.pf",
          "last_run_time": "2026-06-21T15:14:30Z",
          "run_count": 5
        }
      ],
      "windows_event_logs": [
        {
          "log_type": "Security",
          "event_id": 4688,
          "timestamp": "2026-06-21T15:14:30Z",
          "message": "새 프로세스가 생성되었습니다. 프로세스 이름: powershell.exe"
        }
      ]
    }
  }
}
