import json
import time
import os
import hashlib
import requests

# ──────────────────────────────────────────────────────────────────────────────
# 경로 설정
# ──────────────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(BASE_DIR, "suricata", "log", "eve.json")
# 마지막으로 읽은 위치를 저장 → 재시작해도 과거 alert를 다시 안 쏨
OFFSET_FILE_PATH = os.path.join(BASE_DIR, ".forwarder_offset")

FASTAPI_URL = "http://localhost:8080/api/v1/predict"

# 동일 (flow + 시그니처) 조합을 이 시간(초) 안에는 한 번만 전송 (중복/폭주 방지)
DEDUP_COOLDOWN_SEC = 60

print(f"🎯 [TARGET PATH] 포워더가 감시하는 로그 파일: {LOG_FILE_PATH}")

# 최근 전송한 alert 키 -> 마지막 전송 시각
_recent_sent = {}


def make_dedup_key(log_data: dict) -> str:
    """flow 5-튜플 + 시그니처로 중복 판단 키 생성."""
    sig = str(log_data.get("alert", {}).get("signature", ""))
    key_src = (
        f"{log_data.get('src_ip','')}:{log_data.get('src_port','')}"
        f"-{log_data.get('dest_ip','')}:{log_data.get('dest_port','')}"
        f"-{log_data.get('proto','')}-{sig}"
    )
    return hashlib.sha256(key_src.encode()).hexdigest()


def is_duplicate(log_data: dict) -> bool:
    """쿨다운 시간 안에 같은 alert를 이미 보냈으면 True."""
    key = make_dedup_key(log_data)
    now = time.time()

    # 오래된 항목 정리 (메모리 누수 방지)
    for k in [k for k, t in _recent_sent.items() if now - t > DEDUP_COOLDOWN_SEC]:
        _recent_sent.pop(k, None)

    if key in _recent_sent and now - _recent_sent[key] < DEDUP_COOLDOWN_SEC:
        return True
    _recent_sent[key] = now
    return False


def load_offset() -> int:
    try:
        with open(OFFSET_FILE_PATH, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_offset(offset: int) -> None:
    try:
        with open(OFFSET_FILE_PATH, "w") as f:
            f.write(str(offset))
    except Exception as e:
        print(f"⚠️  오프셋 저장 실패: {e}")


def forward_to_fastapi(log_data: dict) -> None:
    try:
        alert = log_data.get("alert", {})
        payload = {
            "src_port": log_data.get("src_port", 0),
            "dest_port": log_data.get("dest_port", 0),
            "is_ephemeral_src": 1 if log_data.get("src_port", 0) > 49151 else 0,
            "has_danger_payload": 1 if "alert" in log_data else 0,
            "severity_weight": float(alert.get("severity", 3.0)),
            "meta_data": {
                "src_ip": log_data.get("src_ip", "0.0.0.0"),
                "dest_ip": log_data.get("dest_ip", "0.0.0.0"),
                "signature": str(alert.get("signature", "Unknown Signature Attack")),
                # 룰의 metadata(mitre_technique_id 등)를 그대로 LLM 컨텍스트로 전달
                "metadata": alert.get("metadata", {}),
                "category": str(alert.get("category", "")),
                "timestamp": str(log_data.get("timestamp", "")),
            },
        }

        response = requests.post(FASTAPI_URL, json=payload, timeout=30)
        if response.status_code == 200:
            sig = payload["meta_data"]["signature"]
            print(f"✅ [SUCCESS] 전송 성공: {sig} (src={payload['meta_data']['src_ip']})")
        else:
            print(f"⚠️  [HTTP {response.status_code}] 백엔드 응답 비정상")

    except Exception as e:
        print(f"❌ [EXCEPTION] {str(e)}")


def monitor_suricata_log() -> None:
    print("👀 Suricata 로그 감시 시작...")

    # 파일이 생성될 때까지 대기
    while not os.path.exists(LOG_FILE_PATH):
        print(f"⚠️  아직 {LOG_FILE_PATH} 가 없습니다. 대기 중...")
        time.sleep(2)

    offset = load_offset()

    # 저장된 오프셋이 현재 파일 크기보다 크면 = 로그가 truncate/rotate 된 것
    # → 처음부터 다시 읽기
    current_size = os.path.getsize(LOG_FILE_PATH)
    if offset > current_size:
        print("🔄 로그 파일이 초기화됨(truncate) 감지 → 오프셋 리셋")
        offset = 0

    print(f"📍 {offset} 바이트 지점부터 이어읽기 시작")

    with open(LOG_FILE_PATH, "r") as f:
        f.seek(offset)
        while True:
            line = f.readline()
            if not line:
                # 더 읽을 게 없으면 현재 위치 저장 후 잠시 대기
                offset = f.tell()
                save_offset(offset)

                # truncate 재확인 (대기 중 파일이 비워질 수 있음)
                try:
                    if os.path.getsize(LOG_FILE_PATH) < offset:
                        print("🔄 감시 중 로그 초기화 감지 → 처음부터 재시작")
                        f.seek(0)
                        offset = 0
                        save_offset(0)
                        continue
                except FileNotFoundError:
                    pass

                time.sleep(0.2)
                continue

            try:
                log_data = json.loads(line)
            except Exception:
                continue

            # alert 이벤트만 처리
            if log_data.get("event_type") != "alert" and "alert" not in log_data:
                continue

            if is_duplicate(log_data):
                # 중복은 조용히 스킵 (로그 폭주 방지)
                continue

            forward_to_fastapi(log_data)
            # 전송 직후 오프셋 갱신
            save_offset(f.tell())


if __name__ == "__main__":
    monitor_suricata_log()
