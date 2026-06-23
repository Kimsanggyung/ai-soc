import json
import time
import os
import requests

# 🚨 [경로 동기화 확실화] 
# 만약 상대 경로가 뒤틀렸다면, 호스트의 절대 경로를 안전하게 잡을 수 있도록 보정합니다.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE_PATH = os.path.join(BASE_DIR, "suricata", "log", "eve.json")

FASTAPI_URL = "http://localhost:8080/api/v1/predict"

print(f"🎯 [TARGET PATH] 포워더가 감시하는 진짜 로그 파일 절대경로: {LOG_FILE_PATH}")

def forward_to_fastapi(log_data):
    try:
        payload = {
            "src_port": log_data.get("src_port", 0),
            "dest_port": log_data.get("dest_port", 0),
            "is_ephemeral_src": 1 if log_data.get("src_port", 0) > 49151 else 0,
            "has_danger_payload": 1 if "alert" in log_data else 0,
            "severity_weight": float(log_data.get("alert", {}).get("severity", 3.0)),
            "meta_data": {
                "src_ip": log_data.get("src_ip", "0.0.0.0"),
                "signature": str(log_data.get("alert", {}).get("signature", "Unknown Signature Attack"))
            }
        }
        
        response = requests.post(FASTAPI_URL, json=payload, timeout=30)
        if response.status_code == 200:
            print("✅ [SUCCESS] 포워더 연동 -> 백엔드 전송 성공!")
            
    except Exception as e:
        print(f"❌ [EXCEPTION] {str(e)}")

def monitor_suricata_log():
    print("👀 Suricata 로그 감시 시작...")
    
    # 🚨 파일이 없을 경우 임의 생성해서 꼬이는 것을 방지하기 위해 파일 존재 여부 상시 체크
    while not os.path.exists(LOG_FILE_PATH):
        print(f"⚠️  도커가 아직 {LOG_FILE_PATH} 파일을 생성하지 않았습니다. 대기 중...")
        time.sleep(2)

    with open(LOG_FILE_PATH, "r") as f:
        # 처음부터 끝까지 누적 로그 스캔 모드
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                log_data = json.loads(line)
                if "alert" in log_data:
                    forward_to_fastapi(log_data)
            except Exception:
                pass

if __name__ == "__main__":
    monitor_suricata_log()