import json
import time
import os
import requests

# 1. 환경 설정 (경로 및 목적지 API 주소)
LOG_FILE_PATH = "suricata/log/eve.json"
FASTAPI_URL = "http://localhost:8000/api/v1/alert"  # 개발 중인 FastAPI 서버 엔드포인트

def forward_to_fastapi(log_data):
    """파싱된 JSON 로그를 FastAPI 서버로 실시간 전송하는 함수"""
    try:
        # 수리카타 로그 중 우리가 필요한 정보만 예쁘게 정제해서 전송
        payload = {
            "timestamp": log_data.get("timestamp"),
            "event_type": log_data.get("event_type"),
            "src_ip": log_data.get("src_ip"),
            "src_port": log_data.get("src_port"),
            "dest_ip": log_data.get("dest_ip"),
            "dest_port": log_data.get("dest_port"),
            "proto": log_data.get("proto"),
            "alert": log_data.get("alert", {})  # 탐지된 룰 정보 (DANGER 메시지 포함)
        }
        
        # FastAPI 서버로 POST 요청 발송 (타임아웃 2초 고정)
        response = requests.post(FASTAPI_URL, json=payload, timeout=2)
        
        if response.status_code == 200:
            print(f"🚀 [SUCCESS] FastAPI 전송 완료: {payload['alert'].get('signature')}")
        else:
            print(f"⚠️ [WARNING] 전송 실패 (상태코드 {response.status_code})")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ [ERROR] FastAPI 서버가 꺼져있거나 연결할 수 없습니다. (에러: {e})")

def watch_eve_json():
    """eve.json 파일을 실시간으로 모니터링하며 새로 추가되는 줄을 파싱하는 함수"""
    print("👀 Suricata 실시간 로그 포워더(forwarder.py) 가동 시작...")
    
    # 만약 아직 수리카타가 로그를 안 만들어내서 파일이 없다면 생길 때까지 대기
    while not os.path.exists(LOG_FILE_PATH):
        print("⏳ eve.json 파일이 아직 생성되지 않았습니다. 수리카타 구동을 기다리는 중...")
        time.sleep(2)

    # 파일을 읽기 모드로 오픈
    with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
        # 파일의 맨 끝(EOF)으로 포인터를 강제 이동시킵니다. (기존 로그 무시, 실행 시점 이후 로그부터 수집)
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            
            # 새로운 줄이 들어오지 않았다면 0.1초 쉬고 다시 읽기 시도 (CPU 과부하 방지)
            if not line:
                time.sleep(0.1)
                continue
            
            # 새로운 줄이 들어왔다면 JSON으로 파싱하여 전송 처리
            try:
                log_data = json.loads(line.strip())
                # 수리카타 로그 중 'alert' 타입(위협 탐지) 로그만 선별하여 백엔드로 포워딩
                if log_data.get("event_type") == "alert":
                    forward_to_fastapi(log_data)
            except json.JSONDecodeError:
                # 가끔 로그가 찍히는 도중 잘려서 읽히는 예외 처리
                continue

if __name__ == "__main__":
    watch_eve_json()