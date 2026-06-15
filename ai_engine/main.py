from fastapi import FastAPI
from schemas import SiemLogInput, MitigationOutput

app = FastAPI(title="Intelligence AI/ML Orchestrations API")

@app.post("/analyze", response_model=MitigationOutput)
def analyze_and_mitigate(log_data: SiemLogInput):
    mock_response = {
        "block_ip": log_data.source_ip,
        "risk_score": 95,
        "attack_type": "SQL Injection Detected",
        "reason": f"위험 IP로 등록된 {log_data.source_ip}에서 악성 페이로드가 유입되어 차단을 권고합니다."
    }
    return mock_response