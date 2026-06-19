import os
from fastapi import FastAPI
from pydantic import BaseModel
from google import genai
from google.genai import types
from schemas import SiemLogInput, MitigationOutput
from sklearn.linear_model import LogisticRegression
import numpy as np

app = FastAPI(title="Intelligence AI/ML Orchestrations API")

client = genai.Client()

X_train = np.array([[120, 0], [1500, 1], [64, 0], [1350, 1], [80, 0], [1600, 1]])
y_train = np.array([0, 1, 0, 1, 0, 1])

ml_model = LogisticRegression()
ml_model.fit(X_train, y_train)

MOCK_BAD_IP_LIST = ["195.133.40.12", "185.220.101.5", "45.146.164.11"]
MOCK_ATTACK_PATTERNS = """
- SQL Injection: UNION SELECT, OR 1=1 구문을 이용한 DB 탈취 행위
- Remote Code Execution (RCE): 웹서버 취약점을 통해 시스템 명령어를 강제 실행하는 행위
- WebShell Upload: 악성 스크립트 파일을 업로드하여 서버 제어권을 장악하는 공격
"""

@app.post("/analyze", response_model=MitigationOutput)
def analyze_and_mitigate(log_data: SiemLogInput):

    danger_keywords = ["UNION", "SELECT", "CONCAT", "bash", "cmd", "eval", "wget"]
    has_danger_word = 1 if any(kw in log_data.payload for kw in danger_keywords) else 0
    
    X_test = np.array([[log_data.packet_length, has_danger_word]])
    ml_prediction = ml_model.predict(X_test)[0]
    

    if ml_prediction == 0 and log_data.source_ip not in MOCK_BAD_IP_LIST:
        return MitigationOutput(
            block_ip="None",
            risk_score=0,
            attack_type="Normal Traffic",
            reason="Scikit-Learn 1차 분석 결과 정상 세션으로 판단되어 통과"
        )

    rag_context = f"""
    [보안 인텔리전스 DB 컨텍스트]
    * 알려진 블랙리스트 IP 목록: {MOCK_BAD_IP_LIST}
    * 위협 패턴 명세:
    {MOCK_ATTACK_PATTERNS}
    """
    
    # --- LLM 1호기
    prompt_llm_1 = f"""
    당신은 고급 침해사고 분석가(LLM 1호기)입니다. 
    제공된 웹/네트워크 로그 데이터와 인텔리전스 DB 자료를 RAG 기반으로 상호 참조하여, 
    공격자가 어떤 취약점을 통해 인프라에 침입을 시도했는지 인과관계를 정밀 추론하세요.
    
    [인입 로그 데이터]
    - 공격 출발 IP: {log_data.source_ip}
    - 통신 프로토콜: {log_data.protocol}
    - 패킷 페이로드 원문: {log_data.payload}
    
    {rag_context}
    
    출력 형식: 현재 발생한 공격 유형, 인텔리전스 DB 상의 일치 지표, 웹서버에 미칠 손상 범위 및 인과관계 분석 스토리를 한글로 명확히 서술하세요.
    """
    
    response_llm_1 = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt_llm_1,
    )
    llm_1_analysis = response_llm_1.text

    # --- LLM 2호기: 
    prompt_llm_2 = f"""
    당신은 보안 제어 오케스트레이터(LLM 2호기)입니다.
    LLM 1호기가 도출한 침해 사고 분석 보고서를 기반으로, 관리자용 핵심 요약 문장(reason)을 1문장으로 가공하세요.
    
    [LLM 1호기 분석 보고서]
    {llm_1_analysis}
    
    [요구 조건]
    - 반드시 인프라 방화벽 정책(iptables 등) 업데이트의 근거가 될 수 있도록 핵심 인과관계 위주로 간결하게 한 줄 요약해서 작성해야 합니다.
    - 예시: "블랙리스트에 등록된 IP에서 SQL Injection 페이로드를 이용한 데이터베이스 탈취 시도가 포착되어 차단을 권고함."
    """
    
    response_llm_2 = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt_llm_2,
    )
    final_reason = response_llm_2.text.strip()

#가중치 부여
    base_risk = 85 if ml_prediction == 1 else 60
    final_risk_score = min(base_risk + (15 if log_data.source_ip in MOCK_BAD_IP_LIST else 0), 100)
    
    return MitigationOutput(
        block_ip=log_data.source_ip,
        risk_score=final_risk_score,
        attack_type="Intelligent Web Attack Detected" if has_danger_word else "Suspicious Traffic Traffic",
        reason=final_reason
    )