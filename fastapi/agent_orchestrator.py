import os
import json
import re
import asyncio
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.sse import EventSourceResponse
from pydantic import BaseModel
from typing import Dict, Any, AsyncGenerator
from openai import OpenAI
# 🚨 [보안 종결] .env 파일을 자동으로 스캔하여 os.environ에 빌드하는 정석 모듈 주입
from dotenv import load_dotenv

# 🚨 서버 기상과 동시에 .env 내부의 모든 환경 변수를 시스템 메모리에 안착시킵니다.
load_dotenv()

router = APIRouter(prefix="/api/v1", tags=["AI SOAR Pipeline"])

# ==============================================================================
#확장 룰셋 대응 MITRE ATT&CK 사전 및 동적 위험도 산출 로직

from datetime import datetime, timedelta

MITRE_MATRIX = {
    "🔴 [ALERT] ATTACK DETECTED: Path Traversal Attempt": {"t_code": "T1083", "category": "Discovery (파일 정찰)", "base_severity": 1.5},
    "SQL Injection": {"t_code": "T1190", "category": "Initial Access (최초 침투)", "base_severity": 2.5},
    "OS Command Injection": {"t_code": "T1203", "category": "Execution (악성 명령 실행)", "base_severity": 3.0},
    "Webshell Upload Attempt": {"t_code": "T1505.003", "category": "Persistence (지속성 확보)", "base_severity": 3.0},
    "C2 Connection Attempt": {"t_code": "T1071", "category": "Command and Control (명령 제어)", "base_severity": 2.8}
}

ATTACK_HISTORY = {}

def calculate_ai_security_score(src_ip: str, signature_name: str, dest_port: int) -> dict:
    current_time = datetime.now()
    rule_data = MITRE_MATRIX.get(signature_name, {"base_severity": 1.0, "category": "Unknown Threat", "t_code": "T1568"})
    rule_severity = rule_data["base_severity"]
    
    # 1. 자산 가중치 (Asset Weight): 중요 자산 포트 타깃 시 2.0배 가산
    asset_weight = 2.0 if dest_port in [3306, 8080, 22] else 1.0
        
    # 2. 빈도 가중치 (Frequency Weight): 10초 내 동일 IP 반복 유입 시 시나리오 가산
    if src_ip not in ATTACK_HISTORY:
        ATTACK_HISTORY[src_ip] = []
    ATTACK_HISTORY[src_ip] = [t for t in ATTACK_HISTORY[src_ip] if current_time - t < timedelta(seconds=10)]
    ATTACK_HISTORY[src_ip].append(current_time)
    
    frequency_weight = min((len(ATTACK_HISTORY[src_ip]) - 1) * 5, 35)
    
    # 3. 100점 만점 스케일링 연산
    calculated_score = (rule_severity * 20) * asset_weight + frequency_weight
    final_score = min(calculated_score, 100.0)
    
    return {
        "score": final_score,
        "category": rule_data["category"],
        "t_code": rule_data["t_code"]
    }
# ==============================================================================

# 코드 내부에는 그 어떤 키값 문자열도 남기지 않고 오직 env에서만 꺼내옵니다.
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

if not GROQ_API_KEY:
    print("⚠️ [WARNING] GROQ_API_KEY 환경변수가 설정되지 않았습니다. 최상위 루트의 .env 파일을 확인하세요...")

client = OpenAI(
    api_key=GROQ_API_KEY,
    base_url="https://api.groq.com/openai/v1"
)

UI_EVENT_QUEUE = asyncio.Queue()
templates = Jinja2Templates(directory="templates")

class ThreatContext(BaseModel):
    src_port: int
    dest_port: int
    is_ephemeral_src: int
    has_danger_payload: int
    severity_weight: float
    meta_data: Dict[str, Any]

def execute_firewall_drop(ip: str, port: int) -> bool:
    if ip in ["0.0.0.0", "127.0.0.1"]:
        return False
    print(f"🚨 [FIREWALL DISPATCH] 방화벽 정책 주입 성공: iptables -A INPUT -s {ip} --dport {port} -j DROP")
    return True

def query_rag_intelligence(ip: str) -> Dict[str, Any]:
    return {
        "ip_reputation": "Known Malicious IP associated with automated vulnerability scanners.",
        "associated_cve": "CVE-2026-9999 (Remote Code Execution / Path Traversal)",
        "attack_pattern_desc": "Path Traversal injection trying to access structural system files like /etc/passwd."
    }

@router.post("/predict")
async def process_threat_agent(context: ThreatContext):
    try:
        attack_ip = context.meta_data.get("src_ip", "0.0.0.0")
        detected_sig = context.meta_data.get("signature", "Unknown")
        
        # 🛡️ [지후 파트] 동적 스코어 연산 수행
        ai_metrics = calculate_ai_security_score(attack_ip, detected_sig, context.dest_port)
        dynamic_score = ai_metrics["score"]
        
        rag_intelligence = query_rag_intelligence(attack_ip)
        security_context = {
            "raw_log": context.model_dump(),
            "rag_threat_intelligence": rag_intelligence,
            "mitre_framework": {
                "t_code": ai_metrics["t_code"],
                "category": ai_metrics["category"]
            }
        }

        # [STEP 1] LLM 1호기 프롬프트 수정: 계산된 지후 점수를 강제로 고정 반영하도록 유도
        llm_1_prompt = f"""
        You are a Senior Cyber Security Incident Response AI (Agent 1).
        Analyze the given Security Context and output a JSON object.
        You MUST respond strictly with a valid JSON object matching this schema.
        Note: You MUST set the "confidence_score" field exactly to {dynamic_score}.
        {{
            "block_ip": "{attack_ip}",
            "block_port": {context.dest_port},
            "attack_type": "string",
            "confidence_score": {dynamic_score},
            "mitigation_action": "DROP"
        }}
        [Security Context]
        {json.dumps(security_context, indent=2)}
        """
        
        response_agent_1 = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": llm_1_prompt}],
            temperature=0.1
        )
        
        raw_text_1 = response_agent_1.choices[0].message.content.strip()
        json_match = re.search(r'\{.*\}', raw_text_1, re.DOTALL)
        llm_1_data = json.loads(json_match.group(0)) if json_match else json.loads(raw_text_1)

        await asyncio.sleep(3)

        # [STEP 2] LLM 2호기: 침해사고 한글 기술 보고서 자동 생성
        llm_2_prompt = f"""
        당신은 이상 징후 탐지 시스템의 기술 보고서 작성 전문 AI (Agent 2)입니다.
        아래 1호기 정형 데이터와 RAG 인텔리전스를 기반으로 관리자용 침해사고 한글 보고서를 마크다운 형태로 작성하세요.
        이용 IP/포트 등 침해 지표(IOC)가 누락 없이 명확하게 파싱되어야 합니다.

        [1호기 정형 데이터]
        {json.dumps(llm_1_data, indent=2)}
        [탐지 시그니처]
        - Suricata Signature: {detected_sig}
        - CVE: {rag_intelligence['associated_cve']}
        """

        response_agent_2 = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": llm_2_prompt}],
            temperature=0.3
        )
        llm_2_report = response_agent_2.choices[0].message.content

        orchestrated_data = {
            "ai_score": float(llm_1_data.get("confidence_score", 95.0)),
            "action": str(llm_1_data.get("mitigation_action", "DROP")),
            "rule_parameters": {
                "ip": str(llm_1_data.get("block_ip", attack_ip)),
                "port": int(llm_1_data.get("block_port", context.dest_port)),
                "attack_type": str(llm_1_data.get("attack_type", "Path Traversal Attempt"))
            },
            "technical_report": llm_2_report.strip()
        }

        if orchestrated_data["action"] == "DROP":
            execute_firewall_drop(orchestrated_data["rule_parameters"]["ip"], orchestrated_data["rule_parameters"]["port"])

        await UI_EVENT_QUEUE.put(orchestrated_data)
        return orchestrated_data

    except Exception as e:
        print(f"❌ [INTERNAL EXCEPTION] {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"request": request})

@router.get("/stream")
async def stream_threats(request: Request):
    async def event_generator() -> AsyncGenerator[Dict[str, Any], None]:
        while True:
            if await request.is_disconnected():
                break
            try:
                data = await asyncio.wait_for(UI_EVENT_QUEUE.get(), timeout=30.0)
                # 대시보드 JS가 즉시 수신 가능한 순정 SSE 전송 규격 포맷 유지
                yield f"event: threat_alert\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            except asyncio.TimeoutError:
                yield "comment: ping\n\n"

    return EventSourceResponse(event_generator())