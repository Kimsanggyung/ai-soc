from pydantic import BaseModel

class SiemLogInput(BaseModel):
    source_ip: str
    packet_length: int
    protocol: str
    payload: str

class MitigationOutput(BaseModel):
    block_ip: str
    risk_score: int  
    attack_type: str
    reason: str      # LLM이 추론한 핵심 인과관계 요약