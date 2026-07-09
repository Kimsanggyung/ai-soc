import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from agent_orchestrator import router as agent_router

app = FastAPI(
    title="AI-SOC SOAR Platform Backend",
    description="Suricata IDS + Llama 3.1 Real-Time Incident Response Pipeline",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(agent_router)

@app.get("/")
def root_check():
    return {"status": "healthy", "platform": "AI-SOC SOAR Core Backend"}

if __name__ == "__main__":
    
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)