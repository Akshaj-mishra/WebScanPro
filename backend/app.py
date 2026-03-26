from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from main.service.scanner import Scanner 
from main.service.report_gen import generate_ai_summary
from test import resp

app = FastAPI(title="WebScanPro API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

@app.get("/")
def health():
    return {"message": "FastAPI backend running"}


@app.post("/result")
async def get_web(request: ScanRequest):
        
        num = resp()
        ai_response = generate_ai_summary(request.url)
        
        return {
                "summary": 'ai_summary',
                "risk_score": num,
                "vulnerabilities": ai_response
}