from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from main.service.scanner import Scanner 
from main.service.report_gen import ReportGenerator
from test import crawl

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
        
        base_url = request.url.split("/vulnerabilities")[0]
        scanner = Scanner(base_url)
        scanner.run_targeted_scan(request.url)
        test = crawl()
        return test