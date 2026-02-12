from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from main.service.scanner import Scaner 

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
    return {"message": "FastAPI backend running "}

@app.post("/result")
async def get_web(request: ScanRequest):
    scan = Scaner(request.url)
    scan_results = scan.crawl()
    
    return {
        "status": "Target Scanning Complete",
        "target_url": request.url,
        "metadata": scan_results 
    }