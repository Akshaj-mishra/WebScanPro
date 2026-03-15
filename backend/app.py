from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from main.service.scanner import Scanner 
from main.service.report_gen import ReportGenerator

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
    
    scanner = Scanner(request.url)
    report_gen = ReportGenerator(request.url)
    
    # Perform the targeted scan based on the URL suffix
    scan_results = scanner.run_targeted_scan(request.url)
    
    # Add results to the report generator logic
    if "sql_injection" in scan_results:
        report_gen.add_sql_results(scan_results["sql_injection"])
    if "xss" in scan_results:
        report_gen.add_xss_results(scan_results["xss"])
    if "idor" in scan_results:
        report_gen.add_idor_results(scan_results["idor"])
    
    # Generate the AI summary
    ai_summary = report_gen.generate_ai_summary()
    
    return {
        "status": "Scan and AI Analysis Complete",
        "target_url": request.url,
        "ai_analysis": ai_summary,
        "raw_results": scan_results
    }