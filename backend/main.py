from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import os
import traceback

from scanner import analyze_extension
from report import generate_pdf

app = FastAPI(title="ExtensionGuard API")

# ==========================================
# BULLETPROOF PATH RESOLUTION
# ==========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

# Auto-detects if you are inside the Podman container OR running locally on Kali
FRONTEND_DIR = "/app/frontend" if os.path.exists("/app/frontend") else os.path.join(PROJECT_ROOT, "frontend")
REPORTS_DIR = "/app/reports" if os.path.exists("/app/reports") else os.path.join(BASE_DIR, "reports")

os.makedirs(REPORTS_DIR, exist_ok=True)

@app.get("/")
def read_root():
    return RedirectResponse(url="/app/")

class ScanRequest(BaseModel):
    extension_id: str

@app.post("/api/scan")
async def scan_extension(request: ScanRequest):
    try:
        results = await analyze_extension(request.extension_id)
        
        try:
            pdf_filename = generate_pdf(results)
            results["report_url"] = f"/reports/{pdf_filename}"
        except Exception as pdf_error:
            print(f"[!] PDF ENGINE CRASH: {pdf_error}")
            if "warnings" not in results: results["warnings"] = []
            results["warnings"].append(f"PDF Engine Offline: {str(pdf_error)}")
            
        return results
    except Exception as e:
        print("[!] CRITICAL API CRASH:")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/api/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    try:
        data = await websocket.receive_json()
        ext_id = data.get("extension_id")
        
        async def send_progress(msg: dict):
            await websocket.send_json(msg)
            
        results = await analyze_extension(ext_id, progress_cb=send_progress)
        
        await send_progress({"step": "info", "message": "Generating PDF intelligence report..."})
        
        try:
            pdf_filename = generate_pdf(results)
            results["report_url"] = f"/reports/{pdf_filename}"
        except Exception as pdf_error:
            print(f"[!] PDF ENGINE CRASH: {pdf_error}")
            if "warnings" not in results: results["warnings"] = []
            results["warnings"].append(f"PDF Engine Offline: {str(pdf_error)}")
        
        await websocket.send_json({"step": "complete", "report": results})
    except Exception as e:
        print("[!] CRITICAL WEBSOCKET CRASH:")
        traceback.print_exc()
        await websocket.send_json({"step": "error", "message": str(e)})
    finally:
        await websocket.close()

app.mount("/app", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
app.mount("/reports", StaticFiles(directory=REPORTS_DIR), name="reports")

if __name__ == "__main__":
    import uvicorn
    # FIXED THE SYNTAX ERROR HERE:
    uvicorn.run(app, host="0.0.0.0", port=8000)