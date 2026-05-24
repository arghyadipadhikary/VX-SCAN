import os
import zipfile
import yara
import requests
import uuid
import shutil
import math
import re
import asyncio
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))

TEMP_DIR = os.getenv("TEMP_DIR", "/app/temp_uploads")
YARA_RULES_PATH = os.getenv("YARA_RULES_PATH", "/app/yara_rules/rules.yar")

# ==========================================
# TRUSTED PUBLISHER ALLOWLIST
# ==========================================
TRUSTED_PUBLISHERS = ["Microsoft", "GitHub", "Google", "Vue", "ms-vscode", "RedHat"]

def calculate_shannon_entropy(text_string: str) -> float:
    if not text_string:
        return 0.0
    p, lns = Counter(text_string), float(len(text_string))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

def semantic_behavior_analysis(code_text: str) -> dict:
    risk_vectors = {
        "execution": len(re.findall(r'(eval\(|child_process|exec\(|spawn\()', code_text)),
        "obfuscation": len(re.findall(r'(Buffer\.from|base64|fromCharCode)', code_text)),
        "network": len(re.findall(r'(fetch\(|http|net\.Socket|WebSocket)', code_text)),
        "fs_access": len(re.findall(r'(fs\.readFileSync|fs\.writeFileSync)', code_text))
    }
    
    anomaly_score = 0
    # TUNING 1: Require higher density for alerts. Normal extensions use network and exec occasionally. Malware spams it.
    if risk_vectors["network"] > 5 and risk_vectors["execution"] > 3:
        anomaly_score += 4
    
    # TUNING 2: Base64 is common for images. Only flag if it's heavily spammed.
    if risk_vectors["obfuscation"] > 15:
        anomaly_score += 3
        
    return {"vectors": risk_vectors, "score": anomaly_score}

def scrape_marketplace(extension_identifier: str) -> dict:
    url = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
    
    headers = {
        "Accept": "application/json;api-version=3.0-preview.1",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0"
    }
    
    payload = {
        "filters": [{"criteria": [{"filterType": 7, "value": extension_identifier}]}],
        "flags": 914
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        data = response.json()
        
        if data.get("results") and data["results"][0].get("extensions"):
            ext_data = data["results"][0]["extensions"][0]
            publisher = ext_data.get("publisher", {}).get("displayName", "Unknown")
            
            installs = "Unknown"
            statistics = ext_data.get("statistics", [])
            for stat in statistics:
                if stat.get("statisticName") == "install":
                    raw_installs = int(stat.get("value", 0))
                    if raw_installs >= 1000000:
                        installs = f"{raw_installs / 1000000:.1f}M"
                    elif raw_installs >= 1000:
                        installs = f"{raw_installs / 1000:.1f}K"
                    else:
                        installs = str(raw_installs)
                    break
                    
            return {
                "publisher": publisher,
                "installs": installs,
                "url": f"https://marketplace.visualstudio.com/items?itemName={extension_identifier}"
            }
        else:
            return {"publisher": "Unknown", "installs": "Unknown", "error": "Extension not found."}
            
    except Exception as e:
        return {"publisher": "Unknown", "installs": "Unknown", "error": str(e)}

async def analyze_extension(extension_id: str, progress_cb=None) -> dict:
    async def notify(msg: dict):
        if progress_cb:
            await progress_cb(msg)
            
    report = {
        "extension_name": extension_id,
        "classification": "SAFE",
        "risk_score": 0,
        "yara_matches": [],
        "warnings": [],
        "nlp_insights": []
    }
    
    await notify({"step": "info", "message": "Gathering Marketplace metadata..."})
    meta = scrape_marketplace(extension_id)
    report.update(meta)
    
    installs_str = report.get("installs", "Unknown")
    publisher_str = report.get("publisher", "Unknown")

    if publisher_str == "Unknown":
        report["risk_score"] += 4
        report["warnings"].append("Publisher could not be verified.")

    if installs_str == "Unknown":
        report["risk_score"] += 3
        report["warnings"].append("Install count hidden or unknown.")
    elif "M" not in installs_str and "K" not in installs_str:
        report["risk_score"] += 3
        report["warnings"].append(f"Suspiciously low download count ({installs_str}).")
    
    try:
        rules = yara.compile(filepath=YARA_RULES_PATH)
        os.makedirs(TEMP_DIR, exist_ok=True)
        
        if "." not in extension_id:
            raise ValueError("Target ID must be formatted as 'publisher.extension'")
            
        publisher, ext_name = extension_id.split('.')
        download_url = f"https://{publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/{publisher}/extension/{ext_name}/latest/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"
        
        vsix_path = os.path.join(TEMP_DIR, f"{uuid.uuid4()}.vsix")
        extract_dir = os.path.join(TEMP_DIR, str(uuid.uuid4()))
        
        await notify({"step": "info", "message": "Downloading payload from Microsoft CDN..."})
        res = requests.get(download_url, headers={"User-Agent": "Mozilla/5.0"}, stream=True, timeout=15)
        
        if res.status_code == 200:
            with open(vsix_path, 'wb') as f:
                for chunk in res.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            await notify({"step": "info", "message": "Unpacking archive..."})
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(vsix_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
                
            files_to_scan = []
            for root, dirs, files in os.walk(extract_dir):
                # TRUE OPTIMIZATION: Stop os.walk from even entering the folder
                if 'node_modules' in dirs:
                    dirs.remove('node_modules')
                    
                for file in files:
                    if file.endswith(('.png', '.jpg', '.gif', '.md', '.txt', '.json')):
                        continue
                    files_to_scan.append(os.path.join(root, file))
                    
            total_files = len(files_to_scan)
            
            for i, file_path in enumerate(files_to_scan):
                file_name = os.path.basename(file_path)
                
                if i % 10 == 0:
                    await notify({"step": "progress", "current": i, "total": total_files, "file": file_name})
                    await asyncio.sleep(0)
                    
                matches = rules.match(filepath=file_path)
                for match in matches:
                    # TUNING 5: Context-Aware YARA. 
                    # Do not fire Node.js alerts on Python/C++ binaries or language files.
                    if "Node" in match.rule and file_name.endswith(('.py', '.pyi', '.pyc', '.pyd', '.h', '.c')):
                        continue
                        
                    report["yara_matches"].append(f"{match.rule} detected in {file_name}")
                
                if file_name.endswith('.js') or file_name.endswith('.ts'):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as js_file:
                            code_content = js_file.read()
                            
                            entropy = calculate_shannon_entropy(code_content)
                            # TUNING 3: Raised entropy threshold to 6.8
                            if entropy > 6.8: 
                                report["risk_score"] += 2
                                report["nlp_insights"].append(f"High entropy ({entropy:.2f}) in {file_name}")
                            
                            behavior = semantic_behavior_analysis(code_content)
                            if behavior["score"] > 0:
                                report["risk_score"] += behavior["score"]
                                report["nlp_insights"].append(f"Anomalous behavior vector in {file_name}: {behavior['vectors']}")
                                
                    except UnicodeDecodeError:
                        pass
            
            await notify({"step": "info", "message": "Purging temporary artifacts..."})
            os.remove(vsix_path)
            shutil.rmtree(extract_dir)
            
        else:
            report["warnings"].append(f"Could not download VSIX payload (HTTP {res.status_code}).")

        # TUNING 4: Reputation Dampening for Verified Global Publishers
        is_trusted = publisher_str in TRUSTED_PUBLISHERS and ("M" in installs_str)
        if is_trusted:
            report["risk_score"] = max(0, report["risk_score"] - 15)
            report["warnings"].append("Trust Discount applied for Verified Global Publisher.")

        # ==========================================
        # FINAL CLASSIFICATION ENGINE
        # ==========================================
        if report["yara_matches"]:
            # If it's a trusted giant and the score is low, downgrade to SUSPICIOUS
            if is_trusted and report["risk_score"] < 8:
                report["classification"] = "SUSPICIOUS"
                report["warnings"].append("YARA match downgraded due to Trusted Publisher status.")
            else:
                report["classification"] = "HARMFUL"
        elif report["risk_score"] >= 8:
            report["classification"] = "HARMFUL"
        elif report["risk_score"] >= 5:
            report["classification"] = "SUSPICIOUS"
            
    except Exception as e:
        report["error"] = f"Analysis pipeline failure: {str(e)}"
        
    return report