from weasyprint import HTML
import os
import uuid

REPORTS_DIR = os.getenv("REPORTS_DIR", "./reports")

def generate_pdf(scan_data: dict) -> str:
    # Determine classification color
    if scan_data.get("classification") == "SAFE":
        color = "green"
    elif scan_data.get("classification") == "SUSPICIOUS":
        color = "orange"
    else:
        color = "red"
        
    # Generate dynamic HTML blocks for NLP and Warnings
    nlp_html = ""
    if scan_data.get("nlp_insights"):
        nlp_html = "<h3>Behavioral & NLP Insights</h3><ul>"
        for insight in scan_data["nlp_insights"]:
            nlp_html += f"<li>{insight}</li>"
        nlp_html += "</ul>"
        
    warnings_html = ""
    if scan_data.get("warnings"):
        warnings_html = "<h3>System Warnings</h3><ul>"
        for warning in scan_data["warnings"]:
            warnings_html += f"<li>{warning}</li>"
        warnings_html += "</ul>"
    
    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 10px; }}
            .classification {{ font-size: 24px; font-weight: bold; color: {color}; }}
            .section {{ margin-top: 30px; }}
            .finding {{ background: #f9f9f9; padding: 10px; border-left: 4px solid {color}; margin-bottom: 10px; }}
        </style>
    </head>
    <body>
        <h1>ExtensionGuard Risk Report</h1>
        <p><strong>Target:</strong> {scan_data.get('extension_name', 'Unknown')}</p>
        <p class="classification">CLASSIFICATION: {scan_data.get('classification', 'UNKNOWN')}</p>
        
        <div class="section">
            <h2>Marketplace Intelligence</h2>
            <ul>
                <li>Publisher: {scan_data.get('publisher', 'Unknown')}</li>
                <li>Installs: {scan_data.get('installs', '0')}</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>Static Analysis Findings</h2>
            <div class="finding">
                <strong>Yara Matches:</strong> {", ".join(scan_data.get('yara_matches', [])) or "None detected"}
            </div>
            <div class="finding">
                <strong>Risk Score:</strong> {scan_data.get('risk_score', 0)} / 10
            </div>
            {warnings_html}
            {nlp_html}
            <p><em>Note: This is an automated static analysis report.</em></p>
        </div>
    </body>
    </html>
    """
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"report_{uuid.uuid4().hex[:8]}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    
    HTML(string=html_content).write_pdf(filepath)
    return filename