from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def serve_html():
    html_file_path = Path("E:\FYP\server\pages\index.html")

    if html_file_path.exists():
        html_content = html_file_path.read_text(encoding="utf-8")  # Ensure proper encoding
        return HTMLResponse(content=html_content, status_code=200)
    else:
        return HTMLResponse(content="<h1>File Not Found</h1>", status_code=404)
