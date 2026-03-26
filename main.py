"""
PQC Posture Scanner — FastAPI Backend

Accepts a GitHub repo URL or code snippet, scans for quantum-vulnerable
cryptography, and returns a full posture report with CBOM.
"""

import os
import shutil
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from pqc_posture import scan_codebase


# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------
_stats: Dict = {"total_scans": 0, "unique_repos": set()}
_rate_limit: Dict[str, float] = {}  # ip -> last_scan_timestamp

SCAN_TIMEOUT_SECONDS = 120
RATE_LIMIT_SECONDS = 10


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="PQC Posture Scanner API",
    version="0.1.0",
    description="Scan codebases for post-quantum cryptography vulnerabilities",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*\.vercel\.app|http://localhost:3000",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    github_url: str = Field(..., description="GitHub repo URL or user/repo shorthand")


class ScanTextRequest(BaseModel):
    code: str = Field(..., description="Code snippet to scan")
    filename: str = Field(default="snippet.py", description="Filename hint for extension detection")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _normalise_github_url(raw: str) -> str:
    """Accept 'user/repo', 'https://github.com/user/repo', etc."""
    url = raw.strip().rstrip("/")
    # Strip .git suffix if present
    if url.endswith(".git"):
        url = url[:-4]
    # Shorthand: user/repo
    if not url.startswith("http"):
        url = f"https://github.com/{url}"
    return url


def _repo_name(url: str) -> str:
    """Extract 'user/repo' from a GitHub URL."""
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return url


def _clone_repo(url: str, dest: str, timeout: int = SCAN_TIMEOUT_SECONDS) -> None:
    """Shallow-clone a repo. Raises HTTPException on failure."""
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, dest],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Clone timed out — repo may be too large")
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() if exc.stderr else "Clone failed"
        raise HTTPException(status_code=400, detail=f"Git clone failed: {detail}")


def _check_rate_limit(ip: str) -> None:
    """Enforce 1 scan per 10 seconds per IP."""
    now = time.time()
    last = _rate_limit.get(ip, 0)
    if now - last < RATE_LIMIT_SECONDS:
        wait = int(RATE_LIMIT_SECONDS - (now - last)) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Rate limited — try again in {wait}s",
        )
    _rate_limit[ip] = now


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/stats")
async def stats():
    return {
        "total_scans": _stats["total_scans"],
        "unique_repos": len(_stats["unique_repos"]),
    }


@app.post("/api/scan")
async def scan_repo(body: ScanRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    url = _normalise_github_url(body.github_url)
    repo_name = _repo_name(url)

    tmp_dir = tempfile.mkdtemp(prefix="pqc_scan_")
    try:
        _clone_repo(url, tmp_dir)

        start = time.time()
        result = scan_codebase(tmp_dir)
        elapsed = time.time() - start

        if elapsed > SCAN_TIMEOUT_SECONDS:
            raise HTTPException(status_code=504, detail="Scan timed out")

        # Track stats
        _stats["total_scans"] += 1
        _stats["unique_repos"].add(repo_name)

        # Replace tmp path with repo name in output
        result["scan_path"] = repo_name

        return result
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.post("/api/scan-text")
async def scan_text(body: ScanTextRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    if not body.code.strip():
        raise HTTPException(status_code=400, detail="Code snippet is empty")

    if len(body.code) > 500_000:
        raise HTTPException(status_code=400, detail="Code snippet too large (max 500KB)")

    tmp_dir = tempfile.mkdtemp(prefix="pqc_text_")
    try:
        # Write snippet to temp file with the given filename
        filepath = os.path.join(tmp_dir, body.filename)
        with open(filepath, "w") as f:
            f.write(body.code)

        result = scan_codebase(tmp_dir)

        # Track stats
        _stats["total_scans"] += 1

        result["scan_path"] = f"snippet:{body.filename}"

        return result
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/badge/{owner}/{repo}.svg")
async def badge(owner: str, repo: str):
    """Return a shields.io-style SVG badge with quantum grade."""
    # Simple in-memory cache (1 hour TTL)
    cache_key = f"{owner}/{repo}"
    if not hasattr(badge, "_cache"):
        badge._cache = {}

    cached = badge._cache.get(cache_key)
    if cached and (time.time() - cached["ts"]) < 3600:
        grade, color = cached["grade"], cached["color"]
    else:
        tmp_dir = tempfile.mkdtemp(prefix="pqc_badge_")
        try:
            url = f"https://github.com/{owner}/{repo}"
            _clone_repo(url, tmp_dir)
            result = scan_codebase(tmp_dir)
            score = result.get("risk_score", 100)
            if score <= 5:
                grade = "A+"
            elif score <= 10:
                grade = "A"
            elif score <= 25:
                grade = "B"
            elif score <= 50:
                grade = "C"
            elif score <= 75:
                grade = "D"
            else:
                grade = "F"

            colors = {
                "A+": "#4c1", "A": "#4c1", "B": "#a4a61d",
                "C": "#dfb317", "D": "#fe7d37", "F": "#e05d44",
            }
            color = colors.get(grade, "#e05d44")
            badge._cache[cache_key] = {"grade": grade, "color": color, "ts": time.time()}
        except Exception:
            grade, color = "?", "#9f9f9f"
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20" role="img">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="130" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="78" height="20" fill="#555"/>
    <rect x="78" width="52" height="20" fill="{color}"/>
    <rect width="130" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="400" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)"  textLength="680">PQC Grade</text>
    <text x="400" y="140" transform="scale(.1)" textLength="680">PQC Grade</text>
    <text x="1035" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="370" font-weight="bold">{grade}</text>
    <text x="1035" y="140" transform="scale(.1)" textLength="370" font-weight="bold">{grade}</text>
  </g>
</svg>'''

    from fastapi.responses import Response
    return Response(content=svg, media_type="image/svg+xml", headers={"Cache-Control": "max-age=3600"})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
