"""
app.py — FastAPI entry point for AI Scam Shield

Exposes a single POST /analyze endpoint that accepts a WhatsApp-style
message and returns a structured risk assessment.

Run with:
    uvicorn app:app --host 0.0.0.0 --port 8000 --reload

Or directly (starts uvicorn programmatically):
    python app.py
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import time
import logging

from risk_classifier import assess_message, RiskAssessment

# ---------------------------------------------------------------------------
# Logging setup — basic, no log aggregation for now
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Scam Shield",
    description=(
        "Lightweight fraud detection for WhatsApp-style messages. "
        "Detects scam patterns common in Nigeria and West Africa."
    ),
    version="0.1.0",
)

# Allow all origins for MVP — tighten this in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class MessageRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=5,
        max_length=5000,
        description="The text message to analyze for scam patterns.",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "message": (
                    "Dear customer, your Access Bank account has been suspended. "
                    "Send your OTP immediately to avoid losing access. "
                    "Do not ignore this message."
                )
            }
        }


class AnalysisResponse(BaseModel):
    risk_score: int
    risk_level: str
    detected_categories: list
    explanation: str
    signal_breakdown: list
    processing_time_ms: float
    message_length: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "AI Scam Shield", "version": "0.1.0"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}


@app.post("/analyze", response_model=AnalysisResponse, tags=["Detection"])
def analyze(request: MessageRequest):
    """
    Analyze a message for scam/fraud patterns.

    Returns a risk score (0–100), risk level, detected fraud categories,
    and a plain-English explanation.
    """
    message = request.message.strip()

    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    start = time.monotonic()

    try:
        result = assess_message(message)
    except Exception as e:
        logger.error(f"Detection error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error during analysis.")

    elapsed_ms = round((time.monotonic() - start) * 1000, 2)

    logger.info(
        f"Analyzed message ({len(message)} chars) — "
        f"score={result.risk_score}, level={result.risk_level}, "
        f"categories={result.detected_categories}, "
        f"time={elapsed_ms}ms"
    )

    return AnalysisResponse(
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        detected_categories=result.detected_categories,
        explanation=result.explanation,
        signal_breakdown=result.signal_breakdown,
        processing_time_ms=elapsed_ms,
        message_length=len(message),
    )


@app.post("/batch", tags=["Detection"])
def batch_analyze(messages: list[str]):
    """
    Analyze multiple messages at once. Max 50 per request.

    TODO: Add proper rate limiting. This is wide open right now.
    """
    if len(messages) > 50:
        raise HTTPException(status_code=400, detail="Max 50 messages per batch request.")

    results = []
    for msg in messages:
        if not msg or not msg.strip():
            results.append({"error": "empty message"})
            continue
        try:
            r = assess_message(msg.strip())
            results.append({
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "detected_categories": r.detected_categories,
                "explanation": r.explanation,
            })
        except Exception as e:
            results.append({"error": str(e)})

    return {"results": results, "count": len(results)}


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
