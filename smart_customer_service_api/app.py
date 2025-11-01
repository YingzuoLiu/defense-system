from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Dict, Any
import json, os, datetime

def main_nlu_model(text: str) -> Optional[Dict[str, Any]]:
    try:
        if "refund" in text.lower():
            return {"intent": "refund_request", "confidence": 0.92}
        if "price" in text.lower():
            return {"intent": "pricing_query", "confidence": 0.88}
        return None
    except Exception:
        return None

def fallback_nlu(text: str) -> Dict[str, Any]:
    text_l = text.lower()
    if "return" in text_l or "退货" in text_l:
        return {"intent": "refund_request", "confidence": 0.7}
    elif "发票" in text_l or "invoice" in text_l:
        return {"intent": "invoice_request", "confidence": 0.6}
    else:
        return {"intent": "unknown", "confidence": 0.4}

def decision_engine(intent: str, confidence: float, user_profile: Dict[str, Any]) -> Dict[str, Any]:
    risk_level = "low"
    decision = "manual_review"

    if confidence < 0.5:
        decision = "uncertain"
    elif intent == "refund_request" and confidence >= 0.8:
        if user_profile.get("return_rate", 0.0) < 0.2:
            decision = "auto_refund"
        else:
            risk_level = "medium"
            decision = "manual_review"
    elif intent == "invoice_request":
        decision = "auto_reply"

    reply_templates = {
        "refund_request": "We're sorry to hear that. We'll help you apply for a refund soon.",
        "invoice_request": "Please provide your order ID so we can issue an invoice.",
        "unknown": "Could you please clarify your request?",
    }
    reply = reply_templates.get(intent, reply_templates["unknown"])

    return {"risk_level": risk_level, "decision": decision, "reply": reply}

def on_prediction_logged(data: Dict[str, Any]):
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "interactions.jsonl")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")

app = FastAPI(title="Smart Customer Service Defense API", version="1.0.0")

class PredictRequest(BaseModel):
    user_id: str
    message: str
    order_amount: Optional[float] = 0.0
    return_rate: Optional[float] = 0.0
    fraud_flag: Optional[bool] = False

class PredictResponse(BaseModel):
    intent: str
    confidence: float
    risk_level: str
    decision: str
    reply: str

@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    nlu_result = main_nlu_model(req.message)
    if not nlu_result:
        nlu_result = fallback_nlu(req.message)

    result = decision_engine(nlu_result["intent"], nlu_result["confidence"], req.dict())

    log_data = {
        "timestamp": datetime.datetime.now().isoformat(),
        "user_id": req.user_id,
        "message": req.message,
        "nlu": nlu_result,
        "result": result
    }
    on_prediction_logged(log_data)

    return PredictResponse(
        intent=nlu_result["intent"],
        confidence=nlu_result["confidence"],
        risk_level=result["risk_level"],
        decision=result["decision"],
        reply=result["reply"]
    )
