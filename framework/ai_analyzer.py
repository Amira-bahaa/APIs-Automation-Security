import os
import json
import logging

logger = logging.getLogger(__name__)


class AIAnalyzer:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self._client = None

    @property
    def client(self):
        if self._client is None and self.api_key:
            try:
                import openai
                self._client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                logger.warning("openai not installed, skipping AI analysis")
        return self._client

    @property
    def available(self):
        return self.client is not None

    def analyze_response(self, endpoint, method, status_code, headers, body, attack_type="general"):
        if not self.available:
            return {"risk_level": "unknown", "findings": ["AI analysis unavailable"], "recommendations": []}

        prompt = f"""Analyze this API response for security issues.

Endpoint: {method} {endpoint}
Attack: {attack_type}
Status: {status_code}
Headers: {json.dumps(dict(headers), indent=2) if headers else "N/A"}
Body (truncated): {str(body)[:1000]}

Check for: info leakage, missing security headers, bad error handling, data exposure, auth issues.
Return JSON with risk_level, findings array, recommendations array."""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=800,
            )
            content = response.choices[0].message.content.strip()
            if content.startswith("{"):
                return json.loads(content)
            if "```json" in content:
                json_str = content.split("```json")[1].split("```")[0].strip()
                return json.loads(json_str)
            return {"risk_level": "unknown", "findings": [content], "recommendations": []}
        except Exception as exc:
            logger.warning(f"AI analysis failed: {exc}")
            return {"risk_level": "unknown", "findings": [f"Error: {exc}"], "recommendations": []}


ai_analyzer = AIAnalyzer()
