"""Optional Google Gemini analysis with secret redaction."""
import json
import re
from typing import Dict
from .models import SecretFinding

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    genai = None
    GENAI_AVAILABLE = False

class AIMixin:
    """AI triage mixed into GHunter."""

    # Keys in scanner JSON output that may carry the actual secret value
    _SECRET_KEYS = {"Raw", "RawV2", "Redacted", "Secret", "Match", "Line"}

    def _ai_context(self, finding: SecretFinding) -> str:
        """Build the finding context sent to the AI.

        By default the raw secret value is stripped so credentials never leave
        the host. Set ai_send_raw=True in Config to opt in to sending raw data.
        """
        if self.config.ai_send_raw:
            return finding.raw_result[:500]

        try:
            data = json.loads(finding.raw_result)
        except (json.JSONDecodeError, TypeError):
            return "[raw data redacted]"

        def scrub(obj):
            if isinstance(obj, dict):
                return {
                    k: ("[REDACTED]" if k in self._SECRET_KEYS else scrub(v))
                    for k, v in obj.items()
                }
            if isinstance(obj, list):
                return [scrub(v) for v in obj]
            return obj

        return json.dumps(scrub(data))[:500]

    def analyze_with_gemini(self, finding: SecretFinding) -> Dict:
        """Analyze finding with Google Gemini AI (synchronous).

        Kept synchronous so it can run inside the repo-scan worker threads.
        """
        if not self.gemini_model:
            return {
                "false_positive": False,
                "needs_review": True,
                "severity": "UNKNOWN",
                "reason": "AI analysis not available"
            }

        try:
            ai_context = self._ai_context(finding)
            prompt = f"""Analyze this potential secret finding and determine:
1. Is this a FALSE POSITIVE? (test data, example, placeholder, etc.)
2. Does it need MANUAL REVIEW?
3. What is the SEVERITY? (CRITICAL, HIGH, MEDIUM, LOW)
4. Brief REASON for your assessment

Finding Details:
- Detector: {finding.detector_name}
- Type: {finding.detector_type}
- Verified: {finding.verified}
- Repository: {finding.repo_url}
- File: {finding.file_path}

Metadata (secret value redacted):
{ai_context}

Respond in JSON format:
{{
  "false_positive": true/false,
  "needs_review": true/false,
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "reason": "brief explanation"
}}
"""

            response = self.gemini_model.generate_content(prompt)
            result_text = response.text.strip()

            # Extract JSON from response
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                return analysis

            return {
                "false_positive": False,
                "needs_review": True,
                "severity": "UNKNOWN",
                "reason": "Could not parse AI response"
            }

        except Exception as e:
            msg = str(e)
            self.logger.error(f"Gemini analysis error: {e}")
            # Store a short, clean reason — never the full provider stack trace
            # (e.g. a 429 quota error is hundreds of lines). The `error` flag
            # tells the report to render this as a muted note, not an assessment.
            if "429" in msg or "quota" in msg.lower() or "rate limit" in msg.lower():
                reason = "AI triage skipped: Gemini rate limit / quota exceeded"
            else:
                reason = "AI triage skipped: analysis failed"
            return {
                "false_positive": False,
                "needs_review": True,
                "severity": "UNKNOWN",
                "reason": reason,
                "error": True,
            }

