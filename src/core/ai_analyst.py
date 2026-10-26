import os
import logging
import json
from google import genai
from google.genai import errors

logger = logging.getLogger("KeyShield")

# Local Mock Database for fallback explanation if API is unavailable
MOCK_ANALYSES = {
    "keyboard": {
        "analysis": "The system identified a process hooking the physical keyboard inputs. This is a critical indicator of software designed to record user passwords or bank details in the background.",
        "recommendation": "kill -9 {pid} && ls -l /proc/{pid}/exe"
    },
    "file": {
        "analysis": "A process attempted unauthorized changes to files containing user passwords (/etc/shadow, /etc/passwd). This is standard for rootkits seeking local privilege hijack.",
        "recommendation": "chattr +i /etc/shadow && lsof /etc/shadow"
    },
    "network": {
        "analysis": "The system caught outbound telemetry connections to an external IP. Malware logs key presses locally then exfiltrates them over ephemeral ports.",
        "recommendation": "iptables -A OUTPUT -d {ip} -j DROP && kill -9 {pid}"
    },
    "persistence": {
        "analysis": "A startup path or service unit was modified. Keyloggers use systemd or cron scripts to load when the machine starts up.",
        "recommendation": "systemctl disable {service} && rm -f {path}"
    },
    "process": {
        "analysis": "A process running from /tmp or temporary directories is using elevated resources. Legitimate binaries execute from standard paths (/bin, /usr/bin).",
        "recommendation": "kill -15 {pid} && file /proc/{pid}/exe"
    }
}

class AiAnalyst:
    """
    Interfaces with the AI model (Gemini or Ollama) to explain complex Linux security events,
    calculate threat impacts, and formulate mitigation shell commands.
    """
    def __init__(self, config):
        self.config = config
        self.enabled = self.config.get("ai_analyst", {}).get("enabled", False)
        self.provider = self.config.get("ai_analyst", {}).get("provider", "gemini").lower()
        self.model_name = self.config.get("ai_analyst", {}).get("model_name", "gemini-2.5-flash")
        self.ollama_url = self.config.get("ai_analyst", {}).get("ollama_url", "http://localhost:11434")
        self.api_key = os.environ.get("GEMINI_API_KEY")
        
        self.client = None
        if self.enabled:
            if self.provider == "gemini":
                if self.api_key:
                    try:
                        # Initialize Google GenAI client
                        self.client = genai.Client()
                        logger.info("Gemini AI Analyst successfully initialized using model: %s", self.model_name)
                    except Exception as e:
                        logger.error("Failed to initialize Gemini GenAI client: %s", e)
                else:
                    logger.warning("AI Analyst is configured to use Gemini, but GEMINI_API_KEY is not set. Operating in offline fallback mode.")
            elif self.provider == "ollama":
                logger.info("Ollama AI Analyst successfully initialized using model: %s at %s", self.model_name, self.ollama_url)

    def generate_text(self, prompt: str) -> str:
        """
        Sends the prompt to the configured AI provider (Gemini or Ollama)
        and returns the resulting text.
        """
        if self.provider == "gemini":
            if not self.client:
                raise ValueError("Gemini client is not initialized (check GEMINI_API_KEY).")
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            return response.text.strip()
        elif self.provider == "ollama":
            import requests
            url = f"{self.ollama_url.rstrip('/')}/api/generate"
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1
                }
            }
            response = requests.post(url, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            return result.get("response", "").strip()
        else:
            raise ValueError(f"Unsupported AI provider: {self.provider}")

    def analyze_incident(self, alert_event):
        """
        Takes a JSON alert event, contacts the configured AI provider for an explanation,
        and returns a dictionary with explanation and recommendation.
        """
        module = alert_event.get("module", "process")
        pid = alert_event.get("pid", "N/A")
        dest_ip = alert_event.get("destination_ip") or alert_event.get("ip") or "185.220.101.4"
        
        # If running offline fallback mode (e.g. Gemini with no API key)
        use_fallback = False
        if self.provider == "gemini" and not self.client:
            use_fallback = True

        if use_fallback:
            mock_data = MOCK_ANALYSES.get(module, MOCK_ANALYSES["process"])
            return {
                "analysis": mock_data["analysis"],
                "recommendation": mock_data["recommendation"].replace("{pid}", str(pid)).replace("{ip}", dest_ip)
            }

        prompt = f"""
        You are a senior Linux cybersecurity analyst. Analyze the following security alert from our agent:
        {json.dumps(alert_event, indent=2)}

        Provide your output in valid, raw JSON format with exactly two keys:
        1. "analysis": A clear, concise explanation of the security risk and why this event is dangerous (max 3 sentences).
        2. "recommendation": A single executable bash command line that can mitigate the issue (e.g. killing the process, blocking the IP, etc.).

        Output ONLY the raw JSON string without markdown code fences.
        """

        try:
            text = self.generate_text(prompt)
            
            # Clean markdown code fences if model returned them anyway
            if text.startswith("```"):
                text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text.rsplit("\n", 1)[0]
            # Strip language tags if present (e.g. ```json)
            if text.startswith("json\n"):
                text = text.split("\n", 1)[1]
            elif text.startswith("json "):
                text = text.split(" ", 1)[1]
                
            result = json.loads(text.strip())
            return {
                "analysis": result.get("analysis", "Security scan incomplete."),
                "recommendation": result.get("recommendation", "N/A")
            }
        except Exception as e:
            logger.error("AI Analysis failed: %s", e)
            mock_data = MOCK_ANALYSES.get(module, MOCK_ANALYSES["process"])
            return {
                "analysis": f"[Fallback Analysis due to error: {e}] " + mock_data["analysis"],
                "recommendation": mock_data["recommendation"].replace("{pid}", str(pid)).replace("{ip}", dest_ip)
            }
