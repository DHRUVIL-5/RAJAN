"""
RAJAN LLM Connector v2
Full provider flexibility — users can use literally any AI provider.

TWO SYSTEM PROMPTS:
  1. RAJAN_CORE_PROMPT  — compulsory, always injected, defines RAJAN identity
  2. USER_SYSTEM_PROMPT — user-customizable, appended after core (optional)

PROVIDERS:
  1. Groq (free, recommended)
  2. OpenRouter (free models available)
  3. OpenAI
  4. Anthropic Claude
  5. HuggingFace
  6. Ollama (local/offline)
  7. Puter.js (free, no API key — GPT-4o, Claude, Gemini, DeepSeek, 500+ models)
  8. Google Gemini (free tier)
  9. Mistral AI (free tier)
  10. Together AI (free $25 credit)
  11. LM Studio (local, OpenAI-compatible)
  12. Custom — any URL, model, headers (covers everything else)
"""

import json
import os
import urllib.request
import urllib.error
import urllib.parse
import time


# ── Compulsory Core System Prompt ────────────────────────────────────────────
# This is ALWAYS injected first. Users cannot override this.
RAJAN_CORE_PROMPT = """You are RAJAN v1.1.0 — an elite AI ethical hacking agent running in a CLI terminal.

IDENTITY:
- You are RAJAN, not any other AI assistant
- You are the user's intelligent cybersecurity partner
- You think and act like an experienced penetration tester
- You are friendly, cool, and professional 😎

CONTEXT:
- You are running inside a terminal (CLI) on the user's device (Termux/Kali/Linux)
- The user is a security researcher or ethical hacker
- You have access to specialized tools: recon, scanning, web testing, CVE lookup, etc.
- You operate within defined scope and only on authorized targets

BEHAVIOR:
- Answer security questions clearly and technically
- When working autonomously, use ReACT: Reason → Act → Observe → Learn
- Map findings to MITRE ATT&CK techniques
- Provide CVSS scores and confidence levels on findings
- Never help with unauthorized hacking — always ask about authorization
- Be concise in CLI context — no markdown formatting in responses, plain text only

EXPERTISE:
- Web application security (XSS, SQLi, IDOR, SSRF, LFI, SSTI, CSRF)
- Network penetration testing (port scanning, service detection)
- OSINT and reconnaissance
- Bug bounty methodology (HackerOne, Bugcrowd, Intigriti)
- CVE research and vulnerability assessment
- Cloud security (AWS, GCP, Azure misconfigurations)
- MITRE ATT&CK framework"""

# ── Default user-customizable addon prompt ────────────────────────────────────
DEFAULT_USER_ADDON = ""  # empty by default — user fills this in


class LLMConnector:
    PROVIDERS = {
        "1": {
            "name": "Groq (Free & Fast — Recommended)",
            "base_url": "https://api.groq.com/openai/v1/chat/completions",
            "models": ["llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b",
                       "mixtral-8x7b-32768", "gemma2-9b-it"],
            "default_model": "llama-3.3-70b-versatile",
            "key_url": "https://console.groq.com",
            "key_required": True,
            "format": "openai",
        },
        "2": {
            "name": "OpenRouter (Free models available)",
            "base_url": "https://openrouter.ai/api/v1/chat/completions",
            "models": ["mistralai/mistral-7b-instruct:free",
                       "google/gemma-3-27b-it:free",
                       "deepseek/deepseek-r1:free",
                       "meta-llama/llama-3.1-8b-instruct:free"],
            "default_model": "mistralai/mistral-7b-instruct:free",
            "key_url": "https://openrouter.ai/keys",
            "key_required": True,
            "format": "openai",
        },
        "3": {
            "name": "OpenAI (GPT-4o / GPT-4o-mini)",
            "base_url": "https://api.openai.com/v1/chat/completions",
            "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
            "default_model": "gpt-4o-mini",
            "key_url": "https://platform.openai.com/api-keys",
            "key_required": True,
            "format": "openai",
        },
        "4": {
            "name": "Anthropic Claude",
            "base_url": "https://api.anthropic.com/v1/messages",
            "models": ["claude-3-haiku-20240307", "claude-3-5-sonnet-20241022",
                       "claude-3-5-haiku-20241022"],
            "default_model": "claude-3-haiku-20240307",
            "key_url": "https://console.anthropic.com",
            "key_required": True,
            "format": "anthropic",
        },
        "5": {
            "name": "HuggingFace Inference API (Free tier)",
            "base_url": "https://api-inference.huggingface.co/models",
            "models": ["mistralai/Mistral-7B-Instruct-v0.3",
                       "microsoft/Phi-3-mini-4k-instruct"],
            "default_model": "mistralai/Mistral-7B-Instruct-v0.3",
            "key_url": "https://huggingface.co/settings/tokens",
            "key_required": True,
            "format": "huggingface",
        },
        "6": {
            "name": "Ollama (Local/Offline — No internet needed)",
            "base_url": "http://localhost:11434/api/chat",
            "models": ["llama3", "mistral", "phi3", "gemma2", "tinyllama",
                       "deepseek-coder", "codellama"],
            "default_model": "mistral",
            "key_url": "No key needed — runs locally. Install: ollama.ai",
            "key_required": False,
            "format": "ollama",
        },
        "7": {
            "name": "Puter.js (Free — No API key — 500+ models)",
            "base_url": "https://api.puter.com/drivers/call",
            "models": ["gpt-4o-mini", "gpt-4o", "claude-3-5-sonnet",
                       "gemini-1.5-flash", "deepseek-chat", "llama-3.1-70b"],
            "default_model": "gpt-4o-mini",
            "key_url": "No key needed — uses Puter.com free account",
            "key_required": False,
            "format": "puter",
        },
        "8": {
            "name": "Google Gemini (Free tier)",
            "base_url": "https://generativelanguage.googleapis.com/v1beta/models",
            "models": ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash-exp"],
            "default_model": "gemini-1.5-flash",
            "key_url": "https://aistudio.google.com/app/apikey",
            "key_required": True,
            "format": "gemini",
        },
        "9": {
            "name": "Mistral AI (Free tier available)",
            "base_url": "https://api.mistral.ai/v1/chat/completions",
            "models": ["mistral-small-latest", "mistral-medium-latest",
                       "open-mistral-7b", "open-mixtral-8x7b"],
            "default_model": "open-mistral-7b",
            "key_url": "https://console.mistral.ai/api-keys",
            "key_required": True,
            "format": "openai",
        },
        "10": {
            "name": "Together AI (Free $25 credit)",
            "base_url": "https://api.together.xyz/v1/chat/completions",
            "models": ["meta-llama/Llama-3-70b-chat-hf",
                       "mistralai/Mixtral-8x7B-Instruct-v0.1",
                       "deepseek-ai/deepseek-coder-33b-instruct"],
            "default_model": "meta-llama/Llama-3-70b-chat-hf",
            "key_url": "https://api.together.ai/settings/api-keys",
            "key_required": True,
            "format": "openai",
        },
        "11": {
            "name": "LM Studio (Local — OpenAI-compatible)",
            "base_url": "http://localhost:1234/v1/chat/completions",
            "models": ["local-model"],
            "default_model": "local-model",
            "key_url": "No key needed — LM Studio running locally",
            "key_required": False,
            "format": "openai",
        },
        "12": {
            "name": "Custom Provider (Any OpenAI-compatible API)",
            "base_url": "",
            "models": [],
            "default_model": "",
            "key_url": "Enter your custom endpoint URL",
            "key_required": True,
            "format": "openai",
        },
    }

    def __init__(self, config_path="memory/llm_config.json"):
        self.config_path = config_path
        self.config = self._load_config()
        self._puter_token = None  # cached Puter.js temp token

    def _load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_config(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)

    def is_configured(self):
        return bool(self.config.get("provider"))

    def get_system_prompt(self):
        """
        Returns the full combined system prompt:
        RAJAN core (compulsory) + user addon (optional)
        """
        core = RAJAN_CORE_PROMPT
        user_addon = self.config.get("user_system_prompt", "").strip()
        if user_addon:
            return f"{core}\n\nUSER PREFERENCES:\n{user_addon}"
        return core

    def setup_interactive(self):
        print("\n╔══════════════════════════════════════════════════════╗")
        print("║         RAJAN — AI Provider Setup                   ║")
        print("╠══════════════════════════════════════════════════════╣")
        print("║  Choose your AI provider:                           ║")
        print("╚══════════════════════════════════════════════════════╝\n")

        for key, p in self.PROVIDERS.items():
            free_tag = " 🆓" if not p["key_required"] else ""
            print(f"  [{key:>2}] {p['name']}{free_tag}")

        print()
        choice = input("  Enter choice (1-12): ").strip()
        if choice not in self.PROVIDERS:
            print("  Invalid — defaulting to Groq.")
            choice = "1"

        provider = self.PROVIDERS[choice]
        print(f"\n  ✅ Selected: {provider['name']}")

        # Handle key requirement
        if provider["key_required"]:
            print(f"  📌 Get your key: {provider['key_url']}")
            api_key = input("  Enter API key: ").strip()
            if not api_key:
                print("  ❌ No key entered. Cancelled.")
                return False
        else:
            api_key = "no-key-required"
            print(f"  ℹ️  {provider['key_url']}")

        # Custom provider — ask for URL and model
        if choice == "12":
            base_url = input("  Enter API base URL (e.g. https://api.example.com/v1/chat/completions): ").strip()
            model = input("  Enter model name: ").strip()
            fmt = input("  Format (openai/anthropic/ollama) [openai]: ").strip() or "openai"
            if not base_url or not model:
                print("  ❌ URL and model required.")
                return False
            provider = {**provider, "base_url": base_url, "default_model": model, "format": fmt}

        # Model selection
        if provider.get("models"):
            print(f"\n  Available models:")
            for i, m in enumerate(provider["models"], 1):
                print(f"    [{i}] {m}")
            mc = input(f"  Choose (1-{len(provider['models'])}) or Enter for default: ").strip()
            try:
                model = provider["models"][int(mc) - 1]
            except Exception:
                model = provider["default_model"]
        else:
            model = provider.get("default_model", "")

        # User system prompt addon
        print(f"\n  ── Optional: Customize RAJAN's personality ──")
        print(f"  RAJAN has a built-in identity (compulsory).")
        print(f"  You can add extra instructions on top (optional).")
        print(f"  Examples: 'Always respond in Spanish' / 'Focus on bug bounty' / 'Be very brief'")
        print(f"  Press Enter to skip.")
        user_addon = input("  Your extra instructions: ").strip()

        self.config = {
            "provider": choice,
            "provider_name": provider["name"],
            "api_key": api_key,
            "model": model,
            "base_url": provider["base_url"],
            "format": provider.get("format", "openai"),
            "user_system_prompt": user_addon,
        }
        self._save_config()
        print(f"\n  ✅ Saved! RAJAN will use {provider['name']} / {model}")
        if user_addon:
            print(f"  ✅ Custom persona: \"{user_addon[:60]}\"")
        return True

    def update_system_prompt(self):
        """Let user update just the custom system prompt addon"""
        print(f"\n  Current custom prompt: \"{self.config.get('user_system_prompt', '(none)')}\"")
        print(f"  Enter new prompt (or Enter to clear):")
        new_prompt = input("  > ").strip()
        self.config["user_system_prompt"] = new_prompt
        self._save_config()
        print(f"  ✅ Updated!")

    def chat(self, messages, system=None, retries=3):
        """Send messages with retry + exponential backoff"""
        if not self.is_configured():
            return "❌ LLM not configured. Run: python3 rajan.py --setup"

        fmt = self.config.get("format", "openai")
        system_prompt = system or self.get_system_prompt()

        last_error = ""
        for attempt in range(retries):
            try:
                if fmt == "anthropic":
                    return self._call_anthropic(messages, system_prompt)
                elif fmt == "huggingface":
                    return self._call_huggingface(messages)
                elif fmt == "ollama":
                    return self._call_ollama(messages, system_prompt)
                elif fmt == "puter":
                    return self._call_puter(messages, system_prompt)
                elif fmt == "gemini":
                    return self._call_gemini(messages, system_prompt)
                else:
                    return self._call_openai(messages, system_prompt)
            except urllib.error.URLError as e:
                last_error = f"Network: {e.reason}"
            except Exception as e:
                last_error = str(e)

            if attempt < retries - 1:
                time.sleep(2 ** attempt)

        return f"❌ LLM failed after {retries} attempts: {last_error}"

    def quick_ask(self, question, retries=3):
        return self.chat([{"role": "user", "content": question}], retries=retries)

    # ── Provider Implementations ──────────────────────────────────────────────

    def _call_openai(self, messages, system_prompt):
        """OpenAI-compatible: Groq, OpenRouter, OpenAI, Mistral, Together, LM Studio, Custom"""
        payload = {
            "model": self.config["model"],
            "messages": [{"role": "system", "content": system_prompt}] + messages,
            "temperature": 0.7,
            "max_tokens": 2048,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config['api_key']}",
        }
        # OpenRouter requires extra headers
        if "openrouter" in self.config.get("base_url", ""):
            headers["HTTP-Referer"] = "https://github.com/DHRUVIL-5/RAJAN"
            headers["X-Title"] = "RAJAN"

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.config["base_url"], data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            result = json.loads(r.read().decode())
            return result["choices"][0]["message"]["content"]

    def _call_anthropic(self, messages, system_prompt):
        payload = {
            "model": self.config["model"],
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": messages,
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config["api_key"],
            "anthropic-version": "2023-06-01",
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.config["base_url"], data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            result = json.loads(r.read().decode())
            return result["content"][0]["text"]

    def _call_huggingface(self, messages):
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
        payload = {"inputs": prompt, "parameters": {"max_new_tokens": 512}}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config['api_key']}",
        }
        url = f"{self.config['base_url']}/{self.config['model']}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            result = json.loads(r.read().decode())
            if isinstance(result, list):
                return result[0].get("generated_text", "No response")
            return str(result)

    def _call_ollama(self, messages, system_prompt):
        payload = {
            "model": self.config["model"],
            "messages": [{"role": "system", "content": system_prompt}] + messages,
            "stream": False,
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.config["base_url"], data=data,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=120) as r:
            result = json.loads(r.read().decode())
            return result["message"]["content"]

    def _call_puter(self, messages, system_prompt):
        """
        Puter.js — free, no API key required.
        Gets a temporary anonymous token, then calls the AI driver.
        Supports 500+ models: GPT-4o, Claude, Gemini, DeepSeek, Llama, etc.
        """
        token = self._get_puter_token()
        if not token:
            return "❌ Could not get Puter.js token. Check internet connection."

        all_messages = [{"role": "system", "content": system_prompt}] + messages
        payload = {
            "interface": "puter-chat-completion",
            "driver": "openai-completion",
            "test_mode": False,
            "method": "complete",
            "args": {
                "messages": all_messages,
                "model": self.config["model"],
                "stream": False,
            }
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.config["base_url"], data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            result = json.loads(r.read().decode())
            # Puter returns OpenAI-style response
            if "result" in result:
                choices = result["result"].get("choices", [])
                if choices:
                    return choices[0]["message"]["content"]
            # Fallback
            return str(result)

    def _get_puter_token(self):
        """Get or refresh a Puter.js anonymous auth token"""
        if self._puter_token:
            return self._puter_token
        # Check config for saved token
        saved = self.config.get("puter_token")
        if saved:
            self._puter_token = saved
            return self._puter_token
        # Get new anonymous token
        try:
            payload = json.dumps({
                "username": f"rajan_user_{int(time.time())}",
                "password": "rajan_pass_" + str(int(time.time())),
            }).encode()
            req = urllib.request.Request(
                "https://api.puter.com/auth/signup",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                result = json.loads(r.read().decode())
                token = result.get("token") or result.get("auth", {}).get("token")
                if token:
                    self._puter_token = token
                    self.config["puter_token"] = token
                    self._save_config()
                    return token
        except Exception:
            pass
        return None

    def _call_gemini(self, messages, system_prompt):
        """Google Gemini API"""
        # Convert messages to Gemini format
        parts = [{"text": f"[SYSTEM]: {system_prompt}\n\n"}]
        for m in messages:
            role = "user" if m["role"] == "user" else "model"
            parts.append({"text": m["content"]})

        payload = {
            "contents": [{"parts": parts}],
            "generationConfig": {"temperature": 0.7, "maxOutputTokens": 2048}
        }
        url = (f"{self.config['base_url']}/{self.config['model']}"
               f":generateContent?key={self.config['api_key']}")
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as r:
            result = json.loads(r.read().decode())
            return result["candidates"][0]["content"]["parts"][0]["text"]
