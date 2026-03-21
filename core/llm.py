"""
RAJAN LLM Connector
Supports: Groq, OpenAI, Claude, OpenRouter, HuggingFace, Ollama
User can use ANY provider — fully flexible
"""

import json
import os
import urllib.request
import urllib.error


class LLMConnector:
    PROVIDERS = {
        "1": {
            "name": "Groq (Recommended - Free & Fast)",
            "base_url": "https://api.groq.com/openai/v1/chat/completions",
            "models": ["llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b", "mixtral-8x7b-32768"],
            "default_model": "llama-3.3-70b-versatile",
            "key_url": "https://console.groq.com",
        },
        "2": {
            "name": "OpenRouter (Free models available)",
            "base_url": "https://openrouter.ai/api/v1/chat/completions",
            "models": ["mistralai/mistral-7b-instruct:free", "google/gemma-3-27b-it:free"],
            "default_model": "mistralai/mistral-7b-instruct:free",
            "key_url": "https://openrouter.ai",
        },
        "3": {
            "name": "OpenAI (GPT-4)",
            "base_url": "https://api.openai.com/v1/chat/completions",
            "models": ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"],
            "default_model": "gpt-4o-mini",
            "key_url": "https://platform.openai.com",
        },
        "4": {
            "name": "Anthropic Claude",
            "base_url": "https://api.anthropic.com/v1/messages",
            "models": ["claude-3-haiku-20240307", "claude-3-5-sonnet-20241022"],
            "default_model": "claude-3-haiku-20240307",
            "key_url": "https://console.anthropic.com",
        },
        "5": {
            "name": "HuggingFace Inference API",
            "base_url": "https://api-inference.huggingface.co/models",
            "models": ["mistralai/Mistral-7B-Instruct-v0.3"],
            "default_model": "mistralai/Mistral-7B-Instruct-v0.3",
            "key_url": "https://huggingface.co/settings/tokens",
        },
        "6": {
            "name": "Ollama (Local/Offline)",
            "base_url": "http://localhost:11434/api/chat",
            "models": ["llama3", "mistral", "phi3", "tinyllama"],
            "default_model": "mistral",
            "key_url": "No key needed - runs locally",
        },
    }

    SYSTEM_PROMPT = """You are RAJAN, an elite AI ethical hacking agent. You are:
- Friendly, cool, and professional 😎
- Expert in cybersecurity, penetration testing, OSINT, bug bounty
- You ONLY work on authorized targets
- You explain findings clearly and suggest next steps
- You follow MITRE ATT&CK framework
- You never help with illegal or unauthorized hacking
- When working autonomously, you think step by step (ReACT: Reason, Act, Observe)
- You are always honest about what you found and what you couldn't test

Always respond in a clear, structured way with findings marked by severity."""

    def __init__(self, config_path="memory/llm_config.json"):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_config(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)

    def is_configured(self):
        return bool(self.config.get("provider") and self.config.get("api_key"))

    def setup_interactive(self):
        """First-time setup — user picks their LLM provider"""
        print("\n╔══════════════════════════════════════════════════╗")
        print("║         RAJAN — LLM Setup (First Time)          ║")
        print("╠══════════════════════════════════════════════════╣")
        print("║  Choose your AI brain for RAJAN:                ║")
        print("╚══════════════════════════════════════════════════╝\n")

        for key, p in self.PROVIDERS.items():
            print(f"  [{key}] {p['name']}")

        print()
        choice = input("  Enter choice (1-6): ").strip()

        if choice not in self.PROVIDERS:
            print("  Invalid choice, defaulting to Groq.")
            choice = "1"

        provider = self.PROVIDERS[choice]
        print(f"\n  ✅ Selected: {provider['name']}")

        if choice == "6":
            api_key = "ollama"
            print("  ℹ️  Make sure Ollama is running: ollama serve")
        else:
            print(f"  📌 Get your API key at: {provider['key_url']}")
            api_key = input("  Enter your API key: ").strip()
            if not api_key:
                print("  ❌ No key entered. Setup cancelled.")
                return False

        # Pick model
        print(f"\n  Available models for {provider['name']}:")
        for i, m in enumerate(provider["models"], 1):
            print(f"    [{i}] {m}")
        model_choice = input(f"  Choose model (1-{len(provider['models'])}) or Enter for default: ").strip()

        try:
            model = provider["models"][int(model_choice) - 1]
        except Exception:
            model = provider["default_model"]

        self.config = {
            "provider": choice,
            "provider_name": provider["name"],
            "api_key": api_key,
            "model": model,
            "base_url": provider["base_url"],
        }
        self._save_config()
        print(f"\n  ✅ Saved! RAJAN will use {provider['name']} with {model}")
        return True

    def chat(self, messages, system=None):
        """Send messages to LLM and get response"""
        if not self.is_configured():
            return "❌ LLM not configured. Run RAJAN setup first."

        provider_id = self.config.get("provider", "1")
        system_prompt = system or self.SYSTEM_PROMPT

        try:
            if provider_id == "4":
                return self._call_claude(messages, system_prompt)
            elif provider_id == "5":
                return self._call_huggingface(messages)
            elif provider_id == "6":
                return self._call_ollama(messages, system_prompt)
            else:
                return self._call_openai_compatible(messages, system_prompt)
        except urllib.error.URLError as e:
            return f"❌ Network error: {e.reason}. Check your connection."
        except Exception as e:
            return f"❌ LLM Error: {str(e)}"

    def _call_openai_compatible(self, messages, system_prompt):
        """Works for Groq, OpenAI, OpenRouter"""
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
        # OpenRouter needs extra headers
        if self.config.get("provider") == "2":
            headers["HTTP-Referer"] = "https://github.com/DHRUVIL-5/RAJAN"
            headers["X-Title"] = "RAJAN"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.config["base_url"], data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"]

    def _call_claude(self, messages, system_prompt):
        """Anthropic Claude API"""
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
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.config["base_url"], data=data, headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["content"][0]["text"]

    def _call_huggingface(self, messages):
        """HuggingFace Inference API"""
        prompt = "\n".join([f"{m['role']}: {m['content']}" for m in messages])
        payload = {"inputs": prompt, "parameters": {"max_new_tokens": 512}}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config['api_key']}",
        }
        url = f"{self.config['base_url']}/{self.config['model']}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            if isinstance(result, list):
                return result[0].get("generated_text", "No response")
            return str(result)

    def _call_ollama(self, messages, system_prompt):
        """Local Ollama"""
        payload = {
            "model": self.config["model"],
            "messages": [{"role": "system", "content": system_prompt}] + messages,
            "stream": False,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.config["base_url"],
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["message"]["content"]

    def quick_ask(self, question):
        """Single question shortcut"""
        return self.chat([{"role": "user", "content": question}])
