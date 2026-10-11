"""Download official client and provider logos."""
import urllib.request
import urllib.error
import ssl
from pathlib import Path

# Unverified context for resilient CDN downloads
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

OUT_DIR = Path("c:/Users/frank/OneDrive/Desktop/Veil/app/ui/assets/logos")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TARGETS = {
    # Clients
    "continue": [
        "https://raw.githubusercontent.com/continuedev/continue/main/extensions/vscode/media/icon.png",
        "https://continue.dev/img/logo.png"
    ],
    "aider": [
        "https://aider.chat/assets/icons/android-chrome-384x384.png",
        "https://aider.chat/assets/aider-square.jpg"
    ],
    "claude_code": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/b/b0/Claude_AI_logo.svg/512px-Claude_AI_logo.svg.png",
        "https://raw.githubusercontent.com/anthropics/claude-code/main/media/icon.png"
    ],
    "cursor": [
        "https://raw.githubusercontent.com/getcursor/cursor/main/assets/icon.png",
        "https://www.cursor.com/favicon.ico",
        "https://cdn.brandfetch.io/ideKwS9dxx/theme/dark/symbol.png"
    ],
    "antigravity": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/c/c1/Google_%22G%22_logo.svg/512px-Google_%22G%22_logo.svg.png"
    ],
    # Providers
    "openai": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/0/04/ChatGPT_logo.svg/512px-ChatGPT_logo.svg.png",
        "https://upload.wikimedia.org/wikipedia/commons/thumb/4/4d/OpenAI_Logo.svg/512px-OpenAI_Logo.svg.png"
    ],
    "anthropic": [
        "https://upload.wikimedia.org/wikipedia/commons/thumb/7/78/Anthropic_logo.svg/512px-Anthropic_logo.svg.png"
    ],
    "ollama": [
        "https://raw.githubusercontent.com/ollama/ollama/main/docs/ollama-logo.svg",
        "https://ollama.com/public/ollama.png"
    ]
}

def download_one(name, urls):
    for url in urls:
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, context=ctx, timeout=8.0) as resp:
                data = resp.read()
                ext = ".png" if not url.endswith((".svg", ".jpg", ".ico")) else Path(url).suffix
                target = OUT_DIR / f"{name}{ext}"
                target.write_bytes(data)
                print(f"[OK] {name} downloaded from {url} ({len(data)} bytes) -> {target.name}")
                return True
        except Exception as e:
            print(f"[FAIL] {name} from {url}: {e}")
    return False

if __name__ == "__main__":
    results = {}
    for name, urls in TARGETS.items():
        results[name] = download_one(name, urls)
    print("\nSummary:", results)
