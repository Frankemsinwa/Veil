# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification file for Veil AI Privacy Gateway."""
import sys
from pathlib import Path

block_cipher = None
root_dir = Path.cwd()

datas = [
    (str(root_dir / 'app' / 'ui'), 'app/ui'),
    (str(root_dir / 'packager' / 'veil.ico'), 'packager'),
]

models_dir = root_dir / 'data' / 'models' / 'semantic'
if models_dir.exists():
    datas.append((str(models_dir), 'data/models/semantic'))

hidden_imports = [
    # Full Veil application tree
    'app',
    'app.main',
    'app.cli',
    'app.entrypoint',
    'app.mcp_server',
    'app.core',
    'app.core.config',
    'app.core.benchmark',
    'app.core.doctor',
    'app.core.circuit_breaker',
    'app.core.events',
    'app.core.exceptions',
    'app.core.log_scrubber',
    'app.clients',
    'app.clients.base',
    'app.clients.models',
    'app.clients.manager',
    'app.clients.cursor',
    'app.clients.continue_ext',
    'app.clients.claude_code',
    'app.clients.aider',
    'app.clients.system_env',
    'app.clients.antigravity',
    'app.clients.opencode',
    'app.engine',
    'app.engine.pipeline',
    'app.engine.regex_scanner',
    'app.engine.entropy_scanner',
    'app.engine.semantic_classifier',
    'app.engine.semantic_models',
    'app.engine.ast_filter',
    'app.engine.policy_engine',
    'app.engine.redactor',
    'app.engine.vector_encoder',
    'app.engine.knowledge_vault',
    'app.engine.models',
    'app.engine.custom_dictionary',
    'app.vault',
    'app.vault.crypto',
    'app.vault.session_vault',
    'app.restoration',
    'app.restoration.restorer',
    'app.audit',
    'app.audit.ledger',
    'app.gui',
    'app.gui.runner',
    'app.gui.window',
    'app.gui.tray',
    'app.gui.autostart',
    'app.providers',
    'app.providers.openai_adapter',
    'app.providers.anthropic_adapter',
    'app.providers.ollama_adapter',
    'app.proxy',
    'app.proxy.ca',
    'app.proxy.interceptor',
    'app.proxy.wininet',
    'app.licensing',
    'app.licensing.models',
    'app.licensing.manager',
    'app.licensing.enforcer',
    'app.billing',
    'app.billing.paystack',
    'app.billing.routes',

    # Neural & Vector ML Dependencies
    'onnxruntime',
    'tokenizers',
    'numpy',

    # Uvicorn ASGI & WebSockets
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.protocols.websockets.websockets_impl',
    'websockets',
    'websockets.legacy',
    'websockets.legacy.server',
    'websockets.legacy.client',

    # Native Window & GUI
    'webview',
    'webview.platforms.winforms',
    'webview.platforms.edgechromium',
    'pystray',
    'pystray._win32',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    'clr',
    'pythonnet',

    # Security & Cryptography
    'cryptography',
    'cryptography.x509',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.primitives.serialization',
    'cryptography.hazmat.primitives.asymmetric.rsa',
    'cryptography.hazmat.primitives.ciphers.aead',
    'argon2',
    'argon2.low_level',

    # Framework & Dependencies
    'fastapi',
    'starlette',
    'pydantic',
    'pydantic_settings',
    'typer',
    'rich',
    'httpx',
]

a = Analysis(
    [str(root_dir / 'app' / 'entrypoint.py')],
    pathex=[str(root_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Veil',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(root_dir / 'packager' / 'veil.ico'),
)
