# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['Zoffline_CN_Tool.py'],
    pathex=[],
    binaries=[],
    datas=[('*.pem', '.'), ('*.p12', '.'), ('caddy.exe', '.'), ('Caddyfile', '.'), ('SEU.ico', '.'), ('NUCU.ico', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Zoffline-CN-Tool',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['logo.ico'],
)
