# -*- mode: python ; coding: utf-8 -*-

# main.spec
from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ['src/main.py'],
    pathex=['src'],  
    binaries=[],
    datas=[
        ('src/cli.py', 'cli.py'),
        ('src/config.py', 'config.py'),
        ('src/utils.py', 'utils.py')
    ],
    hiddenimports=['src.cli', 'src.config', 'src.utils'],
    hookspath=[],
    hooks=collect_submodules('src'),  
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='main',
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
)
