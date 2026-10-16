# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

src_path = Path('src').resolve()

# Collect all netcutter submodules
netcutter_submodules = collect_submodules('netcutter')

# Hidden imports required by dynamic imports and backends
hiddenimports = [
    'PySide6',
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    'PySide6.QtSvg',
    'PySide6.QtSvgWidgets',
    'paramiko',
    'requests',
    'cryptography',
    'scapy',
    'scapy.layers.l2',
    'scapy.layers.inet',
    'scapy.arch.windows',
    'sqlite3',
] + netcutter_submodules

# Data files (assets, icons, QSS stylesheets)
datas = [
    ('assets', 'assets'),
    ('src/netcutter/common', 'netcutter/common'),
]

a = Analysis(
    ['main.py'],
    pathex=[str(src_path), '.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy', 'numpy.testing'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

icon_file = 'assets/icon.ico' if Path('assets/icon.ico').exists() else None

exe_gui = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='HomeNetController',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # Windowed GUI application: No unwanted black terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
)

exe_cli = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='hnc-cli',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,   # Scriptable headless console application for terminal automation
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_file,
)

coll = COLLECT(
    exe_gui,
    exe_cli,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='HomeNetController',
)
