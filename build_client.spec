# build_client.spec — PyInstaller spec (#14 Package client exe)
# Usage: pyinstaller build_client.spec

block_cipher = None

a = Analysis(
    ['client.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('client_config.yaml', '.'),
        ('ca.crt', '.'),
        ('messages_pb2.py', '.'),
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
    name='tls_client',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    onefile=True,
)
