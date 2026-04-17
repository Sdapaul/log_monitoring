# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

block_cipher = None

# Flask 관련 데이터 파일 수집
flask_datas, flask_binaries, flask_hiddenimports = collect_all('flask')
werkzeug_datas, werkzeug_binaries, werkzeug_hiddenimports = collect_all('werkzeug')

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=flask_binaries + werkzeug_binaries,
    datas=[
        # 로컬 정적 파일 (폐쇄망 대응)
        ('static', 'static'),
        # 각 모듈 디렉토리
        ('parsers', 'parsers'),
        ('detectors', 'detectors'),
        ('models', 'models'),
        ('pipeline', 'pipeline'),
        ('reports', 'reports'),
        ('history', 'history'),
        ('utils', 'utils'),
        ('config.py', '.'),
        ('web_app.py', '.'),
    ] + flask_datas + werkzeug_datas,
    hiddenimports=[
        'flask', 'werkzeug', 'werkzeug.serving', 'werkzeug.debug',
        'jinja2', 'click', 'itsdangerous',
        'openpyxl', 'openpyxl.styles', 'openpyxl.utils',
        'parsers.auto_detector', 'parsers.db_access_parser',
        'parsers.web_access_parser', 'parsers.app_log_parser',
        'parsers.generic_parser',
        'detectors.pii_detector', 'detectors.access_counter',
        'detectors.anomaly_scorer', 'detectors.sql_clause_analyzer',
        'models.log_event', 'models.finding', 'models.user_summary',
        'pipeline.runner', 'pipeline.stream_reader', 'pipeline.aggregator',
        'reports.excel_reporter', 'reports.html_reporter',
        'reports.justification_builder',
        'history.manager',
        'utils.date_utils',
    ] + flask_hiddenimports + werkzeug_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'PIL'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='pii_checker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,          # 콘솔창 표시 (로그 확인용)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='pii_checker',
)
