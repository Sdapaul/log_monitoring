# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

# 라이브러리별 데이터/바이너리/hiddenimports 수집
flask_datas,      flask_binaries,      flask_hiddenimports      = collect_all('flask')
werkzeug_datas,   werkzeug_binaries,   werkzeug_hiddenimports   = collect_all('werkzeug')
docx_datas,       docx_binaries,       docx_hiddenimports       = collect_all('docx')
pdfplumber_datas, pdfplumber_binaries, pdfplumber_hiddenimports = collect_all('pdfplumber')
pdfminer_datas,   pdfminer_binaries,   pdfminer_hiddenimports   = collect_all('pdfminer')
pypdfium2_datas,  pypdfium2_binaries,  pypdfium2_hiddenimports  = collect_all('pypdfium2')
pillow_datas,     pillow_binaries,     pillow_hiddenimports     = collect_all('PIL')
openpyxl_datas,   openpyxl_binaries,   openpyxl_hiddenimports   = collect_all('openpyxl')

all_datas = (
    flask_datas + werkzeug_datas +
    docx_datas + pdfplumber_datas + pdfminer_datas +
    pypdfium2_datas + pillow_datas + openpyxl_datas
)
all_binaries = (
    flask_binaries + werkzeug_binaries +
    docx_binaries + pdfplumber_binaries + pdfminer_binaries +
    pypdfium2_binaries + pillow_binaries + openpyxl_binaries
)
all_hiddenimports = (
    flask_hiddenimports + werkzeug_hiddenimports +
    docx_hiddenimports + pdfplumber_hiddenimports + pdfminer_hiddenimports +
    pypdfium2_hiddenimports + pillow_hiddenimports + openpyxl_hiddenimports
)

a = Analysis(
    ['launcher.py'],
    pathex=['.'],
    binaries=all_binaries,
    datas=[
        ('static',    'static'),
        ('parsers',   'parsers'),
        ('detectors', 'detectors'),
        ('models',    'models'),
        ('pipeline',  'pipeline'),
        ('reports',   'reports'),
        ('history',   'history'),
        ('utils',     'utils'),
        ('config.py', '.'),
        ('web_app.py', '.'),
    ] + all_datas,
    hiddenimports=[
        # Flask 스택
        'flask', 'werkzeug', 'werkzeug.serving', 'werkzeug.debug',
        'jinja2', 'click', 'itsdangerous',
        # 문서 처리
        'docx', 'docx.document', 'docx.oxml',
        'pdfplumber', 'pdfminer', 'pdfminer.six',
        'pdfminer.high_level', 'pdfminer.layout',
        'pdfminer.pdfpage', 'pdfminer.pdfinterp',
        'pdfminer.converter', 'pdfminer.pdfdocument',
        'pypdfium2',
        'PIL', 'PIL.Image',
        'openpyxl', 'openpyxl.styles', 'openpyxl.utils',
        'openpyxl.reader.excel',
        # 압축
        'zipfile', 'tarfile',
        # 프로젝트 모듈
        'parsers.auto_detector', 'parsers.db_access_parser',
        'parsers.web_access_parser', 'parsers.app_log_parser',
        'parsers.generic_parser',
        'detectors.pii_detector', 'detectors.access_counter',
        'detectors.anomaly_scorer', 'detectors.sql_clause_analyzer',
        'models.log_event', 'models.finding', 'models.user_summary',
        'pipeline.runner', 'pipeline.stream_reader', 'pipeline.aggregator',
        'pipeline.doc_extractor',
        'reports.excel_reporter', 'reports.html_reporter',
        'reports.justification_builder',
        'history.manager',
        'utils.date_utils',
    ] + all_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas', 'IPython', 'PyQt5'],
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
    console=True,
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
