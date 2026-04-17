"""
개인정보 오남용·과다조회 점검 시스템 - EXE 런처
PyInstaller로 빌드된 단일 실행파일의 진입점
"""
import sys
import os
import threading
import webbrowser
import time
from pathlib import Path

# PyInstaller 번들 실행 시 기준 경로 설정
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys._MEIPASS)
    # 실행파일 옆에 데이터 디렉토리 생성
    WORK_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).parent
    WORK_DIR = BASE_DIR

os.chdir(str(WORK_DIR))
sys.path.insert(0, str(BASE_DIR))

PORT = 5000

def _open_browser():
    time.sleep(1.5)
    webbrowser.open(f'http://localhost:{PORT}')

def main():
    print("=" * 55)
    print("  개인정보 오남용·과다조회 점검 시스템")
    print("=" * 55)
    print(f"  URL  : http://localhost:{PORT}")
    print(f"  종료 : 이 창을 닫거나 Ctrl+C")
    print("=" * 55)

    threading.Thread(target=_open_browser, daemon=True).start()

    from web_app import app, UPLOAD_DIR, REPORTS_DIR, HISTORY_DIR
    UPLOAD_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    HISTORY_DIR.mkdir(exist_ok=True)

    app.run(host='0.0.0.0', port=PORT, debug=False,
            use_reloader=False, threaded=True)

if __name__ == '__main__':
    main()
