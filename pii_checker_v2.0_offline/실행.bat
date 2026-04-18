@echo off
chcp 65001 > nul
echo ================================================
echo   개인정보 오남용·과다조회 점검 시스템 v2.0
echo ================================================
echo.
echo  pii_checker.exe 실행 중...
echo  잠시 후 브라우저가 자동으로 열립니다.
echo  http://localhost:5000
echo.
echo  종료하려면 이 창을 닫으세요.
echo ================================================
echo.
start "" "%~dp0pii_checker\pii_checker.exe"
