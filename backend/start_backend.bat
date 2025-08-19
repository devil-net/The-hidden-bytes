@echo off
cd /d %~dp0

echo Upgrading pip...
python -m pip install --upgrade pip

echo Installing build tools...
pip install wheel setuptools

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate

echo Installing requirements...
pip install --upgrade pip wheel setuptools
pip install -r requirements.txt

if errorlevel 1 (
    echo Error installing requirements. Please check the error message above.
    pause
    exit /b 1
)

echo Starting server...
uvicorn main:app --reload

pause 