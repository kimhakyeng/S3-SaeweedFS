#!/usr/bin/env bash
# ============================================================================
#  file-agent  Linux 단일 바이너리 빌드 (PyInstaller)
#  결과:  dist/file-agent  (+ config.json 복사)
#  사용:  bash build-linux.sh
#  주의:  실제 배포할 Linux 와 같은 배포판/아키텍처에서 빌드해야 호환됩니다.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
echo "python: $($PY --version)"

echo "[1/3] 의존성 설치 (watchdog, pyinstaller)..."
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -r requirements.txt pyinstaller

echo "[2/3] PyInstaller 빌드..."
# boto3/botocore 는 데이터 파일이 있어 --collect-all 로 통째로 수집해야 직접모드가 동작한다.
"$PY" -m PyInstaller --onefile --name file-agent \
    --collect-submodules watchdog \
    --collect-submodules websocket \
    --collect-all boto3 \
    --collect-all botocore \
    agent.py

echo "[3/3] config.json 배치..."
[ -f dist/config.json ] || cp config.json dist/config.json
chmod +x dist/file-agent || true
echo "완료: $(pwd)/dist/file-agent"
