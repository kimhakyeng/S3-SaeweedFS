FROM python:3.12-slim

# 시간대 (한국)
ENV TZ=Asia/Seoul \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# watchdog 만 필요 (표준 라이브러리만 사용)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 데몬 소스 + 기본 config
COPY agent.py .
COPY config.json /app/config.default.json

# 감시 폴더 (호스트에서 볼륨 마운트)
RUN mkdir -p /data/watch
VOLUME ["/data/watch"]

# 이벤트 영속화 + 로그 위치 (호스트로 볼륨 마운트하면 재시작 시 seq 유지)
VOLUME ["/app/state"]

# 8765 노출 (호스트에서 매핑)
EXPOSE 8765

# 컨테이너 시작 시: config.json 없으면 default 복사 → 실행
ENTRYPOINT ["sh", "-c", "\
  if [ ! -f /app/config.json ]; then cp /app/config.default.json /app/config.json; fi; \
  exec python agent.py --config /app/config.json \
"]
