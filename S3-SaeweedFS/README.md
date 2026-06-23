# File Generator

CCTV/카메라 로그 구조를 흉내내어 이미지 파일을 대량 생성하는 테스트용 스크립트입니다.
S3Agent 등 파일 감시·업로드 에이전트의 부하 및 RAM 과부하 테스트에 사용합니다.

## 기능

- 0.3초마다 여러 CAM 폴더에 PNG 이미지를 동시에 생성
- 폴더 구조: `<base>\<날짜>\CAM1 ~ CAMn`
- 이미지 파일명은 각 파일의 생성 시각 (`img_YYYYMMDD_HHMMSS_microsec.png`)
- 사이클 모드: N분 생성 → 폴더 비우기 → 다시 생성 (무한 반복)
- 시스템 RAM + 프로세스(기본 `file-agent`) 메모리 모니터링
- RAM 기록을 txt 파일(`ram_log.txt`)로 저장
- PNG 생성은 외부 라이브러리 불필요 (표준 라이브러리만, 프로세스 추적만 psutil)

## 폴더 구조 예시

```
D:\log\Images\루미너스5x11\
  ├─ 2026-06-22\  CAM1 ~ CAM6
  └─ 2026-06-23\  CAM1 ~ CAM6
```

## 사용법

기본 실행:

```
python file_generator.py
```

더블클릭 실행 (Windows): `실행.bat`

S3Agent 메모리 추적 (psutil 자동 설치): `실행_S3Agent추적.bat`

```
pip install psutil
python file_generator.py --watch-process S3Agent
```

## 옵션

| 옵션 | 기본값 | 설명 |
|---|---|---|
| `--base` | `D:\log\Images\루미너스5x11` | 기본 경로(여러 개 가능, 띄어쓰기) |
| `--dates` | `2026-06-22 2026-06-23` | 날짜 폴더(여러 개) |
| `--cams` | `6` | CAM 폴더 개수 (CAM1~CAMn) |
| `--interval` | `0.3` | 생성 간격(초) |
| `--size` | `32` | 이미지 한 변 px (키우면 부하↑) |
| `--cycle-minutes` | `30` | 한 사이클 생성 시간(분) |
| `--no-purge` | - | 사이클마다 삭제 안 함 |
| `--mon-interval` | `5` | RAM 출력/기록 간격(초) |
| `--watch-process` | `file-agent` | RAM 추적 프로세스(여러 개 가능, 부분일치, psutil 필요). `off` 면 끔 |
| `--log-file` | `ram_log.txt` | RAM 기록 txt 파일 경로. `off` 면 기록 안 함 |

## 요구사항

- Python 3.x
- psutil (선택, 프로세스별 RAM 추적 시)

중지하려면 `Ctrl+C`.
