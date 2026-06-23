"""
file_generator.py  (v3)
CCTV/카메라 로그 구조를 흉내내어 이미지 파일을 생성하는 테스트용 스크립트.

폴더 구조 (기본값):
    D:\\log\\Images\\루미너스5x11\\
        2026-06-22\\ CAM1 ~ CAM6\\
        2026-06-23\\ CAM1 ~ CAM6\\

동작:
- 0.3초마다 모든 CAM 폴더(날짜2 x CAM6 = 12곳)에 각각 PNG 1개씩 생성.
- 30분 생성 -> 전체 폴더 비우기 -> 다시 30분 생성 ... 무한 반복(사이클).
- RAM 사용량 모니터링(시스템 / 선택적으로 특정 프로세스).
- PNG 생성은 외부 라이브러리 불필요. 프로세스별 RAM 추적만 psutil 필요(선택).
- Ctrl+C 로 중지.

사용 예 (Windows):
    python file_generator.py
    python file_generator.py --watch-process S3Agent          # S3Agent 메모리 추적(psutil)
    python file_generator.py --dates 2026-06-22 2026-06-23 --cams 6
    python file_generator.py --no-purge                       # 사이클마다 삭제 안 함

psutil 설치(선택):
    pip install psutil
"""

import argparse
import ctypes
import glob
import os
import struct
import sys
import threading
import time
import zlib
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None


# ----------------------------- PNG 생성 -----------------------------
def make_png(width: int, height: int) -> bytes:
    raw = bytearray()
    rnd = os.urandom(width * height * 3)
    idx = 0
    row_bytes = width * 3
    for _ in range(height):
        raw.append(0)
        raw.extend(rnd[idx:idx + row_bytes])
        idx += row_bytes

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return c + struct.pack(">I", crc)

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 6)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


# ----------------------------- RAM 측정 -----------------------------
def get_system_mem():
    if psutil:
        m = psutil.virtual_memory()
        return m.percent, (m.total - m.available) / 1048576, m.total / 1048576

    if sys.platform.startswith("win"):
        class MEMSTAT(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        st = MEMSTAT()
        st.dwLength = ctypes.sizeof(MEMSTAT)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
        total = st.ullTotalPhys / 1048576
        avail = st.ullAvailPhys / 1048576
        return st.dwMemoryLoad, total - avail, total

    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, v = line.split(":")
            info[k] = int(v.strip().split()[0])
    total = info["MemTotal"] / 1024
    avail = info.get("MemAvailable", info["MemFree"]) / 1024
    return (total - avail) / total * 100, total - avail, total


def find_process_mem(name: str):
    if not psutil:
        return None
    total = 0.0
    cnt = 0
    for p in psutil.process_iter(["name", "memory_info"]):
        try:
            if name.lower() in (p.info["name"] or "").lower():
                total += p.info["memory_info"].rss / 1048576
                cnt += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return total, cnt


# ----------------------------- 모니터 스레드 -----------------------------
_stop = threading.Event()
_peak = {"sys_pct": 0.0, "procs": {}}

# RAM 로그를 기록할 txt 파일 경로 (None 이면 기록 안 함)
LOG_PATH = None


def log(msg: str, also_print: bool = True):
    """화면에 출력하고, LOG_PATH 가 설정돼 있으면 txt 파일에도 한 줄 추가."""
    if also_print:
        print(msg)
    if LOG_PATH:
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except OSError:
            pass


def monitor_loop(interval: float, watch_names):
    while not _stop.is_set():
        pct, used_mb, total_mb = get_system_mem()
        _peak["sys_pct"] = max(_peak["sys_pct"], pct)
        line = (f"[RAM {datetime.now():%Y-%m-%d %H:%M:%S}] 시스템 {pct:5.1f}% "
                f"({used_mb:,.0f}/{total_mb:,.0f} MB)")
        if watch_names:
            if not psutil:
                line += "  | (프로세스 추적엔 psutil 필요: pip install psutil)"
            else:
                for nm in watch_names:
                    pmb, pc = find_process_mem(nm)
                    _peak["procs"][nm] = max(_peak["procs"].get(nm, 0.0), pmb)
                    line += f"  | '{nm}' x{pc}: {pmb:,.1f} MB (peak {_peak['procs'][nm]:,.1f})"
        log(line)
        _stop.wait(interval)


# ----------------------------- 폴더 비우기 -----------------------------
def purge_dir(d: str) -> int:
    n = 0
    for fp in glob.glob(os.path.join(d, "img_*.png")):
        try:
            os.remove(fp)
            n += 1
        except OSError:
            pass
    return n


# ----------------------------- 메인 -----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="CAM 폴더 이미지 생성기 + RAM 모니터 + 사이클")
    ap.add_argument("--base", nargs="+", default=[r"D:\log\Images\루미너스5x11"],
                    help=r"기본 경로(여러 개 가능). 기본 D:\log\Images\루미너스5x11")
    ap.add_argument("--dates", nargs="+", default=["2026-06-22", "2026-06-23"],
                    help="날짜 폴더(여러 개, 기본 2026-06-22 2026-06-23)")
    ap.add_argument("--cams", type=int, default=6, help="CAM 폴더 개수 (기본 6 -> CAM1~CAM6)")
    ap.add_argument("--interval", type=float, default=0.3, help="생성 간격(초), 기본 0.3")
    ap.add_argument("--size", type=int, default=32, help="이미지 한 변 px (기본 32 ~= 3KB)")
    ap.add_argument("--cycle-minutes", type=float, default=30, help="한 사이클 생성 시간(분), 기본 30")
    ap.add_argument("--no-purge", action="store_true", help="사이클마다 폴더를 비우지 않음")
    ap.add_argument("--mon-interval", type=float, default=5, help="RAM 출력 간격(초), 기본 5")
    ap.add_argument("--watch-process", nargs="+", default=["file-agent"],
                    help="RAM 추적할 프로세스 이름(여러 개 가능, 부분일치, psutil 필요). 기본 file-agent. 'off' 면 추적 안 함")
    ap.add_argument("--log-file", default="ram_log.txt",
                    help="RAM 기록을 저장할 txt 파일 (기본 ram_log.txt, 'off' 면 기록 안 함)")
    args = ap.parse_args()

    # RAM 로그 파일 설정
    global LOG_PATH
    if args.log_file and args.log_file.lower() != "off":
        LOG_PATH = os.path.abspath(args.log_file)

    # 프로세스 추적 끄기
    if args.watch_process and len(args.watch_process) == 1 and args.watch_process[0].lower() == "off":
        args.watch_process = None

    # 모든 대상 CAM 폴더 경로 구성: base/date/CAMn
    targets = []
    for base in args.base:
        for date in args.dates:
            for n in range(1, args.cams + 1):
                targets.append(os.path.join(base, date, f"CAM{n}"))
    for d in targets:
        os.makedirs(d, exist_ok=True)

    cycle_sec = args.cycle_minutes * 60

    log(f"\n==================== 실행 시작: {datetime.now():%Y-%m-%d %H:%M:%S} ====================")
    log(f"[시작] 기본경로: {args.base}")
    log(f"[구조] 날짜 {args.dates} x CAM1~CAM{args.cams} = 총 {len(targets)}개 폴더")
    log(f"[설정] 간격 {args.interval}s | 크기 {args.size}px | 사이클 {args.cycle_minutes}분 "
        f"| 사이클 종료 시 삭제: {'아니오' if args.no_purge else '예'}")
    log(f"[RAM ] psutil: {'있음' if psutil else '없음(시스템 RAM만)'} "
        f"| 추적 프로세스: {args.watch_process or '없음'}")
    log(f"[로그] RAM 기록 파일: {LOG_PATH or '없음'}")
    log("[안내] 중지하려면 Ctrl+C\n")

    mon = threading.Thread(target=monitor_loop, args=(args.mon_interval, args.watch_process), daemon=True)
    mon.start()

    total_made = 0
    cycle = 0
    try:
        while True:
            cycle += 1
            made = 0
            t_cycle = time.perf_counter()
            log(f"\n===== 사이클 {cycle} 생성 시작 ({args.cycle_minutes}분, 폴더 {len(targets)}개) =====")
            while time.perf_counter() - t_cycle < cycle_sec:
                t0 = time.perf_counter()
                # 모든 CAM 폴더에 각각 1개씩 (파일명 = 각 파일의 생성 시각)
                for d in targets:
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
                    with open(os.path.join(d, f"img_{ts}.png"), "wb") as f:
                        f.write(make_png(args.size, args.size))
                    made += 1
                    total_made += 1
                elapsed = time.perf_counter() - t0
                time.sleep(max(0.0, args.interval - elapsed))
            log(f"----- 사이클 {cycle} 생성 종료: {made}개 (누적 {total_made}개) -----")
            if not args.no_purge:
                removed = sum(purge_dir(d) for d in targets)
                log(f"----- 폴더 비움: {removed}개 삭제 -----")
    except KeyboardInterrupt:
        _stop.set()
        peak_proc = ""
        if args.watch_process:
            peak_proc = " | " + ", ".join(
                f"{nm} peak {_peak['procs'].get(nm, 0.0):,.1f} MB" for nm in args.watch_process)
        log(f"\n[중지] 총 {total_made}개 생성 | 시스템 RAM peak {_peak['sys_pct']:.1f}%" + peak_proc)
        return 0


if __name__ == "__main__":
    sys.exit(main())
