#!/usr/bin/env python3
"""
file-agent : 디렉터리 감시 → TERESA MQ 백엔드(또는 S3)로 무손실 전송하는 데몬

[역할]  현장 PC 에서 실행한다(Windows 에서는 작업 스케줄러의 SYSTEM 작업).
  1) 지정한 디렉터리를 감시(watchdog + 주기 보정 스캔)하여 새 파일·수정을 감지
  2) 전송
     - backend 모드(기본): 백엔드에 WebSocket 으로 붙어 파일을 보내고, 적재 확인(ack)을
       받은 파일만 원장(sent.jsonl)에 기록한다. 감시 폴더는 캔버스 노드가 내려준다.
     - direct 모드: S3 에 직접 업로드한다.
     - PULL 모드(옛 방식): HTTP 포트로 이벤트(SSE)·파일을 노출하고 백엔드가 가져간다.
  3) 127.0.0.1 HTTP 포트로 상태(/health)와 제어(/control)를 제공한다(컨트롤 UI 가 사용).

Linux / Windows 공통으로 동작. 사용법은 README.md 참고.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import collections
import queue
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse, parse_qs, urlencode

try:
    from watchdog.observers import Observer
    from watchdog.observers.api import ObservedWatch
    from watchdog.events import FileSystemEventHandler
except ImportError as _imp_err:  # pragma: no cover - 배포본에는 항상 들어 있다
    _here = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
    try:
        with open(os.path.join(_here, "agent-crash.log"), "a", encoding="utf-8") as _f:
            _f.write("[%s] watchdog import 실패: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), _imp_err))
    except OSError:
        pass
    if sys.stderr is not None:
        sys.stderr.write("watchdog 가 필요합니다.  pip install watchdog\n")
    sys.exit(1)

VERSION = "1.2.1"

log = logging.getLogger("file-agent")
_PROCESS_STARTED_AT = time.time()

# 배포 템플릿(config.template.json)의 자리표시 토큰. 이 값이나 빈 값으로는 백엔드 모드를 켜지 않는다.
# zip 에 공개된 값이라, 그대로 두면 같은 LAN 의 누구나 이 데몬과 백엔드 노드에 붙을 수 있다.
PLACEHOLDER_TOKEN = "change-me-please-long-random-token"

# UI 의 [중지] 가 남기는 표식. 작업 스케줄러의 5분 감시 트리거가 사용자가 멈춘 데몬을
# 곧바로 되살리지 않게 한다. 기록된 부팅 시각이 지금 부팅과 다르면(재부팅) 무시하고 지운다.
STOP_FLAG_NAME = "stopped.flag"


# ============================================================================
#  네트워크 도달성 헬퍼 (프리플라이트용)
# ============================================================================
# 백엔드로 가는 HTTP 호출(프리플라이트·push·config 폴링)은 WS 연결(websocket-client)과 같은
# 프록시 기준을 쓴다 — 환경 변수(http_proxy 등)만 보고 Windows 사용자 프록시(레지스트리)는 보지 않는다.
# 기준이 다르면 사내 프록시가 설정된 PC 에서 프리플라이트만 프록시로 나가 실패하고 WS 는 영영 열리지 않는다.
_URL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler(urllib.request.getproxies_environment()))


def _url_open(req, timeout: float):
    return _URL_OPENER.open(req, timeout=timeout)


def _split_host_port(url_or_hostport: str, default_port: int = 80) -> tuple[str, int]:
    """http://host:port 또는 host:port 문자열에서 (host, port) 추출."""
    s = (url_or_hostport or "").strip()
    if not s:
        return ("", 0)
    if "://" in s:
        p = urlparse(s)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else default_port)
        return (host, int(port))
    # host:port 형태
    if ":" in s:
        h, _, prt = s.rpartition(":")
        try:
            return (h, int(prt))
        except ValueError:
            return (s, default_port)
    return (s, default_port)


def _tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """host:port 로 TCP 연결이 되는지(= 도달 가능) 확인."""
    if not host or port <= 0:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _detect_local_ip(target_host: str) -> str:
    """backend 가 도달할 수 있는 이 PC 의 IP 를 추정.
    target_host(백엔드) 로 향하는 UDP 소켓의 로컬 주소를 읽어 NIC IP 를 얻는다(실제 패킷 전송 X)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_host or "8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def _strip_jsonc(text: str) -> str:
    """config.json 에서 // 와 /* */ 주석, 그리고 trailing comma 를 제거(JSONC 허용).
    문자열 안의 // (예: http://...) 는 보존한다."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if c == '"':
                in_str = False
            i += 1; continue
        if c == '"':
            in_str = True; out.append(c); i += 1; continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c); i += 1
    import re
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


# ============================================================================
#  필터 파싱 헬퍼
# ============================================================================
def _parse_patterns(v) -> list[str]:
    """패턴 목록 정규화. list 또는 ','/';' 구분 문자열 허용. 빈 값 → []."""
    if v is None:
        return []
    if isinstance(v, str):
        parts = [p.strip() for p in v.replace(";", ",").split(",")]
        return [p for p in parts if p]
    if isinstance(v, (list, tuple)):
        return [str(p).strip() for p in v if str(p).strip()]
    return []


def _parse_size(v) -> int:
    """용량 파싱. int(바이트) 또는 '10MB' 같은 단위 문자열 허용. 0/음수/파싱실패 → 0(무제한)."""
    if v is None:
        return 0
    if isinstance(v, (int, float)):
        return max(0, int(v))
    s = str(v).strip().upper().replace(" ", "")
    if not s:
        return 0
    mult = 1
    for suf, m in (("KB", 1 << 10), ("MB", 1 << 20), ("GB", 1 << 30), ("TB", 1 << 40),
                   ("K", 1 << 10), ("M", 1 << 20), ("G", 1 << 30), ("T", 1 << 40), ("B", 1)):
        if s.endswith(suf):
            s = s[: -len(suf)]
            mult = m
            break
    try:
        return max(0, int(float(s) * mult))
    except ValueError:
        return 0


def _match_any(name: str, patterns: list[str]) -> bool:
    """fnmatch 패턴(대소문자 무시) 하나라도 일치하면 True."""
    low = name.lower()
    return any(fnmatch.fnmatch(low, pat.lower()) for pat in patterns)


class FilterSpec:
    """수집 파일 조건 (감시 폴더별로 개별 지정 가능, 미지정 항목은 전역값 상속).
    - folder_include : 경로 중 한 폴더라도 패턴 일치해야 수집 (특정 패턴 디렉터리 감지 수집)
    - folder_exclude : 일치 폴더 안의 파일 제외 (include 보다 우선)
    - file_include   : 지정 시 파일명이 패턴과 일치해야 수집
    - file_exclude   : 파일명 패턴 일치 시 제외 (include 보다 우선)
    - ext_include    : 지정 시 확장자가 목록에 있어야 수집 (점 없이 'jpg' 형태, 대소문자 무시)
    - ext_exclude    : 확장자 목록 일치 시 제외 (include 보다 우선)
    - min_size       : 이 값 미만(바이트) 파일 제외 (0=제한 없음)
    - max_size       : 이 값 초과(바이트) 파일 제외 (0=제한 없음)
    """

    __slots__ = ("folder_include", "folder_exclude", "file_include", "file_exclude",
                 "ext_include", "ext_exclude", "min_size", "max_size")

    # 속성명 → 허용 키 별칭 (snake_case / camelCase / 노드 props 명 모두 수용)
    _ALIASES = {
        "folder_include": ("folder_include", "folderInclude"),
        "folder_exclude": ("folder_exclude", "folderExclude"),
        "file_include": ("file_include", "fileInclude"),
        "file_exclude": ("file_exclude", "fileExclude"),
        "ext_include": ("ext_include", "extInclude"),
        "ext_exclude": ("ext_exclude", "extExclude"),
        "min_size": ("min_size", "min_file_size", "minFileSize"),
        "max_size": ("max_size", "max_file_size", "maxFileSize"),
    }

    def __init__(self, d: dict | None = None, base: "FilterSpec | None" = None):
        d = d or {}

        def pick(attr: str, parser, default):
            for k in self._ALIASES[attr]:
                if k in d:
                    return parser(d[k])
            return getattr(base, attr) if base is not None else default

        self.folder_include = pick("folder_include", _parse_patterns, [])
        self.folder_exclude = pick("folder_exclude", _parse_patterns, [])
        self.file_include = pick("file_include", _parse_patterns, [])
        self.file_exclude = pick("file_exclude", _parse_patterns, [])
        self.ext_include = [e.lstrip(".").lower() for e in pick("ext_include", _parse_patterns, [])]
        self.ext_exclude = [e.lstrip(".").lower() for e in pick("ext_exclude", _parse_patterns, [])]
        self.min_size = pick("min_size", _parse_size, 0)
        self.max_size = pick("max_size", _parse_size, 0)

    def allow_name(self, rel_dir_parts: list[str], filename: str) -> bool:
        """이름 기반 필터(폴더/파일명/확장자). 크기와 무관하게 조기 판정 가능."""
        # 폴더명 필터
        if self.folder_exclude and any(_match_any(p, self.folder_exclude) for p in rel_dir_parts):
            return False
        if self.folder_include and not any(_match_any(p, self.folder_include) for p in rel_dir_parts):
            return False
        # 파일명 필터
        if self.file_exclude and _match_any(filename, self.file_exclude):
            return False
        if self.file_include and not _match_any(filename, self.file_include):
            return False
        # 확장자 필터
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if self.ext_exclude and ext in self.ext_exclude:
            return False
        if self.ext_include and ext not in self.ext_include:
            return False
        return True

    def allow_size(self, size: int) -> bool:
        if self.min_size and size < self.min_size:
            return False
        if self.max_size and size > self.max_size:
            return False
        return True

    def summary(self) -> str:
        parts = []
        if self.folder_include: parts.append(f"dir+{self.folder_include}")
        if self.folder_exclude: parts.append(f"dir-{self.folder_exclude}")
        if self.file_include: parts.append(f"file+{self.file_include}")
        if self.file_exclude: parts.append(f"file-{self.file_exclude}")
        if self.ext_include: parts.append(f"ext+{self.ext_include}")
        if self.ext_exclude: parts.append(f"ext-{self.ext_exclude}")
        if self.min_size: parts.append(f"min={self.min_size}B")
        if self.max_size: parts.append(f"max={self.max_size}B")
        return ", ".join(parts) if parts else "(없음)"


# ============================================================================
#  감시 대상 한 건 (폴더 + 라벨 + recursive + 개별 필터/수집모드)
#   - label : 이벤트/스토리지 경로의 prefix. "" 이면 prefix 없음(단일 watch_dir 하위호환).
#             여러 폴더(watch_dirs)일 때는 폴더명(basename)을 기본 라벨로 써서
#             relpath 를 "<label>/<상대경로>" 로 네임스페이스 → 파일명 충돌 방지.
#   - filters : 이 폴더 전용 FilterSpec (미지정 키는 전역 필터 상속)
#   - batch   : True 면 watchdog 실시간 감시 대신 주기 스캔(배치성 수집)만 수행
# ============================================================================
class Watch:
    def __init__(self, path: str, label: str = "", recursive: bool = True,
                 filters: "FilterSpec | None" = None, batch: bool = False,
                 batch_interval: float = 0.0):
        self.path: str = os.path.abspath(path)
        self.label: str = (label or "").strip().strip("/")
        self.recursive: bool = bool(recursive)
        self.filters: "FilterSpec | None" = filters   # None 이면 전역 필터 사용
        self.batch: bool = bool(batch)
        self.batch_interval: float = max(0.0, float(batch_interval or 0.0))

    def __repr__(self) -> str:  # 로깅용
        return (f"Watch(path={self.path!r}, label={self.label!r}, recursive={self.recursive}, "
                f"batch={self.batch})")


def _valid_dir_path(p: str) -> bool:
    """감시 폴더 경로로 쓸 수 있는 형태인지 검사.
    dict repr 문자열("{'dir': ...}") 유입이나 Windows 금지 문자를 걸러
    잘못된 set_watch_dirs 로 감시가 통째로 죽는 사고를 방지한다."""
    s = (p or "").strip()
    if not s or s.startswith("{") or s.startswith("["):
        return False
    return not any(ch in s for ch in '<>|"*?')


def _sanitize_label(name: str) -> str:
    """폴더명을 S3 키/URL 에 안전한 라벨로 정규화(공백/역슬래시 등 정리)."""
    s = (name or "").strip().strip("/").replace("\\", "/")
    s = s.split("/")[-1]  # 혹시 경로가 들어와도 마지막 구성요소만
    return s.strip() or "dir"


# ============================================================================
#  설정
# ============================================================================
class Config:
    def __init__(self, d: dict):
        self.host: str = d.get("host", "0.0.0.0")
        self.port: int = int(d.get("port", 8765))
        self.token: str = d.get("token", "")
        self.watch_dir: str = d.get("watch_dir", "")
        self.recursive: bool = bool(d.get("recursive", True))
        self.emit_existing_on_start: bool = bool(d.get("emit_existing_on_start", True))
        self.quiet_period_seconds: float = float(d.get("quiet_period_seconds", 1.0))
        self.compute_sha256: bool = bool(d.get("compute_sha256", False))
        # ── PUSH 모드 ──
        # push_enabled=true 면, 파일 변경 시 backend 로 직접 POST 한다 (외부망/NAT 뒤 데몬용).
        # backend 가 데몬에 접근 못 하는 환경에서 PULL 대신 사용. PULL 과 동시 사용도 무방.
        # push_url 예) http://203.0.113.10:3939  (backend 공인 주소, 끝 슬래시 제외)
        self.push_enabled: bool = bool(d.get("push_enabled", False))
        self.push_url: str = str(d.get("push_url", "")).rstrip("/")
        # ── WS 모드 (양방향) ──
        # ws_enabled=true 면 backend 와 WebSocket 으로 양방향 통신 (파일 업로드 + 역방향 삭제).
        # 데몬이 WS 클라이언트로 outbound 연결하므로 내부/외부망(NAT) 무관. ws_url 예) http://192.0.2.10:3940
        self.ws_enabled: bool = bool(d.get("ws_enabled", False))
        self.ws_url: str = str(d.get("ws_url", "")).rstrip("/")
        # 병렬 전송 연결 수. 1=기존 동작(직렬). 0.3초 고빈도 환경에선 4~8 권장(처리량↑, 누락↓).
        self.ws_senders: int = max(1, int(d.get("ws_senders", 1)))
        # WS 소켓 send 타임아웃(초). 백엔드가 대량 파일에 밀려 TCP 버퍼가 가득 차면
        # 기존에는 send() 가 "영원히" 블록돼 데몬 전체가 멈춘 것처럼 보였다(대용량 일괄 투입 이슈).
        # 이 시간 안에 못 보내면 연결을 끊고 재연결 + 해당 파일 재전송한다(at-least-once).
        self.ws_send_timeout: float = max(5.0, float(d.get("ws_send_timeout", 60.0)))
        # ── 로깅(운영 부하 관리) ──
        # log_level: 기본 INFO(시작/경고/오류만 — 파일당 로그는 DEBUG 라 안 찍힘). 운영은 "WARNING" 권장.
        # log_max_mb / log_backups: 회전 상한. 총 디스크 ≈ log_max_mb*(log_backups+1). 기본 5MB*3=15MB.
        self.log_level: str = str(d.get("log_level", "INFO")).strip().upper()
        self.log_max_mb: int = max(1, int(d.get("log_max_mb", 5)))
        self.log_backups: int = max(0, int(d.get("log_backups", 2)))
        # offer_enabled: 바이트 전송 전 file_offer 왕복(이미 적재분 스킵 질의) 사용 여부. 기본 True.
        #   지배 병목이 백엔드 S3 PUT 경로라 오퍼 제거 단독 효과는 제한적이나, "대상 S3 가 확실히
        #   비어있는 벌크 초기적재"에선 오퍼 RTT(파일당 왕복)를 없애 처리량을 올릴 수 있다.
        #   ⚠️ False 여도 ack/원장(sent.jsonl) 기록·재전송 경로는 그대로 유지 → 무손실 불변식 보존.
        #   ⚠️ 절대 금지: 빈 원장≠빈 S3. 이미 적재된 대량 파일이 있는데 offer_enabled=false 로 재스캔하면
        #      전량 재스트리밍 위험. 반드시 대상 S3 가 비어있음이 확실할 때만 운영자가 수동 지정.
        self.offer_enabled: bool = bool(d.get("offer_enabled", True))
        # ledger_compaction: 원장(sent.jsonl)을 '현재 watch 스코프 & 디스크 실존' 항목만으로
        #   주기 축소한다(ADR-019). 기본 True. 작업자 용량정리 삭제/WatchDir 축소를 자동 추종해
        #   원장·시작메모리·디스크를 '현존 파일 수'로 상한 → 무한기간 운영 가능. S3 무대조(로컬만).
        #   기동 시 1회 + Rescanner 주기(rescan_interval) 로 실행. 0/false 면 기존 LRU 회전만.
        self.ledger_compaction: bool = bool(d.get("ledger_compaction", True))
        # ledger_keep_in_memory: 원장(sent.jsonl) 메모리 보관 상한(항목 수). 기본 30만.
        #   "동시에 디스크에 둘 수 있는 최대 파일 수"보다 크게 잡아야 초과분 재전송이 없다.
        #   항목당 ~350바이트(한글 경로). 예) 500만=약 1.6GB RAM/0.56GB 디스크. 재기동 시 tail 만큼 로드.
        self.ledger_keep_in_memory: int = max(10_000, int(d.get("ledger_keep_in_memory", 300_000)))
        # sync_mode (ADR-022): 개별 플래그 대신 "speed"(기본) | "mirror" 2개 프리셋으로 단순화.
        #   speed  : 삭제 이벤트는 로컬 캐시 정리만 하고 어디로도 전송하지 않는다 — 기존 동작과
        #            100% 동일. 100만 장급 대량 초기적재처럼 "전송만 하고 끝"이면 되는 시나리오.
        #   mirror : 삭제 이벤트를 실시간(watchdog)·배치(원장 컴팩션) 양쪽에서 저우선순위 채널로
        #            백엔드에 계속 전송해 감시 디렉터리와 스토리지가 실시간으로 맞물리게 한다.
        #   최신 Teresa 연결 시 Agent Source syncMode가 런타임 값을 자동 제어한다.
        #   같은 token에 mirror Binding이 하나라도 있으면 삭제 이벤트를 발신하고, 실제 삭제/덮어쓰기는
        #   백엔드가 각 Binding의 speed/mirror 정책으로 최종 분할한다.
        #   알 수 없는 값은 안전한 speed 로 폴백(+경고 로그).
        _sync_mode_raw = str(d.get("sync_mode", "speed")).strip().lower()
        if _sync_mode_raw not in ("speed", "mirror"):
            log.warning("sync_mode 값 인식 불가(%r) — 'speed' 로 폴백", _sync_mode_raw)
            _sync_mode_raw = "speed"
        self.sync_mode: str = _sync_mode_raw
        # ── 수집 파일 조건 (전역 기본값 — watch_dirs 항목별로 개별 지정 시 그쪽이 우선) ──
        #   folder_include/folder_exclude : 폴더명 fnmatch 패턴 (기존과 동일)
        #   file_include/file_exclude     : 파일명 fnmatch 패턴 (예: ["*.tmp", "~$*"])
        #   ext_include/ext_exclude       : 확장자 목록 (점 없이, 예: ["jpg","png"])
        #   min_file_size/max_file_size   : 바이트 또는 "10MB" 형식. 미만/초과 제외. 0=무제한.
        self.filters: FilterSpec = FilterSpec(d)
        # 하위호환 속성(기존 코드 경로용)
        self.folder_include: list[str] = self.filters.folder_include
        self.folder_exclude: list[str] = self.filters.folder_exclude
        # ── 수집 처리 방식 ──
        # collect_mode: "realtime"(기본, watchdog 실시간) | "batch"(주기 스캔만)
        # rescan_interval_seconds: 보정 스캔 주기(초). 실시간 모드에서도 이 주기로 전체 폴더를
        #   재스캔해 watchdog 누락·전송 실패·재부팅 공백을 따라잡는다(원장에 없는 파일만 재전송).
        #   0 이면 보정 스캔 없음. batch 모드 폴더는 이 주기(또는 폴더별 batch_interval)로만 수집.
        self.collect_mode: str = str(d.get("collect_mode", "realtime")).strip().lower()
        self.rescan_interval_seconds: float = max(0.0, float(d.get("rescan_interval_seconds", 300)))
        # ── 무손실/메모리 보호 ──
        # queue_max: WS 전송 대기 큐 상한(이벤트 건수). 초과분은 큐에 넣지 않고 보정 스캔이
        #   원장(sent.jsonl) 대조로 다시 채운다 → 서버 장기 다운에도 RAM 이 무한히 늘지 않음.
        # ack_timeout_seconds: 백엔드 ack 미수신 시 재전송까지 대기 시간.
        self.queue_max: int = max(1000, int(d.get("queue_max", 20000)))
        self.ack_timeout_seconds: float = max(30.0, float(d.get("ack_timeout_seconds", 300)))
        # ── 다중 감시 폴더 ── (필터/수집모드 파싱 이후에 구성해야 폴더별 상속이 동작)
        # watch_dirs 가 있으면 여러 폴더를 한 에이전트가 병렬 감시한다.
        #   "watch_dirs": ["C:/test", "C:/khk"]                         ← 폴더명 자동 prefix(test/, khk/)
        #   "watch_dirs": [{"dir":"C:/test","label":"raw","recursive":true,
        #                   "folder_include":[...], "ext_include":[...], "min_size":"1KB",
        #                   "collect_mode":"batch", "batch_interval":600}, ...] ← 폴더별 필터/모드
        # 비어 있으면 기존 단일 watch_dir 사용(prefix 없음, 완전 하위호환).
        self.watches: list[Watch] = self._build_watches(d.get("watch_dirs"))
        # ── 프리플라이트(연결 사전 점검) ──
        # ws 모드에서 WS 를 열기 전에 양방향 도달성을 먼저 확인한다(무작정 WS 재연결 방지).
        #  - preflight_enabled : 사전 점검 사용 여부(기본 true).
        #  - s3_endpoint       : SeaweedFS S3 엔드포인트. 에이전트→스토리지 직접 도달성 확인용.
        #                        예) http://192.0.2.10:28333  (비우면 해당 확인 생략)
        #  - advertise_host    : backend 가 이 PC 로 역방향 접근할 때 쓸 IP. 비우면 자동 감지.
        self.preflight_enabled: bool = bool(d.get("preflight_enabled", True))
        self.s3_endpoint: str = str(d.get("s3_endpoint", "")).rstrip("/")
        self.advertise_host: str = str(d.get("advertise_host", "")).strip()
        # ── 모드 명시 스위치 ──
        # "direct"  = 데몬이 SeaweedFS 로 직접 업로드(s3_* 사용)
        # "backend" = 백엔드 경유(ws_* 사용)
        # 비우면 s3_endpoint+s3_bucket 유무로 자동 판정(하위호환).
        self.mode: str = str(d.get("mode", "")).strip().lower()
        # ── SeaweedFS 직접 업로드 모드 ──
        # config.json 에 s3_endpoint + s3_bucket 가 있으면 데몬이 백엔드를 거치지 않고
        # SeaweedFS(S3) 에 직접 PUT 한다(boto3 필요). 값이 없으면 기존 ws/push(백엔드 경유).
        # 적재 전용(ingest-only): 삭제 동기화 기능은 제거됨 — 로컬 삭제는 스토리지에 반영 안 함.
        self.s3_bucket: str = str(d.get("s3_bucket", "")).strip()
        self.s3_access_key: str = str(d.get("s3_access_key", "")).strip()
        self.s3_secret_key: str = str(d.get("s3_secret_key", "")).strip()
        self.s3_region: str = (str(d.get("s3_region", "")).strip() or "us-east-1")
        # s3_path_style 제거: 경로식 접근은 S3 클라이언트에서 상시 "path" 로 고정(SeaweedFS 필수, config 무관).
        self.s3_path_prefix: str = str(d.get("s3_path_prefix", "")).strip().strip("/")

    @property
    def s3_direct_enabled(self) -> bool:
        """직접 모드 여부. mode 명시가 우선, 없으면 endpoint+bucket 자동 판정."""
        if self.mode == "direct":
            return True
        if self.mode == "backend":
            return False
        return bool(self.s3_endpoint and self.s3_bucket)

    # ---- 다중 감시 폴더 구성/조회 ----
    def _build_watches(self, raw) -> list[Watch]:
        """watch_dirs(list) 를 Watch 목록으로 정규화. 라벨 중복은 _2,_3 으로 분리."""
        if not raw:
            return []  # 단일 watch_dir 사용 → finalize_watches 에서 채움
        specs: list[Watch] = []
        base_filters = getattr(self, "filters", None)
        for item in raw:
            if isinstance(item, str):
                path = item
                label = _sanitize_label(os.path.basename(os.path.normpath(item)))
                rec = self.recursive
                flt = None
                batch = (getattr(self, "collect_mode", "realtime") == "batch")
                batch_iv = 0.0
            elif isinstance(item, dict):
                path = str(item.get("dir") or item.get("path") or "").strip()
                if not path:
                    continue
                label = str(item.get("label") or "").strip()
                label = _sanitize_label(label) if label else \
                    _sanitize_label(os.path.basename(os.path.normpath(path)))
                rec = bool(item.get("recursive", self.recursive))
                # 폴더별 필터: 필터 키가 하나라도 있으면 전역 필터를 base 로 오버라이드 생성
                _fkeys = [k for keys in FilterSpec._ALIASES.values() for k in keys]
                flt = FilterSpec(item, base=base_filters) if any(k in item for k in _fkeys) else None
                mode = str(item.get("collect_mode", item.get("collectMode", ""))).strip().lower()
                batch = mode == "batch" if mode else (getattr(self, "collect_mode", "realtime") == "batch")
                try:
                    batch_iv = float(item.get("batch_interval", item.get("batchIntervalSec", 0)) or 0)
                except (TypeError, ValueError):
                    batch_iv = 0.0
            else:
                continue
            if not _valid_dir_path(path):
                log.warning("감시 폴더 무시(경로 형식 오류): %r", path)
                continue
            specs.append(Watch(path, label, rec, filters=flt, batch=batch, batch_interval=batch_iv))
        # 라벨 유일성 보장 (서로 다른 폴더가 같은 basename 이면 충돌하므로 분리)
        seen: dict[str, int] = {}
        for w in specs:
            base = w.label or "dir"
            if base in seen:
                seen[base] += 1
                w.label = f"{base}_{seen[base]}"
            else:
                seen[base] = 1
        return specs

    def finalize_watches(self) -> None:
        """watch_dirs 미지정 시 단일 watch_dir 로 watches 를 채운다(라벨 "" = prefix 없음).
        watch_dir 에 ';' 로 여러 경로가 들어오면 다중 폴더로 분리한다."""
        if self.watches:
            # 다중 모드: 표시/하위호환용으로 watch_dir 를 첫 폴더로 맞춰둔다.
            if not self.watch_dir:
                self.watch_dir = self.watches[0].path
            return
        if self.watch_dir:
            parts = [p.strip() for p in self.watch_dir.split(";") if p.strip()]
            if len(parts) > 1:
                self.watches = self._build_watches(parts)  # 폴더명 자동 prefix
                self.watch_dir = self.watches[0].path
            else:
                single = parts[0] if parts else self.watch_dir
                self.watch_dir = single
                self.watches = [Watch(single, label="", recursive=self.recursive)]

    @property
    def is_multi(self) -> bool:
        return len(self.watches) > 1 or (len(self.watches) == 1 and bool(self.watches[0].label))

    def make_relpath(self, abspath: str) -> str | None:
        """절대경로 → 네임스페이스된 relpath("<label>/<rel>"). 어느 watch 에도 없으면 None.
        중첩 폴더면 가장 구체적인(긴) base 를 선택."""
        ap = os.path.realpath(abspath)
        best: tuple[str, Watch] | None = None
        for w in self.watches:
            base = os.path.realpath(w.path)
            try:
                if os.path.commonpath([base, ap]) != base:
                    continue
            except ValueError:
                continue
            if best is None or len(base) > len(os.path.realpath(best[1].path)):
                best = (base, w)
        if best is None:
            return None
        base, w = best
        rel = os.path.relpath(ap, base).replace("\\", "/")
        if rel == ".":
            return w.label or ""
        return f"{w.label}/{rel}" if w.label else rel

    def resolve(self, relpath: str) -> str | None:
        """네임스페이스된 relpath → 실제 절대경로. 경로 탈출/미존재 라벨은 None.
        라벨 있는 watch 를 먼저 매칭하고, 라벨 없는("") watch 는 마지막에 fallback."""
        rel = (relpath or "").replace("\\", "/").lstrip("/")
        if not rel:
            return None
        ordered = sorted(self.watches, key=lambda w: 0 if w.label else 1)
        for w in ordered:
            if w.label:
                prefix = w.label + "/"
                if rel == w.label:
                    sub = ""
                elif rel.startswith(prefix):
                    sub = rel[len(prefix):]
                else:
                    continue
            else:
                sub = rel
            base = os.path.realpath(w.path)
            target = os.path.realpath(os.path.join(base, sub))
            try:
                if os.path.commonpath([base, target]) == base:
                    return target
            except ValueError:
                continue
        return None

    def resolve_for_compaction(self, relpath: str) -> str | None:
        """원장 정리용 resolve. 감시 폴더 자체가 지금 안 보이면 ""(판단 보류)를 돌려준다.
        부팅 직후 네트워크 공유·외장 디스크가 덜 붙은 순간에 '파일 없음'으로 보고
        원장을 지우면, 폴더가 돌아왔을 때 전부 다시 보내게 된다."""
        ap = self.resolve(relpath)
        if ap is None:
            return None
        w = self._find_watch(ap)
        if w is not None and not os.path.isdir(w.path):
            return ""
        return ap

    def _find_watch(self, abspath: str) -> "Watch | None":
        """절대경로가 속한 가장 구체적인(긴 base) Watch 를 찾는다. 없으면 None."""
        ap = os.path.realpath(abspath)
        best: "Watch | None" = None
        best_len = -1
        for w in self.watches:
            base = os.path.realpath(w.path)
            try:
                if os.path.commonpath([base, ap]) != base:
                    continue
            except ValueError:
                continue
            if len(base) > best_len:
                best, best_len = w, len(base)
        return best

    def effective_filters(self, w: "Watch | None") -> FilterSpec:
        """해당 Watch 의 유효 필터 (폴더별 지정이 없으면 전역)."""
        if w is not None and w.filters is not None:
            return w.filters
        return self.filters

    def file_allowed(self, abspath: str, size: int | None = None) -> bool:
        """수집 파일 조건 판정 (폴더 패턴 + 파일명 + 확장자 + 용량).
        size=None 이면 이름 기반 필터만 적용(크기는 안정화 후 _emit 에서 재판정).
        감시 폴더 밖이면 True (make_relpath 단계에서 걸러진다)."""
        w = self._find_watch(abspath)
        if w is None:
            return True
        flt = self.effective_filters(w)
        ap = os.path.realpath(abspath)
        base = os.path.realpath(w.path)
        rel_dir = os.path.relpath(os.path.dirname(ap), base).replace("\\", "/")
        parts = [] if rel_dir in (".", "") else rel_dir.split("/")
        if not flt.allow_name(parts, os.path.basename(ap)):
            return False
        if size is not None and not flt.allow_size(int(size)):
            return False
        return True

    def folder_allowed(self, abspath: str) -> bool:
        """하위호환 진입점 — 이름 기반 필터로 위임."""
        return self.file_allowed(abspath, size=None)

    def _iter_one_watch(self, w: "Watch"):
        """단일 watch 의 파일을 (relpath, abspath, size, mtime) 로 순회 (이름·용량 필터 적용)."""
        base = w.path
        if not os.path.isdir(base):
            return
        if w.recursive:
            walker = (os.path.join(r, fn)
                      for r, _, fs in os.walk(base) for fn in fs)
        else:
            try:
                names = os.listdir(base)
            except OSError as e:
                log.warning("감시 폴더를 읽을 수 없습니다(이번 스캔 건너뜀): %s — %s", base, e)
                return
            walker = (os.path.join(base, fn)
                      for fn in names
                      if os.path.isfile(os.path.join(base, fn)))
        for ap in walker:
            if not self.file_allowed(ap):
                continue
            try:
                st = os.stat(ap)
            except OSError:
                continue
            if not self.file_allowed(ap, size=st.st_size):
                continue  # 용량 조건 미달(이상/이하 제외)
            rel = os.path.relpath(ap, base).replace("\\", "/")
            relpath = f"{w.label}/{rel}" if w.label else rel
            yield (relpath, ap, st.st_size, st.st_mtime)

    def iter_existing(self, only: "Watch | None" = None):
        """모든 watch(또는 only 하나)의 현재 파일을 순회.
        다중 watch 는 폴더별 제너레이터를 라운드로빈으로 인터리브 → 큰 폴더(예: 루미너스 150만)가
        작은 폴더(khktest)의 스캔 시작을 지연시키지 않는다(두 폴더가 처음부터 함께 큐에 투입).
        전송측 라운드로빈(WsClientPool)과 짝을 이뤄 초기 대량 적재에서도 폴더가 동시에 흐른다.
        (스캔 인터리브 + 전송 라운드로빈 = 폴더별 진짜 병렬)"""
        watches = [only] if only is not None else list(self.watches)
        gens = [self._iter_one_watch(w) for w in watches]
        while gens:
            for g in list(gens):
                try:
                    yield next(g)
                except StopIteration:
                    gens.remove(g)

    def set_watches(self, specs: list) -> None:
        """런타임 교체용: watch_dirs 와 동일한 형식(list[str|dict])으로 watches 재구성."""
        self.watches = self._build_watches(specs)
        self.finalize_watches()

    def watch_summary(self) -> list[dict]:
        return [{"dir": w.path, "label": w.label, "recursive": w.recursive,
                 "batch": w.batch, "filters": self.effective_filters(w).summary()}
                for w in self.watches]

    @staticmethod
    def load(path: str) -> "Config":
        # utf-8-sig: PowerShell Set-Content -Encoding UTF8·옛 메모장이 붙이는 BOM 을 허용한다.
        with open(path, "r", encoding="utf-8-sig") as f:
            raw = f.read()
        # JSONC 허용: // , /* */ 주석과 trailing comma 제거 후 파싱
        return Config(json.loads(_strip_jsonc(raw)))


# ============================================================================
#  이벤트 저장소 (메모리 + events.jsonl 영속화, 단조 증가 seq)
#  - 가져가는 쪽이 ?since=<seq> 로 누락 없이 따라잡을 수 있게 한다 (at-least-once)
# ============================================================================
class EventStore:
    # events.jsonl 이 이 크기를 넘으면 최근 이벤트만 남기고 잘라낸다(무한 증가 방지).
    _MAX_PERSIST_BYTES = 50 * 1024 * 1024   # 50 MB
    _ROTATE_CHECK_EVERY = 1000              # append 이 횟수마다 파일 크기 점검

    def __init__(self, persist_path: str, keep_in_memory: int = 5000):
        self._persist_path = persist_path
        self._keep = keep_in_memory
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._events: list[dict] = []
        self._last_seq = 0
        self._appends_since_check = 0
        self._load_existing()

    @staticmethod
    def _read_tail_lines(path: str, max_lines: int) -> list[str]:
        """파일 전체를 메모리에 올리지 않고 끝에서부터 최대 max_lines 줄만 읽는다.
        events.jsonl 이 수 GB 로 커져도 이 함수는 마지막 수 MB 만 읽으므로 OOM 이 없다."""
        block = 1 << 20             # 1 MB 씩 뒤에서부터 읽음
        want = max_lines + 1        # 맨 앞 줄은 잘렸을 수 있어 1줄 여유
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            data = b""
            while pos > 0 and data.count(b"\n") <= want:
                step = min(block, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step) + data
                if len(data) > (want + 1) * 8192:   # 비정상적으로 긴 줄에 대한 안전 상한
                    break
        # 블록 경계에서 멀티바이트(한글)가 잘릴 수 있으므로 errors="ignore".
        # 그렇게 손상되는 건 우리가 어차피 버리는 맨 앞(가장 오래된) 줄뿐이다.
        text = data.decode("utf-8", errors="ignore")
        return text.splitlines()[-max_lines:]

    def _load_existing(self) -> None:
        if not os.path.exists(self._persist_path):
            return
        try:
            lines = self._read_tail_lines(self._persist_path, self._keep)
        except Exception as e:  # noqa: BLE001
            log.warning("events.jsonl 꼬리 읽기 실패(무시): %s", e)
            return
        loaded = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:  # noqa: BLE001  손상된 줄은 건너뛴다(전체 로드 중단 방지)
                continue
            self._last_seq = max(self._last_seq, int(ev.get("seq", 0)))
            self._events.append(ev)
            loaded += 1
        self._events = self._events[-self._keep:]
        log.info("기존 이벤트 로드(꼬리 %d줄): last_seq=%d", loaded, self._last_seq)

    def append(self, ev_type: str, relpath: str, size: int, mtime: float,
               sha256: str | None) -> dict:
        with self._cond:
            self._last_seq += 1
            ev = {
                "seq": self._last_seq,
                "type": ev_type,            # existing | created | modified | moved
                "path": relpath,
                "size": size,
                "mtime": mtime,
                "ts": time.time(),
            }
            if sha256:
                ev["sha256"] = sha256
            self._events.append(ev)
            if len(self._events) > self._keep:
                self._events = self._events[-self._keep:]
            try:
                with open(self._persist_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                self._appends_since_check += 1
                if self._appends_since_check >= self._ROTATE_CHECK_EVERY:
                    self._appends_since_check = 0
                    self._maybe_rotate()
            except Exception as e:  # noqa: BLE001
                log.warning("이벤트 영속화 실패(무시): %s", e)
            self._cond.notify_all()
            return ev

    def _maybe_rotate(self) -> None:
        """파일이 상한을 넘으면 메모리의 최근 이벤트(최대 _keep 개)만으로 다시 쓴다.
        반드시 self._cond(=self._lock) 를 보유한 상태에서 호출한다."""
        try:
            if os.path.getsize(self._persist_path) < self._MAX_PERSIST_BYTES:
                return
        except OSError:
            return
        tmp = self._persist_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                for e in self._events:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            os.replace(tmp, self._persist_path)   # 원자적 교체
            log.info("events.jsonl 회전: 최근 %d건만 유지(파일 축소)", len(self._events))
        except Exception as ex:  # noqa: BLE001
            log.warning("events.jsonl 회전 실패(무시): %s", ex)
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass

    def since(self, seq: int) -> list[dict]:
        with self._lock:
            return [e for e in self._events if e["seq"] > seq]

    def wait_for_new(self, seq: int, timeout: float) -> list[dict]:
        """seq 이후 이벤트가 생길 때까지 대기. timeout 후엔 빈 리스트."""
        with self._cond:
            newer = [e for e in self._events if e["seq"] > seq]
            if newer:
                return newer
            self._cond.wait(timeout)
            return [e for e in self._events if e["seq"] > seq]

    @property
    def last_seq(self) -> int:
        with self._lock:
            return self._last_seq


# ============================================================================
#  SentLedger : 전송 완료 원장 (sent.jsonl)
#  - "이 파일(relpath, size, mtime)은 스토리지에 안전하게 적재됨"을 로컬에 영속 기록.
#  - 백엔드 file_ack(result=stored|exists) 수신 시에만 기록 → 종단 무손실(at-least-once).
#  - 에이전트/서버 재부팅 후 보정 스캔이 원장에 없는 파일만 다시 보낸다
#    (기존 emit_existing_on_start 전량 재전송 → 원장 대조 차등 전송으로 개선).
#  - 메모리 상한(_keep) + 파일 회전(_MAX_BYTES)으로 무한 증가 방지.
#    (원장에서 밀려난 옛 파일은 재전송될 수 있으나 백엔드 skipExisting 이 걸러줌 = 안전한 방향)
# ============================================================================
class SentLedger:
    _MAX_BYTES = 50 * 1024 * 1024
    _ROTATE_CHECK_EVERY = 2000

    def __init__(self, persist_path: str, keep_in_memory: int = 300_000):
        self._path = persist_path
        self._keep = keep_in_memory
        self._lock = threading.Lock()
        self._map: dict[str, tuple[int, int]] = {}   # relpath -> (size, int(mtime))
        self._appends = 0
        # 회전 임계값은 keep 에 비례(항목당 ~256B 여유). 고정 50MB 로 두면 keep 를 크게 잡았을 때
        # 원장 자연 크기(keep×~117B)가 임계값을 상시 초과해 매 회전마다 전량 재작성되는 폭주 방지.
        self._max_bytes = max(self._MAX_BYTES, keep_in_memory * 256)
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            lines = EventStore._read_tail_lines(self._path, self._keep)
        except Exception as e:  # noqa: BLE001
            log.warning("sent.jsonl 읽기 실패(무시): %s", e)
            return
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                self._map[str(r["path"])] = (int(r.get("size", -1)), int(r.get("mtime", 0)))
            except Exception:  # noqa: BLE001
                continue
        log.info("전송 원장 로드: %d건 (sent.jsonl)", len(self._map))

    @staticmethod
    def _mt(mtime: float) -> int:
        return int(mtime)

    def has(self, relpath: str, size: int, mtime: float) -> bool:
        with self._lock:
            rec = self._map.get(relpath)
            return rec is not None and rec == (int(size), self._mt(mtime))

    def record(self, relpath: str, size: int, mtime: float) -> None:
        key = (int(size), self._mt(mtime))
        with self._lock:
            if self._map.get(relpath) == key:
                return
            self._map[relpath] = key
            # 메모리 상한: 가장 오래 전에 기록된 것부터 제거(dict 삽입순 유지 이용)
            while len(self._map) > self._keep:
                self._map.pop(next(iter(self._map)))
            try:
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"path": relpath, "size": key[0], "mtime": key[1],
                                        "ts": round(time.time(), 3)}, ensure_ascii=False) + "\n")
                self._appends += 1
                if self._appends >= self._ROTATE_CHECK_EVERY:
                    self._appends = 0
                    self._maybe_rotate()
            except Exception as e:  # noqa: BLE001
                log.warning("sent.jsonl 기록 실패(무시): %s", e)

    def _maybe_rotate(self) -> None:
        try:
            if os.path.getsize(self._path) < self._max_bytes:
                return
        except OSError:
            return
        tmp = self._path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                for p, (sz, mt) in self._map.items():
                    f.write(json.dumps({"path": p, "size": sz, "mtime": mt}, ensure_ascii=False) + "\n")
            os.replace(tmp, self._path)
            log.info("sent.jsonl 회전: %d건 유지", len(self._map))
        except Exception as e:  # noqa: BLE001
            log.warning("sent.jsonl 회전 실패(무시): %s", e)
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass

    def compact(self, resolver, on_dropped=None) -> tuple[int, int]:
        """원장을 '현재 watch 스코프 안 & 디스크에 실제 존재' 항목만으로 축소한다(ADR-019).
        resolver(relpath) -> 절대경로|None (Config.resolve). None 이거나 파일이 없으면 제거.
        - 소스가 사라진(작업자 용량정리 삭제) / 스코프 밖(WatchDir 축소) 항목을 걷어내
          원장·시작메모리·디스크를 '현존 파일 수'로 상한시킨다. S3/백엔드 무왕복(로컬만).
        - 안전: '디스크에 없는' 항목만 제거 → 현존 파일의 재전송을 유발하지 않음(무손실 불변식 무관).
        - 락 최소화: 느린 디스크 stat 은 락 밖에서 수행.
        - on_dropped(relpath) (ADR-022, 선택): 제거된 각 항목에 대해 호출 — batch collect_mode 처럼
          watchdog 이 없어 on_deleted 가 못 잡는 삭제를 sync_mode=mirror 에서 대신 통지하는 용도.
          None(기본)이면 호출 안 함 — 기존 동작과 100% 동일. 락 해제 후 호출(재진입 안전)."""
        with self._lock:
            items = list(self._map.items())
        dropped_keys: list[str] = []
        missing_keys: list[str] = []   # 디스크에서 사라진 것만 — 삭제 통지 대상
        out_of_scope = 0
        for p, _v in items:
            try:
                ap = resolver(p)
            except Exception:  # noqa: BLE001
                continue   # 판단할 수 없으면 지우지 않는다
            if ap == "":
                continue   # 감시 폴더가 지금 안 보임 — 판단 보류
            if ap is None:
                out_of_scope += 1
                dropped_keys.append(p)
            elif not os.path.exists(ap):
                dropped_keys.append(p)
                missing_keys.append(p)
        if not dropped_keys:
            return (len(items), 0)
        if items and out_of_scope == len(items):
            # 전부 범위 밖이면 감시 구성이 아직 덜 정해졌을 가능성이 크다. 지우지 않는다.
            log.warning("원장 정리 보류: 기록 %d건이 모두 현재 감시 폴더 밖입니다", len(items))
            return (len(items), 0)
        with self._lock:
            for k in dropped_keys:
                self._map.pop(k, None)   # 컴팩션 중 새로 record 된 항목은 보존
            tmp = self._path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    for p, (sz, mt) in self._map.items():
                        f.write(json.dumps({"path": p, "size": sz, "mtime": mt},
                                           ensure_ascii=False) + "\n")
                os.replace(tmp, self._path)
                log.info("sent.jsonl 컴팩션: 유지 %d / 제거 %d (디스크 실존 기준)",
                         len(self._map), len(dropped_keys))
            except Exception as e:  # noqa: BLE001
                log.warning("sent.jsonl 컴팩션 실패(무시): %s", e)
                try:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                except OSError:
                    pass
            kept = len(self._map)
        if on_dropped is not None:
            # 감시 범위에서 빠졌을 뿐인 항목(엣지 해제·라벨 변경)은 로컬에 파일이 남아 있다.
            # 이것을 삭제로 알리면 mirror 노드가 S3 객체를 지운다 — 디스크에서 사라진 것만 알린다.
            for k in missing_keys:
                try:
                    on_dropped(k)
                except Exception:  # noqa: BLE001
                    pass
        return (kept, len(dropped_keys))

    def __len__(self) -> int:
        with self._lock:
            return len(self._map)


# ============================================================================
#  PendingAcks : ack 대기 레지스트리 (전송했지만 아직 백엔드 확인 못 받은 파일)
#  - WS 전송 직후 등록, file_ack 수신 시 해제(+원장 기록).
#  - ack_timeout 경과 항목은 리퍼가 큐로 재투입(at-least-once). 서버 재부팅 중
#    유실된 전송도 이 경로로 자동 복구된다.
# ============================================================================
class PendingAcks:
    def __init__(self, ack_timeout: float):
        self.ack_timeout = ack_timeout
        self._lock = threading.Lock()
        self._map: dict[str, tuple[str, str | None, int, float, float]] = {}
        # relpath -> (ev_type, abspath, size, mtime, sent_ts)

    def put(self, relpath: str, ev_type: str, abspath: str | None,
            size: int, mtime: float) -> None:
        with self._lock:
            self._map[relpath] = (ev_type, abspath, size, mtime, time.time())

    def pop(self, relpath: str):
        with self._lock:
            return self._map.pop(relpath, None)

    def contains(self, relpath: str) -> bool:
        with self._lock:
            return relpath in self._map

    def expired(self) -> list[tuple[str, str, str | None]]:
        """타임아웃 지난 (relpath, ev_type, abspath) 목록을 꺼내면서 제거."""
        now = time.time()
        out: list[tuple[str, str, str | None]] = []
        with self._lock:
            for rp, (ev, ap, _sz, _mt, ts) in list(self._map.items()):
                if now - ts >= self.ack_timeout:
                    self._map.pop(rp, None)
                    out.append((rp, ev, ap))
        return out

    def __len__(self) -> int:
        with self._lock:
            return len(self._map)


# ============================================================================
#  PushClient : PUSH 모드. 파일 변경 시 backend 로 직접 POST.
#   - backend 가 데몬에 접근 못 하는 외부망/NAT 뒤 데몬용 (PULL 대체).
#   - 감지 스레드(StabilityWorker)를 막지 않도록 큐 + 단일 워커 스레드로 비동기 전송.
#   - 엔드포인트: POST {push_url}/api/file-agent/push?type=..&path=..&size=..
#                 Header: X-Agent-Token, Body: 파일 바이트 (deleted 는 빈 본문)
# ============================================================================
class PushClient(threading.Thread):
    def __init__(self, push_url: str, token: str):
        super().__init__(daemon=True)
        self.push_url = push_url.rstrip("/")
        self.token = token
        self.on_fail = None   # abspath -> None. main 에서 runtime.forget_emitted 를 넣는다.
        self._q: "queue.Queue[tuple | None]" = queue.Queue()
        self._stop = threading.Event()

    def enqueue(self, ev_type: str, relpath: str, abspath: str | None) -> None:
        self._q.put((ev_type, relpath, abspath))

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)  # 워커 깨우기

    def run(self) -> None:
        log.info("PUSH 모드 활성: %s/api/file-agent/push", self.push_url)
        while not self._stop.is_set():
            item = self._q.get()
            if item is None:
                break
            ev_type, relpath, abspath = item
            try:
                self._send(ev_type, relpath, abspath)
            except Exception as e:  # noqa: BLE001
                log.warning("push 실패 (%s %s): %s — 다음 보정 스캔 때 다시 시도", ev_type, relpath, e)
                self._failed(abspath)

    def _failed(self, abspath: str | None) -> None:
        if self.on_fail is not None and abspath:
            try:
                self.on_fail(abspath)
            except Exception:  # noqa: BLE001
                pass

    def _send(self, ev_type: str, relpath: str, abspath: str | None) -> None:
        # deleted 또는 파일 없음 → 빈 본문. 그 외 → 파일 바이트 적재.
        if ev_type == "deleted" or not abspath:
            body = b""
            size = 0
        else:
            try:
                with open(abspath, "rb") as f:
                    body = f.read()
            except OSError as e:
                log.warning("push 파일 읽기 실패 %s: %s — 스킵", abspath, e)
                return
            size = len(body)

        qs = urlencode({"type": ev_type, "path": relpath, "size": size})
        url = f"{self.push_url}/api/file-agent/push?{qs}"
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/octet-stream")
        if self.token:
            req.add_header("X-Agent-Token", self.token)

        # 일시적 장애(backend 재시작/엣지 미활성)에 대비해 짧게 재시도.
        last_err: Exception | None = None
        for attempt in range(3):
            try:
                with _url_open(req, timeout=30) as resp:
                    log.info("push OK [%s] %s → HTTP %s", ev_type, relpath, resp.getcode())
                    return
            except urllib.error.HTTPError as he:
                # 404 = 활성 push 엣지 없음(아직 미활성). 재시도해도 동일하므로 한 번만 알리고 종료.
                if he.code == 404:
                    log.info("push 대기 [%s] %s — 활성 push 엣지 없음(다음 보정 스캔 때 다시 시도)", ev_type, relpath)
                    self._failed(abspath)
                    return
                last_err = he
            except Exception as e:  # noqa: BLE001
                last_err = e
            time.sleep(1.0 * (attempt + 1))
        if last_err:
            raise last_err


# ============================================================================
#  WsClient : WS 모드(양방향). backend 와 WebSocket 으로 연결.
#   - 데몬→backend: file_begin(text) + 바이트(binary 256KB 청크) + file_end(text)
#   - backend→데몬: set_watch_dir(감시폴더 변경) / set_listen(포트 변경)
#   - 데몬이 outbound 연결 → 내부/외부망(NAT) 무관. 끊기면 지수백오프 재연결.
#   - websocket-client 라이브러리 필요 (pip install websocket-client).
# ============================================================================
class WsClient(threading.Thread):
    CHUNK = 256 * 1024

    # 오퍼(file_offer) 응답 대기 시간(초). 백엔드가 오퍼를 모르는 구버전이면
    # 응답이 없으므로 타임아웃 후 그냥 전송한다(완전 하위호환).
    # 10s → 3s: 응답 유실 상황에서 전송자당 최악 지연을 줄임 (2026-07-07 오퍼 무응답 이슈).
    OFFER_TIMEOUT = 3.0

    def __init__(self, ws_base: str, token: str, runtime: "Runtime", cfg: "Config | None" = None,
                 shared_q=None, idx: int = 0, pool: "WsClientPool | None" = None):
        super().__init__(daemon=True)
        self.idx = idx
        self.pool = pool
        # 오퍼 협상용 대기 이벤트/판정 (같은 세션으로 응답이 돌아온다)
        self._offer_waits: dict[str, threading.Event] = {}
        self._offer_verdicts: dict[str, str] = {}
        self._offer_timeout_count = 0
        self._offer_reply_logged = 0
        base = ws_base.rstrip("/")
        if base.startswith("https://"):
            wsbase = "wss://" + base[len("https://"):]
        elif base.startswith("http://"):
            wsbase = "ws://" + base[len("http://"):]
        else:
            wsbase = base
        q = urlencode({"token": token}) if token else ""
        self.ws_url = wsbase + "/api/file-agent/ws" + (("?" + q) if q else "")
        # 로그용 — 토큰은 절대 기록하지 않는다(로그는 설치 폴더에 남고 지원 요청 때 밖으로 나간다).
        self._log_url = wsbase + "/api/file-agent/ws" + ("?token=***" if token else "")
        # 프리플라이트는 http(s) 로 호출하므로 원본 http base 를 보관한다.
        if base.startswith(("http://", "https://")):
            self.http_base = base
        elif base.startswith("wss://"):
            self.http_base = "https://" + base[len("wss://"):]
        elif base.startswith("ws://"):
            self.http_base = "http://" + base[len("ws://"):]
        else:
            self.http_base = "http://" + base
        self.token = token
        self.runtime = runtime
        self.cfg = cfg
        self._q: "queue.Queue[tuple | None]" = shared_q if shared_q is not None else queue.Queue()
        self._ws = None
        self._connected = threading.Event()
        self._welcome = threading.Event()   # 이번 연결에서 welcome(기능 협상)을 받았는지
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        # send 타임아웃(초). 백엔드 정체로 TCP 송신버퍼가 차도 send 가 무한 블록되지 않게 한다.
        self.send_timeout: float = float(getattr(cfg, "ws_send_timeout", 60.0)) if cfg else 60.0

    def enqueue(self, ev_type: str, relpath: str, abspath: str | None) -> None:
        self._q.put((ev_type, relpath, abspath))

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)
        try:
            if self._ws is not None:
                self._ws.close()
        except Exception:  # noqa: BLE001
            pass

    def run(self) -> None:
        try:
            import websocket  # websocket-client
        except ImportError:
            log.error("ws_enabled=true 이지만 websocket-client 가 없습니다.  pip install websocket-client")
            return
        log.info("WS 모드 활성: %s", self._log_url)
        threading.Thread(target=self._sender_loop, daemon=True).start()
        backoff = 1.0
        while not self._stop.is_set():
            # ── 프리플라이트 게이트 ──
            # 양방향 도달성(에이전트→SeaweedFS, 백엔드→에이전트 등)이 확인돼야 WS 를 연다.
            # 실패하면 WS 를 열지 않고 백오프 후 재점검(무작정 WS 재연결 방지).
            try:
                passed = self._preflight()
            except Exception as e:  # noqa: BLE001  여기서 예외가 새면 이 스레드가 조용히 죽어 영영 연결하지 않는다
                log.warning("프리플라이트 점검 중 오류: %s", e)
                passed = False
            if not passed:
                log.info("프리플라이트 미통과 — %.0fs 후 재점검 (WS 미연결)", backoff)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            backoff = 1.0
            try:
                self._ws = websocket.WebSocketApp(
                    self.ws_url,
                    header=[f"X-Agent-Token: {self.token}"] if self.token else [],
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_close=self._on_close,
                    on_error=self._on_error,
                )
                self._ws.run_forever(ping_interval=20, ping_timeout=10)
            except Exception as e:  # noqa: BLE001
                log.warning("WS 연결 오류: %s", e)
            self._connected.clear()
            if self._stop.is_set():
                break
            log.info("WS 재연결 %.0fs 후... (재연결 전 프리플라이트 재점검)", backoff)
            self._stop.wait(backoff)
            backoff = min(backoff * 2, 30.0)

    def _preflight(self) -> bool:
        """WS 를 열기 전 도달성을 확인한다.
          1) 에이전트 → SeaweedFS(직접): cfg.s3_endpoint 로 TCP 도달. direct 모드만 — backend 모드는
             파일을 WS 로 백엔드에 넘기고 S3 적재는 백엔드가 하므로 에이전트가 S3 에 닿을 필요가 없다.
          2) 에이전트 → 백엔드          : 프리플라이트 요청이 도달하는지(= 호출 성공).
          3) 백엔드 → 에이전트:port/health : 백엔드가 응답으로 알려줌(backendToAgent). 참고값 — 게이트 아님.
             WS 는 에이전트가 먼저 연결하므로 역방향이 필요 없고, 외부망(NAT 뒤)에선 원래 막혀 있다.
          4) 백엔드 → SeaweedFS          : 백엔드가 응답으로 알려줌(backendToSeaweed).
        1·2·4 가 통과하면 True. cfg 없거나 preflight_enabled=false 면 점검 생략(True).
        (2026-09-15 전에는 1·3 도 게이트여서 외부망에선 WS 를 영원히 못 열었다.)"""
        cfg = self.cfg
        if cfg is None or not getattr(cfg, "preflight_enabled", True):
            return True

        # 1) 에이전트 → SeaweedFS 직접 도달성 (direct 모드만)
        if cfg.s3_endpoint and cfg.s3_direct_enabled:
            sh, sp = _split_host_port(cfg.s3_endpoint, 80)
            if not _tcp_reachable(sh, sp, timeout=3.0):
                log.warning("프리플라이트: 에이전트→SeaweedFS 도달 실패 (%s)", cfg.s3_endpoint)
                return False
            log.info("프리플라이트: 에이전트→SeaweedFS OK (%s)", cfg.s3_endpoint)

        # 2~4) 백엔드 프리플라이트 호출 (역방향 점검은 백엔드가 수행해 결과를 돌려줌)
        backend_host, _ = _split_host_port(self.http_base, 80)
        adv_host = cfg.advertise_host or _detect_local_ip(backend_host)
        params = {"host": adv_host, "port": str(cfg.port)}
        # s3_endpoint 는 direct 모드 전용 값이다. backend 모드에선 S3 적재를 백엔드가 캔버스 노드 주소로 하므로
        # 여기 남아 있는 값은 무관하다. 그런데도 넘기면 백엔드가 그 주소 도달성을 검사하고, 못 닿으면
        # backendToSeaweed=false 가 되어 WS 를 영원히 열지 않는다(다른 사이트 백엔드에 붙을 때 실제로 막힘).
        if cfg.s3_endpoint and cfg.s3_direct_enabled:
            params["s3Endpoint"] = cfg.s3_endpoint
        url = self.http_base + "/api/file-agent/preflight?" + urlencode(params)
        try:
            req = urllib.request.Request(url, method="GET")
            if self.token:
                req.add_header("X-Agent-Token", self.token)
            with _url_open(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            log.warning("프리플라이트: 에이전트→백엔드 호출 실패 (%s) — %s", url, e)
            return False

        # 백엔드의 ok 는 구버전에서 backendToAgent 까지 묶여 있어 그대로 믿지 않는다 — 4) 만 게이트로 본다.
        # backendToSeaweed 가 null(= s3Endpoint 안 보냄)이면 통과.
        ok = data.get("backendToSeaweed") is not False
        log.info("프리플라이트: 통과=%s (backendToSeaweed=%s, backendToAgent=%s[참고], 백엔드 ok=%s, advHost=%s:%s)",
                 ok, data.get("backendToSeaweed"), data.get("backendToAgent"), data.get("ok"), adv_host, cfg.port)
        return ok

    def _on_open(self, ws) -> None:
        # ★ 멈춤 방지 핵심: 소켓에 send 타임아웃을 건다.
        # 백엔드가 대량 파일 처리에 밀려 소켓을 읽지 못하면 TCP 버퍼가 가득 차는데,
        # 타임아웃이 없으면 send() 가 영원히 블록돼 데몬 전체가 멈춘 것처럼 보인다.
        # 타임아웃 초과 시 예외 → _sender_loop 가 연결을 끊고 재연결 + 파일 재전송한다.
        try:
            if ws.sock is not None:
                ws.sock.settimeout(self.send_timeout)
        except Exception as e:  # noqa: BLE001
            log.debug("WS 소켓 타임아웃 설정 실패(무시): %s", e)
        # ★ 전송은 welcome(ack 지원 여부)을 받은 뒤 시작한다. 먼저 보내면 ack 모드가 꺼진 채
        #   나간 파일은 원장에 기록되지 않아 재기동 때마다 다시 보낸다.
        #   welcome 을 보내지 않는 구버전 백엔드를 위해 2초 뒤에는 그냥 시작한다.
        self._welcome.clear()
        ws_ref = ws

        def _open_gate():
            self._welcome.wait(2.0)
            if self._ws is ws_ref and not self._stop.is_set():
                self._connected.set()

        threading.Thread(target=_open_gate, daemon=True, name=f"ws-gate{self.idx}").start()
        log.info("WS 연결됨: %s (send_timeout=%.0fs)", self._log_url, self.send_timeout)

    def _on_close(self, ws, code, msg) -> None:
        self._connected.clear()
        log.info("WS 연결 종료 (code=%s)", code)

    def _on_error(self, ws, err) -> None:
        log.debug("WS 에러: %s", err)

    def _on_message(self, ws, message) -> None:
        # backend → 데몬 명령 처리
        try:
            m = json.loads(message)
        except Exception:  # noqa: BLE001
            return
        t = m.get("type", "")
        if t in ("set_watch_dir", "set_watch_dirs"):
            # watchDir(단수 문자열, ';' 로 여러 폴더) 또는 watchDirs(배열).
            # watchDirs 배열 항목은 문자열 또는 {dir, label, recursive, 필터키...} 객체 —
            # 객체로 오면 노드별 필터/수집모드까지 함께 적용된다.
            # ★ 적용은 별도 스레드에서: 수신 스레드가 스캔에 블록되면 ping 응답을 놓쳐
            #   연결이 끊기고 → 재연결 → 재전송 → 재적용… 폭풍이 생긴다. (동일 구성은 noop)
            wd = str(m.get("watchDir", "")).strip()
            wds = m.get("watchDirs")
            requested_sync_mode = str(m.get("syncMode", "")).strip().lower()
            if requested_sync_mode not in ("speed", "mirror"):
                requested_sync_mode = ""
            reconcile_id = str(m.get("reconcileId", "")).strip()

            def _apply_watch_cmd():
                try:
                    if requested_sync_mode and self.runtime.cfg.sync_mode != requested_sync_mode:
                        previous_mode = self.runtime.cfg.sync_mode
                        self.runtime.cfg.sync_mode = requested_sync_mode
                        log.info("WS: Teresa syncMode 적용: %s → %s", previous_mode, requested_sync_mode)
                    if wds:  # 명시적 배열로 온 경우 (str|dict 혼용 허용 — dict 는 그대로 전달)
                        parts = []
                        for p in wds:
                            if isinstance(p, dict):
                                if str(p.get("dir") or p.get("path") or "").strip():
                                    parts.append(p)
                            elif str(p).strip():
                                parts.append(str(p).strip())
                        result = self.runtime.swap_watches(parts)
                    elif wd:
                        result = self.runtime.apply_watch_spec(wd)
                    else:
                        return
                    status = result.get("status")
                    if status == "noop":
                        log.debug("WS: set_watch_dirs 동일 구성 — noop")
                    else:
                        log.info("WS: backend set_watch_dir(s) 적용 → %s", result)
                    if status in ("ok", "noop"):
                        # 이제 감시 범위는 백엔드가 정한 값이다 — 원장 정리를 허용한다.
                        self.runtime.scope_ready = True
                        # 구성은 같아도 엣지가 새로 켜졌을 수 있다. 앞서 '받을 노드 없음'으로
                        # 돌아온 파일만 다시 보내게 한다(전체 재스캔은 하지 않음).
                        self.runtime.retry_unmatched()
                    if requested_sync_mode == "mirror" and reconcile_id:
                        self.runtime.reconcile_existing(reconcile_id)
                except Exception as e:  # noqa: BLE001
                    log.warning("set_watch_dir(s) 실패: %s", e)

            threading.Thread(target=_apply_watch_cmd, daemon=True, name="ws-watchcmd").start()
        elif t == "set_listen":
            try:
                port = int(m.get("port", 0) or 0)
            except (TypeError, ValueError):
                port = 0
            host = str(m.get("host", "")).strip()
            if port > 0 or host:
                try:
                    log.info("WS: backend set_listen → port=%s host=%s", port, host)
                    self.runtime.swap_listen(port, advertise_host=host or None)
                except Exception as e:  # noqa: BLE001
                    log.warning("set_listen 실패: %s", e)
        elif t == "welcome":
            # 백엔드 기능 협상: features 에 "ack" 가 있으면 오퍼/ack 무손실 모드 활성.
            feats = set(m.get("features") or [])
            if "ack" in feats and not self.runtime.ack_enabled:
                self.runtime.ack_enabled = True
                log.info("WS: 백엔드 ack/offer 지원 감지 — 무손실 확인응답 모드 활성")
            self._welcome.set()
        elif t == "file_want":
            p = str(m.get("path", ""))
            self._offer_verdicts[p] = "want"
            ev = self._offer_waits.get(p)
            if ev is not None:
                ev.set()
            if self._offer_reply_logged < 3:
                self._offer_reply_logged += 1
                log.info("오퍼 응답 수신 [want] (sender%d): %s", self.idx, p)
        elif t == "file_ack":
            # 백엔드가 적재 완료(stored)/이미 존재(exists)/필터 제외(filtered) 등을 확인.
            p = str(m.get("path", ""))
            result = str(m.get("result", "stored"))
            # 오퍼 응답으로 온 ack: 대기 중인 전송 스레드에 스킵 신호
            if p in self._offer_waits:
                self._offer_verdicts[p] = result
                self._offer_waits[p].set()
                if self._offer_reply_logged < 3:
                    self._offer_reply_logged += 1
                    log.info("오퍼 응답 수신 [%s] (sender%d): %s", result, self.idx, p)
            rec = self.runtime.pending_acks.pop(p) if self.runtime.pending_acks else None
            if result in ("stored", "exists") and rec is not None and self.runtime.ledger is not None:
                # rec = (ev_type, abspath, size, mtime, sent_ts)
                self.runtime.ledger.record(p, rec[2], rec[3])
            elif rec is not None and result != "filtered":
                # unmatched(받을 노드 없음) 등 — 적재되지 않았다. '보낸 것'으로 남겨 두면
                # 재기동 전까지 다시 보내지 않으므로 기억을 지우고 재시도 대상에 올린다.
                self.runtime.note_unmatched(p, rec[1])
        elif t == "pong":
            pass

    def _sender_loop(self) -> None:
        while not self._stop.is_set():
            # 풀 모드: 라벨 큐를 라운드로빈으로 소비(폴더 공정). 단독 모드: 자기 큐.
            item = self.pool.get_next() if self.pool is not None else self._q.get()
            if item is None:
                break
            # 연결될 때까지 대기. 미연결이면 되돌려놓고 잠시 후 재시도(at-least-once).
            if not self._connected.wait(timeout=30.0):
                self._requeue(item)
                time.sleep(1.0)
                continue
            ev_type, relpath, abspath = item
            try:
                self._send_file(ev_type, relpath, abspath)
                if self.pool is not None:
                    self.pool.mark_done(relpath)
            except Exception as e:  # noqa: BLE001
                log.warning("WS 전송 실패 (%s %s): %s — 연결 재수립 후 큐 재시도", ev_type, relpath, e)
                self._requeue(item)
                # 파일 전송 도중 실패(타임아웃 포함)하면 백엔드에 file_begin 만 도착한
                # 반쪽 상태가 남을 수 있으므로 연결을 끊어 상태를 리셋한다(재연결은 run 루프가 수행).
                self._connected.clear()
                try:
                    if self._ws is not None:
                        self._ws.close()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(1.0)

    def _requeue(self, item) -> None:
        """실패 항목 재투입. 풀 모드면 라벨 큐로 되돌린다(포화 시 버리고 보정 스캔이 재수집)."""
        if self.pool is not None:
            self.pool.requeue(item)
            return
        try:
            self._q.put_nowait(item)
        except queue.Full:
            log.warning("재투입 큐 포화 (%s) — 보정 스캔으로 재수집 예정", item[1])

    def _offer(self, relpath: str, size: int, mtime: float) -> str:
        """바이트 전송 전에 백엔드에 필요 여부 질의(file_offer).
        반환: "want"(전송 필요) 또는 ack result("exists"/"stored"/"filtered"/"unmatched").
        응답 타임아웃이면 "want" (구버전 백엔드 하위호환)."""
        ev = threading.Event()
        self._offer_waits[relpath] = ev
        self._offer_verdicts.pop(relpath, None)
        try:
            self._send_text({"type": "file_offer", "path": relpath,
                             "size": size, "mtime": round(mtime, 3)})
            if not ev.wait(timeout=self.OFFER_TIMEOUT):
                # 원인 추적용: 오퍼 무응답이 반복되면 백엔드 응답 경로 문제 — 표본/카운트 로그
                self._offer_timeout_count += 1
                if self._offer_timeout_count <= 3 or self._offer_timeout_count % 200 == 0:
                    log.warning("오퍼 응답 시간초과 #%d (sender%d): %s — 강제 전송으로 진행",
                                self._offer_timeout_count, self.idx, relpath)
                return "want"
            return self._offer_verdicts.pop(relpath, "want")
        finally:
            self._offer_waits.pop(relpath, None)

    def _send_file(self, ev_type: str, relpath: str, abspath: str | None) -> None:
        import websocket
        if ev_type == "deleted" or not abspath:
            self._send_text({"type": "deleted", "path": relpath})
            log.debug("WS 전송 [deleted] %s", relpath)
            return
        try:
            st = os.stat(abspath)
            size = st.st_size
        except OSError as e:
            log.warning("WS 파일 읽기 실패 %s: %s — 스킵", abspath, e)
            return

        # ── 오퍼 협상 (백엔드 지원 시): 이미 적재된 파일은 바이트 전송 자체를 생략 ──
        # 재부팅/재활성화 직후 수만 건 재스캔이 있어도 메타데이터 왕복만 발생 → 대역폭·시간 절약.
        # offer_enabled=false 면 오퍼 왕복을 건너뛰고 곧바로 전송(벌크 초기적재용). ack/원장은 아래에서 그대로 유지.
        if self.runtime.ack_enabled and self.runtime.cfg.offer_enabled:
            verdict = self._offer(relpath, size, st.st_mtime)
            if verdict != "want":
                if verdict in ("exists", "stored") and self.runtime.ledger is not None:
                    self.runtime.ledger.record(relpath, size, st.st_mtime)
                elif verdict != "filtered":
                    self.runtime.note_unmatched(relpath, abspath)
                log.debug("WS 오퍼 스킵 [%s] %s (result=%s)", ev_type, relpath, verdict)
                return

        # ack 모드: ★전송 시작 "전에" pending 등록★ — 소파일은 file_end 직후 수 ms 안에
        # ack 가 도착하는데, 등록이 전송 뒤면 ack 가 pending 을 못 찾아 원장 기록을 놓치고
        # (레이스), 그 파일이 재스캔 때마다 영원히 재전송되는 루프가 생긴다 (2026-07-07 실측).
        if self.runtime.ack_enabled and self.runtime.pending_acks is not None:
            self.runtime.pending_acks.put(relpath, ev_type, abspath, size, st.st_mtime)
        try:
            self._send_text({"type": "file_begin", "path": relpath, "event": ev_type,
                             "size": size, "mtime": round(st.st_mtime, 3)})
            with open(abspath, "rb") as f:
                while True:
                    chunk = f.read(self.CHUNK)
                    if not chunk:
                        break
                    with self._send_lock:
                        self._ws.send(chunk, opcode=websocket.ABNF.OPCODE_BINARY)
            self._send_text({"type": "file_end", "path": relpath})
        except Exception:
            # 전송 실패 시 유령 pending 방지 (재시도는 _sender_loop 가 담당)
            if self.runtime.pending_acks is not None:
                self.runtime.pending_acks.pop(relpath)
            raise
        log.debug("WS 전송 [%s] %s (%d bytes)", ev_type, relpath, size)  # 파일당 로그 → DEBUG (운영 부하 방지)

    def _send_text(self, obj: dict) -> None:
        with self._send_lock:
            self._ws.send(json.dumps(obj, ensure_ascii=False))


# ============================================================================
#  S3Uploader : SeaweedFS(S3) 직접 업로드/삭제 (boto3). 직접모드에서만 사용.
#   - config.json 의 s3_* 값으로 동작. 백엔드를 거치지 않고 에이전트 PC → SeaweedFS.
# ============================================================================
class S3Uploader:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._client = None
        self._lock = threading.Lock()

    def _client_or_none(self):
        if self._client is not None:
            return self._client
        with self._lock:
            if self._client is not None:
                return self._client
            try:
                import boto3
                from botocore.config import Config as BotoConfig
            except ImportError:
                log.error("S3 직접모드이나 boto3 가 없습니다.  pip install boto3")
                return None
            kwargs = {
                "endpoint_url": self.cfg.s3_endpoint,
                "region_name": self.cfg.s3_region,
                "config": BotoConfig(
                    s3={"addressing_style": "path"},  # 경로식 고정 (SeaweedFS/MinIO 필수)
                    retries={"max_attempts": 3, "mode": "standard"},
                ),
            }
            if self.cfg.s3_access_key or self.cfg.s3_secret_key:
                kwargs["aws_access_key_id"] = self.cfg.s3_access_key
                kwargs["aws_secret_access_key"] = self.cfg.s3_secret_key
            try:
                self._client = boto3.client("s3", **kwargs)
                log.info("S3 클라이언트 준비: endpoint=%s bucket=%s", self.cfg.s3_endpoint, self.cfg.s3_bucket)
            except Exception as e:  # noqa: BLE001
                log.error("S3 클라이언트 생성 실패: %s", e)
                return None
            return self._client

    def _key(self, relpath: str) -> str:
        rel = relpath.replace("\\", "/").lstrip("/")
        prefix = self.cfg.s3_path_prefix
        return (prefix + "/" + rel) if prefix else rel

    def put(self, relpath: str, abspath: str) -> bool:
        c = self._client_or_none()
        if c is None:
            return False
        key = self._key(relpath)
        try:
            c.upload_file(abspath, self.cfg.s3_bucket, key)
            log.debug("S3 직접 업로드 OK: %s → s3://%s/%s", relpath, self.cfg.s3_bucket, key)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("S3 직접 업로드 실패 (%s): %s", relpath, e)
            return False


# ============================================================================
#  WsClientPool : 여러 WS 연결을 열어 공유 큐에서 병렬로 전송 (처리량 향상)
#   - 단일 연결(직렬)이 0.3초 고빈도 생성을 못 따라가 백로그→유실되는 문제 완화.
#   - 각 연결은 독립 세션이라 backend 가 세션별 스레드로 병렬 수신한다.
#   - 큐 상한(queue_max) + 중복 방지(inflight) → 서버 장기 다운에도 RAM 고정.
#     큐에서 밀려난 파일은 원장(sent.jsonl)에 없으므로 보정 스캔이 다시 집어든다.
# ============================================================================
class WsClientPool:
    def __init__(self, ws_base: str, token: str, runtime: "Runtime",
                 cfg: "Config | None", n: int):
        self._maxsize = getattr(cfg, "queue_max", 20000) if cfg else 20000
        self.runtime = runtime
        self._inflight: set[str] = set()          # 대기/전송 중 relpath (중복 투입 방지)
        self._inflight_lock = threading.Lock()
        # 폴더(라벨)별 전용 큐 + 라운드로빈 스케줄 — 한 폴더가 큐를 독점해 다른 폴더가 굶는 것을 방지.
        # senders 는 공유하되 get_next 가 라벨 큐를 라운드로빈으로 소비 → 여러 폴더가 동시에 흐른다.
        # (전용 sender 그룹 대신 공유+라운드로빈: 한 폴더가 끝나면 그 여력이 다른 폴더로 자동 이동 → 더 효율적)
        self._queues: "dict[str, collections.deque]" = {}
        self._labels: list[str] = []
        self._rr = 0
        self._total = 0
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self.clients = [WsClient(ws_base, token, runtime, cfg, idx=i, pool=self)
                        for i in range(max(1, n))]
        self._reaper = threading.Thread(target=self._reap_loop, daemon=True,
                                        name="ws-ack-reaper")
        # ── ADR-022 sync_mode=mirror: 삭제 이벤트 전용 채널 ──
        # 업로드 큐(_queues/_total/_maxsize)와 완전히 분리한다. 대량 로컬 삭제(작업자 폴더 정리)가
        # 업로드 처리량을 잠식하면 ADR-019/2026-07-08 에서 확보한 속도 불변식을 어기게 되므로,
        # 별도 상한 큐 + 별도 스레드로 격리한다. ack/원장 계약과 무관한 best-effort 채널 —
        # 큐 포화·전송 실패는 드롭(경고 로그)하고 재시도하지 않는다(soft-delete 특성상 허용되는 손실).
        self._deleted_q: "queue.Queue[str | None]" = queue.Queue(maxsize=100_000)
        self._deleted_sender = threading.Thread(target=self._deleted_sender_loop, daemon=True,
                                                 name="ws-deleted-sender")

    @staticmethod
    def _label_of(relpath: str) -> str:
        """relpath 의 최상위 폴더(= watch_dir 라벨). "루미너스/2026-.../a.jpg" → "루미너스". 없으면 ""."""
        s = (relpath or "").replace("\\", "/").lstrip("/")
        i = s.find("/")
        return s[:i] if i > 0 else ""

    def enqueue(self, ev_type: str, relpath: str, abspath: str | None,
                block: bool = False) -> str:
        """라벨(폴더)별 큐에 투입. 반환: "queued" | "dup"(이미 대기 중) | "full"(포화).
        용량은 전체 합계(_total) 기준. block=True(스캔 경로): 가득이면 자리가 날 때까지 짧게 대기 —
        스캔이 전송 속도에 맞춰 걷는 배압이 되고, 대기가 GIL 을 놓아 수신 스레드가 굶지 않는다."""
        with self._inflight_lock:
            if relpath in self._inflight:
                return "dup"
        label = self._label_of(relpath)
        with self._cv:
            while self._total >= self._maxsize:
                if not block or self._stop.is_set():
                    return "full"
                self._cv.wait(0.5)
            with self._inflight_lock:
                if relpath in self._inflight:
                    return "dup"
                self._inflight.add(relpath)
            self._push(label, (ev_type, relpath, abspath), front=False)
            self._cv.notify()
        return "queued"

    def _push(self, label: str, item, front: bool) -> None:
        """_cv 를 보유한 상태에서 호출. 라벨 큐에 항목을 넣고 _total 증가."""
        q = self._queues.get(label)
        if q is None:
            q = collections.deque()
            self._queues[label] = q
            self._labels.append(label)
        if front:
            q.appendleft(item)
        else:
            q.append(item)
        self._total += 1

    def requeue(self, item) -> None:
        """실패/미연결 항목 재투입 — 해당 라벨 큐 앞쪽 우선. 포화면 버리고 보정 스캔에 위임."""
        with self._cv:
            if self._total >= self._maxsize:
                self.mark_done(item[1])
                # '보낸 것'으로 기억된 채 버려지면 보정 스캔도 건너뛴다 — 기억을 지워야 재수집된다.
                self.runtime.forget_emitted(item[2])
                self.request_rescan()
                log.warning("재투입 큐 포화 (%s) — 보정 스캔으로 재수집 예정", item[1])
                return
            self._push(self._label_of(item[1]), item, front=True)
            self._cv.notify()

    def get_next(self):
        """라벨 큐를 라운드로빈으로 순회해 1건 반환(공정 스케줄). 항목 없으면 대기, 종료 시 None."""
        with self._cv:
            while True:
                if self._stop.is_set():
                    return None
                if self._total > 0 and self._labels:
                    n = len(self._labels)
                    for _ in range(n):
                        label = self._labels[self._rr % n]
                        self._rr += 1
                        q = self._queues.get(label)
                        if q:
                            item = q.popleft()
                            self._total -= 1
                            self._cv.notify()   # 포화 대기 중인 enqueuer 깨우기
                            return item
                self._cv.wait(0.5)

    def mark_done(self, relpath: str) -> None:
        with self._inflight_lock:
            self._inflight.discard(relpath)

    def request_rescan(self) -> None:
        ev = getattr(self.runtime, "rescan_event", None)
        if ev is not None:
            ev.set()

    def _reap_loop(self) -> None:
        """ack 타임아웃 리퍼: 확인응답 없는 전송을 주기적으로 재투입(at-least-once).
        서버가 파일 수신 후 적재 전에 재부팅해도 이 경로로 자동 재전송된다."""
        while not self._stop.is_set():
            self._stop.wait(15.0)
            pa = getattr(self.runtime, "pending_acks", None)
            if pa is None or not self.runtime.ack_enabled:
                continue
            expired = pa.expired()
            requeued = handed_off = 0
            for relpath, ev_type, abspath in expired:
                st = self.enqueue(ev_type, relpath, abspath)
                if st == "full":
                    # 여기서 버리면 '보낸 것'으로 기억된 채 보정 스캔도 건너뛴다 — 기억을 지운다.
                    self.runtime.forget_emitted(abspath)
                    handed_off += 1
                else:
                    requeued += 1
            if handed_off:
                self.request_rescan()
            if expired:
                log.warning("ack 타임아웃 %d건 — 재전송 투입 %d건 / 큐 포화로 보정 스캔 위임 %d건 (남은 대기 %d건)",
                            len(expired), requeued, handed_off, len(pa))

    def start(self) -> None:
        for c in self.clients:
            c.start()
        self._reaper.start()
        self._deleted_sender.start()
        log.info("WS 병렬 전송 활성: 연결 %d개 (폴더별 전용 큐·라운드로빈, 상한 %d, offer=%s, sync_mode=%s)",
                 len(self.clients), self._maxsize,
                 "on" if self.runtime.cfg.offer_enabled else "OFF(벌크 초기적재)",
                 getattr(self.runtime.cfg, "sync_mode", "speed"))

    def stop(self) -> None:
        self._stop.set()
        with self._cv:
            self._cv.notify_all()   # 대기 중인 senders/enqueuers 깨워 종료시킨다
        try:
            self._deleted_q.put_nowait(None)
        except queue.Full:
            pass
        for c in self.clients:
            try:
                c.stop()
            except Exception:  # noqa: BLE001
                pass

    def enqueue_deleted(self, relpath: str) -> None:
        """ADR-022 sync_mode=mirror 전용: 로컬 삭제를 업로드 큐와 완전히 분리된 저우선순위
        채널로 전송 큐에 투입. 대량 삭제가 업로드 처리량을 잠식하지 않는다(§2.5-4)."""
        try:
            self._deleted_q.put_nowait(relpath)
        except queue.Full:
            log.warning("삭제 이벤트 큐 포화 — 드롭(best-effort, 유실 허용): %s", relpath)

    def _deleted_sender_loop(self) -> None:
        """삭제 이벤트 전용 송신 루프. 연결된 아무 sender 로나 {"type":"deleted"} 텍스트 프레임만
        보낸다(바이트 전송 없음 — 파일 큐/스로틀과 무관하게 가볍다). ack/원장 계약 밖의
        best-effort 채널이라 실패해도 무손실 계약에 영향 없음 — 실패는 경고 로그 후 드롭."""
        while not self._stop.is_set():
            try:
                relpath = self._deleted_q.get(timeout=1.0)
            except queue.Empty:
                continue
            if relpath is None:
                break
            sent = False
            for _ in range(10):  # 연결된 sender 를 짧게 재시도(최대 ~5초) — 재연결 중 유실 최소화
                if self._stop.is_set():
                    break
                for c in self.clients:
                    if c._connected.is_set():
                        try:
                            c._send_text({"type": "deleted", "path": relpath})
                            sent = True
                        except Exception as e:  # noqa: BLE001
                            log.debug("삭제 이벤트 전송 실패(재시도 예정): %s — %s", relpath, e)
                        break
                if sent:
                    break
                self._stop.wait(0.5)
            if not sent:
                log.warning("삭제 이벤트 전송 포기(연결 없음, best-effort): %s", relpath)


def _mirror_enqueue_deleted(cfg: "Config", ws_client, relpath: str) -> None:
    """ADR-022 공통 게이트: sync_mode=mirror 일 때만 삭제 이벤트를 저우선순위 채널로 전송한다.
    speed(기본)에서는 완전히 no-op — 기존 동작과 100% 동일. 실시간(watchdog, StabilityWorker.emit_deleted)
    과 배치(원장 컴팩션 드롭, Rescanner) 양쪽에서 공통으로 호출되는 단일 진입점이라 두 경로의
    동작이 항상 일치한다. ws_client 가 없거나(push/direct 모드) enqueue_deleted 를 지원하지 않으면
    (구버전 풀 등) 조용히 무시 — 이 채널은 best-effort 라 실패해도 업로드 무손실 계약에 영향 없음."""
    if getattr(cfg, "sync_mode", "speed") != "mirror":
        return
    if ws_client is not None and hasattr(ws_client, "enqueue_deleted"):
        ws_client.enqueue_deleted(relpath)


# ============================================================================
#  감시기 : 파일이 "안정"되면(쓰기 완료) 이벤트로 승격
# ============================================================================
class StabilityWorker(threading.Thread):
    # _emitted 캐시 상한 — 수백만 파일 환경에서도 RAM 이 무한히 늘지 않게 한다.
    _EMITTED_MAX = 200_000

    def __init__(self, cfg: Config, store: EventStore, push_client: "PushClient | None" = None,
                 ws_client=None, s3_uploader: "S3Uploader | None" = None,
                 ledger: "SentLedger | None" = None, pending_acks: "PendingAcks | None" = None,
                 rescan_event: "threading.Event | None" = None):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.store = store
        self.push_client = push_client
        self.ws_client = ws_client            # WsClientPool (또는 None)
        self.s3_uploader = s3_uploader
        self.ledger = ledger                  # 전송 완료 원장 (sent.jsonl)
        self.pending_acks = pending_acks      # ack 대기 레지스트리
        self.rescan_event = rescan_event      # 큐 포화 시 보정 스캔 조기 트리거
        self._lock = threading.Lock()
        self._pending: dict[str, dict] = {}    # abspath -> {size, last_change}
        self._emitted: dict[str, tuple] = {}   # abspath -> (size, mtime) 마지막 발행값(중복방지)
        self._overflow_warned = 0.0
        self._stop = threading.Event()

    def touch(self, abspath: str, ev_type: str, force: bool = False) -> None:
        if os.path.isdir(abspath):
            return
        if not self.cfg.file_allowed(abspath):
            return  # 이름 기반 필터(폴더/파일명/확장자)에 걸림 — 처리 대상 아님
        # ── 스캔(existing) 파일은 안정화 대기 생략, 즉시 발행 ──
        # 초기/보정 스캔이 집는 파일은 이미 쓰기가 끝난 파일이다. 수백만 소파일을
        # pending 에 쌓으면 0.3s 순회(전건 stat)가 병목이 되어 발행이 초당 몇 건으로
        # 떨어지므로(2026-07-07 100KB×210만 테스트 실측), 스캔 경로는 곧장 _emit 한다.
        # 드물게 스캔 순간 쓰기 중인 파일이 섞여도 백엔드 크기 검증(불일치 폐기→재전송)과
        # 후속 modified 이벤트(안정화 경로)가 보정한다.
        if ev_type == "existing":
            self._emit(abspath, ev_type, force=force)
            return
        with self._lock:
            self._pending[abspath] = {"size": -1, "last_change": time.time(), "type": ev_type}

    def emit_deleted(self, abspath: str) -> None:
        """캐시 정리는 항상 수행(동일 경로 재생성 시 새 파일로 다시 추적되게 함) — sync_mode 무관.
        ADR-022: sync_mode=mirror 일 때만 삭제 이벤트를 저우선순위 채널로 백엔드에 전송한다.
        speed(기본)에서는 기존과 100% 동일하게 아무 것도 전송하지 않는다(무시)."""
        with self._lock:
            self._pending.pop(abspath, None)
            self._emitted.pop(abspath, None)
        if getattr(self.cfg, "sync_mode", "speed") != "mirror":
            log.debug("로컬 삭제 감지 — 무시(sync_mode=speed): %s", abspath)
            return
        if not self.cfg.file_allowed(abspath):
            return  # 수집 조건 밖 파일의 삭제는 통지하지 않음(생성/수정과 동일 기준)
        relpath = self.cfg.make_relpath(abspath)
        if not relpath:
            return  # 감시 폴더 밖
        _mirror_enqueue_deleted(self.cfg, self.ws_client, relpath)
        log.debug("삭제 이벤트 전송 큐 투입(sync_mode=mirror): %s", relpath)

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            time.sleep(0.3)
            now = time.time()
            ready: list[tuple[str, str]] = []
            with self._lock:
                for path, info in list(self._pending.items()):
                    if not os.path.exists(path):
                        self._pending.pop(path, None)
                        continue
                    try:
                        size = os.path.getsize(path)
                    except OSError:
                        continue
                    if size != info["size"]:
                        info["size"] = size
                        info["last_change"] = now
                        continue
                    # 크기 변화 없음 + 조용한 시간 경과 + 열기 가능하면 확정
                    if (now - info["last_change"]) >= self.cfg.quiet_period_seconds \
                            and self._can_open(path):
                        ready.append((path, info["type"]))
                        self._pending.pop(path, None)

            for path, ev_type in ready:
                self._emit(path, ev_type)

    @staticmethod
    def _can_open(path: str) -> bool:
        try:
            with open(path, "rb"):
                return True
        except OSError:
            return False

    def _emit(self, abspath: str, ev_type: str, force: bool = False) -> None:
        try:
            st = os.stat(abspath)
        except OSError:
            return
        # ── 용량 필터: 크기가 확정된 시점(안정화 후)에 이상/이하 제외 판정 ──
        if not self.cfg.file_allowed(abspath, size=st.st_size):
            return
        key = (st.st_size, int(st.st_mtime))
        with self._lock:
            if not force and self._emitted.get(abspath) == key:
                return  # 동일 내용 재발행 방지
            self._emitted[abspath] = key
            while len(self._emitted) > self._EMITTED_MAX:
                self._emitted.pop(next(iter(self._emitted)))
        relpath = self.cfg.make_relpath(abspath)
        if not relpath:
            return  # 감시 폴더 밖이면 무시
        # ── 전송 원장 대조: 이미 적재 확인된 파일은 재전송하지 않음 (재부팅/재스캔 무손실·무중복) ──
        if not force and self.ledger is not None and self.ledger.has(relpath, st.st_size, st.st_mtime):
            return
        # ── ack 대기 중인 파일은 중복 투입하지 않음 ──
        if self.pending_acks is not None and self.pending_acks.contains(relpath):
            return
        sha = self._sha256(abspath) if self.cfg.compute_sha256 else None

        # WS 모드: 상한 큐에 투입.
        #  - 스캔(existing) 경로: block=True — 큐가 차면 자리 날 때까지 대기(배압).
        #    스캔이 전송 속도에 맞춰 진행되므로 드롭·재스캔 낭비와 CPU 독점이 없다.
        #  - 실시간(watchdog) 경로: 비차단 — 가득 차면 버리고 보정 스캔이 재수집.
        if self.ws_client is not None:
            status = self.ws_client.enqueue(ev_type, relpath, abspath,
                                            block=(ev_type == "existing"))
            if status == "full":
                with self._lock:
                    self._emitted.pop(abspath, None)
                if self.rescan_event is not None:
                    self.rescan_event.set()
                now = time.time()
                if now - self._overflow_warned > 30:
                    self._overflow_warned = now
                    log.warning("전송 큐 포화(%s) — 이벤트 보류, 보정 스캔으로 재수집 예정", relpath)
                return
            if status == "dup":
                return  # 이미 큐에 대기 중 — 저널/재전송 불필요
        ev = self.store.append(ev_type, relpath, st.st_size, st.st_mtime, sha)
        log.debug("이벤트 #%d %s  %s (%d bytes)", ev["seq"], ev_type, relpath, st.st_size)  # 파일당 로그 → DEBUG
        # PUSH 모드: backend 로 파일 바이트 직접 전송
        if self.push_client is not None:
            self.push_client.enqueue(ev_type, relpath, abspath)
        # 직접 모드: 백엔드를 거치지 않고 SeaweedFS(S3) 에 바로 업로드. 성공 시 원장 기록.
        if self.s3_uploader is not None:
            if self.s3_uploader.put(relpath, abspath):
                if self.ledger is not None:
                    self.ledger.record(relpath, st.st_size, st.st_mtime)
            else:
                # 실패한 파일을 '보낸 것'으로 기억하면 재기동 전까지 다시 올리지 않는다.
                # 전수 재스캔을 곧바로 깨우지는 않는다(S3 장애 중 스캔 폭주 방지) — 주기 보정 스캔에 맡긴다.
                with self._lock:
                    self._emitted.pop(abspath, None)

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()


class _Handler(FileSystemEventHandler):
    def __init__(self, worker: StabilityWorker):
        self.worker = worker

    def on_created(self, event):
        if not event.is_directory:
            self.worker.touch(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self.worker.touch(event.src_path, "modified")

    def on_moved(self, event):
        # 드래그-드롭 등으로 디렉터리 안으로 이동된 경우 dest 를 새 파일로 취급
        if not event.is_directory:
            self.worker.touch(event.dest_path, "moved")

    def on_deleted(self, event):
        # 파일 삭제 → 추적 캐시만 정리 (적재 전용: 삭제는 스토리지에 반영 안 함).
        if not event.is_directory:
            self.worker.emit_deleted(event.src_path)


# ============================================================================
#  Runtime : 런타임에 swap 가능한 자원(observer/worker/cfg.watch_dir) 보관소.
#  /control/watch_dir POST 가 호출되면 observer/worker 를 안전하게 교체한다.
# ============================================================================
class Runtime:
    def __init__(self, cfg: "Config", store: "EventStore", push_client: "PushClient | None" = None,
                 ws_client=None, s3_uploader: "S3Uploader | None" = None,
                 ledger: "SentLedger | None" = None):
        self.cfg = cfg
        self.store = store
        self.push_client = push_client
        self.ws_client = ws_client  # WS 모드: 생성 후 runtime.ws_client = ... 로 주입(순환 회피)
        self.s3_uploader = s3_uploader  # 직접 모드: SeaweedFS 직접 업로드
        self.ledger = ledger                                  # 전송 완료 원장 (sent.jsonl)
        self.pending_acks = PendingAcks(cfg.ack_timeout_seconds)  # ack 대기 레지스트리
        self.ack_enabled = False                              # welcome features 협상 결과
        self.rescan_event = threading.Event()                 # 보정 스캔 조기 트리거
        self._last_reconcile_id = ""                         # mirror 전체 대조 명령 중복 제거
        self.worker: "StabilityWorker | None" = None
        self.observer = None  # watchdog Observer
        self.httpd = None          # AgentHTTPServer (listen 포트 동적 교체용)
        self.http_thread = None    # serve_forever 스레드
        self._lock = threading.Lock()
        # 감시 범위가 확정됐는지. 백엔드가 감시 폴더를 내려주는 모드에서는 첫 set_watch_dirs 전까지
        # 로컬 config 의 폴더가 임시값일 뿐이라, 그 기준으로 원장을 정리하면 멀쩡한 기록이 지워진다.
        # main 에서 모드에 맞게 정한다(직접 모드 등은 처음부터 True).
        self.scope_ready = True
        # 백엔드가 '받을 노드 없음(unmatched)'으로 돌려보낸 파일 — 엣지가 켜지면 다시 보낸다.
        self._unmatched: dict[str, str] = {}   # relpath -> abspath
        self._unmatched_lock = threading.Lock()
        self._unmatched_overflow = False
        self._unmatched_logged = 0.0
        self._unmatched_seen = 0                # 마지막 요약 로그 이후 새로 보류된 건수
        self._last_full_retry = 0.0
        self._unscheduled: list = []            # 실시간 감시를 걸지 못한 폴더(아직 없음 등)
        self.app_dir = ""                       # 설치 폴더 — 여기 안에는 감시 폴더를 자동으로 만들지 않는다

    # ---- 재전송 보조 ----
    def forget_emitted(self, abspath: "str | None") -> None:
        """이 파일을 '이미 발행함' 기억에서 지운다 → 다음 스캔 때 다시 발행된다."""
        w = self.worker
        if w is None or not abspath:
            return
        with w._lock:
            w._emitted.pop(abspath, None)

    def note_unmatched(self, relpath: str, abspath: "str | None") -> None:
        """백엔드가 '받을 노드 없음' 등으로 돌려보낸 파일을 보류 목록에 둔다.

        '보낸 것' 기억(_emitted)은 그대로 둔다 — 지우면 보정 스캔마다 같은 파일을 끝없이
        다시 오퍼한다. 다시 보내는 때는 백엔드가 감시 구성을 새로 내려줄 때(엣지 활성화)다.
        """
        if not abspath:
            return
        now = time.time()
        with self._unmatched_lock:
            if len(self._unmatched) < 100_000:
                self._unmatched[relpath] = abspath
            else:
                self._unmatched_overflow = True
            self._unmatched_seen += 1
            if now - self._unmatched_logged < 60:
                return
            self._unmatched_logged = now
            seen, self._unmatched_seen = self._unmatched_seen, 0
            pending = len(self._unmatched)
        log.warning("받을 노드가 없어 보류 중인 파일 %d건 (최근 %d건 추가) — 캔버스 노드의 Token·WatchDir·"
                    "엣지 활성화를 확인하세요. 엣지가 켜지면 자동으로 다시 보냅니다.", pending, seen)

    def unmatched_count(self) -> int:
        with self._unmatched_lock:
            return len(self._unmatched)

    def retry_unmatched(self) -> None:
        """보류된 파일만 다시 발행한다. 백엔드는 set_watch_dirs 를 연결마다(최대 ws_senders 번) 보내므로
        처음 받은 호출이 목록을 가져가고 나머지는 빈 목록으로 끝난다."""
        now = time.time()
        with self._unmatched_lock:
            items = list(self._unmatched.values())
            self._unmatched.clear()
            overflow = self._unmatched_overflow
            if overflow and now - self._last_full_retry < 600:
                overflow = False          # 넘친 경우의 전체 재발행은 10분에 한 번만
            if overflow:
                self._unmatched_overflow = False
                self._last_full_retry = now
        worker = self.worker
        if worker is None:
            return
        if overflow:
            # 목록 상한을 넘겨 일부를 기억하지 못했다 — 전체 기억을 비우고 보정 스캔으로 다시 대조한다.
            with worker._lock:
                worker._emitted.clear()
            log.info("보류 파일이 너무 많아 전체를 다시 대조합니다")
            self.rescan_event.set()
        if not items:
            return
        log.info("받을 노드가 없어 보류됐던 파일 %d건을 다시 보냅니다", len(items))

        def _retry():
            for ap in items:
                if self.worker is not worker:
                    return  # 감시 구성이 바뀌었다 — 새 구성의 초기 스캔이 다시 집는다
                self.forget_emitted(ap)
                worker.touch(ap, "existing")

        threading.Thread(target=_retry, daemon=True, name="unmatched-retry").start()

    def _schedule_watch(self, w) -> bool:
        """이미 시작된 observer 에 폴더 하나를 건다. 실패하면 남은 흔적을 지우고 False.

        watchdog 는 시작된 observer 에서만 schedule() 안에서 폴더를 연다. 그래서 observer 를
        먼저 시작해 두고 폴더마다 따로 걸어야, 볼 수 없는 폴더 하나가 전체를 멈추지 않는다.
        """
        if not os.path.isdir(w.path):
            return False
        handler = _Handler(self.worker)
        try:
            self.observer.schedule(handler, w.path, recursive=w.recursive)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("실시간 감시를 걸지 못했습니다(폴더가 보이면 자동 재시도): %s — %s", w.path, e)
            try:
                self.observer.remove_handler_for_watch(handler, ObservedWatch(w.path, recursive=w.recursive))
            except Exception:  # noqa: BLE001
                pass
            return False

    def schedule_pending_watches(self) -> None:
        """부팅 때 없던(볼 수 없던) 감시 폴더가 보이면 실시간 감시를 건다(Rescanner 가 주기적으로 호출)."""
        with self._lock:
            if not self._unscheduled or self.observer is None or self.worker is None:
                return
            still = []
            for w in self._unscheduled:
                if self._schedule_watch(w):
                    log.info("감시 시작(지연): %s — 이제 폴더가 보입니다", w.path)
                    self.rescan_event.set()
                else:
                    still.append(w)
            self._unscheduled = still

    def unscheduled_paths(self) -> list[str]:
        return [w.path for w in list(self._unscheduled)]

    def reconcile_existing(self, reconcile_id: str) -> None:
        """mirror Binding 활성화 시 현재 디렉터리 전체를 원장과 무관하게 1회 재제안한다.
        같은 명령이 병렬 WS 연결마다 반복 수신돼도 reconcile_id로 중복 실행하지 않는다."""
        reconcile_id = str(reconcile_id or "").strip()
        if not reconcile_id:
            return
        with self._lock:
            if reconcile_id == self._last_reconcile_id:
                return
            self._last_reconcile_id = reconcile_id
            scan_worker = self.worker
        if scan_worker is None:
            return

        def _scan():
            scanned = 0
            for _rel, ap_full, _size, _mtime in self.cfg.iter_existing():
                if self.worker is not scan_worker:
                    log.info("mirror 전체 대조 중단(감시 구성 교체) — %d개 투입", scanned)
                    return
                scan_worker.touch(ap_full, "existing", force=True)
                scanned += 1
            log.info("mirror 초기 전체 대조 완료: %d개 파일 재제안 (reconcileId=%s)",
                     scanned, reconcile_id)

        threading.Thread(target=_scan, daemon=True, name="mirror-reconcile").start()

    def attach_http_server(self, httpd, thread) -> None:
        """main 에서 띄운 HTTP 서버를 런타임이 관리하도록 등록(포트 동적 교체 위해)."""
        self.httpd = httpd
        self.http_thread = thread

    def swap_listen(self, port: int, advertise_host: str | None = None) -> dict:
        """런타임에 HTTP 리슨 포트를 교체한다. bind host 는 cfg.host(보통 0.0.0.0) 유지.
        advertise_host(노드 Address)는 프리플라이트 역방향 점검용으로만 갱신한다(bind 와 무관)."""
        with self._lock:
            changed = {}
            if advertise_host and advertise_host != self.cfg.advertise_host:
                self.cfg.advertise_host = advertise_host
                changed["advertise_host"] = advertise_host
            try:
                port = int(port)
            except (TypeError, ValueError):
                port = 0
            if port > 0 and port != self.cfg.port:
                previous = self.cfg.port
                old = self.httpd
                try:
                    if old is not None:
                        old.shutdown()
                        old.server_close()
                except Exception as e:  # noqa: BLE001
                    log.warning("기존 HTTP 서버 종료 실패(무시): %s", e)
                try:
                    new = AgentHTTPServer((self.cfg.host, port), self.cfg, self.store, runtime=self)
                except OSError as e:
                    log.error("새 포트 bind 실패 %s:%s — 기존 포트로 복구: %s", self.cfg.host, port, e)
                    try:
                        recover = AgentHTTPServer((self.cfg.host, previous), self.cfg, self.store, runtime=self)
                        t = threading.Thread(target=recover.serve_forever, daemon=True)
                        t.start()
                        self.httpd = recover
                        self.http_thread = t
                    except Exception:  # noqa: BLE001
                        log.error("기존 포트 복구도 실패 — HTTP 서버 없음 상태")
                    return {"status": "error", "reason": f"bind failed: {e}", "port": self.cfg.port}
                t = threading.Thread(target=new.serve_forever, daemon=True)
                t.start()
                self.httpd = new
                self.http_thread = t
                self.cfg.port = port
                changed["port"] = port
                log.info("listen 포트 변경: %s → %s (bind host=%s)", previous, port, self.cfg.host)
                ensure_firewall_port(port)  # 바뀐 포트를 방화벽에 자동 허용(관리자 권한 시)
            if not changed:
                return {"status": "noop", "port": self.cfg.port, "advertise_host": self.cfg.advertise_host}
            return {"status": "ok", "port": self.cfg.port,
                    "advertise_host": self.cfg.advertise_host, **changed}

    def start(self) -> None:
        """초기 observer/worker 부팅."""
        with self._lock:
            self._start_unlocked()

    def _start_unlocked(self) -> None:
        for w in self.cfg.watches:
            if self.app_dir and _is_inside(w.path, self.app_dir):
                # 설치 폴더 안에 폴더를 만들면 설치 폴더 권한 잠금이 막힌다(옛 기본값 C:/file-agent/watch).
                if not os.path.isdir(w.path):
                    log.warning("설치 폴더 안의 감시 폴더는 자동으로 만들지 않습니다: %s", w.path)
                continue
            try:
                os.makedirs(w.path, exist_ok=True)
            except OSError as e:
                log.warning("감시 폴더를 지금은 만들 수 없습니다(나중에 다시 확인): %s — %s", w.path, e)
        self._unscheduled = []
        self.worker = StabilityWorker(self.cfg, self.store, self.push_client, self.ws_client,
                                      self.s3_uploader, ledger=self.ledger,
                                      pending_acks=self.pending_acks,
                                      rescan_event=self.rescan_event)
        self.worker.start()
        # 시작 시 기존 파일 announce (선택) — 모든 watch 폴더 순회.
        # 원장(sent.jsonl)에 있는 파일은 _emit 에서 걸러지므로 "미적재분만" 따라잡는다.
        # ★ 별도 스레드: 배압(enqueue block) 때문에 스캔은 전송 속도에 맞춰 장시간 걸린다.
        #   메인 스레드/락을 붙잡으면 /health·감시 교체(swap)·종료가 스캔 내내 막히므로 분리.
        if self.cfg.emit_existing_on_start:
            scan_worker = self.worker

            def _initial_scan():
                n = 0
                for _rel, ap_full, _size, _mtime in self.cfg.iter_existing():
                    if self.worker is not scan_worker:
                        log.info("초기 스캔 중단(감시 구성 교체) — %d개 투입 후 새 구성 스캔에 양보", n)
                        return
                    scan_worker.touch(ap_full, "existing")
                    n += 1
                log.info("초기 스캔 완료: %d개 투입 (원장 기적재분은 자동 제외)", n)

            threading.Thread(target=_initial_scan, daemon=True, name="initial-scan").start()
        # watch 폴더마다 observer.schedule → 한 Observer 가 여러 폴더 병렬 감시.
        # batch 폴더는 실시간 감시 없이 주기 스캔(Rescanner)으로만 수집한다.
        # observer 를 먼저 시작한다 — 이후 schedule() 이 폴더를 바로 열어서, 볼 수 없는 폴더는
        # 그 폴더만 실패한다(시작 전에 걸어 두면 start() 에서 한꺼번에 실패해 전체가 멈춘다).
        self.observer = Observer()
        self.observer.start()
        for w in self.cfg.watches:
            if w.batch:
                log.info("감시 시작(배치): %s (label=%s, interval=%.0fs — watchdog 미사용)",
                         w.path, w.label or "(none)",
                         w.batch_interval or self.cfg.rescan_interval_seconds or 60.0)
                continue
            if not self._schedule_watch(w):
                if not os.path.isdir(w.path):
                    log.warning("감시 폴더가 보이지 않습니다(보이면 자동으로 감시 시작): %s", w.path)
                self._unscheduled.append(w)
                continue
            flt = self.cfg.effective_filters(w)
            log.info("감시 시작: %s (label=%s, recursive=%s, 필터: %s)",
                     w.path, w.label or "(none)", w.recursive, flt.summary())

    def stop(self) -> None:
        with self._lock:
            self._stop_unlocked()

    def _stop_unlocked(self) -> None:
        if self.observer is not None:
            try:
                self.observer.stop()
                if self.observer.is_alive():
                    self.observer.join(timeout=5)
            except Exception as e:  # noqa: BLE001
                log.warning("observer 정지 실패(무시): %s", e)
            self.observer = None
        if self.worker is not None:
            try:
                self.worker.stop()
            except Exception as e:  # noqa: BLE001
                log.warning("worker 정지 실패(무시): %s", e)
            self.worker = None

    def swap_watch_dir(self, new_dir: str, recursive: bool | None = None) -> dict:
        """런타임에 단일 watch_dir 교체. observer/worker 재시작.(하위호환: prefix 없음)"""
        new_dir = os.path.abspath(new_dir)
        with self._lock:
            previous = self.cfg.watch_dir
            same_single = (not self.cfg.is_multi and new_dir == os.path.abspath(previous or ""))
            if same_single and (recursive is None or recursive == self.cfg.recursive):
                return {"status": "noop", "watch_dir": previous, "reason": "already same"}
            os.makedirs(new_dir, exist_ok=True)
            self._stop_unlocked()
            if recursive is not None:
                self.cfg.recursive = bool(recursive)
            self.cfg.watch_dir = new_dir
            # 단일 폴더로 재구성 (label="" → 기존과 동일하게 prefix 없음)
            self.cfg.watches = [Watch(new_dir, label="", recursive=self.cfg.recursive)]
            self._start_unlocked()
            log.info("watch_dir 변경: %s → %s", previous, new_dir)
            return {"status": "ok", "watch_dir": new_dir, "previous": previous,
                    "recursive": self.cfg.recursive, "watches": self.cfg.watch_summary()}

    @staticmethod
    def _watch_sig(cfg: "Config", watches: list) -> tuple:
        """감시 구성 시그니처 — 동일 구성 재적용(no-op) 판정용."""
        return tuple(sorted(
            (w.path.replace("\\", "/").rstrip("/").lower(), w.label, bool(w.recursive),
             bool(w.batch), float(w.batch_interval or 0.0),
             cfg.effective_filters(w).summary())
            for w in watches))

    def swap_watches(self, specs: list) -> dict:
        """런타임에 다중 감시 폴더 교체. specs 는 watch_dirs 와 동일 형식(list[str|dict]).
        - 동일 구성이면 no-op: 백엔드가 세션마다/재연결마다 set_watch_dirs 를 반복 전송해도
          감시 재시작·전체 재스캔이 일어나지 않는다 (재연결 폭풍 방지).
        - 적용 실패 시 이전 감시 구성으로 자동 복구한다 — 잘못된 명령 한 번에
          감시가 통째로 멈춘 채 방치되는 사고(무중단 위반)를 막는다."""
        with self._lock:
            try:
                candidate = self.cfg._build_watches(specs)
                if candidate and self._watch_sig(self.cfg, candidate) == self._watch_sig(self.cfg, self.cfg.watches):
                    log.debug("watch_dirs 동일 구성 — noop (재시작 없음)")
                    return {"status": "noop", "watches": self.cfg.watch_summary()}
            except Exception:  # noqa: BLE001  시그니처 계산 실패 시 기존 경로로 진행
                pass
            prev_watches = list(self.cfg.watches)
            prev_watch_dir = self.cfg.watch_dir
            self._stop_unlocked()
            try:
                self.cfg.set_watches(specs)
                if not self.cfg.watches:
                    raise ValueError("적용 가능한 감시 폴더가 없음")
                # 폴더를 만들 수 없는 경우(네트워크 공유 미연결 등)는 _start_unlocked 가
                # 경고만 남기고 나중에 다시 건다 — 백엔드가 정한 구성을 버리지 않는다.
                self._start_unlocked()
            except Exception as e:  # noqa: BLE001
                log.error("watch_dirs 적용 실패(%s) — 이전 감시 구성으로 복구", e)
                self._stop_unlocked()   # 반쯤 만들어진 worker·observer 를 먼저 정리(스레드 누수 방지)
                self.cfg.watches = prev_watches
                self.cfg.watch_dir = prev_watch_dir
                try:
                    self._start_unlocked()
                except Exception as e2:  # noqa: BLE001
                    log.error("이전 감시 구성 복구 실패: %s", e2)
                return {"status": "error", "reason": str(e), "watches": self.cfg.watch_summary()}
            summary = self.cfg.watch_summary()
            log.info("watch_dirs 변경 → %s", summary)
            result = {"status": "ok", "watches": summary}
            if self._unscheduled:
                result["unscheduled"] = self.unscheduled_paths()
            return result

    def apply_watch_spec(self, raw: str, recursive: bool | None = None) -> dict:
        """watchDir 문자열 적용. ';' 로 구분된 여러 폴더면 다중 감시(폴더명 prefix),
        하나면 단일 감시(prefix 없음, 하위호환). 백엔드 노드의 WatchDir 한 칸에
        'C:\\test;C:\\khk' 처럼 넣으면 한 노드로 여러 폴더를 감시할 수 있다."""
        parts = [p.strip() for p in str(raw or "").split(";") if p.strip()]
        if len(parts) > 1:
            return self.swap_watches(parts)
        if len(parts) == 1:
            return self.swap_watch_dir(parts[0], recursive)
        return {"status": "noop", "reason": "empty watch spec"}


# ============================================================================
#  ConfigPoller : PUSH 모드 전용. backend 에서 watch_dir 를 주기적으로 받아와 적용.
#   - PUSH 모드는 backend→데몬 접근이 불가하므로 POST /control/watch_dir 를 받을 수 없다.
#   - 대신 데몬이 backend 의 GET /api/file-agent/config 를 폴링해서, 노드의 watchDir 가
#     바뀌면 runtime.swap_watch_dir 로 동적 교체한다. (UI 에서 외부망 데몬 dir 변경 가능)
#   - 반환된 watch_dir 가 비어있으면 무시하고 데몬 자체 config.json 의 watch_dir 를 유지.
# ============================================================================
class ConfigPoller(threading.Thread):
    def __init__(self, push_url: str, token: str, runtime: "Runtime", interval: float = 10.0):
        super().__init__(daemon=True)
        self.url = push_url.rstrip("/") + "/api/file-agent/config"
        self.token = token
        self.runtime = runtime
        self.interval = max(3.0, float(interval))
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        log.info("CONFIG 폴링 시작: %s (%.0fs 주기)", self.url, self.interval)
        self._stop.wait(2.0)  # backend 미준비 대비 첫 폴 약간 지연
        while not self._stop.is_set():
            try:
                self._poll_once()
            except urllib.error.HTTPError as he:
                # 404 = 해당 token 의 활성 push 엣지 없음 → 정상(엣지 미활성). 조용히 대기.
                if he.code != 404:
                    log.debug("config 폴 HTTP %s", he.code)
            except Exception as e:  # noqa: BLE001
                log.debug("config 폴 실패: %s", e)
            self._stop.wait(self.interval)

    def _poll_once(self) -> None:
        req = urllib.request.Request(self.url, method="GET")
        if self.token:
            req.add_header("X-Agent-Token", self.token)
        with _url_open(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8") or "{}")

        # listen 포트 / advertise host 동기화 (노드 Port/Address → 데몬에 동적 적용)
        try:
            new_port = int(data.get("port") or 0)
        except (TypeError, ValueError):
            new_port = 0
        new_host = str(data.get("host") or "").strip()
        if (new_port > 0 and new_port != self.runtime.cfg.port) or \
           (new_host and new_host != self.runtime.cfg.advertise_host):
            log.info("CONFIG: backend listen 변경 지시 → port=%s host=%s", new_port, new_host)
            self.runtime.swap_listen(new_port, advertise_host=new_host or None)

        # 다중 폴더: backend 가 watch_dirs(list) 를 주면 그쪽을 우선 적용
        new_dirs = data.get("watch_dirs")
        if new_dirs:
            current = self.runtime.cfg.watch_summary()
            # 단순 비교: 폴더 경로 집합이 같으면 noop
            cur_paths = {os.path.abspath(w["dir"]) for w in current}
            new_paths = set()
            for it in new_dirs:
                p = it if isinstance(it, str) else str((it or {}).get("dir") or (it or {}).get("path") or "")
                if p:
                    new_paths.add(os.path.abspath(p))
            if new_paths and new_paths != cur_paths:
                log.info("CONFIG: backend 가 watch_dirs 변경 지시 → %s", new_dirs)
                result = self.runtime.swap_watches(list(new_dirs))
                log.info("CONFIG: watch_dirs 적용 결과 %s", result)
            return

        new_dir = str(data.get("watch_dir") or "").strip()
        if not new_dir:
            return  # 빈 값이면 데몬 자체 config 유지
        if not self.runtime.cfg.is_multi and \
           os.path.abspath(new_dir) == os.path.abspath(self.runtime.cfg.watch_dir):
            return  # 이미 같은 경로
        log.info("CONFIG: backend 가 watch_dir 변경 지시 → %s", new_dir)
        result = self.runtime.apply_watch_spec(new_dir)  # ';' 구분 여러 폴더 지원
        log.info("CONFIG: watch_dir 적용 결과 %s", result)


# ============================================================================
#  Rescanner : 배치 수집 + 보정(reconciliation) 스캔
#   - batch 폴더: 이 스레드가 주기적으로 스캔하는 것이 유일한 수집 경로(배치성 수집).
#   - realtime 폴더: rescan_interval_seconds 주기(기본 300s)로 전체를 재대조해
#     watchdog 누락·큐 포화 드롭·ack 유실·재부팅 공백을 따라잡는다.
#   - 원장(sent.jsonl)에 있는 파일은 StabilityWorker._emit 에서 걸러지므로
#     "아직 적재 확인 안 된 파일"만 다시 흘러간다 → 무손실 + 무중복 + RAM 안정.
#   - 큐 포화(rescan_event) 시 조기 기동.
# ============================================================================
class Rescanner(threading.Thread):
    def __init__(self, cfg: "Config", runtime: "Runtime"):
        super().__init__(daemon=True, name="rescanner")
        self.cfg = cfg
        self.runtime = runtime
        # threading.Thread 에는 내부용 _stop() 메서드가 있어 같은 이름을 쓰면 is_alive() 가 깨진다.
        self._stop_evt = threading.Event()
        self._next_run: dict[str, float] = {}   # watch.path -> 다음 실행 시각
        self._last_end: dict[str, float] = {}   # watch.path -> 마지막 스캔 종료 시각
        self._last_compact: float = 0.0         # 원장 컴팩션 마지막 실행 시각(ADR-019)
        self.last_scan_at: float = 0.0          # /health 표시용
        self.last_loop_at: float = 0.0

    def stop(self) -> None:
        self._stop_evt.set()

    def _interval_for(self, w: "Watch") -> float:
        if w.batch:
            return w.batch_interval or self.cfg.rescan_interval_seconds or 60.0
        return self.cfg.rescan_interval_seconds  # 0 = 보정 스캔 없음

    def run(self) -> None:
        log.info("보정/배치 스캐너 시작 (기본 주기 %.0fs, 큐 포화 시 조기 기동)",
                 self.cfg.rescan_interval_seconds)
        # 시작 직후엔 emit_existing_on_start 가 이미 1회 스캔했으므로 주기만큼 대기 후 시작.
        while not self._stop_evt.is_set():
            triggered = self.runtime.rescan_event.wait(timeout=5.0)
            if self._stop_evt.is_set():
                break
            if triggered:
                self.runtime.rescan_event.clear()
            self.last_loop_at = time.time()
            try:
                self._tick(triggered)
            except Exception as e:  # noqa: BLE001  스캐너가 죽으면 배치 수집·보정이 조용히 멈춘다
                log.error("보정/배치 스캔 중 오류(다음 주기에 계속): %s", e, exc_info=True)

    def _tick(self, triggered: bool) -> None:
        now = time.time()
        worker = self.runtime.worker
        if worker is None:
            return
        self.runtime.schedule_pending_watches()
        # 배치 폴더(유일한 수집 경로)를 실시간 폴더의 보정 스캔보다 먼저 처리한다.
        for w in sorted(list(self.cfg.watches), key=lambda x: 0 if x.batch else 1):
            iv = self._interval_for(w)
            if iv <= 0 and not triggered:
                continue  # 보정 스캔 꺼짐 (배치 아님 + interval=0)
            base_iv = iv if iv > 0 else 60.0
            # 첫 만남에 '다음 실행 시각'을 저장해 둔다. get 으로만 읽으면 매번 now+주기로
            # 다시 계산돼 영원히 도래하지 않는다(= 주기 보정 스캔이 한 번도 안 돌던 결함).
            due = self._next_run.setdefault(w.path, now + base_iv)
            if triggered:
                if now < self._last_end.get(w.path, 0.0) + 60.0:
                    continue  # 조기 기동이 잦아도 같은 폴더를 1분 안에 다시 훑지 않는다
            elif now < due:
                continue
            started = time.time()
            scanned = 0
            for _relpath, ap, _size, _mtime in self.cfg.iter_existing(only=w):
                if self.runtime.worker is not worker or self._stop_evt.is_set():
                    break  # 감시 구성 교체/종료 — 이번 스캔 양보
                worker.touch(ap, "existing")
                scanned += 1
            ended = time.time()
            took = ended - started
            # 다음 실행은 '끝난 시각' 기준. 스캔이 주기보다 오래 걸리는 큰 폴더는 소요시간의 3배를 쉰다.
            self._next_run[w.path] = ended + max(base_iv, took * 3)
            self._last_end[w.path] = ended
            self.last_scan_at = ended
            log.info("%s 스캔: %s — %d개 파일 대조 (%.1f초, 다음 %.0f초 뒤, 미적재분만 전송)",
                     "배치" if w.batch else "보정", w.path, scanned, took,
                     self._next_run[w.path] - ended)
        # 보정 스캔 뒤 원장 컴팩션(ADR-019): 스코프 밖/디스크에 없는 항목 제거.
        #   rescan_interval(최소 60s)마다 1회로 제한 — 잦은 트리거에도 과다 실행 방지.
        _lg = getattr(self.runtime, "ledger", None)
        if self.cfg.ledger_compaction and _lg is not None and self.runtime.scope_ready:
            if self._last_compact == 0.0:
                # 첫 정리는 한 주기 뒤로 미룬다 — 기동 직후엔 네트워크 폴더가 덜 붙었을 수 있다.
                self._last_compact = now
            elif now - self._last_compact >= max(self.cfg.rescan_interval_seconds, 60.0):
                self._last_compact = now
                try:
                    # ADR-022: sync_mode=mirror 면 디스크에서 사라진 항목을 삭제 이벤트로도 통지 —
                    # collect_mode=batch 처럼 watchdog 이 없어 on_deleted 를 못 받는 폴더의 유일한
                    # 삭제 감지 경로. speed(기본)에서는 on_dropped 가 즉시 no-op.
                    _lg.compact(self.cfg.resolve_for_compaction,
                                on_dropped=lambda rp: _mirror_enqueue_deleted(
                                    self.cfg, self.runtime.ws_client, rp))
                except Exception as _e:  # noqa: BLE001
                    log.warning("원장 주기 컴팩션 실패(무시): %s", _e)


# ============================================================================
#  HTTP 서버
# ============================================================================
class AgentHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, cfg: Config, store: EventStore, runtime: "Runtime | None" = None):
        self.cfg = cfg
        self.store = store
        self.runtime = runtime  # /control/watch_dir 등 동적 제어용
        super().__init__(addr, AgentRequestHandler)


class AgentRequestHandler(BaseHTTPRequestHandler):
    server_version = f"file-agent/{VERSION}"

    # 액세스 로그는 우리 로거로
    def log_message(self, fmt, *args):
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---- 인증 ----
    def _authorized(self, qs: dict) -> bool:
        cfg: Config = self.server.cfg  # type: ignore[attr-defined]
        if not cfg.token:
            return True  # 토큰 미설정이면 검사 안 함(권장 X)
        supplied = self.headers.get("X-Agent-Token") or (qs.get("token", [""])[0])
        return hmac.compare_digest(str(supplied), cfg.token)

    def _remote_allowed(self, path: str) -> bool:
        """다른 PC 에서 온 요청을 받아도 되는 경로인지.

        백엔드 WS 모드·직접 모드에서는 파일을 이 데몬이 내보내므로, 원격에서 파일을 읽거나
        감시 폴더를 바꿀 일이 없다. 이때 원격에는 /health(백엔드의 도달성 점검)만 연다.
        데몬은 SYSTEM 권한이라, 토큰이 새면 /control 로 감시 폴더를 바꾼 뒤 /files 로
        아무 파일이나 읽을 수 있기 때문이다. 옛 PULL 모드는 백엔드가 원격으로
        /events·/files·/control 을 부르므로 그대로 둔다.
        """
        ip = str(self.client_address[0] if self.client_address else "")
        if ip.startswith("127.") or ip in ("::1", "::ffff:127.0.0.1"):
            return True
        runtime = getattr(self.server, "runtime", None)
        pull_mode = (runtime is not None and runtime.ws_client is None
                     and runtime.s3_uploader is None and runtime.push_client is None)
        return pull_mode or path == "/health"

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        if not self._remote_allowed(path):
            self._json(403, {"error": "local only", "path": path})
            return
        if not self._authorized(qs):
            self._json(401, {"error": "unauthorized"})
            return

        cfg: Config = self.server.cfg          # type: ignore[attr-defined]
        store: EventStore = self.server.store  # type: ignore[attr-defined]

        if path == "/health":
            runtime: "Runtime | None" = getattr(self.server, "runtime", None)
            body = {
                "status": "ok",
                "name": "file-agent",
                "version": VERSION,
                "watch_dir": cfg.watch_dir,          # 하위호환(첫 폴더)
                "watch_dirs": cfg.watch_summary(),   # 다중 폴더 목록
                "recursive": cfg.recursive,
                "last_seq": store.last_seq,
                # 재부팅 뒤 자동 실행 확인용: 이 프로세스가 언제 떴는지와 그때의 부팅 시각
                "pid": os.getpid(),
                "started_at": round(_PROCESS_STARTED_AT, 1),
                "boot_at": round(_boot_epoch(), 1),
            }
            if runtime is not None:
                body["ledger_size"] = len(runtime.ledger) if runtime.ledger else 0
                body["pending_acks"] = len(runtime.pending_acks) if runtime.pending_acks else 0
                body["ack_mode"] = runtime.ack_enabled
                body["unmatched"] = runtime.unmatched_count()
                body["unwatched_dirs"] = runtime.unscheduled_paths()
                rs = getattr(runtime, "rescanner", None)
                if rs is not None:
                    body["rescanner_alive"] = rs.is_alive()
                    body["last_scan_at"] = rs.last_scan_at
            self._json(200, body)
        elif path == "/list":
            self._json(200, {"files": self._list_files(cfg)})
        elif path == "/events/poll":
            since = int(qs.get("since", ["0"])[0])
            wait = float(qs.get("wait", ["25"])[0])  # 롱폴 최대 대기(초)
            evs = store.wait_for_new(since, timeout=max(0.0, min(wait, 60.0)))
            self._json(200, {"events": evs, "last_seq": store.last_seq})
        elif path == "/events":
            self._sse(store, int(qs.get("since", ["0"])[0]))
        elif path == "/files":
            self._send_file(cfg, qs.get("path", [""])[0])
        else:
            self._json(404, {"error": "not found", "path": path})

    def do_POST(self):  # noqa: N802
        """동적 제어 엔드포인트.
        - POST /control/watch_dir   body: {"watch_dir":"...", "recursive":bool?}
          → observer/worker 안전 교체 후 결과 반환.
        backend 가 노드 활성화 시 호출해서 노드 설정값을 데몬에 반영하는 용도.
        """
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        if not self._remote_allowed(path):
            self._json(403, {"error": "local only", "path": path})
            return
        if not self._authorized(qs):
            self._json(401, {"error": "unauthorized"})
            return

        if path == "/control/watch_dir":
            runtime: "Runtime | None" = getattr(self.server, "runtime", None)
            if runtime is None:
                self._json(503, {"error": "runtime not available"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b"{}"
                body = json.loads(raw.decode("utf-8") or "{}")
            except Exception as e:  # noqa: BLE001
                self._json(400, {"error": "bad json", "detail": str(e)})
                return
            specs = body.get("watch_dirs")
            if isinstance(specs, list) and specs:
                # 목록 형태(UI): 문자열·dict 항목을 그대로 적용 — 라벨·폴더별 필터가 유지된다.
                try:
                    self._json(200, runtime.swap_watches(specs))
                except Exception as e:  # noqa: BLE001
                    log.error("swap_watches 실패: %s", e)
                    self._json(500, {"error": "swap failed", "detail": str(e)})
                return
            new_dir = (body.get("watch_dir") or "").strip()
            if not new_dir:
                self._json(400, {"error": "watch_dir required"})
                return
            recursive = body.get("recursive", None)
            try:
                # ';' 구분 여러 폴더 지원 (단일이면 기존과 동일)
                result = runtime.apply_watch_spec(new_dir, recursive)
                self._json(200, result)
            except Exception as e:  # noqa: BLE001
                log.error("swap_watch_dir 실패: %s", e)
                self._json(500, {"error": "swap failed", "detail": str(e)})
        else:
            self._json(404, {"error": "not found", "path": path})

    # ---- /list ----
    @staticmethod
    def _list_files(cfg: Config) -> list[dict]:
        # 모든 watch 폴더의 파일을 네임스페이스된 relpath 로 나열
        return [{"path": relpath, "size": size, "mtime": mtime}
                for relpath, _ap, size, mtime in cfg.iter_existing()]

    # ---- /events (SSE) ----
    def _sse(self, store: EventStore, since: int):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        last = since
        try:
            # 우선 밀린 이벤트부터 재생
            for ev in store.since(last):
                self._sse_send(ev)
                last = ev["seq"]
            # 이후 실시간 스트림 + 하트비트
            while True:
                evs = store.wait_for_new(last, timeout=15.0)
                if evs:
                    for ev in evs:
                        self._sse_send(ev)
                        last = ev["seq"]
                else:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # 구독자 연결 종료

    def _sse_send(self, ev: dict) -> None:
        data = json.dumps(ev, ensure_ascii=False)
        self.wfile.write(f"id: {ev['seq']}\ndata: {data}\n\n".encode("utf-8"))
        self.wfile.flush()

    # ---- /files (다운로드) ----
    def _send_file(self, cfg: Config, relpath: str):
        if not relpath:
            self._json(400, {"error": "path 파라미터 필요"})
            return
        # 네임스페이스된 relpath → 실제 절대경로(라벨로 폴더 해석 + 경로 탈출 방지)
        target = cfg.resolve(relpath)
        if not target:
            self._json(403, {"error": "forbidden path"})
            return
        if not os.path.isfile(target):
            self._json(404, {"error": "file not found", "path": relpath})
            return
        try:
            size = os.path.getsize(target)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            # RFC 5987 — HTTP 헤더는 latin-1 만 허용하므로 한글 등 비-ASCII 파일명은
            # ASCII fallback + filename*=UTF-8''<percent-encoded> 두 가지 동시 제공.
            # 이렇게 안 하면 한글 파일 다운로드 시 UnicodeEncodeError 로 데몬이 죽는다.
            from urllib.parse import quote as _urlquote
            basename = os.path.basename(target)
            ascii_fallback = basename.encode("ascii", "replace").decode("ascii")
            encoded = _urlquote(basename, safe="")
            self.send_header(
                "Content-Disposition",
                f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"
            )
            self.end_headers()
            with open(target, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass


# ============================================================================
#  부트스트랩
# ============================================================================
_LOG_FMT = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
_LOG_PATH_HOLDER = {"path": None}


def setup_logging(log_path: str) -> None:
    """초기 로깅(config 로드 전). 기본 INFO + 5MB*3 회전. config 로드 후 apply_log_config 로 재적용."""
    _LOG_PATH_HOLDER["path"] = log_path
    log.setLevel(logging.INFO)
    # --noconsole(windowed) 빌드에서는 sys.stdout 이 None — 콘솔 핸들러 생략(파일 로그만).
    if sys.stdout is not None:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(_LOG_FMT)
        log.addHandler(sh)
    try:
        fh = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024,
                                 backupCount=2, encoding="utf-8")
        fh.setFormatter(_LOG_FMT)
        log.addHandler(fh)
    except Exception:  # noqa: BLE001
        pass


def apply_log_config(cfg) -> None:
    """config 의 log_level/log_max_mb/log_backups 를 반영 — 운영 부하·용량 관리.
    기본 INFO 에선 파일당 로그(DEBUG)가 안 찍혀 부하가 낮고, WARNING 이면 경고/오류만 남는다."""
    try:
        log.setLevel(getattr(logging, cfg.log_level, logging.INFO))
    except Exception:  # noqa: BLE001
        log.setLevel(logging.INFO)
    path = _LOG_PATH_HOLDER.get("path")
    if not path:
        return
    # 기존 RotatingFileHandler 를 config 회전값으로 교체 (총 디스크 상한 = max_mb*(backups+1)).
    for h in list(log.handlers):
        if isinstance(h, RotatingFileHandler):
            log.removeHandler(h)
            try: h.close()
            except Exception: pass  # noqa: BLE001
    try:
        fh = RotatingFileHandler(path, maxBytes=cfg.log_max_mb * 1024 * 1024,
                                 backupCount=cfg.log_backups, encoding="utf-8")
        fh.setFormatter(_LOG_FMT)
        log.addHandler(fh)
    except Exception:  # noqa: BLE001
        pass
    log.info("로그 설정: level=%s, 회전 %dMB*%d (총 상한 ~%dMB)",
             cfg.log_level, cfg.log_max_mb, cfg.log_backups + 1, cfg.log_max_mb * (cfg.log_backups + 1))


def _is_inside(path: str, folder: str) -> bool:
    try:
        a = os.path.normcase(os.path.realpath(path))
        b = os.path.normcase(os.path.realpath(folder))
        return os.path.commonpath([a, b]) == b
    except (ValueError, OSError):
        return False


def _thread_excepthook(hook_args) -> None:
    """스레드가 예외로 죽으면 조용히 사라지지 않게 로그에 남긴다."""
    if hook_args.exc_type is SystemExit:
        return
    name = getattr(hook_args.thread, "name", "?")
    log.error("스레드 %s 가 예외로 멈췄습니다", name,
              exc_info=(hook_args.exc_type, hook_args.exc_value, hook_args.exc_traceback))


def app_dir() -> str:
    # PyInstaller 단일 exe 로 묶였을 때도 "실행 파일 옆" 경로를 쓰기 위함
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


# ============================================================================
#  단일 인스턴스 가드 (중복 실행 방지)
#  같은 포트로 이미 떠 있는 file-agent 가 있으면 새 인스턴스는 스스로 종료한다.
#  잠금 객체는 전역에 보관해 프로세스가 살아있는 동안 잠금이 유지되게 한다(GC 방지).
#  - Windows : Named Mutex (CreateMutexW + ERROR_ALREADY_EXISTS)
#  - POSIX   : 잠금파일 + flock(LOCK_EX|LOCK_NB)
# ============================================================================
_singleton_handle = None  # 잠금 핸들/파일을 살려두는 전역 참조


def acquire_single_instance(port: int) -> bool:
    """실행 중인 인스턴스가 없으면 잠금을 잡고 True, 이미 있으면 False.

    ★ 한 PC 에 데몬은 하나만 둔다 — 포트가 달라도 공존시키지 않는다(2026-09-16 변경).
      이전에는 포트별 뮤텍스라 둘 이상이 동시에 떴는데, 그러면
        · 같은 폴더에서 돌 때 원장(sent.jsonl)을 함께 써서 무손실이 깨지고
        · token 이 같으면 백엔드가 양쪽에 set_watch_dirs 를 보내 같은 파일을 이중 전송한다.
      여기서 False 가 나면 호출부가 _kill_other_instances() 로 기존 것을 정리하고 교체한다.

    잠금 자체를 만들 수 없는 환경 오류는 fail-closed(False) 로 처리해 중복 실행을 막는다.
    """
    global _singleton_handle
    del port  # 더 이상 포트로 가르지 않는다(호출부 호환 위해 인자만 유지).
    name = "file-agent-singleton"
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        ERROR_ALREADY_EXISTS = 183
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        # 세션 간에도 단 하나만 — Global\ 네임스페이스 사용.
        handle = kernel32.CreateMutexW(None, False, f"Global\\{name}")
        last = kernel32.GetLastError()
        if not handle:
            # 예약 작업(SYSTEM)과 수동 실행(일반 사용자)은 Global mutex의 기본
            # DACL이 달라 Open/Create가 ERROR_ACCESS_DENIED(5)로 실패할 수 있다.
            # 이때 실행을 허용하면 SYSTEM 인스턴스와 사용자 인스턴스가 동시에
            # 떠서 동일 파일을 중복 전송한다. 접근 거부는 기존 mutex가 존재하는
            # 것으로 fail-closed 처리하고, 그 외 오류도 안전하게 실행을 막는다.
            log.error("단일 인스턴스 뮤텍스 획득 실패 — 새 인스턴스 실행 차단: err=%s", last)
            return False
        if last == ERROR_ALREADY_EXISTS:
            kernel32.CloseHandle(handle)
            return False
        _singleton_handle = handle  # 프로세스 종료 시 OS 가 자동 해제
        return True
    # POSIX
    try:
        import fcntl
    except ImportError:
        return True
    lock_path = os.path.join(app_dir(), f".{name}.lock")
    try:
        f = open(lock_path, "w")
    except OSError as e:
        log.warning("단일 인스턴스 잠금파일 열기 실패(중복검사 건너뜀): %s", e)
        return True
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return False
    _singleton_handle = f  # 닫히면 잠금 해제 → 프로세스 동안 유지
    return True


def _kill_other_instances(port: int = 0) -> None:
    """자기 자신을 제외한 모든 file-agent.exe 프로세스를 강제 종료 (Windows 전용).
    좀비/멈춤 인스턴스가 뮤텍스·포트를 쥐고 있어도 새 실행이 자리를 차지할 수 있게 한다.
    ※ PyInstaller onefile 은 부트로더(부모)+본체(자식) 한 쌍으로 뜨므로,
      자기 자신뿐 아니라 '자기 부모'도 제외해야 한다 (부모를 /T 로 죽이면 자신도 죽는다)."""
    if os.name != "nt":
        return
    try:
        import subprocess
        me = os.getpid()
        try:
            parent = os.getppid()
        except OSError:
            parent = 0
        keep = {0, me, parent}
        # (1) 이름 기준 — file-agent.exe + file-agent.new.exe(배포 스테이징 이름)
        for image in ("file-agent.exe", "file-agent.new.exe"):
            cmd = ["taskkill", "/F", "/T", "/IM", image, "/FI", f"PID ne {me}"]
            if parent:
                cmd += ["/FI", f"PID ne {parent}"]
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            msg = ((r.stdout or "") + (r.stderr or "")).strip().replace("\r\n", " / ")
            if msg:
                log.info("기존 인스턴스 정리(이름=%s): %s", image, msg)
        # (2) 포트 기준 — 지정 포트를 LISTEN 중인 옛 에이전트(개발용 python 실행 포함) 종료.
        #     포트는 '로컬 주소' 칸의 끝자리와 정확히 비교한다 — 부분 문자열로 찾으면
        #     876 이 8765 에 걸린다. 그리고 에이전트로 볼 수 없는 프로그램은 건드리지 않는다
        #     (같은 포트를 쓰는 남의 서비스를 죽이지 않도록).
        if port and int(port) > 0:
            nr = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                                capture_output=True, text=True, errors="replace")
            want = str(int(port))
            pids = set()
            for line in (nr.stdout or "").splitlines():
                parts = line.split()
                if len(parts) < 5 or parts[3].upper() != "LISTENING":
                    continue
                if parts[1].rsplit(":", 1)[-1] != want:
                    continue
                try:
                    pid = int(parts[-1])
                except ValueError:
                    continue
                if pid not in keep:
                    pids.add(pid)
            for pid in list(pids):
                tr = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                    capture_output=True, text=True, errors="replace")
                image = (tr.stdout or "").strip().split(",", 1)[0].strip('"').lower()
                if not (image.startswith("file-agent") or image.startswith("python")) \
                        or image.startswith("file-agent-ui"):
                    log.warning("포트 %s 를 다른 프로그램(%s, PID %s)이 쓰고 있어 건드리지 않습니다.",
                                want, image or "?", pid)
                    pids.discard(pid)
            for pid in pids:
                kr = subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                                    capture_output=True, text=True, errors="replace")
                log.info("기존 인스턴스 정리(포트 %s, PID %s): %s", int(port), pid,
                         ((kr.stdout or "") + (kr.stderr or "")).strip().replace("\r\n", " / "))
    except Exception as e:  # noqa: BLE001
        log.warning("기존 인스턴스 정리 실패(무시): %s", e)


# 기본 config 템플릿 — config.json 도 config.template.json 도 없을 때만 쓴다(배포본에는 템플릿 파일이 있다).
DEFAULT_CONFIG_JSON = """{
  // config.template.json 과 같은 키·값(주석만 짧음). 두 파일이 어긋나지 않게 함께 고친다.
  "mode": "backend",                  // "backend" = TERESA MQ 백엔드 경유 | "direct" = S3 직접 업로드
  "watch_dirs": [],                   // backend 모드에서는 캔버스 노드의 WatchDir 가 우선
  "token": "change-me-please-long-random-token",   // file-agent-ui.exe 의 [새 토큰 생성] 으로 바꾼다
  "port": 8765,                       // 이 PC 에서 여는 포트(백엔드 포트 아님)
  "ws_senders": 48,
  "ws_send_timeout": 60,
  "offer_enabled": true,
  "ledger_compaction": true,
  "ledger_keep_in_memory": 5000000,
  "rescan_interval_seconds": 3600,
  "sync_mode": "speed",
  "ack_timeout_seconds": 3600,
  "log_level": "INFO",
  "log_max_mb": 50,
  "log_backups": 10,
  "ws_url": "",                       // backend 모드: 접속할 백엔드 주소 (이 PC 의 주소가 아님)
  "s3_endpoint": "",                  // direct 모드 전용
  "s3_bucket": "",
  "s3_access_key": "",
  "s3_secret_key": "",
  "s3_path_prefix": ""
}
"""

CONFIG_TEMPLATE_NAME = "config.template.json"


def ensure_config(path: str) -> bool:
    """config.json 이 없으면 옆의 config.template.json(없으면 내장 템플릿)으로 만든다. 만들었으면 True."""
    if os.path.isfile(path):
        return False
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        template = os.path.join(os.path.dirname(os.path.abspath(path)), CONFIG_TEMPLATE_NAME)
        if os.path.isfile(template):
            with open(template, encoding="utf-8-sig") as f:
                body = f.read()
        else:
            body = DEFAULT_CONFIG_JSON
        with open(path, "w", encoding="utf-8") as f:
            f.write(body)
        log.info("config.json 생성: %s — file-agent-ui.exe 로 주소·토큰·감시 폴더를 설정하세요.", path)
        return True
    except OSError as e:
        log.error("config.json 생성 실패 %s: %s", path, e)
        return False


def token_problem(token: str) -> str:
    """토큰을 쓸 수 없는 이유. 쓸 수 있으면 ""."""
    t = (token or "").strip()
    if not t:
        return "토큰이 비어 있습니다"
    if t == PLACEHOLDER_TOKEN:
        return "토큰이 배포 기본값 그대로입니다"
    return ""


def startup_problem(cfg: "Config") -> str:
    """기존 데몬을 건드리기 전에 확인하는 설정 오류. 문제가 없으면 "".

    토큰은 모든 모드에서 본다. 데몬은 SYSTEM 권한이라, 비었거나 공개된 기본값이면
    이 PC 의 일반 사용자가 127.0.0.1 로 붙어 감시 폴더를 바꾸고 아무 파일이나 읽을 수 있다.
    """
    tp = token_problem(cfg.token)
    if tp:
        return (tp + " — file-agent-ui.exe 「연결」 탭에서 [새 토큰 생성] 후 저장하세요 "
                "(backend 모드면 캔버스 노드의 Token 도 같은 값으로)")
    if cfg.s3_direct_enabled:
        if not (cfg.s3_endpoint and cfg.s3_bucket):
            return "direct 모드인데 s3_endpoint 또는 s3_bucket 이 비어 있습니다"
        return ""
    if cfg.ws_enabled or cfg.mode == "backend":
        url = (cfg.ws_url or "").strip()
        if not url:
            return "백엔드 모드인데 백엔드 주소(ws_url)가 비어 있습니다"
        try:
            p = urlparse(url if "://" in url else "http://" + url)
            _ = p.port   # 포트가 숫자가 아니거나 범위를 벗어나면 ValueError
        except ValueError as e:
            return f"백엔드 주소 형식이 잘못됐습니다 ({url}): {e}"
        if p.scheme not in ("http", "https", "ws", "wss") or not p.hostname:
            return f"백엔드 주소 형식이 잘못됐습니다 ({url})"
    if cfg.push_enabled and not cfg.push_url:
        return "push_enabled=true 인데 push_url 이 비어 있습니다"
    return ""


def _boot_epoch() -> float:
    """이번 부팅 시각(epoch 초). 알 수 없으면 0."""
    try:
        if os.name == "nt":
            import ctypes
            k32 = ctypes.windll.kernel32
            k32.GetTickCount64.restype = ctypes.c_uint64
            return time.time() - k32.GetTickCount64() / 1000.0
        with open("/proc/uptime", encoding="ascii") as f:
            return time.time() - float(f.read().split()[0])
    except Exception:  # noqa: BLE001
        return 0.0


def user_stop_active(base: str) -> bool:
    """UI [중지] 표식이 이번 부팅에 만든 것이면 True. 지난 부팅 것이면 지우고 False."""
    path = os.path.join(base, STOP_FLAG_NAME)
    try:
        with open(path, encoding="utf-8") as f:
            data = json.loads(f.read() or "{}")
    except FileNotFoundError:
        return False
    except Exception:  # noqa: BLE001
        data = {}
    try:
        flag_boot = float(data.get("boot", 0) or 0)
    except (TypeError, ValueError, AttributeError):
        flag_boot = 0.0
    now_boot = _boot_epoch()
    if flag_boot and now_boot and abs(now_boot - flag_boot) < 120:
        return True
    try:
        os.remove(path)
        log.info("지난 부팅 때의 [중지] 표식을 지웠습니다 — 자동 실행을 재개합니다.")
    except OSError:
        pass
    return False


def ensure_firewall_port(port: int) -> None:
    """listen 포트를 Windows 방화벽 인바운드에 허용(best-effort).
    데몬이 관리자 권한일 때만 성공한다(작업 스케줄러 RunLevel Highest 권장).
    포트별 룰 이름(file-agent-<port>)을 써서 중복/충돌을 피한다."""
    if os.name != "nt":
        return
    try:
        port = int(port)
    except (TypeError, ValueError):
        return
    if port <= 0:
        return
    try:
        import subprocess
        name = f"file-agent-{port}"
        # 동일 이름 룰 정리 후 재등록(멱등).
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                       capture_output=True, text=True, errors="replace")
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}",
             "dir=in", "action=allow", "protocol=TCP", f"localport={port}"],
            capture_output=True, text=True, errors="replace",
        )
        if r.returncode == 0:
            log.info("방화벽 포트 허용: TCP %s (rule=%s)", port, name)
        else:
            log.warning("방화벽 포트 자동 허용 실패(관리자 권한 필요) TCP %s: %s",
                        port, (r.stderr or r.stdout or "").strip())
    except Exception as e:  # noqa: BLE001
        log.debug("방화벽 설정 건너뜀: %s", e)


def _run_powershell(script: str) -> int:
    """PowerShell 스크립트 실행(설치/제거용). Windows 전용."""
    try:
        import subprocess
        r = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, errors="replace",
        )
        if r.stdout:
            log.info(r.stdout.strip())
        if r.returncode != 0:
            log.error("PowerShell 실패(rc=%s): %s", r.returncode, (r.stderr or "").strip())
        return r.returncode
    except FileNotFoundError:
        log.error("powershell 을 찾을 수 없습니다 (Windows 에서만 --install 지원).")
        return 2


def _ps_q(value: str) -> str:
    """PowerShell 작은따옴표 문자열 안에 넣을 값. 경로에 ' 가 있어도 깨지지 않게 두 번 쓴다."""
    out = str(value)
    for q in ("'", "\u2018", "\u2019", "\u201a", "\u201b"):
        out = out.replace(q, q + q)
    return out


def _harden_install_dir_ps() -> str:
    """설치 폴더 권한 잠금용 PowerShell 조각($work 사용). 실패해도 설치는 계속하고 결과를 출력한다.

    SYSTEM 작업이 실행하는 exe 를 일반 사용자가 바꿔치기하면 곧바로 SYSTEM 권한을 얻는다.
    C:\\file-agent 같은 폴더는 기본으로 'Authenticated Users 수정 가능'이라 막아야 한다.
      · 폴더: SYSTEM·Administrators 모든 권한. Users 는 폴더 열람만((CI)RX — 파일에는 상속 안 됨).
      · 파일: 새로 생기는 파일(로그·원장·설정)은 SYSTEM·Administrators 만 읽는다.
              실행에 필요한 exe·bat·템플릿·BUILD-INFO 에만 Users 읽기/실행을 따로 준다.
      · OWNER RIGHTS 를 읽기/실행으로 제한 — 압축을 푼 일반 사용자가 소유자여도 권한을 바꿀 수 없다.
      · 소유자는 Administrators (폴더와 바로 아래 파일만 — 하위 폴더는 재귀하지 않는다).
      · 하위 폴더가 있으면(옛 기본 감시 폴더 등) 먼저 현재 권한을 고정(/inheritance:d)해,
        그 폴더에 쓰는 프로그램은 그대로 쓸 수 있게 한다.
    icacls 오류는 로컬 EAP=Continue 에서 2>&1 로 받아 결과에 남긴다(PS 5.1 에서 EAP=Stop 과 섞지 않는다).
    """
    return (
        "& {"
        "$ErrorActionPreference='Continue';"
        "$fail=@();"
        "foreach($d in @(Get-ChildItem -LiteralPath $work -Directory -Force -ErrorAction SilentlyContinue)){"
        "$o=& icacls.exe $d.FullName /inheritance:d 2>&1 | ForEach-Object {\"$_\"};"
        "if($LASTEXITCODE -ne 0){$fail+=('하위 폴더 '+$d.Name+': '+($o -join ' '))}"
        "else{Write-Host ('acl: 하위 폴더 권한 고정 — '+$d.Name)}"
        "};"
        "$o=& icacls.exe $work /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'"
        " '*S-1-5-32-545:(CI)RX' '*S-1-3-4:(OI)(CI)RX' 2>&1 | ForEach-Object {\"$_\"};"
        "if($LASTEXITCODE -ne 0){$fail+=('폴더: '+($o -join ' '))}"
        "$o=& icacls.exe $work /setowner '*S-1-5-32-544' 2>&1 | ForEach-Object {\"$_\"};"
        "if($LASTEXITCODE -ne 0){$fail+=('폴더 소유자: '+($o -join ' '))}"
        "foreach($f in @(Get-ChildItem -LiteralPath $work -File -Force -ErrorAction SilentlyContinue)){"
        "$o=& icacls.exe $f.FullName /setowner '*S-1-5-32-544' 2>&1 | ForEach-Object {\"$_\"};"
        "if($LASTEXITCODE -ne 0){$fail+=('소유자 '+$f.Name+': '+($o -join ' '))}"
        "if(@('.exe','.bat') -contains $f.Extension.ToLower() -or @('config.template.json','BUILD-INFO.txt') -contains $f.Name){"
        "$o=& icacls.exe $f.FullName /grant '*S-1-5-32-545:RX' 2>&1 | ForEach-Object {\"$_\"};"
        "if($LASTEXITCODE -ne 0){$fail+=('실행 권한 '+$f.Name+': '+($o -join ' '))}"
        "}"
        "};"
        "foreach($n in @('config.json','config.json.bak')){"
        "$f=Join-Path $work $n;"
        "if(Test-Path -LiteralPath $f){$o=& icacls.exe $f /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' 2>&1 | ForEach-Object {\"$_\"};"
        "if($LASTEXITCODE -ne 0){$fail+=($n+': '+($o -join ' '))}}"
        "};"
        "if($fail.Count -gt 0){Write-Host ('WARN acl: 설치 폴더 잠금 일부 실패(NTFS 로컬 디스크인지 확인) — '+($fail -join ' / '))}"
        "else{Write-Host 'acl: 설치 폴더를 관리자 전용 쓰기로 잠갔습니다'}"
        "};"
    )


def self_install(task_name: str, port: int) -> int:
    """exe 자기 자신을 방화벽 허용 + 작업 스케줄러에 등록하고 시작한다.

    트리거 세 개:
      · 부팅 시(30초 지연) — 로그인하지 않아도 수집 시작
      · 로그인 시
      · 5분마다 — 데몬이 죽어 있으면 다시 띄운다. 작업 스케줄러의 '실패 시 다시 시작'은
        프로세스가 오류 코드로 끝난 경우에는 동작하지 않기 때문이다(2026-09-17 이 PC 에서 확인).
        이미 떠 있으면 IgnoreNew 로 무시되고, 작업 밖에서 뜬 데몬이 있으면 --from-task 인스턴스가 양보한다.
    """
    if not getattr(sys, "frozen", False):
        log.error("--install 은 빌드된 file-agent.exe 에서만 동작합니다.")
        return 2
    exe = sys.executable
    work = os.path.dirname(exe)
    ps = (
        "$ErrorActionPreference='Stop';"
        f"$exe='{_ps_q(exe)}'; $work='{_ps_q(work)}'; $port={int(port)}; $task='{_ps_q(task_name)}';"
        + _harden_install_dir_ps() +
        "if(-not (Get-NetFirewallRule -DisplayName $task -ErrorAction SilentlyContinue)){"
        "New-NetFirewallRule -DisplayName $task -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null};"
        "$a=New-ScheduledTaskAction -Execute $exe -Argument '--from-task' -WorkingDirectory $work;"
        # AtStartup 은 30초 늦춘다 — 부팅 직후엔 네트워크·디스크가 아직 안 올라와 첫 기동이 헛돌기 쉽다.
        "$t1=New-ScheduledTaskTrigger -AtStartup; $t1.Delay='PT30S';"
        "$t2=New-ScheduledTaskTrigger -AtLogOn;"
        "$at=(Get-Date).AddMinutes(5); $iv=New-TimeSpan -Minutes 5;"
        # Windows 10 이상은 기간을 비우면 '무기한'. 옛 버전은 기간이 필수라 10년으로 준다.
        "try{$t3=New-ScheduledTaskTrigger -Once -At $at -RepetitionInterval $iv}"
        "catch{$t3=New-ScheduledTaskTrigger -Once -At $at -RepetitionInterval $iv -RepetitionDuration ([TimeSpan]::FromDays(3650))};"
        # 기본값은 배터리 전환 시 작업 중지·배터리 부팅 시 미기동·우선순위 7(낮음)이다.
        # 노트북·UPS 현장에서 수집이 멈추지 않도록 전원 조건을 풀고 우선순위를 보통(4)으로 올린다.
        "$s=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries"
        " -Priority 4 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)"
        " -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew;"
        # SYSTEM 계정 + Highest: 로그인 없이 부팅 시 관리자 권한으로 실행(방화벽 제어 가능).
        "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
        "Register-ScheduledTask -TaskName $task -Action $a -Trigger @($t1,$t2,$t3) -Settings $s -Principal $p"
        " -Description 'TERESA MQ file-agent (boot + logon + 5min watchdog)' -Force | Out-Null;"
        "Start-ScheduledTask -TaskName $task;"
        "Write-Host ('installed: '+$task+' (port '+$port+')')"
    )
    rc = _run_powershell(ps)
    if rc != 0:
        log.error("설치 실패 — 관리자 권한으로 다시 실행하세요.")
    return rc


def self_uninstall(task_name: str) -> int:
    """작업 스케줄러 등록 + 방화벽 룰 제거.

    방화벽 룰은 두 종류다 — 설치 때 만든 '<task>' 와, 관리자 권한으로 돈 데몬이
    ensure_firewall_port() 로 만든 '<task>-<포트>'. 둘 다 지운다.
    """
    ps = (
        f"$task='{_ps_q(task_name)}';"
        "try{Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue}catch{};"
        "try{Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}catch{};"
        "try{Get-NetFirewallRule -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -eq $task -or $_.DisplayName -match ('^'+[regex]::Escape($task)+'-\\d+$') } | "
        "Remove-NetFirewallRule}catch{};"
        "Write-Host ('uninstalled: '+$task)"
    )
    return _run_powershell(ps)


def main() -> int:
    base = app_dir()
    ap = argparse.ArgumentParser(description="file-agent : 디렉터리 감시 + 노출 데몬")
    ap.add_argument("--config", default=os.path.join(base, "config.json"))
    ap.add_argument("--dir", help="감시할 디렉터리 (config 보다 우선)")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--token")
    ap.add_argument("--no-recursive", action="store_true")
    ap.add_argument("--install", action="store_true",
                    help="이 exe 를 방화벽 허용 + 자동시작 작업으로 등록 후 시작 (관리자 권한 필요)")
    ap.add_argument("--uninstall", action="store_true", help="등록된 작업/방화벽 룰 제거")
    ap.add_argument("--no-replace", action="store_true",
                    help="기존 인스턴스가 있으면 교체하지 않고 종료 (기본: 기존 것을 정리하고 새로 시작)")
    ap.add_argument("--task-name", default="file-agent", help="작업 스케줄러 이름 (기본 file-agent)")
    # 작업 스케줄러가 붙이는 표시. 이때는 사용자의 [중지]를 존중하고, 이미 떠 있는 데몬에 양보한다.
    ap.add_argument("--from-task", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    setup_logging(os.path.join(base, "agent.log"))
    threading.excepthook = _thread_excepthook

    # 셀프 설치/제거: exe 한 개만으로 등록 가능
    if args.uninstall:
        return self_uninstall(args.task_name)
    if args.install:
        ensure_config(args.config)              # 설치 시 config 없으면 템플릿으로 생성
        try:
            install_cfg = Config.load(args.config)
        except Exception as e:  # noqa: BLE001
            log.error("설치 중단 — config.json 을 읽을 수 없습니다: %s", e)
            return 2
        # 부팅 작업은 인자 없이 config.json 만 읽는다 — 설치 때 CLI 로 다른 값을 주면 등록 뒤에 어긋난다.
        if args.token and args.token != install_cfg.token:
            log.error("설치 중단 — --token 이 config.json 의 토큰과 다릅니다. UI 에서 저장한 뒤 다시 켜세요.")
            return 2
        if args.port and args.port != install_cfg.port:
            log.error("설치 중단 — --port 가 config.json 의 port 와 다릅니다. UI 에서 저장한 뒤 다시 켜세요.")
            return 2
        install_cfg.finalize_watches()
        problem = startup_problem(install_cfg)
        if problem:
            # 이대로 등록하면 부팅·5분마다 시작 거부만 반복한다. 공개된 기본 토큰도 여기서 막는다.
            log.error("설치 중단 — %s", problem)
            return 2
        if os.path.abspath(base).startswith("\\\\"):
            log.error("설치 중단 — 네트워크 경로(%s)에는 설치할 수 없습니다. 로컬 디스크에 두세요.", base)
            return 2
        port = install_cfg.port or 8765
        try:
            os.remove(os.path.join(base, STOP_FLAG_NAME))   # 켜기 = 다시 돌게 하겠다는 뜻
        except OSError:
            pass
        log.info("설치: 방화벽에 TCP %s 허용", port)
        return self_install(args.task_name, port)

    held_instance = False
    if args.from_task:
        if user_stop_active(base):
            return 0
        # 5분 감시: 이미 돌고 있으면 설정을 읽거나 폴더를 만들기 전에 조용히 끝낸다.
        if not acquire_single_instance(0):
            return 0
        held_instance = True

    # 첫 실행도 그냥 되도록: config 없으면 기본 템플릿 자동 생성
    ensure_config(args.config)

    try:
        cfg = Config.load(args.config)
    except FileNotFoundError:
        log.error("설정 파일이 없습니다: %s", args.config)
        return 2
    except Exception as e:  # noqa: BLE001
        log.error("설정 로드 실패: %s", e)
        return 2

    apply_log_config(cfg)   # config 의 log_level/회전값 반영 (운영 부하·용량 관리)

    # CLI 오버라이드
    if args.dir:
        # --dir 는 단일 폴더 강제(다중 watch_dirs 무시) — 디버깅/단발 실행용
        cfg.watch_dir = args.dir
        cfg.watches = []
    if args.host:
        cfg.host = args.host
    if args.port:
        cfg.port = args.port
    if args.token:
        cfg.token = args.token
    if args.no_recursive:
        cfg.recursive = False
        for w in cfg.watches:
            w.recursive = False

    # watch_dirs 미지정 시 단일 watch_dir 로 watches 채움(라벨 "" = prefix 없음, 하위호환)
    cfg.finalize_watches()

    # ★ 설정 오류는 기존 데몬을 정리하기 '전에' 거른다. 잘못된 exe 를 실수로 실행해도
    #   정상 운영 중인 데몬을 죽이고 자기도 종료해 버리는 일이 없게 한다.
    problem = startup_problem(cfg)
    if problem:
        log.error("시작하지 않습니다 — %s", problem)
        return 2
    backend_driven = (not cfg.s3_direct_enabled
                      and (cfg.ws_enabled or cfg.mode == "backend" or cfg.push_enabled))
    if not cfg.watches:
        if not backend_driven:
            log.error("감시 폴더가 없습니다. config.json 의 watch_dir 또는 watch_dirs 를 지정하세요.")
            return 2
        log.info("감시 폴더는 백엔드 캔버스 노드가 내려줍니다 — 연결되면 감시를 시작합니다.")
    # 감시 폴더 생성은 Runtime 이 한다(볼 수 없는 폴더는 경고만, 설치 폴더 안은 만들지 않음).
    if not cfg.token:
        log.warning("token 이 비어 있습니다. 이 PC 안에서는 무인증으로 접근됩니다(권장하지 않음).")
    for w in cfg.watches:
        if _is_inside(w.path, base):
            log.warning("감시 폴더가 설치 폴더 안에 있습니다(%s). 설치 폴더 밖으로 옮기는 것을 권장합니다.", w.path)

    # 중복 실행 방지 + 교체 시작(기본): 같은 포트로 이미 떠 있으면
    #  - 기본 동작: 기존 인스턴스(좀비/멈춤 포함)를 강제 종료하고 이 인스턴스가 자리를 차지한다.
    #    → "exe 더블클릭 = 항상 깨끗한 재시작". 뮤텍스는 OS 가 프로세스 종료 시 자동 해제.
    #  - --no-replace 지정 시: 기존처럼 이 인스턴스가 양보하고 종료.
    #  ※ 기존 인스턴스가 SYSTEM(스케줄러) 권한이면 일반 권한으로는 못 죽일 수 있음
    #     → 그 경우 file-agent-ui.exe 의 [다시 시작](관리자)을 쓰라고 로그에 남긴다.
    if not held_instance and not acquire_single_instance(cfg.port):
        if args.from_task:
            # 5분 감시 트리거: 이미 누군가 돌고 있으면 건드리지 않는다.
            log.debug("이미 실행 중인 데몬이 있어 자동 실행 점검만 하고 끝냅니다.")
            return 0
        if args.no_replace:
            log.error("이미 file-agent 가 실행 중입니다(포트 무관 — 한 PC 에 하나만 허용). "
                      "(--no-replace) 이 인스턴스는 종료합니다.")
            return 3
        log.warning("기존 인스턴스 감지 — 교체 시작: 이전 file-agent 프로세스를 정리합니다.")
        _kill_other_instances(cfg.port)
        acquired = False
        for _ in range(20):  # 최대 10초 대기 (뮤텍스/포트 해제)
            time.sleep(0.5)
            if acquire_single_instance(cfg.port):
                acquired = True
                break
        if not acquired:
            log.error("기존 인스턴스를 정리하지 못했습니다(권한 부족 가능성). "
                      "file-agent-ui.exe 의 [다시 시작]을 쓰거나 관리자 권한으로 실행하세요.")
            return 3
        log.info("교체 완료 — 새 인스턴스로 계속합니다.")

    log.info("==================== file-agent %s 시작 ====================", VERSION)
    if cfg.is_multi:
        for w in cfg.watches:
            log.info("감시 디렉터리: %s → prefix '%s/' (recursive=%s)",
                     w.path, w.label, w.recursive)
    else:
        log.info("감시 디렉터리: %s (recursive=%s)", cfg.watch_dir, cfg.recursive)
    log.info("HTTP 노출: http://%s:%d", cfg.host, cfg.port)

    store = EventStore(os.path.join(base, "events.jsonl"))
    # 포트를 먼저 잡는다 — 다른 프로그램이 쓰고 있으면 원장·전송을 시작하기 전에 분명한 오류로 끝낸다.
    try:
        httpd = AgentHTTPServer((cfg.host, cfg.port), cfg, store, runtime=None)
    except OSError as e:
        log.error("시작하지 않습니다 — 포트 %s:%d 를 열 수 없습니다(다른 프로그램이 사용 중?): %s",
                  cfg.host, cfg.port, e)
        return 2

    # 시작 시 현재 listen 포트를 방화벽에 자동 허용(관리자 권한일 때만 성공).
    ensure_firewall_port(cfg.port)

    # 전송 완료 원장: 재부팅/서버 다운 후에도 "적재 확인된 파일"을 기억해 차등 전송.
    #   메모리 보관 상한은 config(ledger_keep_in_memory) — 동시 보관 파일 수보다 크게.
    ledger = SentLedger(os.path.join(base, "sent.jsonl"), keep_in_memory=cfg.ledger_keep_in_memory)
    # 기동 시 원장 컴팩션(ADR-019): 스코프 밖/디스크에 없는 항목 제거 → 시작메모리·디스크 상한.
    # (워커 시작 전이라 append 경쟁 없음. cfg.finalize_watches 는 위에서 이미 수행됨.)
    # 백엔드가 감시 폴더를 정하는 모드에서는 지금 폴더 목록이 임시값이라 여기서 정리하지 않는다 —
    # 첫 set_watch_dirs 를 받은 뒤 Rescanner 가 정리한다.
    if cfg.ledger_compaction and not backend_driven:
        try:
            _kept, _dropped = ledger.compact(cfg.resolve_for_compaction)
            log.info("원장 시작 컴팩션: 유지 %d / 제거 %d", _kept, _dropped)
        except Exception as _e:  # noqa: BLE001
            log.warning("원장 시작 컴팩션 실패(무시): %s", _e)

    # ── 모드 결정 ──
    # 직접 모드: config.json 에 s3_endpoint + s3_bucket 가 있으면 백엔드를 거치지 않고
    # 데몬이 SeaweedFS 에 직접 업로드한다(데몬 단독). 이때 ws/push(백엔드 경유)는 비활성.
    # 그 외(직접모드 아님): 기존대로 백엔드 워크플로우가 적재 역할을 수행(ws/push/pull).
    s3_uploader: "S3Uploader | None" = None
    direct = cfg.s3_direct_enabled
    if direct:
        s3_uploader = S3Uploader(cfg)
        log.info("S3 직접 업로드 모드: s3://%s (endpoint=%s) — 백엔드 경유 안 함",
                 cfg.s3_bucket, cfg.s3_endpoint)

    # PUSH 모드: backend 로 직접 전송하는 클라이언트 (설정 시에만 생성, 직접모드면 생략)
    push_client: "PushClient | None" = None
    if cfg.push_enabled and not direct:
        if not cfg.push_url:
            log.error("push_enabled=true 이지만 push_url 이 비어 있습니다. config.json 에 push_url 을 지정하세요.")
            return 2
        push_client = PushClient(cfg.push_url, cfg.token)
        push_client.start()
        log.info("PUSH 대상: %s (token %s)", cfg.push_url, "설정됨" if cfg.token else "없음(무인증)")

    # Runtime 이 observer/worker 를 보유 → /control/watch_dir 로 런타임 교체 가능
    runtime = Runtime(cfg, store, push_client, s3_uploader=s3_uploader, ledger=ledger)
    runtime.scope_ready = not backend_driven
    runtime.app_dir = base
    if push_client is not None:
        push_client.on_fail = runtime.forget_emitted

    # WS 모드: backend 와 양방향 WebSocket. (직접모드면 생략)
    # ws_client 는 runtime(명령 처리용)이 필요하고 runtime.start() 전에 주입해야 worker 가 ws 로도 enqueue 한다.
    # mode=="backend" 면 ws_enabled 안 적어도 ws 를 켠다.
    # 항상 WsClientPool 사용 (n=1 이면 기존 단일 연결과 동일) — 상한 큐/inflight/ack 리퍼 일원화.
    ws_client: "WsClientPool | None" = None
    if (cfg.ws_enabled or cfg.mode == "backend") and not direct:
        if not cfg.ws_url:
            log.error("백엔드 모드인데 ws_url 이 비어 있습니다. config.json 에 ws_url 을 지정하세요.")
            return 2
        ws_client = WsClientPool(cfg.ws_url, cfg.token, runtime, cfg, cfg.ws_senders)
        runtime.ws_client = ws_client

    # ★ WS 연결을 초기 스캔보다 먼저 연다 — 스캔(수십만 건, 배압으로 장시간)이 끝나기를
    # 기다렸다가 연결하면 그동안 전송이 한 건도 못 나간다 (2026-07-07 이슈).
    if ws_client is not None:
        ws_client.start()
        log.info("WS 대상: %s (token %s)", cfg.ws_url, "설정됨" if cfg.token else "없음(무인증)")

    runtime.start()

    # 배치 수집 + 보정 스캔 스레드 (무중단·무손실 보조 경로)
    rescanner = Rescanner(cfg, runtime)
    runtime.rescanner = rescanner
    rescanner.start()

    # PUSH 모드: backend 에서 watch_dir 를 폴링해 동적 적용 (외부망 데몬도 UI 에서 dir 변경 가능)
    config_poller: "ConfigPoller | None" = None
    if cfg.push_enabled and push_client is not None:
        config_poller = ConfigPoller(cfg.push_url, cfg.token, runtime)
        config_poller.start()

    httpd.runtime = runtime
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    # 런타임이 HTTP 서버를 관리하도록 등록 → 노드 Port 변경 시 swap_listen 으로 동적 재바인딩.
    runtime.attach_http_server(httpd, server_thread)

    stop_evt = threading.Event()

    def _shutdown(*_):
        log.info("종료 신호 수신.")
        stop_evt.set()

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, _shutdown)
        except (ValueError, OSError):
            pass

    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        log.info("정리 중...")
        try:
            (runtime.httpd or httpd).shutdown()
        except Exception:  # noqa: BLE001
            pass
        if config_poller is not None:
            config_poller.stop()
        rescanner.stop()
        runtime.stop()
        if push_client is not None:
            push_client.stop()
        if ws_client is not None:
            ws_client.stop()
        log.info("file-agent 종료.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001  (SystemExit·KeyboardInterrupt 는 그대로 통과)
        # --noconsole exe 에서 처리 안 된 예외가 나면 PyInstaller 부트로더가 오류 창을 띄우고 멈춘다.
        # SYSTEM 계정으로 부팅할 때는 그 창을 누를 사람이 없어 프로세스가 영원히 대기한다.
        # 로그에 남기고 끝낸다 — 작업 스케줄러의 5분 감시 트리거가 다시 띄운다.
        import traceback as _tb
        _msg = _tb.format_exc()
        try:
            log.error("기동 실패 — 처리되지 않은 예외\n%s", _msg)
        except Exception:  # noqa: BLE001
            pass
        try:  # 로깅 설정 전에 터졌을 수도 있으니 파일에도 남긴다
            with open(os.path.join(app_dir(), "agent-crash.log"), "a", encoding="utf-8") as _f:
                _f.write("[%s]\n%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), _msg))
        except Exception:  # noqa: BLE001
            pass
        sys.exit(1)
