#!/usr/bin/env python3
"""
file-agent : 디렉터리 감시 + 이벤트/파일 노출 데몬 (Pull 모델)

[역할]  로컬 PC(예: 10.1.55.91)에서 실행.
  1) 지정한 디렉터리를 감시(watchdog)하여 새 파일 생성/이동(드롭)을 감지
  2) HTTP 포트를 하나 열어, 가져가는 쪽(teresaMqback / 225 서버)이
     - 파일 생성 "이벤트"를 구독(SSE) 또는 폴링하고
     - 해당 "파일 내용"을 다운로드
     할 수 있게 노출한다.

Linux / Windows 공통으로 동작. 표준 라이브러리 + watchdog 만 사용.

자세한 HTTP API 규격은 README.md 참고.
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
    from watchdog.events import FileSystemEventHandler
except ImportError:
    sys.stderr.write("watchdog 가 필요합니다.  pip install watchdog\n")
    raise

VERSION = "1.2.0"

log = logging.getLogger("file-agent")


# ============================================================================
#  네트워크 도달성 헬퍼 (프리플라이트용)
# ============================================================================
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
        # push_url 예) http://211.57.136.85:3939  (backend 공인 주소, 끝 슬래시 제외)
        self.push_enabled: bool = bool(d.get("push_enabled", False))
        self.push_url: str = str(d.get("push_url", "")).rstrip("/")
        # ── WS 모드 (양방향) ──
        # ws_enabled=true 면 backend 와 WebSocket 으로 양방향 통신 (파일 업로드 + 역방향 삭제).
        # 데몬이 WS 클라이언트로 outbound 연결하므로 내부/외부망(NAT) 무관. ws_url 예) http://10.1.55.225:3940
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
        #                        예) http://10.1.55.225:28333  (비우면 해당 확인 생략)
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
            walker = (os.path.join(base, fn)
                      for fn in os.listdir(base)
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
        with open(path, "r", encoding="utf-8") as f:
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

    def compact(self, resolver) -> tuple[int, int]:
        """원장을 '현재 watch 스코프 안 & 디스크에 실제 존재' 항목만으로 축소한다(ADR-019).
        resolver(relpath) -> 절대경로|None (Config.resolve). None 이거나 파일이 없으면 제거.
        - 소스가 사라진(작업자 용량정리 삭제) / 스코프 밖(WatchDir 축소) 항목을 걷어내
          원장·시작메모리·디스크를 '현존 파일 수'로 상한시킨다. S3/백엔드 무왕복(로컬만).
        - 안전: '디스크에 없는' 항목만 제거 → 현존 파일의 재전송을 유발하지 않음(무손실 불변식 무관).
        - 락 최소화: 느린 디스크 stat 은 락 밖에서 수행."""
        with self._lock:
            items = list(self._map.items())
        dropped_keys: list[str] = []
        for p, _v in items:
            try:
                ap = resolver(p)
            except Exception:  # noqa: BLE001
                ap = None
            if ap is None or not os.path.exists(ap):
                dropped_keys.append(p)
        if not dropped_keys:
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
            return (len(self._map), len(dropped_keys))

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
                log.warning("push 실패 (%s %s): %s", ev_type, relpath, e)

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
                with urllib.request.urlopen(req, timeout=30) as resp:
                    log.info("push OK [%s] %s → HTTP %s", ev_type, relpath, resp.getcode())
                    return
            except urllib.error.HTTPError as he:
                # 404 = 활성 push 엣지 없음(아직 미활성). 재시도해도 동일하므로 한 번만 알리고 종료.
                if he.code == 404:
                    log.info("push 대기 [%s] %s — 활성 push 엣지 없음(엣지 활성화 후 다시 시도됨)", ev_type, relpath)
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
        # 프리플라이트는 http(s) 로 호출하므로 원본 http base 를 보관한다.
        self.http_base = base if base.startswith(("http://", "https://")) else ("http://" + base)
        self.token = token
        self.runtime = runtime
        self.cfg = cfg
        self._q: "queue.Queue[tuple | None]" = shared_q if shared_q is not None else queue.Queue()
        self._ws = None
        self._connected = threading.Event()
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
        log.info("WS 모드 활성: %s", self.ws_url)
        threading.Thread(target=self._sender_loop, daemon=True).start()
        backoff = 1.0
        while not self._stop.is_set():
            # ── 프리플라이트 게이트 ──
            # 양방향 도달성(에이전트→SeaweedFS, 백엔드→에이전트 등)이 확인돼야 WS 를 연다.
            # 실패하면 WS 를 열지 않고 백오프 후 재점검(무작정 WS 재연결 방지).
            if not self._preflight():
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
        """WS 를 열기 전 양방향 도달성을 확인한다.
          1) 에이전트 → SeaweedFS(직접): cfg.s3_endpoint 로 TCP 도달.
          2) 에이전트 → 백엔드          : 프리플라이트 요청이 도달하는지(= 호출 성공).
          3) 백엔드 → 에이전트:port/health : 백엔드가 응답으로 알려줌(backendToAgent).
          4) 백엔드 → SeaweedFS          : 백엔드가 응답으로 알려줌(backendToSeaweed).
        모두 통과해야 True. cfg 없거나 preflight_enabled=false 면 점검 생략(True)."""
        cfg = self.cfg
        if cfg is None or not getattr(cfg, "preflight_enabled", True):
            return True

        # 1) 에이전트 → SeaweedFS 직접 도달성
        if cfg.s3_endpoint:
            sh, sp = _split_host_port(cfg.s3_endpoint, 80)
            if not _tcp_reachable(sh, sp, timeout=3.0):
                log.warning("프리플라이트: 에이전트→SeaweedFS 도달 실패 (%s)", cfg.s3_endpoint)
                return False
            log.info("프리플라이트: 에이전트→SeaweedFS OK (%s)", cfg.s3_endpoint)

        # 2~4) 백엔드 프리플라이트 호출 (역방향 점검은 백엔드가 수행해 결과를 돌려줌)
        backend_host, _ = _split_host_port(self.http_base, 80)
        adv_host = cfg.advertise_host or _detect_local_ip(backend_host)
        params = {"host": adv_host, "port": str(cfg.port)}
        if cfg.s3_endpoint:
            params["s3Endpoint"] = cfg.s3_endpoint
        url = self.http_base + "/api/file-agent/preflight?" + urlencode(params)
        try:
            req = urllib.request.Request(url, method="GET")
            if self.token:
                req.add_header("X-Agent-Token", self.token)
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            log.warning("프리플라이트: 에이전트→백엔드 호출 실패 (%s) — %s", url, e)
            return False

        ok = bool(data.get("ok"))
        log.info("프리플라이트: 백엔드 응답 ok=%s (backendToAgent=%s, backendToSeaweed=%s, advHost=%s:%s)",
                 ok, data.get("backendToAgent"), data.get("backendToSeaweed"), adv_host, cfg.port)
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
        self._connected.set()
        log.info("WS 연결됨: %s (send_timeout=%.0fs)", self.ws_url, self.send_timeout)

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

            def _apply_watch_cmd():
                try:
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
                    if result.get("status") == "noop":
                        log.debug("WS: set_watch_dirs 동일 구성 — noop")
                    else:
                        log.info("WS: backend set_watch_dir(s) 적용 → %s", result)
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
                log.info("WS 오퍼 스킵 [%s] %s (result=%s)", ev_type, relpath, verdict)
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
            for relpath, ev_type, abspath in expired:
                st = self.enqueue(ev_type, relpath, abspath)
                if st == "full":
                    self.request_rescan()
            if expired:
                log.warning("ack 타임아웃 %d건 재전송 투입 (남은 대기 %d건)", len(expired), len(pa))

    def start(self) -> None:
        for c in self.clients:
            c.start()
        self._reaper.start()
        log.info("WS 병렬 전송 활성: 연결 %d개 (폴더별 전용 큐·라운드로빈, 상한 %d, offer=%s)",
                 len(self.clients), self._maxsize,
                 "on" if self.runtime.cfg.offer_enabled else "OFF(벌크 초기적재)")

    def stop(self) -> None:
        self._stop.set()
        with self._cv:
            self._cv.notify_all()   # 대기 중인 senders/enqueuers 깨워 종료시킨다
        for c in self.clients:
            try:
                c.stop()
            except Exception:  # noqa: BLE001
                pass


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

    def touch(self, abspath: str, ev_type: str) -> None:
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
            self._emit(abspath, ev_type)
            return
        with self._lock:
            self._pending[abspath] = {"size": -1, "last_change": time.time(), "type": ev_type}

    def emit_deleted(self, abspath: str) -> None:
        """적재 전용(ingest-only): 로컬 삭제는 어디에도 전송/반영하지 않는다.
        pending/emitted 캐시만 정리해 동일 경로 재생성 시 새 파일로 다시 추적되게 한다."""
        with self._lock:
            self._pending.pop(abspath, None)
            self._emitted.pop(abspath, None)
        log.debug("로컬 삭제 감지 — 무시(적재 전용): %s", abspath)

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

    def _emit(self, abspath: str, ev_type: str) -> None:
        try:
            st = os.stat(abspath)
        except OSError:
            return
        # ── 용량 필터: 크기가 확정된 시점(안정화 후)에 이상/이하 제외 판정 ──
        if not self.cfg.file_allowed(abspath, size=st.st_size):
            return
        key = (st.st_size, int(st.st_mtime))
        with self._lock:
            if self._emitted.get(abspath) == key:
                return  # 동일 내용 재발행 방지
            self._emitted[abspath] = key
            while len(self._emitted) > self._EMITTED_MAX:
                self._emitted.pop(next(iter(self._emitted)))
        relpath = self.cfg.make_relpath(abspath)
        if not relpath:
            return  # 감시 폴더 밖이면 무시
        # ── 전송 원장 대조: 이미 적재 확인된 파일은 재전송하지 않음 (재부팅/재스캔 무손실·무중복) ──
        if self.ledger is not None and self.ledger.has(relpath, st.st_size, st.st_mtime):
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
            if self.s3_uploader.put(relpath, abspath) and self.ledger is not None:
                self.ledger.record(relpath, st.st_size, st.st_mtime)

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
        self.worker: "StabilityWorker | None" = None
        self.observer = None  # watchdog Observer
        self.httpd = None          # AgentHTTPServer (listen 포트 동적 교체용)
        self.http_thread = None    # serve_forever 스레드
        self._lock = threading.Lock()

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
            os.makedirs(w.path, exist_ok=True)
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
        self.observer = Observer()
        scheduled = 0
        for w in self.cfg.watches:
            if w.batch:
                log.info("감시 시작(배치): %s (label=%s, interval=%.0fs — watchdog 미사용)",
                         w.path, w.label or "(none)",
                         w.batch_interval or self.cfg.rescan_interval_seconds or 60.0)
                continue
            self.observer.schedule(_Handler(self.worker), w.path, recursive=w.recursive)
            scheduled += 1
            flt = self.cfg.effective_filters(w)
            log.info("감시 시작: %s (label=%s, recursive=%s, 필터: %s)",
                     w.path, w.label or "(none)", w.recursive, flt.summary())
        if scheduled:
            self.observer.start()

    def stop(self) -> None:
        with self._lock:
            self._stop_unlocked()

    def _stop_unlocked(self) -> None:
        if self.observer is not None:
            try:
                self.observer.stop()
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
                for w in self.cfg.watches:
                    os.makedirs(w.path, exist_ok=True)
                self._start_unlocked()
            except Exception as e:  # noqa: BLE001
                log.error("watch_dirs 적용 실패(%s) — 이전 감시 구성으로 복구", e)
                self.cfg.watches = prev_watches
                self.cfg.watch_dir = prev_watch_dir
                try:
                    self._start_unlocked()
                except Exception as e2:  # noqa: BLE001
                    log.error("이전 감시 구성 복구 실패: %s", e2)
                return {"status": "error", "reason": str(e), "watches": self.cfg.watch_summary()}
            summary = self.cfg.watch_summary()
            log.info("watch_dirs 변경 → %s", summary)
            return {"status": "ok", "watches": summary}

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
        with urllib.request.urlopen(req, timeout=10) as resp:
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
        self._stop = threading.Event()
        self._next_run: dict[str, float] = {}   # watch.path -> 다음 실행 시각
        self._last_compact: float = 0.0         # 원장 컴팩션 마지막 실행 시각(ADR-019)

    def stop(self) -> None:
        self._stop.set()

    def _interval_for(self, w: "Watch") -> float:
        if w.batch:
            return w.batch_interval or self.cfg.rescan_interval_seconds or 60.0
        return self.cfg.rescan_interval_seconds  # 0 = 보정 스캔 없음

    def run(self) -> None:
        log.info("보정/배치 스캐너 시작 (기본 주기 %.0fs, 큐 포화 시 조기 기동)",
                 self.cfg.rescan_interval_seconds)
        # 시작 직후엔 emit_existing_on_start 가 이미 1회 스캔했으므로 주기만큼 대기 후 시작.
        while not self._stop.is_set():
            triggered = self.runtime.rescan_event.wait(timeout=5.0)
            if self._stop.is_set():
                break
            if triggered:
                self.runtime.rescan_event.clear()
            now = time.time()
            worker = self.runtime.worker
            if worker is None:
                continue
            for w in list(self.cfg.watches):
                iv = self._interval_for(w)
                if iv <= 0 and not triggered:
                    continue  # 보정 스캔 꺼짐 (배치 아님 + interval=0)
                due = self._next_run.get(w.path, now + (iv if iv > 0 else 60.0))
                if not triggered and now < due:
                    continue
                self._next_run[w.path] = now + (iv if iv > 0 else 60.0)
                scanned = 0
                for _relpath, ap, _size, _mtime in self.cfg.iter_existing(only=w):
                    if self.runtime.worker is not worker or self._stop.is_set():
                        break  # 감시 구성 교체/종료 — 이번 스캔 양보
                    worker.touch(ap, "existing")
                    scanned += 1
                log.info("%s 스캔: %s — %d개 파일 대조 투입 (미적재분만 전송됨)",
                         "배치" if w.batch else "보정", w.path, scanned)
            # 보정 스캔 뒤 원장 컴팩션(ADR-019): 스코프 밖/디스크에 없는 항목 제거.
            #   rescan_interval(최소 60s)마다 1회로 제한 — 잦은 트리거에도 과다 실행 방지.
            _lg = getattr(self.runtime, "ledger", None)
            if self.cfg.ledger_compaction and _lg is not None:
                if now - self._last_compact >= max(self.cfg.rescan_interval_seconds, 60.0):
                    self._last_compact = now
                    try:
                        _lg.compact(self.cfg.resolve)
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
            }
            if runtime is not None:
                body["ledger_size"] = len(runtime.ledger) if runtime.ledger else 0
                body["pending_acks"] = len(runtime.pending_acks) if runtime.pending_acks else 0
                body["ack_mode"] = runtime.ack_enabled
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
    """같은 포트로 실행 중인 인스턴스가 없으면 잠금을 잡고 True, 이미 있으면 False.
    잠금 자체를 만들 수 없는 환경 오류는 '막지 않음'(True) 으로 보수적으로 처리한다."""
    global _singleton_handle
    name = f"file-agent-port-{int(port)}"
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
            log.warning("단일 인스턴스 뮤텍스 생성 실패(중복검사 건너뜀): err=%s", last)
            return True
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


def _kill_other_instances() -> None:
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
        cmd = ["taskkill", "/F", "/T", "/IM", "file-agent.exe", "/FI", f"PID ne {me}"]
        if parent:
            cmd += ["/FI", f"PID ne {parent}"]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        msg = ((r.stdout or "") + (r.stderr or "")).strip().replace("\r\n", " / ")
        log.info("기존 인스턴스 정리: %s", msg or f"rc={r.returncode}")
    except Exception as e:  # noqa: BLE001
        log.warning("기존 인스턴스 정리 실패(무시): %s", e)


# 기본 config 템플릿 — config.json 이 없으면 첫 실행 시 이 내용으로 생성한다(편집해서 사용).
DEFAULT_CONFIG_JSON = """{
  // ★ 모드 선택 — 이 한 줄로 결정: "direct" 또는 "backend"
  "mode": "direct",

  // ===================== 공통 =====================
  // 감시할 폴더. 둘 중 하나만 쓰면 됨:
  //  (1) 단일 폴더  : "watch_dir": "C:/file-agent/watch"   (prefix 없음)
  //  (2) 여러 폴더  : "watch_dirs": ["C:/test", "C:/khk"]  (폴더명 자동 prefix → test/..., khk/...)
  //     라벨/recursive 개별 지정도 가능:
  //     "watch_dirs": [{"dir":"C:/test","label":"raw","recursive":true}, {"dir":"C:/khk"}]
  "watch_dir": "C:/file-agent/watch",
  // "watch_dirs": ["C:/test", "C:/khk"],
  "token": "change-me-please-long-random-token",
  "port": 8765,

  // ===== mode=="backend" 일 때만 사용 =====
  "ws_url": "http://10.1.55.225:3940",  // 백엔드 주소

  // ===== mode=="direct" 일 때만 사용 =====
  "s3_endpoint": "http://10.1.55.225:28333",
  "s3_bucket": "noteTest",
  "s3_access_key": "",
  "s3_secret_key": ""
}
"""


def ensure_config(path: str) -> bool:
    """config.json 이 없으면 기본 템플릿으로 생성. 생성했으면 True."""
    if os.path.isfile(path):
        return False
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(DEFAULT_CONFIG_JSON)
        log.info("기본 config.json 생성: %s — watch_dir/token/(직접모드면 s3_*) 편집하세요.", path)
        return True
    except OSError as e:
        log.error("config.json 생성 실패 %s: %s", path, e)
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


def self_install(task_name: str, port: int) -> int:
    """exe 자기 자신을 방화벽 허용 + 작업 스케줄러(로그인 시 시작, 죽으면 재시작)에 등록 후 시작."""
    if not getattr(sys, "frozen", False):
        log.error("--install 은 빌드된 file-agent.exe 에서만 동작합니다.")
        return 2
    exe = sys.executable
    work = os.path.dirname(exe)
    ps = (
        "$ErrorActionPreference='Stop';"
        f"$exe='{exe}'; $work='{work}'; $port={int(port)}; $task='{task_name}';"
        "if(-not (Get-NetFirewallRule -DisplayName $task -ErrorAction SilentlyContinue)){"
        "New-NetFirewallRule -DisplayName $task -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null};"
        "$a=New-ScheduledTaskAction -Execute $exe -WorkingDirectory $work;"
        # 부팅 시(AtStartup) + 로그인 시(AtLogOn) 둘 다 트리거 → 로그인 안 해도 부팅하면 자동 수집 시작.
        "$t1=New-ScheduledTaskTrigger -AtStartup;"
        "$t2=New-ScheduledTaskTrigger -AtLogOn;"
        "$s=New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew;"
        # SYSTEM 계정 + Highest: 로그인 없이 부팅 시 관리자 권한으로 실행(방화벽 제어 가능).
        "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
        "Register-ScheduledTask -TaskName $task -Action $a -Trigger @($t1,$t2) -Settings $s -Principal $p -Description 'TERESA MQ file-agent' -Force | Out-Null;"
        "Start-ScheduledTask -TaskName $task;"
        "Write-Host ('installed: '+$task+' (port '+$port+')')"
    )
    rc = _run_powershell(ps)
    if rc != 0:
        log.error("설치 실패 — 관리자 권한 PowerShell 에서 다시 실행하세요.")
    return rc


def self_uninstall(task_name: str) -> int:
    """작업 스케줄러 등록 + 방화벽 룰 제거."""
    ps = (
        f"$task='{task_name}';"
        "try{Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue}catch{};"
        "try{Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue}catch{};"
        "try{Get-NetFirewallRule -DisplayName $task -ErrorAction SilentlyContinue | Remove-NetFirewallRule}catch{};"
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
    args = ap.parse_args()

    setup_logging(os.path.join(base, "agent.log"))

    # 셀프 설치/제거: exe 한 개만으로 등록 가능
    if args.uninstall:
        return self_uninstall(args.task_name)
    if args.install:
        ensure_config(args.config)              # 설치 시 config 없으면 기본 생성
        # 방화벽에 열 포트: --port 우선, 없으면 config.json 의 port (노드 Port 와 맞춰둔 값).
        port = args.port
        if not port:
            try:
                with open(args.config, encoding="utf-8") as f:
                    # 주석(JSONC) config 도 읽도록 _strip_jsonc 사용
                    port = int(json.loads(_strip_jsonc(f.read())).get("port", 8765))
            except Exception:  # noqa: BLE001
                port = 8765
        log.info("설치: 방화벽에 TCP %s 허용 (config.json/노드 Port 와 동일해야 함)", port)
        return self_install(args.task_name, port)

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
    if not cfg.watches:
        log.error("감시 폴더가 없습니다. config.json 의 watch_dir 또는 watch_dirs 를 지정하세요.")
        return 2
    for w in cfg.watches:
        os.makedirs(w.path, exist_ok=True)
    if not cfg.token:
        log.warning("token 이 비어 있습니다. 포트가 무인증으로 열립니다(보안상 권장하지 않음).")

    # 중복 실행 방지 + 교체 시작(기본): 같은 포트로 이미 떠 있으면
    #  - 기본 동작: 기존 인스턴스(좀비/멈춤 포함)를 강제 종료하고 이 인스턴스가 자리를 차지한다.
    #    → "exe 더블클릭 = 항상 깨끗한 재시작". 뮤텍스는 OS 가 프로세스 종료 시 자동 해제.
    #  - --no-replace 지정 시: 기존처럼 이 인스턴스가 양보하고 종료.
    #  ※ 기존 인스턴스가 SYSTEM(스케줄러) 권한이면 일반 권한으로는 못 죽일 수 있음
    #     → 그 경우 관리자 권한(에이전트_재시작.bat, UAC 승인)이 필요하다고 로그에 남긴다.
    if not acquire_single_instance(cfg.port):
        if args.no_replace:
            log.error("이미 같은 포트(%d)로 file-agent 가 실행 중입니다. (--no-replace) 이 인스턴스는 종료합니다.", cfg.port)
            return 3
        log.warning("기존 인스턴스 감지 — 교체 시작: 이전 file-agent 프로세스를 정리합니다.")
        _kill_other_instances()
        acquired = False
        for _ in range(20):  # 최대 10초 대기 (뮤텍스/포트 해제)
            time.sleep(0.5)
            if acquire_single_instance(cfg.port):
                acquired = True
                break
        if not acquired:
            log.error("기존 인스턴스를 정리하지 못했습니다(권한 부족 가능성). "
                      "'에이전트_재시작.bat'을 관리자 권한(UAC 예)으로 실행하세요.")
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

    # 시작 시 현재 listen 포트를 방화벽에 자동 허용(관리자 권한일 때만 성공).
    ensure_firewall_port(cfg.port)

    store = EventStore(os.path.join(base, "events.jsonl"))
    # 전송 완료 원장: 재부팅/서버 다운 후에도 "적재 확인된 파일"을 기억해 차등 전송.
    #   메모리 보관 상한은 config(ledger_keep_in_memory) — 동시 보관 파일 수보다 크게.
    ledger = SentLedger(os.path.join(base, "sent.jsonl"), keep_in_memory=cfg.ledger_keep_in_memory)
    # 기동 시 원장 컴팩션(ADR-019): 스코프 밖/디스크에 없는 항목 제거 → 시작메모리·디스크 상한.
    # (워커 시작 전이라 append 경쟁 없음. cfg.finalize_watches 는 위에서 이미 수행됨.)
    if cfg.ledger_compaction:
        try:
            _kept, _dropped = ledger.compact(cfg.resolve)
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
    rescanner.start()

    # PUSH 모드: backend 에서 watch_dir 를 폴링해 동적 적용 (외부망 데몬도 UI 에서 dir 변경 가능)
    config_poller: "ConfigPoller | None" = None
    if cfg.push_enabled and push_client is not None:
        config_poller = ConfigPoller(cfg.push_url, cfg.token, runtime)
        config_poller.start()

    httpd = AgentHTTPServer((cfg.host, cfg.port), cfg, store, runtime=runtime)
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
    sys.exit(main())
# v1.2.0 — 수집 필터(파일명/확장자/용량)·전송원장(ack)·배치/보정 스캔 추가
