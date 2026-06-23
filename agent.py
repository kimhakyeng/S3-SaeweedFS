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
import hashlib
import hmac
import json
import logging
import os
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

VERSION = "1.0.0"

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
#  감시 대상 한 건 (폴더 + 라벨 + recursive)
#   - label : 이벤트/스토리지 경로의 prefix. "" 이면 prefix 없음(단일 watch_dir 하위호환).
#             여러 폴더(watch_dirs)일 때는 폴더명(basename)을 기본 라벨로 써서
#             relpath 를 "<label>/<상대경로>" 로 네임스페이스 → 파일명 충돌 방지.
# ============================================================================
class Watch:
    def __init__(self, path: str, label: str = "", recursive: bool = True):
        self.path: str = os.path.abspath(path)
        self.label: str = (label or "").strip().strip("/")
        self.recursive: bool = bool(recursive)

    def __repr__(self) -> str:  # 로깅용
        return f"Watch(path={self.path!r}, label={self.label!r}, recursive={self.recursive})"


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
        # ── 다중 감시 폴더 ──
        # watch_dirs 가 있으면 여러 폴더를 한 에이전트가 병렬 감시한다.
        #   "watch_dirs": ["C:/test", "C:/khk"]                         ← 폴더명 자동 prefix(test/, khk/)
        #   "watch_dirs": [{"dir":"C:/test","label":"raw","recursive":true}, ...]  ← 라벨/recursive 개별 지정
        # 비어 있으면 기존 단일 watch_dir 사용(prefix 없음, 완전 하위호환).
        self.watches: list[Watch] = self._build_watches(d.get("watch_dirs"))
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
        # SeaweedFS(S3) 에 직접 PUT/DELETE 한다(boto3 필요). 값이 없으면 기존 ws/push(백엔드 경유).
        self.s3_bucket: str = str(d.get("s3_bucket", "")).strip()
        self.s3_access_key: str = str(d.get("s3_access_key", "")).strip()
        self.s3_secret_key: str = str(d.get("s3_secret_key", "")).strip()
        self.s3_region: str = (str(d.get("s3_region", "")).strip() or "us-east-1")
        self.s3_path_style: bool = bool(d.get("s3_path_style", True))
        self.s3_path_prefix: str = str(d.get("s3_path_prefix", "")).strip().strip("/")
        self.s3_enable_delete: bool = bool(d.get("s3_enable_delete", True))

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
        for item in raw:
            if isinstance(item, str):
                path = item
                label = _sanitize_label(os.path.basename(os.path.normpath(item)))
                rec = self.recursive
            elif isinstance(item, dict):
                path = str(item.get("dir") or item.get("path") or "").strip()
                if not path:
                    continue
                label = str(item.get("label") or "").strip()
                label = _sanitize_label(label) if label else \
                    _sanitize_label(os.path.basename(os.path.normpath(path)))
                rec = bool(item.get("recursive", self.recursive))
            else:
                continue
            specs.append(Watch(path, label, rec))
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

    def iter_existing(self):
        """모든 watch 의 현재 파일을 (relpath, abspath, size, mtime) 로 순회."""
        for w in self.watches:
            base = w.path
            if not os.path.isdir(base):
                continue
            if w.recursive:
                walker = (os.path.join(r, fn)
                          for r, _, fs in os.walk(base) for fn in fs)
            else:
                walker = (os.path.join(base, fn)
                          for fn in os.listdir(base)
                          if os.path.isfile(os.path.join(base, fn)))
            for ap in walker:
                try:
                    st = os.stat(ap)
                except OSError:
                    continue
                rel = os.path.relpath(ap, base).replace("\\", "/")
                relpath = f"{w.label}/{rel}" if w.label else rel
                yield (relpath, ap, st.st_size, st.st_mtime)

    def set_watches(self, specs: list) -> None:
        """런타임 교체용: watch_dirs 와 동일한 형식(list[str|dict])으로 watches 재구성."""
        self.watches = self._build_watches(specs)
        self.finalize_watches()

    def watch_summary(self) -> list[dict]:
        return [{"dir": w.path, "label": w.label, "recursive": w.recursive}
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
    def __init__(self, persist_path: str, keep_in_memory: int = 5000):
        self._persist_path = persist_path
        self._keep = keep_in_memory
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._events: list[dict] = []
        self._last_seq = 0
        self._load_existing()

    def _load_existing(self) -> None:
        if not os.path.exists(self._persist_path):
            return
        try:
            with open(self._persist_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ev = json.loads(line)
                    self._last_seq = max(self._last_seq, int(ev.get("seq", 0)))
                    self._events.append(ev)
            self._events = self._events[-self._keep:]
            log.info("기존 이벤트 로드: last_seq=%d", self._last_seq)
        except Exception as e:  # noqa: BLE001
            log.warning("events.jsonl 로드 실패(무시): %s", e)

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
            except Exception as e:  # noqa: BLE001
                log.warning("이벤트 영속화 실패(무시): %s", e)
            self._cond.notify_all()
            return ev

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
#   - 데몬→backend: file_begin(text) + 바이트(binary 256KB 청크) + file_end(text) / deleted(text)
#   - backend→데몬: delete_local(로컬 파일 삭제 = S3 역방향 삭제) / set_watch_dir(감시폴더 변경)
#   - 데몬이 outbound 연결 → 내부/외부망(NAT) 무관. 끊기면 지수백오프 재연결.
#   - websocket-client 라이브러리 필요 (pip install websocket-client).
# ============================================================================
class WsClient(threading.Thread):
    CHUNK = 256 * 1024

    def __init__(self, ws_base: str, token: str, runtime: "Runtime", cfg: "Config | None" = None):
        super().__init__(daemon=True)
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
        self._q: "queue.Queue[tuple | None]" = queue.Queue()
        self._ws = None
        self._connected = threading.Event()
        self._stop = threading.Event()
        self._send_lock = threading.Lock()

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
        self._connected.set()
        log.info("WS 연결됨: %s", self.ws_url)

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
        if t == "delete_local":
            self._delete_local(str(m.get("path", "")))
        elif t in ("set_watch_dir", "set_watch_dirs"):
            # watchDir(단수) 또는 watchDirs(복수). 단수 문자열에 ';' 가 있으면 여러 폴더로 분리.
            wd = str(m.get("watchDir", "")).strip()
            wds = m.get("watchDirs")
            try:
                if wds:  # 명시적 배열로 온 경우
                    parts = [str(p).strip() for p in wds if str(p).strip()]
                    log.info("WS: backend set_watch_dirs → %s", parts)
                    self.runtime.swap_watches(parts)
                elif wd:
                    log.info("WS: backend set_watch_dir → %s", wd)
                    self.runtime.apply_watch_spec(wd)
            except Exception as e:  # noqa: BLE001
                log.warning("set_watch_dir(s) 실패: %s", e)
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
        elif t in ("welcome", "pong"):
            pass

    def _sender_loop(self) -> None:
        while not self._stop.is_set():
            item = self._q.get()
            if item is None:
                break
            # 연결될 때까지 대기. 미연결이면 되돌려놓고 잠시 후 재시도(at-least-once).
            if not self._connected.wait(timeout=30.0):
                self._q.put(item)
                time.sleep(1.0)
                continue
            ev_type, relpath, abspath = item
            try:
                self._send_file(ev_type, relpath, abspath)
            except Exception as e:  # noqa: BLE001
                log.warning("WS 전송 실패 (%s %s): %s — 큐 재시도", ev_type, relpath, e)
                self._q.put(item)
                time.sleep(1.0)

    def _send_file(self, ev_type: str, relpath: str, abspath: str | None) -> None:
        import websocket
        if ev_type == "deleted" or not abspath:
            self._send_text({"type": "deleted", "path": relpath})
            log.info("WS 전송 [deleted] %s", relpath)
            return
        try:
            size = os.path.getsize(abspath)
        except OSError as e:
            log.warning("WS 파일 읽기 실패 %s: %s — 스킵", abspath, e)
            return
        self._send_text({"type": "file_begin", "path": relpath, "event": ev_type, "size": size})
        with open(abspath, "rb") as f:
            while True:
                chunk = f.read(self.CHUNK)
                if not chunk:
                    break
                with self._send_lock:
                    self._ws.send(chunk, opcode=websocket.ABNF.OPCODE_BINARY)
        self._send_text({"type": "file_end", "path": relpath})
        log.info("WS 전송 [%s] %s (%d bytes)", ev_type, relpath, size)

    def _send_text(self, obj: dict) -> None:
        with self._send_lock:
            self._ws.send(json.dumps(obj, ensure_ascii=False))

    def _delete_local(self, relpath: str) -> None:
        if not relpath:
            return
        target = self.runtime.cfg.resolve(relpath)
        if not target:
            log.warning("delete_local 경로 해석 실패/탈출 차단: %s", relpath)
            return
        try:
            if os.path.isfile(target):
                os.remove(target)
                log.info("WS delete_local: 로컬 삭제 %s", relpath)
            else:
                log.debug("delete_local: 대상 없음(이미 삭제) %s", relpath)
        except OSError as e:
            log.warning("delete_local 실패 %s: %s", relpath, e)


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
                    s3={"addressing_style": "path" if self.cfg.s3_path_style else "auto"},
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
            log.info("S3 직접 업로드 OK: %s → s3://%s/%s", relpath, self.cfg.s3_bucket, key)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("S3 직접 업로드 실패 (%s): %s", relpath, e)
            return False

    def delete(self, relpath: str) -> bool:
        c = self._client_or_none()
        if c is None:
            return False
        key = self._key(relpath)
        try:
            c.delete_object(Bucket=self.cfg.s3_bucket, Key=key)
            log.info("S3 직접 삭제 OK: s3://%s/%s", self.cfg.s3_bucket, key)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("S3 직접 삭제 실패 (%s): %s", relpath, e)
            return False


# ============================================================================
#  감시기 : 파일이 "안정"되면(쓰기 완료) 이벤트로 승격
# ============================================================================
class StabilityWorker(threading.Thread):
    def __init__(self, cfg: Config, store: EventStore, push_client: "PushClient | None" = None,
                 ws_client: "WsClient | None" = None, s3_uploader: "S3Uploader | None" = None):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.store = store
        self.push_client = push_client
        self.ws_client = ws_client
        self.s3_uploader = s3_uploader
        self._lock = threading.Lock()
        self._pending: dict[str, dict] = {}    # abspath -> {size, last_change}
        self._emitted: dict[str, tuple] = {}   # abspath -> (size, mtime) 마지막 발행값(중복방지)
        self._stop = threading.Event()

    def touch(self, abspath: str, ev_type: str) -> None:
        if os.path.isdir(abspath):
            return
        with self._lock:
            self._pending[abspath] = {"size": -1, "last_change": time.time(), "type": ev_type}

    def emit_deleted(self, abspath: str) -> None:
        """삭제 이벤트는 stability check 불가 (이미 파일 없음). 즉시 deleted 이벤트 발행."""
        # pending/emitted 캐시에서도 제거 (동일 경로 재생성 시 깔끔하게 다시 추적)
        with self._lock:
            self._pending.pop(abspath, None)
            self._emitted.pop(abspath, None)
        relpath = self.cfg.make_relpath(abspath)
        if not relpath:
            return  # 감시 폴더 밖이면 무시
        # size=0, mtime=0 — deleted 이벤트는 메타 의미 없음
        ev = self.store.append("deleted", relpath, 0, 0.0, None)
        log.info("이벤트 #%d deleted  %s", ev["seq"], relpath)
        # PUSH 모드: backend 로 직접 전송 (빈 본문)
        if self.push_client is not None:
            self.push_client.enqueue("deleted", relpath, None)
        # WS 모드: backend 로 deleted 전송
        if self.ws_client is not None:
            self.ws_client.enqueue("deleted", relpath, None)
        # 직접 모드: SeaweedFS(S3) 에서 직접 삭제 (s3_enable_delete=true 일 때만)
        if self.s3_uploader is not None and self.cfg.s3_enable_delete:
            self.s3_uploader.delete(relpath)

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
        key = (st.st_size, int(st.st_mtime))
        with self._lock:
            if self._emitted.get(abspath) == key:
                return  # 동일 내용 재발행 방지
            self._emitted[abspath] = key
        relpath = self.cfg.make_relpath(abspath)
        if not relpath:
            return  # 감시 폴더 밖이면 무시
        sha = self._sha256(abspath) if self.cfg.compute_sha256 else None
        ev = self.store.append(ev_type, relpath, st.st_size, st.st_mtime, sha)
        log.info("이벤트 #%d %s  %s (%d bytes)", ev["seq"], ev_type, relpath, st.st_size)
        # PUSH 모드: backend 로 파일 바이트 직접 전송
        if self.push_client is not None:
            self.push_client.enqueue(ev_type, relpath, abspath)
        # WS 모드: backend 로 파일 바이트 직접 전송 (file_begin/binary/file_end)
        if self.ws_client is not None:
            self.ws_client.enqueue(ev_type, relpath, abspath)
        # 직접 모드: 백엔드를 거치지 않고 SeaweedFS(S3) 에 바로 업로드
        if self.s3_uploader is not None:
            self.s3_uploader.put(relpath, abspath)

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
        # 파일 삭제 → 즉시 "deleted" 이벤트 발행 (stability 체크 불필요, 파일 이미 없음).
        # backend 가 받아서 S3 에서도 deleteObject 수행.
        if not event.is_directory:
            self.worker.emit_deleted(event.src_path)


# ============================================================================
#  Runtime : 런타임에 swap 가능한 자원(observer/worker/cfg.watch_dir) 보관소.
#  /control/watch_dir POST 가 호출되면 observer/worker 를 안전하게 교체한다.
# ============================================================================
class Runtime:
    def __init__(self, cfg: "Config", store: "EventStore", push_client: "PushClient | None" = None,
                 ws_client: "WsClient | None" = None, s3_uploader: "S3Uploader | None" = None):
        self.cfg = cfg
        self.store = store
        self.push_client = push_client
        self.ws_client = ws_client  # WS 모드: 생성 후 runtime.ws_client = ... 로 주입(순환 회피)
        self.s3_uploader = s3_uploader  # 직접 모드: SeaweedFS 직접 업로드
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
        self.worker = StabilityWorker(self.cfg, self.store, self.push_client, self.ws_client, self.s3_uploader)
        self.worker.start()
        # 시작 시 기존 파일 announce (선택) — 모든 watch 폴더 순회
        if self.cfg.emit_existing_on_start:
            for relpath, ap_full, _size, _mtime in self.cfg.iter_existing():
                self.worker.touch(ap_full, "existing")
        # watch 폴더마다 observer.schedule → 한 Observer 가 여러 폴더 병렬 감시
        self.observer = Observer()
        for w in self.cfg.watches:
            self.observer.schedule(_Handler(self.worker), w.path, recursive=w.recursive)
            log.info("감시 시작: %s (label=%s, recursive=%s)",
                     w.path, w.label or "(none)", w.recursive)
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

    def swap_watches(self, specs: list) -> dict:
        """런타임에 다중 감시 폴더 교체. specs 는 watch_dirs 와 동일 형식(list[str|dict])."""
        with self._lock:
            self._stop_unlocked()
            self.cfg.set_watches(specs)
            for w in self.cfg.watches:
                os.makedirs(w.path, exist_ok=True)
            self._start_unlocked()
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
            self._json(200, {
                "status": "ok",
                "name": "file-agent",
                "version": VERSION,
                "watch_dir": cfg.watch_dir,          # 하위호환(첫 폴더)
                "watch_dirs": cfg.watch_summary(),   # 다중 폴더 목록
                "recursive": cfg.recursive,
                "last_seq": store.last_seq,
            })
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
def setup_logging(log_path: str) -> None:
    fmt = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s",
                            "%Y-%m-%d %H:%M:%S")
    log.setLevel(logging.INFO)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    try:
        fh = RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024,
                                 backupCount=2, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except Exception:  # noqa: BLE001
        pass


def app_dir() -> str:
    # PyInstaller 단일 exe 로 묶였을 때도 "실행 파일 옆" 경로를 쓰기 위함
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


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
  "s3_secret_key": "",
  "s3_path_style": true
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
    runtime = Runtime(cfg, store, push_client, s3_uploader=s3_uploader)

    # WS 모드: backend 와 양방향 WebSocket. (직접모드면 생략)
    # ws_client 는 runtime(명령 처리용)이 필요하고 runtime.start() 전에 주입해야 worker 가 ws 로도 enqueue 한다.
    # mode=="backend" 면 ws_enabled 안 적어도 ws 를 켠다.
    ws_client: "WsClient | None" = None
    if (cfg.ws_enabled or cfg.mode == "backend") and not direct:
        if not cfg.ws_url:
            log.error("백엔드 모드인데 ws_url 이 비어 있습니다. config.json 에 ws_url 을 지정하세요.")
            return 2
        ws_client = WsClient(cfg.ws_url, cfg.token, runtime, cfg)
        runtime.ws_client = ws_client

    runtime.start()

    if ws_client is not None:
        ws_client.start()
        log.info("WS 대상: %s (token %s)", cfg.ws_url, "설정됨" if cfg.token else "없음(무인증)")

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
        runtime.stop()
        if push_client is not None:
            push_client.stop()
        if ws_client is not None:
            ws_client.stop()
        log.info("file-agent 종료.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
