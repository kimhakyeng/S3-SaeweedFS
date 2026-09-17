#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""file-agent 데몬 컨트롤 UI (tkinter)

메모장으로 config.json 을 고치던 작업을 대체한다. 데몬(agent.py / file-agent.exe)은
그대로 두고, 이 UI 는 **별도 프로세스**로 떠서 설정을 쓰고 상태를 읽는다.

설계 원칙
---------
1. 데몬을 대체하지 않는다. 무손실 엔진(오퍼/ack/원장/리퍼)은 손대지 않는다.
2. config.json 의 한글 주석을 보존한다. 최상위 키의 값 부분만 바꿔 쓰고,
   다시 읽어 검증한 뒤 임시 파일 → 교체로 저장한다. 검증을 통과해야 .bak 을 갱신한다.
3. UI 는 상주하지 않는다. 필요할 때 띄우고 닫는다 → 평시 RAM 0.
   상태 조회(2초 주기)는 별도 스레드에서 하고, 로그는 파일 끝 256KB 만 읽는다.
4. UI exe 는 관리자 권한으로 빌드한다(requireAdministrator). 데몬은 작업 스케줄러의
   SYSTEM 작업으로 돌리고, UI 는 그 작업을 시작·중지·등록·해제한다.

사용법
------
    python agent_ui.py [--config <경로>]
기본 config 경로는 실행 파일과 같은 폴더의 config.json.
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
from tkinter import filedialog, messagebox, ttk

UI_VERSION = "1.1.0"
TASK_NAME = "file-agent"
POLL_SECONDS = 2.0
LOG_TAIL_BYTES = 256 * 1024
CANARY_BUCKET = "zz-teresa-probe-nonexistent-0d41a7"
# 배포 템플릿에 들어가는 자리표시 토큰. install.bat 과 같은 문자열이어야
# "토큰을 안 바꾼 채 설치" 를 양쪽에서 똑같이 막는다.
DEFAULT_TOKEN_PLACEHOLDER = "change-me-please-long-random-token"
CONFIG_TEMPLATE_NAME = "config.template.json"
# 데몬(agent.py)과 같은 이름 — [중지] 를 누르면 남겨, 5분 감시 트리거가 되살리지 않게 한다.
STOP_FLAG_NAME = "stopped.flag"
# 이 PC 에 데몬이 뜰 수 있는 실행 파일 이름(확장자 제외). UI 자신(file-agent-ui)은 넣지 않는다.
AGENT_IMAGES = ("file-agent", "file-agent.new")
# 완전 제거 때 지우는 파일. 이 목록 밖의 파일이 있으면 폴더는 남긴다.
KNOWN_FILES = ("file-agent.exe", "file-agent.new.exe", "file-agent-ui.exe",
               "config.json", "config.json.bak", "config.json.tmp", CONFIG_TEMPLATE_NAME,
               "install.bat", "uninstall.bat", "BUILD-INFO.txt", "agent-crash.log", STOP_FLAG_NAME)
# 회전·임시 파일은 정확한 이름 규칙으로만 고른다(사용자 파일 'agent.log.txt' 같은 것은 건드리지 않는다).
KNOWN_PATTERN = re.compile(r"^(agent\.log(\.\d+)?|(events|sent)\.jsonl(\.tmp|\.\d+)?)$", re.IGNORECASE)
# config.json 에 키가 없을 때 데몬(agent.Config)이 쓰는 값. UI 도 같은 값으로 보여 줘야
# '열기만 하고 저장'했을 때 데몬 동작이 바뀌지 않는다.
UI_DEFAULTS = {
    "port": 8765,
    "token": "",
    "ws_senders": 1,
    "ws_send_timeout": 60,
    "offer_enabled": True,
    "ack_timeout_seconds": 300,
    "rescan_interval_seconds": 300,
    "ledger_compaction": True,
    "ledger_keep_in_memory": 300000,
    "sync_mode": "speed",
    "log_level": "INFO",
    "log_max_mb": 5,
    "log_backups": 2,
    "s3_endpoint": "",
    "s3_bucket": "",
    "s3_access_key": "",
    "s3_secret_key": "",
    "s3_path_prefix": "",
}

# 상단 헤더는 DLIT 로고(흰 글씨)가 보이도록 로고 원본의 어두운 배경색을 쓴다.
HEADER_BG = "#23282d"
HEADER_FG = "#eceff1"
HEADER_SUB = "#9ea7af"
STATE_OK = "#5fd08a"
STATE_WARN = "#f0b44c"
STATE_BAD = "#ff6b6b"


def resource_path(name: str) -> str:
    """번들된 리소스 경로. exe(PyInstaller) 안에서는 임시 풀림 폴더, 소스 실행이면 옆의 assets."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "assets", name)


# ─────────────────────────────────────────────────────────────────────────────
# config.json (JSONC) 읽기 / 주석 보존 쓰기
# ─────────────────────────────────────────────────────────────────────────────

def strip_jsonc(text: str) -> str:
    """// 와 /* */ 주석, trailing comma 제거. 문자열 리터럴 안은 건드리지 않는다."""
    out = []
    i, n = 0, len(text)
    in_str = False
    esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n:
            if text[i + 1] == "/":
                while i < n and text[i] != "\n":
                    i += 1
                continue
            if text[i + 1] == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        out.append(c)
        i += 1
    joined = "".join(out)
    joined = re.sub(r",(\s*[}\]])", r"\1", joined)
    return joined


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8-sig") as f:
        raw = f.read()
    return json.loads(strip_jsonc(raw))


def _skip_ws_comments(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        if text[i] in " \t\r\n\ufeff":
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            break
    return i


def _scan_string(text: str, i: int) -> int:
    """text[i] 가 '"' 일 때, 닫는 따옴표 다음 위치."""
    i += 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        i += 1
    raise ValueError("닫히지 않은 문자열이 있습니다")


def _scan_value(text: str, i: int) -> int:
    """i 에서 시작하는 JSON 값의 끝 위치. 문자열·주석 안의 괄호는 세지 않는다."""
    n = len(text)
    if i >= n:
        raise ValueError("값이 없습니다")
    c = text[i]
    if c == '"':
        return _scan_string(text, i)
    if c in "[{":
        depth = 0
        while i < n:
            c = text[i]
            if c == '"':
                i = _scan_string(text, i)
                continue
            if text.startswith("//", i) or text.startswith("/*", i):
                i = _skip_ws_comments(text, i)
                continue
            if c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise ValueError("닫히지 않은 괄호가 있습니다")
    j = i
    while j < n and text[j] not in ",}] \t\r\n/":
        j += 1
    if j == i:
        raise ValueError("값 위치에 예상치 못한 문자 %r" % c)
    return j


def _top_level_spans(text: str):
    """최상위 객체의 {키: (값 시작, 값 끝)} 과 닫는 중괄호 위치."""
    i = _skip_ws_comments(text, 0)
    if i >= len(text) or text[i] != "{":
        raise ValueError("최상위가 { } 객체가 아닙니다")
    i += 1
    spans: dict[str, tuple[int, int]] = {}
    while True:
        i = _skip_ws_comments(text, i)
        if i >= len(text):
            raise ValueError("닫히지 않은 객체입니다")
        c = text[i]
        if c == "}":
            return spans, i
        if c == ",":
            i += 1
            continue
        if c != '"':
            raise ValueError("키 위치에 예상치 못한 문자 %r" % c)
        kend = _scan_string(text, i)
        key = json.loads(text[i:kend])
        i = _skip_ws_comments(text, kend)
        if i >= len(text) or text[i] != ":":
            raise ValueError("'%s' 뒤에 ':' 가 없습니다" % key)
        i = _skip_ws_comments(text, i + 1)
        vend = _scan_value(text, i)
        spans[key] = (i, vend)
        i = vend


_MISSING = object()


def _render_changes(text: str, changes: dict, keys: list[str]) -> str:
    spans, close_idx = _top_level_spans(text)
    edits: list[tuple[int, int, str]] = []
    missing = []
    for k in keys:
        lit = json.dumps(changes[k], ensure_ascii=False)
        if k in spans:
            a, b = spans[k]
            edits.append((a, b, lit))
        else:
            missing.append('%s: %s' % (json.dumps(k, ensure_ascii=False), lit))
    if missing:
        if spans:
            last_end = max(b for _a, b in spans.values())
            edits.append((last_end, last_end, "".join(",\n  " + m for m in missing)))
        else:
            edits.append((close_idx, close_idx, "\n  " + ",\n  ".join(missing) + "\n"))
    # 뒤에서부터 적용해야 앞쪽 위치가 어긋나지 않는다(같은 위치면 삽입이 먼저).
    for a, b, lit in sorted(edits, key=lambda e: (e[0], e[1]), reverse=True):
        text = text[:a] + lit + text[b:]
    return text


def _secure_file_acl(path: str) -> None:
    """토큰·자격증명이 든 파일을 SYSTEM·Administrators 만 읽게 한다(Windows 관리자일 때만).

    데몬은 SYSTEM 으로 돈다. 일반 사용자가 토큰을 읽으면 127.0.0.1 로 데몬에 붙어
    감시 폴더를 바꾸고 아무 파일이나 읽을 수 있으므로 막는다.
    """
    if os.name != "nt" or not is_admin() or not os.path.exists(path):
        return
    try:
        _run_hidden(["icacls", path, "/inheritance:r", "/grant:r",
                     "*S-1-5-18:F", "*S-1-5-32-544:F"], timeout=15)
    except Exception:  # noqa: BLE001
        pass


def secure_config_files(config_path: str) -> None:
    for p in (config_path, config_path + ".bak"):
        _secure_file_acl(p)


def write_config_preserving_comments(path: str, changes: dict) -> tuple[list[str], str]:
    """바뀐 최상위 키의 '값' 부분만 바꿔 되쓴다. 주석·들여쓰기·키 순서를 보존한다.

    반환: (실제로 바뀐 키 목록, 안내문). 파일에 없던 키는 마지막 항목 뒤에 추가한다.
    ① 바꾼 결과를 다시 파싱해 바꾼 키는 새 값, 나머지 키는 옛 값 그대로인지 확인하고
    ② 임시 파일에 쓴 뒤 교체한다. 확인에 실패하면 주석을 포기하고 순수 JSON 으로 쓴다
       — 설정이 깨진 채 저장돼 데몬이 다음 부팅에 못 뜨는 것보다 낫다.
    """
    with open(path, "rb") as f:
        raw = f.read()
    had_bom = raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    current = json.loads(strip_jsonc(text))
    keys = [k for k, v in changes.items() if current.get(k, _MISSING) != v]
    if not keys and not had_bom:
        return [], ""

    merged = dict(current)
    merged.update({k: changes[k] for k in keys})
    note = "파일 앞의 BOM 을 지웠습니다(UTF-8, BOM 없음으로 저장)." if had_bom else ""
    try:
        new_text = _render_changes(text, changes, keys) if keys else text
        if json.loads(strip_jsonc(new_text)) != merged:
            raise ValueError("다시 읽은 값이 기대와 다릅니다")
    except ValueError as e:
        new_text = json.dumps(merged, ensure_ascii=False, indent=2) + "\n"
        if json.loads(new_text) != merged:
            raise ValueError("대체 저장 형식도 검증에 실패했습니다 — 파일은 바뀌지 않았습니다") from e
        note = ("주석을 유지한 채 고칠 수 없어(%s) 주석 없는 형식으로 저장했습니다. "
                "이전 파일은 %s.bak 에 있습니다." % (e, os.path.basename(path)))

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(new_text)
        f.flush()
        os.fsync(f.fileno())
    try:
        shutil.copy2(path, path + ".bak")
    except OSError:
        pass
    os.replace(tmp, path)
    secure_config_files(path)
    return keys, note


# ─────────────────────────────────────────────────────────────────────────────
# 데몬과의 통신
# ─────────────────────────────────────────────────────────────────────────────

def agent_get(port: int, token: str, path: str, timeout: float = 3.0) -> tuple[bool, dict | str]:
    url = "http://127.0.0.1:%d%s" % (port, path)
    req = urllib.request.Request(url)
    if token:
        req.add_header("X-Agent-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return False, "HTTP %d" % e.code
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__


def agent_post(port: int, token: str, path: str, body: dict, timeout: float = 15.0):
    url = "http://127.0.0.1:%d%s" % (port, path)
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if token:
        req.add_header("X-Agent-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return False, "HTTP %d" % e.code
    except Exception as e:  # noqa: BLE001
        return False, type(e).__name__


def tcp_open(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def split_hostport(url: str, default_port: int = 80) -> tuple[str, int]:
    p = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    return p.hostname or "", p.port or (443 if p.scheme == "https" else default_port)


# ─────────────────────────────────────────────────────────────────────────────
# 관리자 권한이 필요한 동작 (데몬 시작/중지/자동실행 등록)
# ─────────────────────────────────────────────────────────────────────────────

def _run_hidden(args, timeout: float = 30.0, encoding: str | None = None):
    """콘솔 창을 띄우지 않고 외부 명령을 실행한다.

    pythonw(창 없는 파이썬)에서 subprocess 를 그냥 부르면 자식 프로세스마다
    검은 콘솔 창이 깜빡인다 — 폴링으로 반복 호출하면 창이 계속 뜬다.
    CREATE_NO_WINDOW + STARTF_USESHOWWINDOW 를 함께 줘서 확실히 막는다.
    """
    kw = {"capture_output": True, "text": True, "errors": "replace", "timeout": timeout}
    if encoding:
        kw["encoding"] = encoding
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE
        kw["startupinfo"] = si
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return subprocess.run(args, **kw)


def autostart_info() -> dict | None:
    """작업 스케줄러에 등록된 자동 실행 정보. 없으면 {}, 알 수 없으면 None.

    반환 키: command(실행 파일), arguments, user(계정 SID/이름), watchdog(5분 감시 트리거 여부)
    """
    if os.name != "nt":
        return None
    try:
        r = _run_hidden(["schtasks", "/Query", "/TN", TASK_NAME, "/XML"], timeout=10)
    except Exception:  # noqa: BLE001
        return None
    if r.returncode != 0:
        return {}
    xml = r.stdout or ""

    def tag(name):
        m = re.search(r"<%s>(.*?)</%s>" % (name, name), xml, re.S)
        return (m.group(1).strip() if m else "").replace("&amp;", "&").replace("&quot;", '"')

    return {
        "command": tag("Command").strip('"'),
        "arguments": tag("Arguments"),
        "user": tag("UserId"),
        "watchdog": "<Repetition>" in xml,
    }


def autostart_registered() -> bool | None:
    info = autostart_info()
    return None if info is None else bool(info)


def boot_epoch() -> float:
    """이번 부팅 시각(epoch 초) — 데몬(agent.py)과 같은 방식으로 계산한다."""
    try:
        if os.name == "nt":
            import ctypes  # noqa: PLC0415
            k32 = ctypes.windll.kernel32
            k32.GetTickCount64.restype = ctypes.c_uint64
            return time.time() - k32.GetTickCount64() / 1000.0
    except Exception:  # noqa: BLE001
        pass
    return 0.0


def stop_flag_active(folder: str) -> bool:
    """[중지] 표식이 이번 부팅 것인지(데몬이 5분 감시 때 존중하는 조건과 같다)."""
    try:
        with open(os.path.join(folder, STOP_FLAG_NAME), encoding="utf-8") as f:
            data = json.loads(f.read() or "{}")
        flag_boot = float(data.get("boot", 0) or 0)
    except Exception:  # noqa: BLE001
        return False
    now = boot_epoch()
    return bool(flag_boot and now and abs(now - flag_boot) < 120)


def is_admin() -> bool:
    """이 프로세스가 관리자 권한으로 돌고 있는지."""
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes  # noqa: PLC0415
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def run_elevated(commands: list[str], timeout: float = 120.0) -> tuple[bool, str]:
    """명령을 임시 .ps1 로 써서 관리자 권한으로 실행한다. UAC 창이 한 번 뜬다.

    중첩 따옴표로 명령을 문자열에 욱여넣으면 경로에 공백·한글이 있을 때 깨진다.
    파일로 넘기고 결과도 파일로 받아 그대로 보여준다.
    """
    tmp = os.environ.get("TEMP") or os.environ.get("TMP") or "."
    stamp = str(int(time.time() * 1000))
    ps1 = os.path.join(tmp, "file-agent-ui-%s.ps1" % stamp)
    out = os.path.join(tmp, "file-agent-ui-%s.log" % stamp)
    body = ("$ErrorActionPreference='Continue'\n"
            "try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}\n"
            + "\n".join(commands) + "\n")
    try:
        with open(ps1, "w", encoding="utf-8-sig") as f:
            f.write(body)

        # 이미 관리자로 떠 있으면 UAC 를 다시 띄우지 않고 바로 실행한다.
        # (배포본 UI 는 관리자 권한으로 빌드되므로 보통 이 경로를 탄다.)
        if is_admin():
            r0 = _run_hidden(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1],
                timeout=timeout, encoding="utf-8")
            detail0 = ((r0.stdout or "") + (r0.stderr or "")).strip()
            return r0.returncode == 0, detail0

        launcher = (
            "$p = Start-Process powershell -Verb RunAs -WindowStyle Hidden -PassThru "
            "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%s'; "
            "$p.WaitForExit(); exit $p.ExitCode" % ps1
        )
        r = _run_hidden(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command",
             "& { %s } *> '%s'" % (launcher, out)], timeout=timeout)
        detail = ""
        try:
            with open(out, "rb") as f:
                blob = f.read()
            # PowerShell 5.1 의 *> 는 UTF-16 으로 쓴다.
            enc = "utf-16" if blob[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
            detail = blob.decode(enc, errors="replace").strip()
        except OSError:
            detail = ((r.stdout or "") + (r.stderr or "")).strip()
        return r.returncode == 0, detail
    except subprocess.TimeoutExpired:
        return False, "시간이 초과되었습니다. UAC 창에서 '예'를 누르셨는지 확인하세요."
    except Exception as e:  # noqa: BLE001
        return False, "%s: %s" % (type(e).__name__, e)
    finally:
        for p in (ps1, out):
            try:
                os.remove(p)
            except OSError:
                pass


def agent_processes() -> list[tuple[int, int, str]]:
    """실행 중인 데몬 프로세스 [(PID, 세션 번호, 이미지 이름)]. 세션 0 = 백그라운드(SYSTEM 작업)."""
    try:
        r = _run_hidden(["tasklist", "/FI", "IMAGENAME eq file-agent*", "/FO", "CSV", "/NH"],
                        timeout=10)
    except Exception:  # noqa: BLE001
        return []
    wanted = {name + ".exe" for name in AGENT_IMAGES}
    out = []
    for row in csv.reader(io.StringIO(r.stdout or "")):
        if len(row) < 4 or row[0].strip().lower() not in wanted:
            continue
        try:
            out.append((int(row[1]), int(row[3]), row[0].strip()))
        except ValueError:
            continue
    return out


def agent_pids() -> list[int]:
    """실행 중인 file-agent.exe / file-agent.new.exe PID 목록."""
    return [pid for pid, _sess, _img in agent_processes()]


def ps_quote(value: str) -> str:
    """PowerShell 작은따옴표 문자열. 곡선 작은따옴표(‘ ’ ‚ ‛)도 PowerShell 은 따옴표로 보므로 함께 두 번 쓴다."""
    out = str(value)
    for q in ("'", "\u2018", "\u2019", "\u201a", "\u201b"):
        out = out.replace(q, q + q)
    return "'" + out + "'"


# 관리자 스크립트 공통 부분: 데몬 확실히 끄기 / 작업이 멈출 때까지 기다리기.
# 함수 안에서 Write-Output 을 쓰면 반환값에 섞이므로 안내는 Write-Host 로만 한다.
PS_COMMON = [
    "$task = %s" % ps_quote(TASK_NAME),
    "$agentNames = @(%s)" % ", ".join(ps_quote(n) for n in AGENT_IMAGES),
    "function Get-AgentProcs([string]$exePath = '') {",
    "  @(Get-Process -Name $agentNames -ErrorAction SilentlyContinue |",
    "    Where-Object { -not $exePath -or $_.Path -eq $exePath })",
    "}",
    # exePath 를 주면 그 실행 파일로 뜬 프로세스만 끈다(다른 폴더의 운영 데몬 보호).
    "function Stop-Agents([int]$TimeoutSec = 20, [string]$exePath = '') {",
    "  $deadline = (Get-Date).AddSeconds($TimeoutSec)",
    "  while ($true) {",
    "    $ps = @(Get-AgentProcs $exePath)",
    "    if ($ps.Count -eq 0) { return $true }",
    "    foreach ($p in $ps) { & taskkill.exe /F /T /PID $p.Id *> $null }",
    "    if ((Get-Date) -gt $deadline) { break }",
    "    Start-Sleep -Milliseconds 500",
    "  }",
    "  $left = @(Get-AgentProcs $exePath)",
    "  if ($left.Count -eq 0) { return $true }",
    "  Write-Host ('종료되지 않은 PID: ' + (($left | ForEach-Object { $_.Id }) -join ', '))",
    "  return $false",
    "}",
    "function Stop-AgentTask {",
    "  if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {",
    "    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue",
    "  }",
    "}",
    "function Wait-TaskIdle([int]$TimeoutSec = 10) {",
    "  $deadline = (Get-Date).AddSeconds($TimeoutSec)",
    "  while ((Get-Date) -lt $deadline) {",
    "    $t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue",
    "    if (-not $t -or $t.State -ne 'Running') { return }",
    "    Start-Sleep -Milliseconds 500",
    "  }",
    "}",
    "function Get-AgentFirewallRules {",
    "  @(Get-NetFirewallRule -DisplayName $task, ($task + '-*') -ErrorAction SilentlyContinue |",
    "    Where-Object { $_.DisplayName -eq $task -or $_.DisplayName -match ('^' + [regex]::Escape($task) + '-\\d+$') })",
    "}",
    "function Remove-AgentRegistration {",
    "  Stop-AgentTask",
    "  if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {",
    "    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue",
    "  }",
    "  Get-AgentFirewallRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue",
    "  $ok = $true",
    "  if (-not (Stop-Agents)) { $ok = $false }",
    "  if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {",
    "    Write-Host '작업 스케줄러: 아직 남아 있음'; $ok = $false",
    "  } else { Write-Host '작업 스케줄러: 제거됨' }",
    "  $left = @(Get-AgentFirewallRules)",
    "  if ($left.Count -gt 0) {",
    "    Write-Host ('방화벽: 아직 남아 있음 — ' + (($left | ForEach-Object { $_.DisplayName }) -join ', ')); $ok = $false",
    "  } else { Write-Host '방화벽: 제거됨' }",
    "  return $ok",
    "}",
    # [켜기] 뒤 설치 폴더 잠금이 실제로 걸렸는지 결과창에 보여 준다(SID 로 비교 — 언어와 무관).
    "function Show-FolderLock([string]$folder) {",
    "  try {",
    "    $acl = Get-Acl -LiteralPath $folder",
    "    $bad = @()",
    "    foreach ($r in $acl.Access) {",
    "      if ($r.AccessControlType -ne 'Allow') { continue }",
    "      $sid = ''",
    "      try { $sid = $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch {}",
    "      if (@('S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-3-0') -notcontains $sid) { continue }",
    "      if (([int]$r.FileSystemRights -band 0x500D0156) -ne 0) { $bad += ($r.IdentityReference.Value + ' ' + $r.FileSystemRights) }",
    # 파일로 상속되는 항목이 있으면 일반 사용자가 로그·원장·새 설정 파일을 읽을 수 있다.
    "      elseif (($r.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0 -and $sid -ne 'S-1-3-0') { $bad += ($r.IdentityReference.Value + ' 파일 읽기(상속)') }",
    "    }",
    "    $ownerBad = @()",
    "    foreach ($n in @('file-agent.exe', 'file-agent-ui.exe')) {",
    "      $f = Join-Path $folder $n",
    "      if (Test-Path -LiteralPath $f) {",
    "        $o = (Get-Acl -LiteralPath $f).GetOwner([Security.Principal.SecurityIdentifier]).Value",
    "        if ($o -ne 'S-1-5-32-544') { $ownerBad += ('소유자 ' + $n) }",
    "      }",
    "    }",
    "    $why = @()",
    "    if (-not $acl.AreAccessRulesProtected) { $why += '상속 권한이 남아 있음' }",
    "    $why += $bad",
    "    $why += $ownerBad",
    "    if ($why.Count -eq 0) { Write-Host '폴더 잠금: 적용됨 (일반 사용자는 읽기·실행만)' }",
    "    else { Write-Host ('폴더 잠금: 안 됨 — ' + ($why -join ', ') + ' — NTFS 로컬 디스크인지 확인하세요') }",
    "  } catch { Write-Host ('폴더 잠금: 확인 실패 — ' + $_.Exception.Message) }",
    "}",
]


def ps_write_stop_flag(folder: str) -> str:
    body = json.dumps({"boot": round(boot_epoch(), 1), "at": time.strftime("%Y-%m-%d %H:%M:%S")})
    return "Set-Content -LiteralPath %s -Value %s -Encoding ASCII" % (
        ps_quote(os.path.join(folder, STOP_FLAG_NAME)), ps_quote(body))


def ps_remove_stop_flag(folder: str) -> str:
    return "Remove-Item -LiteralPath %s -Force -ErrorAction SilentlyContinue" % ps_quote(
        os.path.join(folder, STOP_FLAG_NAME))


def token_problem(token) -> str:
    t = str(token or "").strip()
    if not t:
        return "토큰이 비어 있습니다"
    if t == DEFAULT_TOKEN_PLACEHOLDER:
        return "토큰이 배포 기본값 그대로입니다"
    return ""


def install_location_problem(folder: str) -> tuple[str, bool]:
    """설치 폴더로 부적절한 이유와 '막아야 하는지'. 문제가 없으면 ("", False)."""
    f = os.path.normcase(os.path.abspath(folder))

    def under(base):
        if not base:
            return False
        b = os.path.normcase(os.path.abspath(base))
        return f == b or f.startswith(b.rstrip("\\/") + os.sep)

    if f.startswith("\\\\"):
        return ("네트워크 경로에는 설치할 수 없습니다. 부팅 때 SYSTEM 이 접근하지 못합니다 — "
                "로컬 디스크(예: C:\\file-agent)에 두세요.", True)
    if os.name == "nt":
        try:
            import ctypes  # noqa: PLC0415
            root = os.path.splitdrive(f)[0] + "\\"
            if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:   # 3 = DRIVE_FIXED
                return ("USB·네트워크 드라이브에는 설치할 수 없습니다. 로컬 고정 디스크(예: C:\\file-agent)에 두세요.", True)
        except Exception:  # noqa: BLE001
            pass
    if under(os.environ.get("TEMP")) or under(os.environ.get("TMP")) or \
            (os.sep + "appdata" + os.sep + "local" + os.sep + "temp" + os.sep) in (f + os.sep):
        return ("임시 폴더에서 실행 중입니다. zip 안의 exe 를 바로 연 것 같습니다 — "
                "압축을 먼저 풀고 그 폴더에서 다시 실행하세요.", True)
    if os.path.splitdrive(f)[1] in ("\\", "/", ""):
        return ("드라이브 최상위에 바로 두지 말고 전용 폴더(예: C:\\file-agent)를 만드세요.", True)
    nested = ""
    parent = os.path.dirname(f)
    if parent and os.path.isfile(os.path.join(parent, "file-agent.exe")):
        nested = parent
    else:
        try:
            for name in os.listdir(folder):
                if os.path.isfile(os.path.join(folder, name, "file-agent.exe")):
                    nested = os.path.join(folder, name)
                    break
        except OSError:
            pass
    if nested:
        return ("다른 file-agent 폴더(%s)와 겹쳐 있습니다. 압축을 설치 폴더 안에 푼 것 같습니다 — "
                "file-agent 폴더 '안의 파일'만 설치 폴더에 두세요." % nested, False)
    users = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "Users")
    if under(os.environ.get("USERPROFILE")) or under(users):
        return ("사용자 폴더(바탕화면·다운로드 등) 아래입니다. PC 켤 때 SYSTEM 이 실행할 파일이므로 "
                "C:\\file-agent 처럼 고정된 폴더를 권장합니다.", False)
    return "", False


def find_agent_exe(config_path: str) -> str:
    folder = os.path.dirname(os.path.abspath(config_path))
    for name in ("file-agent.exe",):
        cand = os.path.join(folder, name)
        if os.path.exists(cand):
            return cand
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────────────────────

# (config 키, 라벨, 위젯종류, 재시작 필요 여부)
# ★ 백엔드 주소와 이 PC 자신의 포트는 성격이 전혀 다르므로 절대 한 상자에 섞지 않는다.
# ws_url 은 UI 에서 호스트/포트/TLS 세 칸으로 나눠 받고 저장할 때 합친다.
# ("http://127.0.0.1:3940" 을 통째로 타이핑하게 두면 3940 이 왜 붙는지 늘 헷갈린다.)
BACKEND_FIELDS = [
    ("token", "토큰", "entry", True),
]
LOCAL_FIELDS = [
    ("port", "이 에이전트가 여는 포트", "int", True),
]
CONN_FIELDS = BACKEND_FIELDS + LOCAL_FIELDS
# 내부 값 대신 사람이 읽는 말로 고른다. (값, 화면에 보일 말) 순서대로 목록에 뜬다.
CHOICE_LABELS = {
    "log_level": [
        ("INFO", "보통 — 연결·설정 변경·경고 (권장)"),
        ("WARNING", "적게 — 경고·오류만"),
        ("DEBUG", "전부 — 파일 하나하나까지 (문제 추적용, 양이 매우 많음)"),
        ("ERROR", "오류만"),
    ],
    "sync_mode": [
        ("speed", "적재만 (권장) — 로컬에서 지워도 S3 에서는 안 지움"),
        ("mirror", "삭제도 알림 — 로컬에서 지우면 S3 에서도 지움 (캔버스 노드도 mirror 여야 동작, 복구 불가)"),
    ],
}

PERF_FIELDS = [
    ("ws_senders", "병렬 WS 연결 수", "int", True),
    ("ws_send_timeout", "WS send 타임아웃(초)", "int", True),
    ("offer_enabled", "보내기 전에 이미 적재됐는지 묻기", "bool", True),
    ("ack_timeout_seconds", "ack 재전송 대기(초)", "int", True),
    ("rescan_interval_seconds", "보정 스캔 주기(초)", "int", True),
    ("ledger_compaction", "원장 자동 축소", "bool", True),
    ("ledger_keep_in_memory", "원장 메모리 보관 상한(건)", "int", True),
]
# 동기화 모드는 성능 설정과 성격이 달라(데이터 삭제가 걸림) 전용 탭에서 설명과 함께 보여 준다.
SYNC_FIELDS = [
    ("sync_mode", "이 에이전트의 동기화 모드", "pick", True),
]
LOG_FIELDS = [
    ("log_level", "로그 남기는 정도", "pick", True),
    ("log_max_mb", "로그 회전 크기(MB)", "int", True),
    ("log_backups", "로그 보관 개수", "int", True),
]
S3_FIELDS = [
    ("s3_endpoint", "S3 엔드포인트", "entry", True),
    ("s3_bucket", "버킷", "entry", True),
    ("s3_access_key", "AccessKey", "entry", True),
    ("s3_secret_key", "SecretKey", "secret", True),
    ("s3_path_prefix", "경로 프리픽스", "entry", True),
]


class AgentUI(tk.Tk):
    def __init__(self, config_path: str):
        super().__init__()
        self.config_path = os.path.abspath(config_path)
        self.title("DLIT file-agent 컨트롤 %s — %s" % (UI_VERSION, self.config_path))
        self.geometry("980x720")
        try:
            self.iconbitmap(default=resource_path("dlit.ico"))
        except tk.TclError:
            pass
        self.minsize(820, 600)

        self.cfg: dict = {}
        self.vars: dict[str, tk.Variable] = {}
        self._pick_maps: dict[str, dict[str, str]] = {}
        self._poll_stop = threading.Event()
        self._log_pos = 0
        self._busy = False
        self._action_buttons: list = []
        self._health_body: dict = {}

        try:
            self.cfg = load_config(self.config_path)
        except Exception as e:  # noqa: BLE001
            self.cfg = self._recover_broken_config(e)
        # 폴링 스레드는 tk 변수를 만지지 않는다 — 저장된 값(데몬이 실제로 쓰는 값)을 여기 둔다.
        self._poll_port = self._saved_port()
        self._poll_token = str(self.cfg.get("token", ""))

        self._build()
        # 저장 때는 '화면에서 바뀐 값'만 파일에 쓴다 — 파일에 없던 키를 기본값으로 채워 넣지 않는다.
        try:
            self._initial = self._collect()
        except ValueError:
            self._initial = {}
        self._start_poller()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _recover_broken_config(self, err) -> dict:
        """config.json 을 읽을 수 없을 때: 원본을 남기고 .bak(없으면 템플릿)으로 되돌릴지 묻는다."""
        folder = os.path.dirname(self.config_path)
        candidates = [self.config_path + ".bak", os.path.join(folder, CONFIG_TEMPLATE_NAME)]
        source = ""
        for c in candidates:
            try:
                load_config(c)
                source = c
                break
            except Exception:  # noqa: BLE001
                continue
        msg = "%s\n\n%s: %s" % (self.config_path, type(err).__name__, err)
        if not source:
            messagebox.showerror("설정 읽기 실패", msg + "\n\n되돌릴 파일(.bak·템플릿)도 없습니다.")
            return {}
        if not messagebox.askyesno(
                "설정 읽기 실패",
                msg + "\n\n아래 파일로 되돌릴까요? 지금 파일은 .broken-<시각> 으로 남겨 둡니다.\n  %s" % source):
            return {}
        broken = self.config_path + ".broken-" + time.strftime("%Y%m%d-%H%M%S")
        try:
            shutil.copy2(self.config_path, broken)
            shutil.copyfile(source, self.config_path + ".tmp")
            os.replace(self.config_path + ".tmp", self.config_path)
            secure_config_files(self.config_path)
            _secure_file_acl(broken)
            messagebox.showinfo("설정 되돌림", "되돌렸습니다. 값을 확인하고 저장하세요.\n원본: %s" % broken)
            return load_config(self.config_path)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("되돌리기 실패", "%s: %s" % (type(e).__name__, e))
            return {}

    def _cfg_value(self, key: str):
        """파일 값, 없으면 데몬이 쓰는 기본값."""
        if key in self.cfg:
            return self.cfg.get(key)
        return UI_DEFAULTS.get(key)

    # ---- 레이아웃 ----
    def _build(self):
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        style.configure("Status.TLabel", font=("Segoe UI", 10))
        style.configure("Big.TLabel", font=("Segoe UI", 13, "bold"))
        style.configure("Hint.TLabel", foreground="#666")

        top = tk.Frame(self, bg=HEADER_BG, padx=16, pady=10)
        top.pack(fill="x")
        self._logo_img = None
        try:
            self._logo_img = tk.PhotoImage(file=resource_path("dlit-logo-header.png"))
            tk.Label(top, image=self._logo_img, bg=HEADER_BG).pack(side="left")
            tk.Frame(top, bg="#3b4249", width=1, height=34).pack(side="left", padx=16)
        except tk.TclError:
            pass
        tk.Label(top, text="file-agent 컨트롤", bg=HEADER_BG, fg=HEADER_FG,
                 font=("Segoe UI", 11, "bold")).pack(side="left")
        self.lbl_state = tk.Label(top, text="확인 중…", bg=HEADER_BG, fg=HEADER_FG,
                                  font=("Segoe UI", 11, "bold"))
        self.lbl_state.pack(side="left", padx=(24, 0))
        self.lbl_detail = tk.Label(top, text="", bg=HEADER_BG, fg=HEADER_SUB, font=("Segoe UI", 9))
        self.lbl_detail.pack(side="left", padx=(10, 0))

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=12, pady=6)
        self.tab_status = ttk.Frame(nb, padding=12)
        self.tab_conn = ttk.Frame(nb, padding=12)
        self.tab_dirs = ttk.Frame(nb, padding=12)
        self.tab_sync = ttk.Frame(nb, padding=12)
        self.tab_s3 = ttk.Frame(nb, padding=12)
        self.tab_perf = ttk.Frame(nb, padding=12)
        self.tab_log = ttk.Frame(nb, padding=12)
        nb.add(self.tab_status, text="상태")
        nb.add(self.tab_conn, text="연결")
        nb.add(self.tab_dirs, text="감시 폴더")
        nb.add(self.tab_sync, text="동기화(삭제·덮어쓰기)")
        nb.add(self.tab_s3, text="S3 (direct)")
        nb.add(self.tab_perf, text="성능·무손실")
        nb.add(self.tab_log, text="로그")

        self._build_status(self.tab_status)
        self._build_conn(self.tab_conn)
        self._build_dirs(self.tab_dirs)
        self._build_sync(self.tab_sync)
        self._build_s3(self.tab_s3)
        self._build_perf(self.tab_perf)
        self._build_log(self.tab_log)

        bar = ttk.Frame(self, padding=(12, 2, 12, 12))
        bar.pack(fill="x")

        g1 = ttk.LabelFrame(bar, text="바꾼 설정", padding=(10, 6))
        g1.pack(side="left", fill="y")
        b = ttk.Button(g1, text="저장만", width=10, command=self.on_save)
        b.pack(side="left")
        self._action_buttons.append(b)
        b = ttk.Button(g1, text="저장하고 다시 시작", command=self.on_save_restart)
        b.pack(side="left", padx=6)
        self._action_buttons.append(b)

        g2 = ttk.LabelFrame(bar, text="지금 실행 중인 데몬", padding=(10, 6))
        g2.pack(side="left", fill="y", padx=10)
        for text, act, w, px in (("시작", "start", 8, 0), ("중지", "stop", 8, 6), ("다시 시작", "restart", 10, 0)):
            b = ttk.Button(g2, text=text, width=w, command=lambda a=act: self.on_daemon(a))
            b.pack(side="left", padx=px)
            self._action_buttons.append(b)

        g3 = ttk.LabelFrame(bar, text="PC 켤 때 자동 실행", padding=(10, 6))
        g3.pack(side="left", fill="y")
        for text, act, px in (("켜기", "install", 0), ("끄기", "uninstall", 6)):
            b = ttk.Button(g3, text=text, width=8, command=lambda a=act: self.on_daemon(a))
            b.pack(side="left", padx=px)
            self._action_buttons.append(b)
        self.autostart_state = tk.StringVar(value="확인 중…")
        ttk.Label(g3, textvariable=self.autostart_state, style="Status.TLabel").pack(side="left", padx=(4, 0))

    # ---- 탭: 상태 ----
    def _build_status(self, parent):
        grid = ttk.Frame(parent)
        grid.pack(fill="x")
        self.status_vals: dict[str, tk.StringVar] = {}
        rows = [
            ("version", "에이전트 버전"),
            ("runas", "실행 방식"),
            ("started", "데몬 기동 시각"),
            ("mode", "모드"),
            ("watch", "감시 폴더"),
            ("ledger", "원장 보관 건수"),
            ("pending", "ack 대기 (미완료 전송)"),
            ("unmatched", "받을 노드 없어 보류"),
            ("unwatched", "볼 수 없는 감시 폴더"),
            ("ackmode", "무손실 ack 모드"),
            ("lastseq", "이벤트 시퀀스"),
        ]
        for i, (key, label) in enumerate(rows):
            ttk.Label(grid, text=label, style="Hint.TLabel", width=24, anchor="w").grid(
                row=i, column=0, sticky="w", pady=3)
            v = tk.StringVar(value="—")
            self.status_vals[key] = v
            ttk.Label(grid, textvariable=v, style="Status.TLabel").grid(row=i, column=1, sticky="w", pady=3)

        ttk.Separator(parent, orient="horizontal").pack(fill="x", pady=12)
        ttk.Label(parent, text="RAM 예상치", style="Big.TLabel").pack(anchor="w")
        self.ram_hint = tk.StringVar(value="—")
        ttk.Label(parent, textvariable=self.ram_hint, style="Hint.TLabel",
                  wraplength=880, justify="left").pack(anchor="w", pady=(4, 0))

        ttk.Separator(parent, orient="horizontal").pack(fill="x", pady=12)
        ttk.Label(parent, text="임시 폴더 정리", style="Big.TLabel").pack(anchor="w")
        ttk.Label(parent, style="Hint.TLabel", wraplength=880, justify="left",
                  text="데몬과 이 UI 는 실행할 때마다 임시 폴더(_MEI…)에 풀립니다. 강제 종료가 쌓이면 "
                       "이 폴더가 남아 디스크를 차지합니다. 사용자·Windows 임시 폴더에서 10분 넘게 지난 것만 보고, "
                       "실행 중인 프로그램이 쓰는 폴더(파이썬 DLL 이 잠긴 폴더)는 건너뜁니다.").pack(
            anchor="w", pady=(4, 0))
        row = ttk.Frame(parent)
        row.pack(anchor="w", pady=(8, 0))
        ttk.Button(row, text="남은 용량 확인", command=self.on_scan_temp).pack(side="left")
        ttk.Button(row, text="정리", command=self.on_clean_temp).pack(side="left", padx=6)
        self.temp_hint = tk.StringVar(value="확인 전")
        ttk.Label(parent, textvariable=self.temp_hint, style="Status.TLabel",
                  wraplength=880, justify="left").pack(anchor="w", pady=(6, 0))

        ttk.Separator(parent, orient="horizontal").pack(fill="x", pady=12)
        ttk.Label(parent, text="이 PC 에서 완전히 제거", style="Big.TLabel").pack(anchor="w")
        ttk.Label(parent, style="Hint.TLabel", wraplength=880, justify="left",
                  text="데몬을 끄고 PC 켤 때 자동 실행·방화벽 규칙을 해제한 뒤, 이 창을 닫으면서 "
                       "file-agent 가 만든 파일(실행 파일·설정·원장·로그)만 지웁니다. 폴더에 다른 파일이 있으면 "
                       "폴더는 남깁니다. 설정과 원장(sent.jsonl)은 지우기 전에 사용자 폴더에 백업합니다.").pack(
            anchor="w", pady=(4, 0))
        ttk.Button(parent, text="완전 제거…", command=self.on_full_remove).pack(anchor="w", pady=(8, 0))

    def on_full_remove(self):
        # 소스(agent_ui.py)로 띄운 상태에서 누르면 개발 폴더를 건드린다 — 배포본에서만 허용.
        if not getattr(sys, "frozen", False):
            messagebox.showinfo("완전 제거",
                                "배포본(file-agent-ui.exe)으로 실행했을 때만 쓸 수 있습니다.\n"
                                "소스 폴더를 실수로 지우지 않도록 막아 두었습니다.")
            return
        if self._busy:
            return
        folder = os.path.dirname(os.path.abspath(sys.executable))
        if not os.path.exists(os.path.join(folder, "file-agent.exe")):
            messagebox.showerror("완전 제거",
                                 "이 폴더에 file-agent.exe 가 없어 설치 폴더로 볼 수 없습니다.\n%s" % folder)
            return
        bad = self._removal_blocker(folder)
        if bad:
            messagebox.showerror("완전 제거 중단", bad)
            return
        targets, others = self._removal_targets(folder)
        exe_path = os.path.join(folder, "file-agent.exe")
        info = autostart_info() or {}
        other_task = bool(info) and os.path.normcase(info.get("command", "")) != os.path.normcase(exe_path)
        first_line = ("· 이 폴더의 데몬만 중지 — 자동 실행은 다른 폴더(%s)의 것이라 그대로 둡니다\n"
                      % info.get("command") if other_task
                      else "· 데몬 중지, PC 켤 때 자동 실행·방화벽 규칙 해제\n")
        if not messagebox.askyesno(
                "완전 제거",
                "아래를 진행합니다.\n\n" + first_line +
                "· 이 폴더에서 file-agent 파일 %d개 삭제 (%s)\n"
                "· %s\n"
                "· 원장(sent.jsonl)이 지워지므로 다시 설치하면 파일을 처음부터 다시 보냅니다\n"
                "  (백업본을 새 설치 폴더에 넣으면 이어서 보냅니다)\n\n"
                "이 창은 닫히고, 몇 초 뒤 파일이 지워집니다. 계속할까요?"
                % (len(targets), folder,
                   ("다른 파일 %d개가 있어 폴더는 남깁니다" % len(others)) if others
                   else "폴더가 비면 폴더도 지웁니다"),
                icon="warning"):
            return

        backup, backup_err = self._backup_before_remove(folder)
        if backup_err and not messagebox.askyesno(
                "완전 제거", "설정·원장 백업에 실패했습니다: %s\n그래도 지울까요?" % backup_err, icon="warning"):
            return
        uipids = sorted({os.getpid(), os.getppid()})
        # 창이 닫혀 exe 잠금이 풀린 뒤 지워야 하므로, 따로 떠서 이 UI 가 끝나기를 기다렸다가 지운다.
        # 경로에 공백·한글이 있어도 깨지지 않게 명령을 인코딩해서 넘긴다.
        names = ", ".join(ps_quote(t) for t in targets) or "@()"
        inner = "\n".join([
            "$folder = %s" % ps_quote(folder),
            "foreach ($id in @(%s)) { Wait-Process -Id $id -Timeout 60 -ErrorAction SilentlyContinue }"
            % ", ".join(str(x) for x in uipids),
            "Start-Sleep -Seconds 1",
            "$names = @(%s)" % names,
            "for ($i = 0; $i -lt 30; $i++) {",
            "  $left = @($names | Where-Object { Test-Path -LiteralPath (Join-Path $folder $_) })",
            "  if ($left.Count -eq 0) { break }",
            "  foreach ($n in $left) { Remove-Item -LiteralPath (Join-Path $folder $n) -Force -ErrorAction SilentlyContinue }",
            "  Start-Sleep -Seconds 1",
            "}",
            "if (-not (Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue)) {",
            "  Remove-Item -LiteralPath $folder -Force -ErrorAction SilentlyContinue",
            "}",
        ])
        enc = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
        if other_task:
            release = ["if (-not (Stop-Agents 20 %s)) { Write-Host '이 폴더의 데몬을 멈추지 못해 삭제를 진행하지 않습니다.'; exit 1 }"
                       % ps_quote(exe_path)]
        else:
            release = ["if (-not (Remove-AgentRegistration)) { Write-Host '해제에 실패해 삭제를 진행하지 않습니다.'; exit 1 }"]
        cmds = PS_COMMON + release + [
            ps_remove_stop_flag(folder),
            "try {",
            "  Start-Process powershell -WindowStyle Hidden -ErrorAction Stop "
            "-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','%s'" % enc,
            "} catch { Write-Host ('파일 삭제 작업을 시작하지 못했습니다(자동 실행 해제는 끝남): ' + $_.Exception.Message); exit 2 }",
            "exit 0",
        ]

        def after(ok, out):
            if not ok:
                messagebox.showerror("완전 제거", "데몬·자동 실행을 해제하지 못해 중단했습니다.\n\n%s"
                                     % (out or "(출력 없음)"))
                return
            messagebox.showinfo(
                "완전 제거",
                "제거를 시작했습니다. 이 창을 닫으면 몇 초 뒤 파일이 지워집니다.%s"
                % (("\n\n백업 위치: %s" % backup) if backup else ""))
            self._on_close()

        self._run_in_background("완전 제거", cmds, after)

    def _removal_blocker(self, folder: str) -> str:
        """이 폴더를 정리하면 안 되는 이유. 괜찮으면 ""."""
        f = os.path.normcase(os.path.abspath(folder))
        if os.path.splitdrive(f)[1] in ("\\", "/", ""):
            return "드라이브 최상위(%s)는 정리하지 않습니다." % folder
        forbidden = []
        for env in ("USERPROFILE", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData",
                    "PUBLIC", "TEMP"):
            v = os.environ.get(env)
            if v:
                forbidden.append(v)
        home = os.environ.get("USERPROFILE") or ""
        for sub in ("Desktop", "Documents", "Downloads", "OneDrive", "바탕 화면", "문서", "다운로드"):
            if home:
                forbidden.append(os.path.join(home, sub))
        for v in forbidden:
            if f == os.path.normcase(os.path.abspath(v)):
                return ("설치 폴더가 %s 자체입니다. 이런 폴더는 정리하지 않습니다 — "
                        "file-agent 파일만 직접 지우세요." % folder)
        dirs = list(self._cfg_watch_dirs())
        body = self._health_body or {}
        for d in body.get("watch_dirs") or []:
            dirs.append(str(d.get("dir") if isinstance(d, dict) else d))
        for d in dirs:
            try:
                dd = os.path.normcase(os.path.abspath(d))
            except (TypeError, ValueError):
                continue
            if dd == f or dd.startswith(f.rstrip("\\/") + os.sep):
                return ("감시 폴더(%s)가 설치 폴더 안에 있습니다. 수집 데이터가 함께 지워질 수 있어 중단합니다.\n"
                        "감시 폴더를 다른 곳으로 옮긴 뒤 다시 시도하세요." % d)
        return ""

    @staticmethod
    def _removal_targets(folder: str) -> tuple[list[str], list[str]]:
        targets, others = [], []
        try:
            entries = os.listdir(folder)
        except OSError:
            return targets, others
        known = {k.lower() for k in KNOWN_FILES}
        for name in entries:
            low = name.lower()
            if (low in known or KNOWN_PATTERN.match(name)) and os.path.isfile(os.path.join(folder, name)):
                targets.append(name)
                continue
            others.append(name)
        return sorted(targets), sorted(others)

    def _backup_before_remove(self, folder: str) -> tuple[str, str]:
        """설정·원장을 사용자 폴더에 복사하고 크기까지 확인한다. (백업 폴더, 실패 사유)."""
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        dest = os.path.join(base, "file-agent-backup", time.strftime("%Y%m%d-%H%M%S"))
        copied = 0
        try:
            os.makedirs(dest, exist_ok=True)
            for name in os.listdir(folder):
                low = name.lower()
                if low in ("config.json", "config.json.bak") or re.match(r"^sent\.jsonl(\.\d+)?$", low):
                    src = os.path.join(folder, name)
                    dst = os.path.join(dest, name)
                    shutil.copy2(src, dst)
                    if os.path.getsize(src) != os.path.getsize(dst):
                        return dest, "%s 크기가 다릅니다" % name
                    copied += 1
        except OSError as e:
            return dest, "%s: %s" % (type(e).__name__, e)
        return (dest if copied else ""), ""

    @staticmethod
    def _mei_bases() -> list[str]:
        bases = []
        for cand in (os.environ.get("TEMP"), os.environ.get("TMP"),
                     os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
                     os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SystemTemp")):
            if cand and os.path.isdir(cand):
                key = os.path.normcase(os.path.abspath(cand))
                if key not in {os.path.normcase(os.path.abspath(b)) for b in bases}:
                    bases.append(cand)
        return bases

    @classmethod
    def _scan_mei(cls) -> tuple[list[str], int]:
        mine = os.path.normcase(os.path.abspath(getattr(sys, "_MEIPASS", ""))) if hasattr(sys, "_MEIPASS") else ""
        found, total = [], 0
        for base in cls._mei_bases():
            try:
                names = os.listdir(base)
            except OSError:
                continue
            for name in names:
                if not name.startswith("_MEI"):
                    continue
                full = os.path.join(base, name)
                if not os.path.isdir(full) or os.path.normcase(os.path.abspath(full)) == mine:
                    continue
                try:
                    if time.time() - os.path.getmtime(full) < 600:
                        continue    # 막 풀린 폴더는 지금 시작 중인 프로그램의 것일 수 있다
                except OSError:
                    continue
                size = 0
                for root, _dirs, files in os.walk(full):
                    for fn in files:
                        try:
                            size += os.path.getsize(os.path.join(root, fn))
                        except OSError:
                            pass
                found.append(full)
                total += size
        return found, total

    def on_scan_temp(self):
        self.temp_hint.set("확인 중…")

        def work():
            found, total = self._scan_mei()
            text = ("_MEI 폴더 %d개, 약 %.0f MB (10분 넘게 지난 것)" % (len(found), total / (1024 ** 2))
                    if found else "정리할 폴더가 없습니다.")
            self.after(0, lambda: self.temp_hint.set(text))

        threading.Thread(target=work, daemon=True, name="ui-mei-scan").start()

    def on_clean_temp(self):
        if not messagebox.askokcancel(
                "임시 폴더 정리",
                "10분 넘게 지난 _MEI 폴더를 지웁니다.\n"
                "실행 중인 데몬·UI 가 쓰는 폴더(파이썬 DLL 이 잠긴 폴더)는 건너뜁니다."):
            return
        self.temp_hint.set("정리 중…")

        def work():
            import glob  # noqa: PLC0415
            found, _total = self._scan_mei()
            removed = skipped = 0
            for full in found:
                dlls = glob.glob(os.path.join(full, "python3*.dll"))
                if not dlls:
                    skipped += 1        # 사용 중인지 판별할 수 없으면 건드리지 않는다
                    continue
                try:
                    # 실행 중인 프로세스가 올린 DLL 은 지워지지 않는다(PermissionError) — 그걸로 사용 중을 판별한다.
                    # 폴더 이름 바꾸기는 사용 중이어도 성공하므로 판별에 쓸 수 없다.
                    for d in dlls:
                        os.remove(d)
                except OSError:
                    skipped += 1
                    continue
                shutil.rmtree(full, ignore_errors=True)
                removed += 1
            text = "%d개 삭제, %d개 건너뜀(사용 중이거나 판별 불가)." % (removed, skipped)
            self.after(0, lambda: self.temp_hint.set(text))

        threading.Thread(target=work, daemon=True, name="ui-mei-clean").start()

    # ---- 탭: 연결 ----
    def _build_conn(self, parent):
        # 데몬과 같은 규칙: mode 가 없으면 s3_endpoint·s3_bucket 이 있을 때 direct, 아니면 backend.
        mode0 = str(self.cfg.get("mode") or "").strip().lower()
        if mode0 not in ("backend", "direct"):
            mode0 = "direct" if (self.cfg.get("s3_endpoint") and self.cfg.get("s3_bucket")) else "backend"
        mode = tk.StringVar(value=mode0)
        self.vars["mode"] = mode
        box = ttk.LabelFrame(parent, text="동작 모드", padding=10)
        box.pack(fill="x")
        ttk.Radiobutton(box, text="backend — 백엔드(TERESA MQ) 경유로 적재", value="backend",
                        variable=mode, command=self._sync_mode_ui).pack(anchor="w")
        ttk.Radiobutton(box, text="direct — 데몬이 S3 에 직접 업로드 (백엔드 없음)", value="direct",
                        variable=mode, command=self._sync_mode_ui).pack(anchor="w")
        ttk.Label(box, style="Hint.TLabel", wraplength=880, justify="left",
                  text="direct 모드는 캔버스 노드를 쓰지 않고 아래 'S3 (direct)' 탭의 값 하나만 사용합니다. "
                       "따라서 여러 S3 로 나눠 보내는 병렬 적재는 backend 모드에서만 됩니다.").pack(anchor="w", pady=(6, 0))

        # ── ① 상대편: 접속할 백엔드 ──────────────────────────────────────
        self.conn_box = ttk.LabelFrame(
            parent, text="① 접속할 곳 — 백엔드 (TERESA MQ 서버)", padding=10)
        self.conn_box.pack(fill="x", pady=(10, 0))

        # ws_url 을 호스트 / 포트 / TLS 세 칸으로 분해해서 보여준다.
        host0, port0, https0, path0 = self._split_ws_url(str(self.cfg.get("ws_url", "")))
        self.vars["__host"] = tk.StringVar(value=host0)
        self.vars["__port"] = tk.StringVar(value=(str(port0) if port0 else ""))
        self.vars["__https"] = tk.BooleanVar(value=https0)

        ttk.Label(self.conn_box, text="백엔드 서버 주소", width=28, anchor="w").grid(
            row=0, column=0, sticky="w", pady=4)
        hostrow = ttk.Frame(self.conn_box)
        hostrow.grid(row=0, column=1, columnspan=2, sticky="w", pady=4)
        host_entry = ttk.Entry(hostrow, textvariable=self.vars["__host"], width=26)
        host_entry.pack(side="left")
        host_entry.bind("<FocusOut>", lambda _e: self._normalize_host_field())
        ttk.Label(hostrow, text="  포트 ").pack(side="left")
        ttk.Entry(hostrow, textvariable=self.vars["__port"], width=7).pack(side="left")
        ttk.Checkbutton(hostrow, text="HTTPS", variable=self.vars["__https"]).pack(side="left", padx=(10, 0))
        ttk.Label(hostrow, text="  경로(선택) ").pack(side="left")
        self.vars["__path"] = tk.StringVar(value=path0)
        ttk.Entry(hostrow, textvariable=self.vars["__path"], width=12).pack(side="left")
        ttk.Label(hostrow, text="재시작 필요", style="Hint.TLabel").pack(side="left", padx=(10, 0))

        ttk.Label(self.conn_box, text="", style="Hint.TLabel").grid(row=1, column=0, sticky="w")
        ttk.Label(self.conn_box, style="Hint.TLabel", wraplength=560, justify="left",
                  text="IP 또는 호스트명을 적으세요. 주소를 통째로 붙여 넣으면 칸을 옮길 때 알아서 갈라 줍니다.\n"
                       "포트는 그 백엔드가 실제로 쓰는 값입니다. 배포마다 다르니 관리자에게 확인하세요.\n"
                       "경로는 백엔드가 하위 경로에 붙어 있을 때만 채우세요(예: mq). 보통은 비웁니다.").grid(
            row=1, column=1, columnspan=2, sticky="w")

        ttk.Label(self.conn_box, text="토큰", width=28, anchor="w").grid(row=2, column=0, sticky="w", pady=4)
        self.vars["token"] = tk.StringVar(value=str(self.cfg.get("token", "")))
        token_entry = ttk.Entry(self.conn_box, textvariable=self.vars["token"], width=52)
        token_entry.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Label(self.conn_box, text="재시작 필요", style="Hint.TLabel").grid(
            row=2, column=2, sticky="w", padx=(10, 0))

        r = 3
        ttk.Label(self.conn_box, text="실제 접속 주소", width=28, anchor="w",
                  style="Hint.TLabel").grid(row=r, column=0, sticky="w", pady=(2, 0))
        self.dial_preview = tk.StringVar(value="—")
        ttk.Label(self.conn_box, textvariable=self.dial_preview, font=("Consolas", 9),
                  foreground="#1a5fb4", wraplength=560, justify="left").grid(
            row=r, column=1, columnspan=2, sticky="w", pady=(2, 0))

        ttk.Label(self.conn_box, style="Hint.TLabel", wraplength=860, justify="left",
                  text="여기는 '접속할 백엔드 서버'를 가리킵니다. 이 PC 의 IP 를 적는 칸이 아닙니다.\n"
                       "    · 백엔드가 이 PC 에서 돌면  →  127.0.0.1   ← 망이 바뀌어도 안 깨지므로 권장\n"
                       "    · 백엔드가 다른 서버면      →  그 서버의 IP 또는 호스트명\n"
                       "여러 S3 로 나눠 보내는 병렬 적재는 여기가 아니라 캔버스에서 정합니다 — "
                       "백엔드는 한 곳만 적고, S3 Bucket 노드마다 Endpoint 를 다르게 두면 됩니다.").grid(
            row=r + 1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        btns = ttk.Frame(self.conn_box)
        btns.grid(row=r + 2, column=0, sticky="w", pady=(8, 0))
        ttk.Button(btns, text="백엔드 연결 테스트", command=self.on_test_backend).pack(side="left")
        token_btn = ttk.Button(btns, text="새 토큰 생성", command=self.on_new_token)
        token_btn.pack(side="left", padx=6)
        self._always_enabled = (token_entry, token_btn)
        self.backend_result = tk.StringVar(value="")
        ttk.Label(self.conn_box, textvariable=self.backend_result, style="Status.TLabel",
                  wraplength=620, justify="left").grid(row=r + 2, column=1, columnspan=2,
                                                       sticky="w", pady=(8, 0))

        # ── ② 내 쪽: 이 PC 의 에이전트 자신 ──────────────────────────────
        self.local_box = ttk.LabelFrame(
            parent, text="② 이 PC 의 에이전트 자신 — 백엔드와 무관", padding=10)
        self.local_box.pack(fill="x", pady=10)
        self._add_fields(self.local_box, LOCAL_FIELDS)
        ttk.Label(
            self.local_box, style="Hint.TLabel", wraplength=860, justify="left",
            text="데몬이 자기 상태 조회용으로 여는 포트입니다. 위 백엔드 포트(보통 3940)와 아무 관계가 없습니다.\n"
                 "캔버스의 Agent Source 노드에 있는 Port 칸이 이 값과 짝입니다. 바꿀 일이 거의 없습니다.\n"
                 "※ 같은 노드의 Address 칸은 ws 모드에서 아무 영향이 없습니다 — 백엔드가 에이전트에 "
                 "접속하는 게 아니라 에이전트가 백엔드로 접속하기 때문입니다.").grid(
            row=len(LOCAL_FIELDS), column=0, columnspan=3, sticky="w", pady=(8, 0))

        for key in ("__host", "__port", "__https", "__path", "token"):
            self.vars[key].trace_add("write", lambda *_: self._update_dial_preview())
        self._update_dial_preview()
        self._sync_mode_ui()

    @staticmethod
    def _split_ws_url(url: str) -> tuple[str, int, bool, str]:
        """config 의 ws_url 을 (호스트, 포트, https여부, 경로) 로 분해한다. 못 읽으면 빈 값.

        경로는 리버스 프록시 뒤에 백엔드가 있는 배포를 위한 것이다.
        예) http://example.com:28004/mq  ->  ("example.com", 28004, False, "/mq")
        """
        u = (url or "").strip().rstrip("/")
        if not u:
            return "", 0, False, ""
        https = u.startswith(("https://", "wss://"))
        try:
            p = urllib.parse.urlparse(u if "://" in u else "http://" + u)
            port = p.port
        except ValueError:
            return "", 0, https, ""
        base = (p.path or "").rstrip("/")
        return (p.hostname or ""), (port or (443 if https else 0)), https, base

    def _normalize_host_field(self) -> None:
        """주소 칸에 'http://h:3940/mq' 나 'h:3940' 을 넣었으면 호스트·포트·HTTPS·경로 칸으로 나눈다."""
        raw = str(self.vars["__host"].get()).strip().rstrip("/")
        if not raw:
            return
        host, port, https, path = raw, 0, None, ""
        if "://" in raw or "/" in raw:
            h2, p2, s2, b2 = self._split_ws_url(raw)
            if not h2:
                return   # 못 읽는 값은 그대로 두고 검증에서 알린다
            host, port, path = h2, p2, b2
            if "://" in raw:
                https = s2
                if not port and not str(self.vars["__port"].get()).strip():
                    port = 443 if s2 else 80   # 'http://host' 처럼 포트를 생략했으면 표준 포트
        elif raw.count(":") == 1:
            h2, _, p2 = raw.partition(":")
            if p2.isdigit():
                host, port = h2, int(p2)
        if host != raw:
            self.vars["__host"].set(host)
        if port:
            self.vars["__port"].set(str(port))
        if https is not None:
            self.vars["__https"].set(bool(https))
        if path and not str(self.vars["__path"].get()).strip():
            self.vars["__path"].set(path.strip("/"))

    def _host_problem(self) -> str:
        host = str(self.vars["__host"].get()).strip()
        if not host:
            return "백엔드 서버 주소를 입력하세요."
        if any(ch in host for ch in " /:\\?#@"):
            return "백엔드 서버 주소에는 IP 나 호스트명만 적으세요(포트·경로는 옆 칸에): %s" % host
        return ""

    def _port_value(self) -> int:
        raw = str(self.vars["__port"].get()).strip()
        try:
            port = int(raw)
        except ValueError:
            return 0
        return port if 1 <= port <= 65535 else 0

    def _compose_ws_url(self) -> str:
        """입력 칸으로 ws_url 을 만든다. 칸 값은 바꾸지 않는다(정리는 _normalize_host_field)."""
        if self._host_problem():
            return ""
        port = self._port_value()
        if not port:
            return ""
        host = str(self.vars["__host"].get()).strip()
        scheme = "https" if bool(self.vars["__https"].get()) else "http"
        base = str(self.vars["__path"].get()).strip().strip("/")
        tail = ("/" + base) if base else ""
        return "%s://%s:%d%s" % (scheme, host, port, tail)

    def _path_problem(self) -> str:
        """경로 칸에 주소를 넣는 실수를 잡는다. 문제가 없으면 빈 문자열."""
        p = str(self.vars["__path"].get()).strip()
        if not p:
            return ""
        if "://" in p or re.search(r"\d{1,3}(\.\d{1,3}){3}", p) or ":" in p or " " in p:
            return ("「경로(선택)」에 주소가 들어갔습니다. 이 칸은 백엔드가 하위 경로에 붙어 있을 때만 "
                    "'mq' 처럼 경로 이름만 적습니다. 보통은 비워 두세요.")
        return ""

    def _update_dial_preview(self):
        bad = self._path_problem()
        if bad:
            self.dial_preview.set("⚠ " + bad)
            return
        base = self._compose_ws_url()
        token = str(self.vars["token"].get()).strip()
        if not base:
            hp = self._host_problem()
            if hp and str(self.vars["__host"].get()).strip():
                self.dial_preview.set("— 주소 칸에서 다른 칸으로 옮기면 주소·포트를 나눠 드립니다")
            elif str(self.vars["__port"].get()).strip() and not self._port_value():
                self.dial_preview.set("⚠ 포트는 1~65535 사이 숫자여야 합니다")
            else:
                self.dial_preview.set("— (백엔드 서버 주소와 포트를 입력하세요)")
            return
        ws = ("wss://" + base[len("https://"):]) if base.startswith("https://") \
            else ("ws://" + base[len("http://"):])
        shown = (token[:12] + "…") if len(token) > 12 else (token or "(없음)")
        self.dial_preview.set("%s/api/file-agent/ws?token=%s" % (ws, shown))

    def on_new_token(self):
        if not messagebox.askokcancel(
                "새 토큰 생성",
                "랜덤 64자리 토큰을 만들어 입력란에 넣습니다.\n\n"
                "저장하고 데몬을 재시작한 뒤, 백엔드 노드의 Token 도 같은 값으로 바꿔야 연결됩니다."):
            return
        import secrets  # noqa: PLC0415
        tok = secrets.token_hex(32)
        self.vars["token"].set(tok)
        try:
            self.clipboard_clear()
            self.clipboard_append(tok)
            extra = "\n(클립보드에도 복사했습니다.)"
        except tk.TclError:
            extra = ""
        self.backend_result.set("새 토큰을 넣었습니다. 저장 후 재시작하고, 백엔드 노드 Token 도 맞추세요." + extra)

    def _sync_mode_ui(self):
        """direct 모드에서는 백엔드 주소 칸만 잠근다. 토큰은 모든 모드에서 필요하므로 그대로 둔다."""
        direct = self.vars["mode"].get() == "direct"
        keep = set(getattr(self, "_always_enabled", ()))

        def walk(widget):
            for child in widget.winfo_children():
                if child in keep:
                    continue
                try:
                    child.configure(state=("disabled" if direct else "normal"))
                except tk.TclError:
                    pass
                walk(child)

        walk(self.conn_box)

    # ---- 탭: 감시 폴더 ----
    def _build_dirs(self, parent):
        ttk.Label(parent, style="Hint.TLabel", wraplength=880, justify="left",
                  text="backend 모드에서는 캔버스 노드의 WatchDir 가 감시 폴더를 정합니다. 여기 목록은 "
                       "백엔드에 붙기 전 임시값이라 비워 둬도 됩니다.\n"
                       "direct 모드에서는 이 목록이 전부입니다. 폴더의 마지막 이름이 서로 겹치면 안 되고, "
                       "로컬 디스크 경로를 쓰세요 — 부팅 때 SYSTEM 으로 돌기 때문에 매핑 드라이브(Z: 등)는 보이지 않습니다. "
                       "설치 폴더 안에는 두지 마세요.").pack(anchor="w")

        mid = ttk.Frame(parent)
        mid.pack(fill="both", expand=True, pady=10)
        self.dir_list = tk.Listbox(mid, height=10, activestyle="none")
        self.dir_list.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.dir_list.yview)
        sb.pack(side="left", fill="y")
        self.dir_list.configure(yscrollcommand=sb.set)

        side = ttk.Frame(mid, padding=(10, 0, 0, 0))
        side.pack(side="left", fill="y")
        ttk.Button(side, text="폴더 추가", command=self.on_dir_add).pack(fill="x")
        ttk.Button(side, text="선택 삭제", command=self.on_dir_del).pack(fill="x", pady=6)
        ttk.Separator(side, orient="horizontal").pack(fill="x", pady=8)
        ttk.Button(side, text="데몬에 즉시 적용", command=self.on_dirs_apply).pack(fill="x")
        ttk.Label(side, style="Hint.TLabel", wraplength=150, justify="left",
                  text="direct 모드에서 재시작 없이 감시 폴더만 교체합니다.").pack(anchor="w", pady=(6, 0))

        # 폴더별 필터 등 dict 로 적힌 항목은 원본을 기억해 두고 저장 때 그대로 되살린다.
        self._watch_items = list(self.cfg.get("watch_dirs") or [])
        for d in self._cfg_watch_dirs():
            self.dir_list.insert("end", d)
        self.legacy_hint = tk.StringVar(value="")
        ttk.Label(parent, textvariable=self.legacy_hint, style="Hint.TLabel", wraplength=880,
                  justify="left", foreground="#b0452a").pack(anchor="w")
        if self._legacy_single_dir():
            self.legacy_hint.set(
                "이 설정은 예전 방식(watch_dir 한 폴더)입니다. S3 경로 앞에 폴더 이름이 붙지 않습니다. "
                "목록을 바꿔 저장하면 폴더 이름이 붙는 방식으로 바뀌어, 이미 올린 파일도 새 경로로 다시 올라갑니다.")

    def _watch_items_for(self, paths: list[str]) -> list:
        norm = lambda x: os.path.normcase(os.path.normpath(str(x)))  # noqa: E731
        by_path = {}
        for item in getattr(self, "_watch_items", []):
            if isinstance(item, dict):
                d = item.get("dir") or item.get("path")
                if d:
                    by_path[norm(d)] = item
            elif isinstance(item, str):
                by_path.setdefault(norm(item), item)
        return [by_path.get(norm(pth), pth) for pth in paths]

    def _legacy_single_dir(self) -> bool:
        """watch_dirs 없이 watch_dir 한 폴더만 쓰는 옛 설정인지(이때 S3 경로에 폴더 이름이 붙지 않는다)."""
        if self.cfg.get("watch_dirs"):
            return False
        parts = [x for x in str(self.cfg.get("watch_dir") or "").split(";") if x.strip()]
        return len(parts) == 1

    def _cfg_watch_dirs(self) -> list[str]:
        raw = self.cfg.get("watch_dirs") or []
        if not raw:
            # 옛 설정: watch_dir(단수, ';' 로 여러 개 가능)
            return [x.strip() for x in str(self.cfg.get("watch_dir") or "").split(";") if x.strip()]
        out = []
        for item in raw:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                p = item.get("dir") or item.get("path")
                if p:
                    out.append(str(p))
        return out

    # ---- 탭: S3 ----
    def _build_s3(self, parent):
        box = ttk.LabelFrame(parent, text="direct 모드 S3 설정", padding=10)
        box.pack(fill="x")
        self._add_fields(box, S3_FIELDS)
        ttk.Button(box, text="S3 연결 테스트", command=self.on_test_s3).grid(
            row=len(S3_FIELDS), column=0, sticky="w", pady=(10, 0))
        self.s3_result = tk.StringVar(value="")
        ttk.Label(box, textvariable=self.s3_result, style="Status.TLabel",
                  wraplength=700, justify="left").grid(row=len(S3_FIELDS), column=1,
                                                       columnspan=2, sticky="w", pady=(10, 0))
        ttk.Label(parent, style="Hint.TLabel", wraplength=880, justify="left",
                  text="연결 테스트는 '엔드포인트가 정말 S3 인지'까지 확인합니다. 웹 UI 주소를 넣으면 어떤 요청에도 "
                       "200 을 돌려주기 때문에 단순 접속 확인만으로는 통과해 버립니다. 그래서 존재할 수 없는 "
                       "버킷명으로 한 번 더 찔러 보고, 거기에도 성공하면 S3 가 아니라고 판정합니다.").pack(
            anchor="w", pady=(12, 0))

    # ---- 탭: 성능 ----
    def _build_sync(self, parent):
        box = ttk.LabelFrame(parent, text="이 에이전트", padding=10)
        box.pack(fill="x")
        self._add_fields(box, SYNC_FIELDS)
        ttk.Label(box, style="Hint.TLabel", wraplength=820, justify="left",
                  text="여기서 정하는 것은 '로컬에서 지운 파일을 백엔드에 알릴지' 하나뿐입니다. "
                       "덮어쓴 파일은 이 값과 상관없이 항상 다시 보냅니다.").grid(
            row=len(SYNC_FIELDS), column=0, columnspan=3, sticky="w", pady=(6, 0))

        # 목적별로 에이전트와 캔버스 노드를 각각 어떻게 둘지
        guide = ttk.LabelFrame(parent, text="무엇을 하려면 어떻게 두나", padding=(12, 8))
        guide.pack(fill="x", pady=12)
        head = ("하고 싶은 것", "이 에이전트", "캔버스 S3 Bucket 노드 (SyncMode)")
        rows = [
            ("새 파일만 올리기 — 이미지처럼 한 번 만들면 안 바뀌는 파일", "적재만", "speed"),
            ("덮어쓴 내용까지 S3 에 반영", "상관없음", "mirror"),
            ("로컬에서 지운 파일을 S3 에서도 삭제", "삭제도 알림", "mirror"),
        ]
        for c, text in enumerate(head):
            ttk.Label(guide, text=text, font=("Segoe UI", 9, "bold")).grid(
                row=0, column=c, sticky="w", padx=(0, 28), pady=(0, 6))
        ttk.Separator(guide, orient="horizontal").grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 6))
        for r, (goal, agent_side, node_side) in enumerate(rows, start=2):
            ttk.Label(guide, text=goal).grid(row=r, column=0, sticky="w", padx=(0, 28), pady=3)
            strong_a = agent_side not in ("적재만", "상관없음")
            ttk.Label(guide, text=agent_side, foreground="#b0452a" if strong_a else "",
                      font=("Segoe UI", 9, "bold" if strong_a else "normal")).grid(
                row=r, column=1, sticky="w", padx=(0, 28), pady=3)
            strong_n = node_side == "mirror"
            ttk.Label(guide, text=node_side, foreground="#b0452a" if strong_n else "",
                      font=("Segoe UI", 9, "bold" if strong_n else "normal")).grid(
                row=r, column=2, sticky="w", pady=3)

        notes = ttk.LabelFrame(parent, text="꼭 알아둘 것", padding=(12, 8))
        notes.pack(fill="x")
        for line in (
            "· 삭제는 에이전트와 노드가 둘 다 켜져 있어야 일어납니다. 한쪽만 켜면 아무 일도 없습니다. 지운 파일은 복구되지 않습니다.",
            "· 백엔드는 노드의 모드를 에이전트에 알려 주지 않습니다. 캔버스에서 바꿨다면 여기서도 따로 바꿔야 합니다.",
            "· 노드가 speed 면 덮어쓴 파일을 '이미 올린 파일'로 보고 건너뜁니다. 오류 없이 완료로 기록되므로 "
            "S3 에는 처음 내용이 조용히 남습니다. 나중에 노드를 mirror 로 바꿔도 이미 건너뛴 파일은 그대로이니, "
            "그 파일을 한 번 더 저장해 수정 시각을 바꿔 주세요.",
            "· 삭제·덮어쓰기는 노드의 PathPrefix 안에서만 일어납니다. 다른 자료가 함께 있는 버킷이면 PathPrefix 를 꼭 지정하세요.",
        ):
            ttk.Label(notes, text=line, wraplength=860, justify="left").pack(anchor="w", pady=2)

    def _build_perf(self, parent):
        box = ttk.LabelFrame(parent, text="전송 성능 · 무손실", padding=10)
        box.pack(fill="x")
        self._add_fields(box, PERF_FIELDS)
        ttk.Label(parent, style="Hint.TLabel", wraplength=880, justify="left",
                  text="원장 보관 상한은 RAM 을 직접 좌우합니다 — 항목당 약 350B 로, 500만 건이면 약 1.6GB 입니다. "
                       "'동시에 디스크에 두는 최대 파일 수'보다 크게, 그러나 필요 이상 크지 않게 잡으세요.").pack(
            anchor="w", pady=(12, 0))
        for key in ("ledger_keep_in_memory",):
            v = self.vars.get(key)
            if v is not None:
                v.trace_add("write", lambda *_: self._update_ram_hint())

    # ---- 탭: 로그 ----
    def _build_log(self, parent):
        box = ttk.LabelFrame(parent, text="로그 설정", padding=10)
        box.pack(fill="x")
        self._add_fields(box, LOG_FIELDS)

        ttk.Label(parent, text="agent.log (최근 내용)", style="Big.TLabel").pack(anchor="w", pady=(12, 4))
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True)
        self.log_text = tk.Text(wrap, height=14, wrap="none", font=("Consolas", 9))
        self.log_text.pack(side="left", fill="both", expand=True)
        lsb = ttk.Scrollbar(wrap, orient="vertical", command=self.log_text.yview)
        lsb.pack(side="left", fill="y")
        self.log_text.configure(yscrollcommand=lsb.set, state="disabled")
        logbtns = ttk.Frame(parent)
        logbtns.pack(anchor="w", pady=(6, 0))
        ttk.Button(logbtns, text="새로고침", command=self._refresh_log).pack(side="left")
        ttk.Button(logbtns, text="로그 파일 전체 열기", command=self.on_open_log).pack(side="left", padx=6)
        ttk.Button(logbtns, text="폴더 열기", command=self.on_open_folder).pack(side="left")
        ttk.Button(logbtns, text="지원용 파일 만들기", command=self.on_support_bundle).pack(side="left", padx=6)
        ttk.Label(logbtns, style="Hint.TLabel",
                  text="  화면에는 마지막 부분만 보여 줍니다. 문의할 때는 [지원용 파일 만들기]로 모은 zip 을 보내세요.").pack(
            side="left", padx=(8, 0))
        self._refresh_log()

    def on_open_log(self):
        path = os.path.join(os.path.dirname(self.config_path), "agent.log")
        if not os.path.exists(path):
            messagebox.showwarning("로그 없음", "agent.log 가 아직 없습니다:\n%s" % path)
            return
        try:
            os.startfile(path)  # noqa: S606
        except OSError as e:
            messagebox.showerror("열기 실패", str(e))

    def on_support_bundle(self):
        """문의용 zip 을 바탕화면에 만든다. 토큰·S3 키는 가린다.

        설치 폴더는 관리자만 읽을 수 있게 잠겨 있다. 탐색기에서 '계속'을 눌러 열면 그 사용자에게
        권한이 영구히 추가돼 잠금이 약해지므로, 관리자로 뜬 이 UI 가 대신 모은다.
        """
        import zipfile  # noqa: PLC0415
        folder = os.path.dirname(self.config_path)
        desktop = os.path.join(os.environ.get("USERPROFILE") or os.path.expanduser("~"), "Desktop")
        if not os.path.isdir(desktop):
            desktop = os.path.expanduser("~")
        out = os.path.join(desktop, "file-agent-support-%s.zip" % time.strftime("%Y%m%d-%H%M%S"))
        secret_keys = ("token", "s3_access_key", "s3_secret_key")
        mask_log = re.compile(r"(token=)[^&\s'\"]+", re.IGNORECASE)
        try:
            with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
                for name in sorted(os.listdir(folder)):
                    full = os.path.join(folder, name)
                    if not os.path.isfile(full):
                        continue
                    low = name.lower()
                    if low == "config.json":
                        try:
                            data = load_config(full)
                            for k in secret_keys:
                                if data.get(k):
                                    data[k] = "***(%d자)" % len(str(data[k]))
                            z.writestr(name, json.dumps(data, ensure_ascii=False, indent=2))
                        except Exception as e:  # noqa: BLE001
                            z.writestr(name + ".error.txt", "읽기 실패: %s" % e)
                    elif re.match(r"^agent\.log(\.\d+)?$", low) or low in ("agent-crash.log", "build-info.txt"):
                        with open(full, "rb") as f:
                            text = f.read().decode("utf-8", errors="replace")
                        z.writestr(name, mask_log.sub(r"\1***", text))
                snap = {
                    "ui_version": UI_VERSION,
                    "collected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "install_folder": folder,
                    "health": self._health_body,
                    "autostart": autostart_info(),
                    "processes": agent_processes(),
                    "stopped_flag": stop_flag_active(folder),
                }
                z.writestr("ui-snapshot.json", json.dumps(snap, ensure_ascii=False, indent=2, default=str))
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("지원용 파일", "만들지 못했습니다: %s: %s" % (type(e).__name__, e))
            return
        messagebox.showinfo("지원용 파일", "바탕화면에 만들었습니다(토큰·S3 키는 가렸습니다).\n%s" % out)

    def on_open_folder(self):
        folder = os.path.dirname(self.config_path)
        try:
            os.startfile(folder)  # noqa: S606
        except OSError as e:
            messagebox.showerror("열기 실패", str(e))

    # ---- 공용 필드 빌더 ----
    def _add_fields(self, parent, fields):
        for i, (key, label, kind, needs_restart) in enumerate(fields):
            ttk.Label(parent, text=label, width=28, anchor="w").grid(row=i, column=0, sticky="w", pady=4)
            cur = self._cfg_value(key)
            if kind == "bool":
                var = tk.BooleanVar(value=bool(cur))
                ttk.Checkbutton(parent, variable=var).grid(row=i, column=1, sticky="w", pady=4)
            elif kind == "pick":
                pairs = CHOICE_LABELS[key]
                labels = [lb for _v, lb in pairs]
                val2lb = {v: lb for v, lb in pairs}
                var = tk.StringVar(value=val2lb.get(str(cur), labels[0]))
                ttk.Combobox(parent, textvariable=var, values=labels, state="readonly",
                             width=48).grid(row=i, column=1, sticky="w", pady=4)
                self._pick_maps[key] = {lb: v for v, lb in pairs}
            elif kind.startswith("choice:"):
                opts = kind.split(":", 1)[1].split(",")
                var = tk.StringVar(value=str(cur if cur is not None else opts[0]))
                ttk.Combobox(parent, textvariable=var, values=opts, state="readonly",
                             width=28).grid(row=i, column=1, sticky="w", pady=4)
            else:
                var = tk.StringVar(value="" if cur is None else str(cur))
                ttk.Entry(parent, textvariable=var, width=52,
                          show="*" if kind == "secret" else "").grid(row=i, column=1, sticky="w", pady=4)
            self.vars[key] = var
            if needs_restart:
                ttk.Label(parent, text="재시작 필요", style="Hint.TLabel").grid(
                    row=i, column=2, sticky="w", padx=(10, 0))

    # ---- 값 수집 ----
    def _collect(self) -> dict:
        out: dict = {}
        typed = {k: kind for k, _l, kind, _r in
                 CONN_FIELDS + SYNC_FIELDS + PERF_FIELDS + LOG_FIELDS + S3_FIELDS}
        for key, var in self.vars.items():
            if key.startswith("__"):
                continue
            if key == "mode":
                out["mode"] = var.get()
                continue
            kind = typed.get(key, "entry")
            raw = var.get()
            if kind == "pick":
                mapping = self._pick_maps.get(key, {})
                out[key] = mapping.get(str(raw), CHOICE_LABELS[key][0][0])
            elif kind == "bool":
                out[key] = bool(raw)
            elif kind == "int":
                s = str(raw).strip()
                if s == "":
                    continue
                try:
                    out[key] = int(float(s))
                except ValueError:
                    raise ValueError("'%s' 에는 숫자를 넣어야 합니다: %r" % (key, raw))
            else:
                out[key] = str(raw).strip()
        self._normalize_host_field()
        if out.get("mode") == "backend" or self._compose_ws_url():
            out["ws_url"] = self._compose_ws_url()
        out["watch_dirs"] = self._watch_items_for(list(self.dir_list.get(0, "end")))
        return out

    # ---- 동작 ----
    def on_save(self, silent: bool = False) -> bool:
        try:
            values = self._collect()
        except ValueError as e:
            messagebox.showerror("입력 오류", str(e))
            return False
        problems = self._validate(values)
        if problems:
            messagebox.showerror("저장 전 확인", "\n".join("· " + p for p in problems))
            return False
        changes = self._changed_values(values)
        if "watch_dirs" in changes and self._legacy_single_dir():
            if not messagebox.askyesno(
                    "감시 폴더 방식 변경",
                    "예전 방식(watch_dir 한 폴더)을 목록 방식으로 바꿉니다.\n"
                    "S3 경로 앞에 폴더 이름이 붙게 되어, 이미 올린 파일도 새 경로로 다시 올라갑니다.\n"
                    "계속할까요?", icon="warning"):
                return False
        tok = str(values.get("token", ""))
        if "token" in changes and len(tok) < 16:
            if not messagebox.askyesno(
                    "짧은 토큰",
                    "토큰이 %d자로 짧습니다. 같은 망의 누군가가 추측할 수 있습니다.\n"
                    "[새 토큰 생성] 을 권장합니다. 그래도 저장할까요?" % len(tok), icon="warning"):
                return False
        try:
            changed, note = write_config_preserving_comments(self.config_path, changes)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("저장 실패", "%s: %s\n\n파일은 바뀌지 않았습니다." % (type(e).__name__, e))
            return False
        try:
            self.cfg = load_config(self.config_path)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("저장 후 확인 실패", "%s: %s" % (type(e).__name__, e))
            return False
        self._watch_items = list(self.cfg.get("watch_dirs") or [])
        self._poll_port = self._saved_port()
        self._poll_token = str(self.cfg.get("token", ""))
        self._initial = dict(values)
        if self._legacy_single_dir() is False and "watch_dirs" in changed:
            self.legacy_hint.set("")
        if note:
            messagebox.showwarning("저장됨 — 형식 변경", note)
        if not silent:
            if changed:
                messagebox.showinfo("저장됨",
                                    "바뀐 항목 %d개:\n%s\n\n이전 설정: %s.bak\n"
                                    "대부분의 값은 데몬을 다시 시작해야 적용됩니다."
                                    % (len(changed), ", ".join(changed), os.path.basename(self.config_path)))
            else:
                messagebox.showinfo("저장됨", "바뀐 항목이 없습니다.")
        return True

    def _saved_port(self) -> int:
        try:
            return int(self.cfg.get("port", 8765))
        except (TypeError, ValueError):
            return 8765

    def _changed_values(self, values: dict) -> dict:
        base = getattr(self, "_initial", {}) or {}
        return {k: v for k, v in values.items() if base.get(k, _MISSING) != v}

    def _unsaved_changes(self) -> list[str]:
        try:
            values = self._collect()
        except ValueError:
            return ["(입력 오류)"]
        return sorted(self._changed_values(values))

    def _validate(self, v: dict) -> list[str]:
        problems = []
        tp = token_problem(v.get("token"))
        if tp:
            problems.append(tp + " — 「연결」 탭의 [새 토큰 생성] 을 누르세요. "
                                 "backend 모드라면 캔버스 노드의 Token 도 같은 값으로 맞춰야 합니다.")
        if v.get("mode") == "backend":
            hp = self._host_problem()
            if hp:
                problems.append(hp)
            if not self._port_value():
                problems.append("백엔드 포트를 1~65535 사이 숫자로 입력하세요 — 배포마다 다릅니다.")
            bad = self._path_problem()
            if bad:
                problems.append(bad)
            url = v.get("ws_url", "")
            if url and "/api/" in url:
                problems.append("경로 칸에 /api/... 를 넣지 마세요 — 에이전트가 자동으로 붙입니다.")
        else:
            if not v.get("s3_endpoint") or not v.get("s3_bucket"):
                problems.append("direct 모드에는 s3_endpoint 와 s3_bucket 이 필요합니다.")
            if not v.get("watch_dirs"):
                problems.append("direct 모드에는 감시 폴더가 최소 하나 필요합니다.")
        paths = [str(d.get("dir") or d.get("path") or "") if isinstance(d, dict) else str(d)
                 for d in v.get("watch_dirs", [])]
        names = [os.path.basename(os.path.normpath(d)).lower() for d in paths if d]
        dupes = {n for n in names if names.count(n) > 1}
        if dupes:
            problems.append("감시 폴더의 마지막 이름이 겹칩니다(%s) — 라우팅이 깨집니다."
                            % ", ".join(sorted(dupes)))
        folder = os.path.normcase(os.path.dirname(os.path.abspath(self.config_path)))
        for d in paths:
            dd = os.path.normcase(os.path.abspath(d)) if d else ""
            if dd and (dd == folder or dd.startswith(folder.rstrip("\\/") + os.sep)):
                problems.append("감시 폴더(%s)를 설치 폴더 안에 두지 마세요." % d)
        if int(v.get("ledger_keep_in_memory", 0) or 0) > 20_000_000:
            problems.append("원장 메모리 상한이 2천만 건을 넘습니다 — RAM 약 7GB 이상입니다.")
        return problems

    def on_save_restart(self):
        if self.on_save(silent=True):
            self.on_daemon("restart")

    def on_dir_add(self):
        d = filedialog.askdirectory(title="감시할 폴더 선택")
        if d:
            self.dir_list.insert("end", os.path.normpath(d).replace("\\", "/"))

    def on_dir_del(self):
        for i in reversed(self.dir_list.curselection()):
            self.dir_list.delete(i)

    def on_dirs_apply(self):
        if self.vars["mode"].get() == "backend":
            messagebox.showinfo(
                "즉시 적용",
                "backend 모드에서는 감시 폴더를 캔버스 노드의 WatchDir 가 정합니다.\n"
                "여기서 바꿔도 백엔드가 곧 되돌리므로, 캔버스에서 바꾸세요.")
            return
        dirs = list(self.dir_list.get(0, "end"))
        if not dirs:
            messagebox.showwarning("적용 불가", "감시 폴더가 비어 있습니다.")
            return
        items = self._watch_items_for(dirs)
        ok, res = agent_post(self._poll_port, self._poll_token, "/control/watch_dir", {"watch_dirs": items})
        if ok:
            messagebox.showinfo("적용됨", "데몬 응답:\n%s\n\n다음 재시작 뒤에도 유지하려면 [저장만] 을 누르세요."
                                % json.dumps(res, ensure_ascii=False, indent=2))
        else:
            messagebox.showerror("적용 실패", "데몬에 붙지 못했습니다 (%s).\n데몬이 실행 중인지 확인하세요." % res)

    def on_test_backend(self):
        """포트가 열렸는지만 보면 프론트 포트(웹페이지)도 통과해 버린다.
        에이전트가 실제로 부르는 /api/file-agent/preflight 가 JSON 으로 답하는지까지 확인한다."""
        self._normalize_host_field()
        url = self._compose_ws_url()
        if not url:
            self.backend_result.set(self._host_problem() or "포트를 1~65535 사이 숫자로 입력하세요.")
            return
        host, port = split_hostport(url, 0)
        if not host or not port:
            self.backend_result.set("주소 형식이 올바르지 않습니다.")
            return
        token = str(self.vars["token"].get()).strip()
        if not token:
            self.backend_result.set("토큰을 먼저 입력하세요 — 백엔드가 토큰 없는 요청은 거부합니다.")
            return
        self.backend_result.set("확인 중…")
        self.update_idletasks()
        threading.Thread(target=self._test_backend_worker,
                         args=(url, host, port, token, self._poll_port), daemon=True).start()

    def _test_backend_worker(self, base, host, port, token, agent_port):
        def done(msg):
            self.after(0, lambda: self.backend_result.set(msg))

        if not tcp_open(host, port):
            done("접속 실패 — %s:%d 에 닿지 않습니다. 주소·포트와 망 상태를 확인하세요." % (host, port))
            return

        q = urllib.parse.urlencode({"host": "127.0.0.1", "port": agent_port})
        req = urllib.request.Request("%s/api/file-agent/preflight?%s" % (base.rstrip("/"), q))
        req.add_header("X-Agent-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read(4096)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                done("%s:%d 는 열려 있지만 file-agent 백엔드가 아닙니다(HTTP 404). "
                     "포트가 맞는지, 백엔드에 file-agent 기능이 켜져 있는지 확인하세요." % (host, port))
            else:
                done("백엔드가 요청을 거절했습니다(HTTP %d)." % e.code)
            return
        except Exception as e:  # noqa: BLE001
            reason = str(getattr(e, "reason", e))
            # HTTPS 로 물었는데 상대가 평문 HTTP 면 "WRONG_VERSION_NUMBER" 류 SSL 오류가 난다.
            # 같은 주소를 http 로 다시 물어 보고, 되면 체크를 풀라고 정확히 알려 준다.
            if base.startswith("https://") and ("SSL" in reason.upper() or "WRONG_VERSION" in reason.upper()):
                plain = "http://" + base[len("https://"):]
                try:
                    preq = urllib.request.Request("%s/api/file-agent/preflight?%s" % (plain.rstrip("/"), q))
                    preq.add_header("X-Agent-Token", token)
                    with urllib.request.urlopen(preq, timeout=10) as presp:
                        pbody = json.loads(presp.read(4096).decode("utf-8"))
                    if isinstance(pbody, dict) and pbody.get("agentToBackend"):
                        done("이 포트는 암호화(HTTPS)를 쓰지 않습니다 — [HTTPS] 체크를 해제하고 저장하세요. "
                             "(일반 연결로는 %s:%d 의 백엔드가 정상 응답합니다)" % (host, port))
                        return
                except Exception:  # noqa: BLE001
                    pass
                done("HTTPS 연결에 실패했습니다(%s). 백엔드 포트에 바로 붙는다면 [HTTPS] 체크를 해제하세요."
                     % reason[:80])
                return
            done("응답을 받지 못했습니다: %s" % reason[:120])
            return

        try:
            body = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            done("%s:%d 는 열려 있지만 백엔드가 아니라 웹 페이지가 응답합니다 — "
                 "프론트엔드 포트를 넣으신 것 같습니다. 백엔드 포트로 바꾸세요." % (host, port))
            return

        if isinstance(body, dict) and body.get("agentToBackend"):
            done("정상 — %s:%d 의 TERESA MQ 백엔드가 응답했습니다. "
                 "[저장하고 다시 시작] 후 캔버스 노드의 Token 이 이 값과 같은지 확인하세요." % (host, port))
        else:
            done("응답은 왔지만 예상한 형식이 아닙니다: %s" % str(body)[:120])

    def on_test_s3(self):
        endpoint = str(self.vars["s3_endpoint"].get()).strip()
        bucket = str(self.vars["s3_bucket"].get()).strip()
        ak = str(self.vars["s3_access_key"].get()).strip()
        sk = str(self.vars["s3_secret_key"].get()).strip()
        if not endpoint or not bucket:
            self.s3_result.set("엔드포인트와 버킷을 먼저 입력하세요.")
            return
        self.s3_result.set("확인 중…")
        self.update_idletasks()
        threading.Thread(target=self._test_s3_worker, args=(endpoint, bucket, ak, sk), daemon=True).start()

    def _test_s3_worker(self, endpoint, bucket, ak, sk):
        def done(msg):
            self.after(0, lambda: self.s3_result.set(msg))
        try:
            import boto3  # noqa: PLC0415
            import botocore  # noqa: PLC0415
            from botocore.client import Config as BotoConfig  # noqa: PLC0415
        except ImportError:
            done("boto3 가 설치되어 있지 않아 테스트할 수 없습니다 (pip install boto3).")
            return

        host, port = split_hostport(endpoint, 80)
        if not tcp_open(host, port):
            done("접속 실패 — %s:%d 에 닿지 않습니다." % (host, port))
            return

        s3 = boto3.client(
            "s3", endpoint_url=endpoint, region_name="us-east-1",
            aws_access_key_id=ak or None, aws_secret_access_key=sk or None,
            config=BotoConfig(s3={"addressing_style": "path"}, signature_version="s3v4",
                              retries={"max_attempts": 1}, connect_timeout=6, read_timeout=15))

        # 1) 카나리아 — 없는 버킷에도 성공하면 S3 가 아니다.
        try:
            s3.head_bucket(Bucket=CANARY_BUCKET)
            done("S3 엔드포인트가 아닙니다 — 존재하지 않는 버킷에도 성공 응답을 돌려줍니다.\n"
                 "웹 UI 주소를 넣지 않았는지 확인하세요: %s" % endpoint)
            return
        except botocore.exceptions.ClientError:
            pass
        except Exception as e:  # noqa: BLE001
            done("확인 실패: %s: %s" % (type(e).__name__, str(e)[:120]))
            return

        # 2) 실제 버킷
        try:
            s3.head_bucket(Bucket=bucket)
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code in ("InvalidAccessKeyId", "SignatureDoesNotMatch") or status == 403:
                done("인증 실패 (%s) — AccessKey/SecretKey 를 확인하세요." % (code or status))
            else:
                done("버킷에 접근할 수 없습니다 (%s / HTTP %s)." % (code, status))
            return
        except Exception as e:  # noqa: BLE001
            done("확인 실패: %s: %s" % (type(e).__name__, str(e)[:120]))
            return

        # 3) 쓰기 왕복
        key = "_file-agent-ui-probe.txt"
        try:
            s3.put_object(Bucket=bucket, Key=key, Body=b"file-agent ui probe")
            s3.delete_object(Bucket=bucket, Key=key)
            done("정상 — 실제 S3 확인, 인증 성공, 버킷 접근 및 쓰기/삭제까지 완료했습니다.")
        except Exception as e:  # noqa: BLE001
            done("읽기는 되지만 쓰기에 실패했습니다: %s: %s" % (type(e).__name__, str(e)[:120]))

    def on_daemon(self, action: str):
        if self._busy:
            return
        exe = find_agent_exe(self.config_path)
        folder = os.path.dirname(self.config_path)
        if action in ("start", "restart", "install") and not exe:
            messagebox.showerror("실행 파일 없음",
                                 "file-agent.exe 를 찾지 못했습니다:\n%s" % folder)
            return

        if action in ("start", "restart", "install"):
            # 데몬은 파일에 저장된 값만 읽는다. 저장 안 한 입력이 있으면 먼저 정리한다.
            pending = self._unsaved_changes()
            if pending:
                ans = messagebox.askyesnocancel(
                    "저장하지 않은 변경",
                    "저장하지 않은 변경이 있습니다: %s\n\n"
                    "예 = 저장하고 진행 / 아니오 = 저장된 설정으로 진행" % ", ".join(pending[:8]))
                if ans is None:
                    return
                if ans and not self.on_save(silent=True):
                    return
            try:
                saved = load_config(self.config_path)
            except Exception as e:  # noqa: BLE001
                messagebox.showerror("설정 읽기 실패", "%s: %s" % (type(e).__name__, e))
                return
            tp = token_problem(saved.get("token"))
            if tp:
                messagebox.showerror(
                    "시작할 수 없음",
                    "%s.\n\n「연결」 탭에서 [새 토큰 생성] → [저장만] 을 누른 뒤 다시 시도하세요.\n"
                    "backend 모드라면 캔버스 노드의 Token 도 같은 값으로 맞춰야 합니다." % tp)
                return
            if str(saved.get("mode", "")).lower() == "backend" and not str(saved.get("ws_url", "")).strip():
                messagebox.showerror("시작할 수 없음", "저장된 백엔드 주소가 없습니다. 「연결」 탭에서 입력하고 저장하세요.")
                return

        info = autostart_info() or {}
        procs = agent_processes()
        running = [pid for pid, _s, _i in procs]
        this_exe = exe or os.path.join(folder, "file-agent.exe")
        task_ok = bool(info) and os.path.normcase(info.get("command", "")) == os.path.normcase(this_exe)
        other_task = bool(info) and not task_ok
        if other_task and action in ("stop", "uninstall"):
            messagebox.showwarning(
                "다른 폴더에서 운영 중",
                "PC 켤 때 자동 실행은 다른 폴더의 데몬에 등록돼 있습니다.\n  %s\n\n"
                "여기서 누르면 그 운영 데몬이 멈추거나 해제됩니다. 그 폴더의 file-agent-ui.exe 에서 누르세요.\n"
                "이 폴더가 옛 설치라면 버튼을 쓰지 말고 탐색기로 파일만 지우면 됩니다." % info.get("command"))
            return
        if action in ("start", "restart") and info and not task_ok:
            if not messagebox.askyesno(
                    "자동 실행 경로가 다름",
                    "PC 켤 때 자동 실행이 다른 실행 파일을 가리킵니다.\n  등록됨: %s\n  이 폴더: %s\n\n"
                    "이번에는 이 폴더의 데몬을 현재 사용자 세션에서 띄웁니다(로그오프하면 멈춤).\n"
                    "고치려면 이 폴더에서 [켜기] 를 다시 누르세요. 계속할까요?"
                    % (info.get("command") or "?", exe)):
                return

        exe_q, folder_q = ps_quote(exe), ps_quote(folder)
        stop_cmds = ["Stop-AgentTask", "$stopped = Stop-Agents"]
        if task_ok:
            start_cmds = [
                ps_remove_stop_flag(folder),
                "Wait-TaskIdle",
                "Start-ScheduledTask -TaskName $task",
                "Write-Host '작업 스케줄러(SYSTEM, 백그라운드)로 시작했습니다.'",
            ]
        else:
            start_cmds = [
                ps_remove_stop_flag(folder),
                "Start-Process -FilePath %s -WorkingDirectory %s" % (exe_q, folder_q),
                "Write-Host '현재 사용자 세션에서 시작했습니다 — 로그오프하면 멈춥니다. "
                "부팅 때도 돌게 하려면 [켜기] 를 누르세요.'",
            ]
        verify_up = False

        if action == "stop":
            if not running:
                messagebox.showinfo("중지", "실행 중인 데몬이 없습니다.")
                return
            detail = ("[시작] 을 누르거나 PC 를 '다시 시작'(재부팅)할 때까지 자동으로 다시 켜지지 않습니다.\n"
                      "빠른 시작이 켜진 PC 는 시작 메뉴 [종료] 후 전원을 켜도 멈춘 상태로 남습니다.") if info else ""
            if not messagebox.askokcancel("중지", "데몬(PID %s)을 멈춥니다.\n%s"
                                          % (", ".join(map(str, running)), detail)):
                return
            cmds = [ps_write_stop_flag(folder)] + stop_cmds + [
                "if ($stopped) { Write-Host '데몬을 멈췄습니다.'; exit 0 } else { exit 1 }"]
            label = "중지"
        elif action in ("start", "restart"):
            if action == "start" and running:
                if not messagebox.askokcancel(
                        "시작", "이미 실행 중입니다 (PID %s).\n멈췄다가 다시 시작할까요?"
                                % ", ".join(map(str, running))):
                    return
            cmds = stop_cmds + ["if (-not $stopped) { exit 1 }"] + start_cmds + ["exit 0"]
            label = "다시 시작" if running else "시작"
            verify_up = True
        elif action == "install":
            where, block = install_location_problem(folder)
            if where and block:
                messagebox.showerror("설치 위치", where)
                return
            msg = ("이 폴더의 데몬을 PC 켤 때 자동으로, 로그인 없이 SYSTEM 권한으로 돌게 등록합니다.\n"
                   "  · 부팅 30초 뒤·로그인 때 시작, 꺼져 있으면 5분마다 다시 켬\n"
                   "  · 방화벽 규칙 등록, 이 폴더를 관리자만 고칠 수 있게 잠금\n"
                   "  · 지금 도는 데몬은 멈췄다가 작업으로 다시 띄움\n\n"
                   "등록 뒤에는 이 폴더를 옮기거나 이름을 바꾸지 마세요.\n  %s" % folder)
            if where:
                msg += "\n\n⚠ " + where
            if other_task:
                msg += "\n\n지금은 다른 폴더(%s)에 등록돼 있습니다. 이 폴더로 옮깁니다." % info.get("command")
            if not messagebox.askokcancel("PC 켤 때 자동 실행 켜기", msg, icon="warning" if (where or other_task) else "info"):
                return
            port = self._saved_port()
            # 방화벽 규칙은 exe --install 이 '없을 때만' 만든다. 포트를 바꿨다면
            # 낡은 포트의 규칙이 남아 새 포트가 막히므로, 불일치하면 먼저 지운다.
            cmds = stop_cmds + [
                "if (-not $stopped) { exit 1 }",
                "$rule = @(Get-NetFirewallRule -DisplayName $task -ErrorAction SilentlyContinue)",
                "if ($rule.Count -gt 0) {",
                "  $pf = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue",
                "  if ($pf -and ($pf.LocalPort -ne '%d')) {" % port,
                "    Write-Host ('방화벽 규칙 포트 ' + $pf.LocalPort + ' -> %d 로 갱신')" % port,
                "    $rule | Remove-NetFirewallRule -ErrorAction SilentlyContinue",
                "  }",
                "}",
                ps_remove_stop_flag(folder),
                # GUI exe 는 & 로 부르면 기다리지 않는다 — 끝날 때까지 기다려 종료 코드를 받는다.
                "$p = Start-Process -FilePath %s -ArgumentList '--install' -WorkingDirectory %s "
                "-WindowStyle Hidden -Wait -PassThru" % (exe_q, folder_q),
                "$t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue",
                "if (-not $t) { Write-Host '작업 스케줄러: 등록되지 않았습니다 — 「로그」 탭에서 원인을 확인하세요.'; exit 1 }",
                "$trig = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace '^MSFT_Task','' -replace 'Trigger$','' }) -join ', '",
                "Write-Host ('작업 스케줄러: ' + $t.State + ' / 계정 ' + $t.Principal.UserId + ' / 권한 ' + $t.Principal.RunLevel + ' / 트리거 ' + $trig)",
                "$r2 = @(Get-NetFirewallRule -DisplayName $task -ErrorAction SilentlyContinue)",
                "if ($r2.Count -gt 0) {",
                "  $p2 = $r2[0] | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue",
                "  Write-Host ('방화벽: ' + $r2[0].Enabled + ' / 포트 ' + $p2.LocalPort + ' / 프로파일 ' + $r2[0].Profile)",
                "} else { Write-Host '방화벽: 규칙 없음' }",
                "Get-AgentFirewallRules | Where-Object { $_.DisplayName -ne $task -and $_.DisplayName -ne ($task + '-%d') } |"
                " ForEach-Object { Write-Host ('옛 포트 방화벽 규칙 제거: ' + $_.DisplayName);"
                " $_ | Remove-NetFirewallRule -ErrorAction SilentlyContinue }" % port,
                "Show-FolderLock %s" % folder_q,
                "if ($p.ExitCode -ne 0) { Write-Host ('설치 종료 코드 ' + $p.ExitCode + ' — 「로그」 탭에서 원인을 확인하세요'); exit 1 }",
                "exit 0",
            ]
            label = "자동 실행 켜기"
            verify_up = True
        else:
            if not messagebox.askokcancel(
                    "PC 켤 때 자동 실행 끄기",
                    "자동 실행 등록과 방화벽 규칙을 지우고, 지금 도는 데몬도 멈춥니다.\n"
                    "계속 돌리려면 끈 뒤 [시작] 을 누르세요(로그오프하면 멈춤)."):
                return
            cmds = [ps_remove_stop_flag(folder),
                    "if (Remove-AgentRegistration) { exit 0 } else { exit 1 }"]
            label = "자동 실행 끄기"

        def after(ok, out):
            if verify_up:
                self._verify_started(label, ok, out)
                return
            if ok:
                messagebox.showinfo(label, "완료했습니다.\n\n%s" % (out or ""))
            else:
                messagebox.showerror(label, "실패했습니다.\n\n%s" % (out or "(출력 없음)"))

        self._run_in_background(label, PS_COMMON + cmds, after)

    def _run_in_background(self, label: str, cmds: list[str], after) -> None:
        """관리자 스크립트를 별도 스레드에서 돌리고, 끝나면 after(ok, 출력)를 화면 스레드에서 부른다."""
        self._set_busy(True, "%s 처리 중…" % label)

        def work():
            ok, out = run_elevated(cmds)

            def finish():
                self._set_busy(False)
                after(ok, out)

            self.after(0, finish)

        threading.Thread(target=work, daemon=True, name="ui-action").start()

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        for b in self._action_buttons:
            try:
                b.configure(state=("disabled" if busy else "normal"))
            except tk.TclError:
                pass
        if busy:
            self.lbl_detail.configure(text=text)
        self.configure(cursor="watch" if busy else "")

    def _verify_started(self, label: str, ok: bool, out: str) -> None:
        """데몬이 실제로 응답할 때까지(최대 25초) 기다린 뒤 결과를 알린다."""
        if not ok:
            messagebox.showerror(label, "실패했습니다.\n\n%s" % (out or "(출력 없음)"))
            return
        port, token = self._poll_port, self._poll_token
        self._set_busy(True, "%s — 데몬 응답 확인 중…" % label)

        def wait():
            # 첫 기동은 백신 검사·큰 원장 읽기로 수십 초 걸릴 수 있다.
            deadline = time.time() + 90
            good, body = False, ""
            while time.time() < deadline:
                good, body = agent_get(port, token, "/health", timeout=2.0)
                if good:
                    break
                if time.time() > deadline - 75 and not agent_processes() and self._log_tail_errors():
                    break   # 프로세스도 없고 오류가 기록됐다 — 더 기다릴 이유가 없다
                time.sleep(1.5)
            procs = agent_processes()
            tail = "" if good else self._log_tail_errors()

            def finish():
                self._set_busy(False)
                if good:
                    where = ("백그라운드(SYSTEM)" if any(sess == 0 for _p, sess, _i in procs)
                             else "현재 사용자 세션")
                    messagebox.showinfo(label, "완료 — 데몬이 %s 에서 응답합니다 (PID %s).\n\n%s"
                                        % (where, ", ".join(str(p) for p, _s, _i in procs) or "?", out or ""))
                elif procs:
                    messagebox.showwarning(
                        label, "프로세스(PID %s)는 떴지만 90초 동안 127.0.0.1:%d 가 응답하지 않았습니다.\n"
                               "아직 기동 중일 수 있습니다 — 1~2분 뒤 「상태」 탭을 다시 보세요.\n"
                               "계속 응답이 없으면 포트·토큰이 저장된 값과 같은지 확인하세요.\n\n%s\n%s"
                        % (", ".join(str(p) for p, _s, _i in procs), port, out or "", tail))
                else:
                    messagebox.showerror(
                        label, "데몬이 올라오지 않았습니다.\n\n%s\n\n최근 로그:\n%s"
                        % (out or "", tail or "(오류 기록 없음 — 「로그」 탭을 확인하세요)"))

            self.after(0, finish)

        threading.Thread(target=wait, daemon=True, name="ui-verify").start()

    def _log_tail_errors(self, limit: int = 6) -> str:
        path = os.path.join(os.path.dirname(self.config_path), "agent.log")
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                f.seek(max(0, size - 64 * 1024))
                lines = f.read().decode("utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        picked = [ln for ln in lines if " ERROR " in ln or "[ERROR]" in ln or "시작하지 않습니다" in ln]
        crash = os.path.join(os.path.dirname(self.config_path), "agent-crash.log")
        try:
            if os.path.getmtime(crash) > time.time() - 600:
                with open(crash, encoding="utf-8", errors="replace") as f:
                    last = [ln for ln in f.read().splitlines() if ln.strip()]
                picked += ["(agent-crash.log) " + ln for ln in last[-3:]]
        except OSError:
            pass
        return "\n".join(picked[-limit:])

    # ---- 상태 폴링 ----
    def _port(self) -> int:
        return self._poll_port

    def _start_poller(self):
        folder = os.path.dirname(self.config_path)

        def loop():
            n = 0
            info = None
            while not self._poll_stop.is_set():
                ok, body = agent_get(self._poll_port, self._poll_token, "/health")
                procs = agent_processes()
                if n % 5 == 0:   # 작업 스케줄러 조회는 10초마다면 충분하다
                    info = autostart_info()
                snap = {"ok": ok, "body": body, "procs": procs, "info": info,
                        "stopped": stop_flag_active(folder)}
                n += 1
                try:
                    self.after(0, lambda sn=snap: self._render_status(sn))
                except (RuntimeError, tk.TclError):
                    return
                self._poll_stop.wait(POLL_SECONDS)

        threading.Thread(target=loop, daemon=True, name="ui-poller").start()

    def _render_status(self, snap: dict):
        if self._busy:
            return
        ok, body, procs, info = snap["ok"], snap["body"], snap["procs"], snap["info"]
        exe = find_agent_exe(self.config_path)
        if info is None:
            self.autostart_state.set("확인 불가")
        elif not info:
            self.autostart_state.set("꺼짐 — PC 를 다시 켜면 데몬이 안 뜹니다")
        elif exe and os.path.normcase(info.get("command", "")) != os.path.normcase(exe):
            self.autostart_state.set("다른 폴더에서 운영 중 — 여기서 [끄기]·[중지] 금지 (옮기려면 [켜기])")
        elif not info.get("watchdog") or "--from-task" not in info.get("arguments", ""):
            self.autostart_state.set("켜짐 (옛 등록 — [켜기] 를 한 번 더 누르면 5분 감시가 추가됨)")
        else:
            self.autostart_state.set("켜짐 — 부팅·로그인 때, 꺼져 있으면 5분마다")

        pids = [pid for pid, _s, _i in procs]
        bg = any(sess == 0 for _p, sess, _i in procs)
        pidtxt = ("PID %s" % ", ".join(map(str, pids))) if pids else "프로세스 없음"
        runas = ("백그라운드 (SYSTEM 작업 — 로그오프해도 계속)" if bg
                 else ("현재 사용자 세션 — 로그오프하면 멈춤" if pids else "—"))
        self.status_vals["runas"].set(runas)
        if not ok:
            self._health_body = {}
            if pids:
                self.lbl_state.configure(text="응답 없음", fg=STATE_WARN)
                self.lbl_detail.configure(
                    text="프로세스는 떠 있으나(%s) 127.0.0.1:%d 가 응답하지 않습니다 (%s) — "
                         "시작 중이거나 포트·토큰이 다릅니다." % (pidtxt, self._poll_port, body))
            elif snap.get("stopped"):
                self.lbl_state.configure(text="중지됨", fg=STATE_WARN)
                self.lbl_detail.configure(text="[중지] 로 멈춘 상태입니다. [시작] 을 누르거나 PC 를 '다시 시작'하면 돕니다 "
                                               "(빠른 시작 PC 는 [종료] 후 켜도 멈춘 상태).")
            else:
                self.lbl_state.configure(text="데몬 정지됨", fg=STATE_BAD)
                self.lbl_detail.configure(
                    text=("실행 중인 데몬이 없습니다. 자동 실행이 켜져 있으면 5분 안에 다시 뜹니다 — "
                          "계속 꺼지면 「로그」 탭을 확인하세요.") if info else "실행 중인 데몬이 없습니다.")
            for key, v in self.status_vals.items():
                if key != "runas":
                    v.set("—")
            if info and exe and os.path.normcase(info.get("command", "")) != os.path.normcase(exe):
                self.lbl_detail.configure(text="자동 실행은 다른 폴더(%s)에 등록돼 있습니다. 이 폴더가 옛 설치라면 "
                                               "버튼을 쓰지 말고 파일만 지우세요." % info.get("command"))
            self._update_ram_hint()
            return
        self._health_body = body if isinstance(body, dict) else {}
        self.lbl_state.configure(text="데몬 실행 중", fg=STATE_OK)
        self.lbl_detail.configure(text="%s · 127.0.0.1:%d 응답 정상" % (pidtxt, self._poll_port))
        dirs = body.get("watch_dirs") or []
        if isinstance(dirs, list):
            shown = ", ".join(str(d.get("dir") if isinstance(d, dict) else d) for d in dirs) or \
                "— (백엔드가 아직 감시 폴더를 내려주지 않았습니다)"
        else:
            shown = str(dirs)
        self.status_vals["version"].set(str(body.get("version", "—")))
        try:
            st = float(body.get("started_at") or 0)
            bt = float(body.get("boot_at") or 0)
            if st:
                txt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st))
                if bt:
                    txt += "  (PC 부팅 %s, 부팅 후 %d분)" % (
                        time.strftime("%m-%d %H:%M", time.localtime(bt)), max(0, int((st - bt) // 60)))
                self.status_vals["started"].set(txt)
        except (TypeError, ValueError):
            pass
        um = int(body.get("unmatched", 0) or 0)
        self.status_vals["unmatched"].set(
            "0" if um == 0 else "{:,}   ← 캔버스 노드 Token·WatchDir·엣지 활성화를 확인하세요".format(um))
        uw = body.get("unwatched_dirs") or []
        self.status_vals["unwatched"].set(
            "없음" if not uw else ", ".join(map(str, uw)) + "   ← SYSTEM 이 볼 수 없는 경로(매핑 드라이브 등)")
        self.status_vals["mode"].set(str(self.cfg.get("mode", "—")))
        self.status_vals["watch"].set(shown)
        self.status_vals["ledger"].set("{:,}".format(int(body.get("ledger_size", 0) or 0)))
        pending = int(body.get("pending_acks", 0) or 0)
        self.status_vals["pending"].set(
            "{:,}".format(pending) + ("" if pending == 0 else "   ← 아직 적재 확인 안 된 파일"))
        self.status_vals["ackmode"].set("켜짐" if body.get("ack_mode") else "꺼짐")
        self.status_vals["lastseq"].set("{:,}".format(int(body.get("last_seq", 0) or 0)))
        self._update_ram_hint()

    def _update_ram_hint(self):
        try:
            keep = int(float(str(self.vars.get("ledger_keep_in_memory", tk.StringVar(value="0")).get())))
        except (ValueError, TypeError):
            keep = 0
        gb = keep * 350 / (1024 ** 3)
        self.ram_hint.set(
            "원장 보관 상한 {:,} 건 → 약 {:.2f} GB (항목당 약 350B, 한글 경로 기준).\n"
            "이 값은 '메모리에 들고 있을 최대 건수'입니다. 실제 사용량은 현재 보관 건수에 비례하며, "
            "원장 자동 축소를 켜 두면 디스크에 남아 있는 파일 수까지만 유지됩니다.".format(keep, gb))

    def _refresh_log(self):
        path = os.path.join(os.path.dirname(self.config_path), "agent.log")
        text = ""
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                if size > LOG_TAIL_BYTES:
                    f.seek(size - LOG_TAIL_BYTES)
                    f.readline()
                text = f.read().decode("utf-8", errors="replace")
        except OSError as e:
            text = "로그를 읽을 수 없습니다: %s" % e
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _on_close(self):
        self._poll_stop.set()
        self.destroy()


def main() -> int:
    here = os.path.dirname(os.path.abspath(sys.argv[0]))
    ap = argparse.ArgumentParser(description="file-agent 데몬 컨트롤 UI")
    ap.add_argument("--config", default=os.path.join(here, "config.json"),
                    help="config.json 경로 (기본: 실행 파일과 같은 폴더)")
    args = ap.parse_args()
    if not os.path.exists(args.config):
        template = os.path.join(os.path.dirname(os.path.abspath(args.config)), CONFIG_TEMPLATE_NAME)
        try:
            shutil.copyfile(template, args.config)
        except OSError as e:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("설정 없음", "config.json 도, 템플릿(%s)도 쓸 수 없습니다:\n%s\n\n%s"
                                 % (CONFIG_TEMPLATE_NAME, args.config, e))
            return 2
        secure_config_files(args.config)
    AgentUI(args.config).mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
