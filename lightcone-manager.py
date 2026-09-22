#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lightcone Manager - GUI Console for Lightcone Tunnel
"""

import os
import sys
import re
import socket
import asyncio
import subprocess
import signal
import uuid
import random
import logging
import yaml
import atexit
import importlib.util
from collections import deque
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from nicegui import ui, app

# ============================================================================
# Global constants
# ============================================================================
MANAGER_VERSION = "1.1.0"
MAX_LOG_LINES = 2000
LOG_SYNC_INTERVAL = 0.25
PORT_FALLBACK_MIN = 32768
PORT_FALLBACK_MAX = 65535
PORT_FALLBACK_ATTEMPTS = 30

logger = logging.getLogger("lightcone-manager")


# ============================================================================
# PyInstaller worker dispatch
# ============================================================================
# When frozen, the manager binary is re-invoked with --worker <config>; we
# load the tunnel module from the bundle and call its main() function. When
# running from source, the manager spawns `python lightcone-tunnel.py <cfg>`
# normally and this branch is never taken.
if "--worker" in sys.argv:
    search_dirs = [os.path.dirname(os.path.abspath(sys.argv[0]))]
    if hasattr(sys, '_MEIPASS'):
        search_dirs.insert(0, sys._MEIPASS)

    target_script = None
    for directory in search_dirs:
        for filename in ["lightcone-tunnel.py", "lightcone_tunnel.py"]:
            candidate = os.path.join(directory, filename)
            if os.path.exists(candidate):
                target_script = candidate
                break
        if target_script:
            break

    if not target_script:
        print(f"Error: lightcone-tunnel.py not found in: {search_dirs}")
        sys.exit(1)

    try:
        spec = importlib.util.spec_from_file_location("lightcone_tunnel", target_script)
        lightcone_tunnel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lightcone_tunnel)

        worker_idx = sys.argv.index("--worker")
        if worker_idx + 1 < len(sys.argv):
            config_path = sys.argv[worker_idx + 1]
            sys.argv = [sys.argv[0], config_path]
            lightcone_tunnel.main()
        sys.exit(0)
    except Exception as e:
        print(f"Error executing worker module: {e}")
        sys.exit(1)


# ============================================================================
# Paths & settings
# ============================================================================
def get_base_dir() -> Path:
    """Retrieve absolute path to application binary or script directory."""
    if getattr(sys, 'frozen', False):
        return Path(os.path.dirname(sys.executable))
    return Path(__file__).parent.resolve()


BASE_DIR = get_base_dir()
LOCK_FILE = BASE_DIR / "manager.lock"
SETTINGS_FILE = BASE_DIR / "manager_settings.yaml"
CONFIGS_DIR = BASE_DIR / "configs"


def acquire_instance_lock():
    """Ensure single instance execution across platforms."""
    try:
        if sys.platform == "win32":
            import msvcrt
            lock_handle = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR)
            msvcrt.locking(lock_handle, msvcrt.LK_NBLCK, 1)
            return lock_handle
        else:
            import fcntl
            lock_handle = open(LOCK_FILE, "w")
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock_handle
    except Exception:
        print("Error: Another instance of Lightcone Manager is already running.")
        sys.exit(1)


def release_instance_lock():
    """Release instance file lock and explicitly purge lockfile."""
    global lock_handle
    if lock_handle is not None:
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(lock_handle, msvcrt.LK_UNLCK, 1)
                os.close(lock_handle)
            else:
                import fcntl
                fcntl.flock(lock_handle, fcntl.LOCK_UN)
                lock_handle.close()
        except Exception:
            pass
        finally:
            lock_handle = None

    if LOCK_FILE.exists():
        try:
            LOCK_FILE.unlink()
        except Exception:
            pass


lock_handle = acquire_instance_lock()
atexit.register(release_instance_lock)


DEFAULT_SETTINGS = {
    "gui_host": "127.0.0.1",
    "gui_port": 8000,
    "auto_start_enabled": False,
    "default_config": "",
    "language": "zh-CN",
}


def load_settings() -> Dict[str, Any]:
    """Load settings from YAML file or initialize defaults."""
    if not SETTINGS_FILE.exists():
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            merged = DEFAULT_SETTINGS.copy()
            merged.update(data)
            return merged
    except Exception:
        return DEFAULT_SETTINGS.copy()


def save_settings(settings: Dict[str, Any]) -> None:
    """Save current settings dictionary to local YAML file."""
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(settings, f, allow_unicode=True)
    except Exception as e:
        logger.warning(f"Failed to save settings: {e}")


def get_tunnel_script_path() -> Optional[Path]:
    """Locate lightcone-tunnel.py relative to base execution directory or PyInstaller bundle."""
    search_dirs = [BASE_DIR]
    if hasattr(sys, '_MEIPASS'):
        search_dirs.insert(0, Path(sys._MEIPASS))

    for directory in search_dirs:
        for fname in ["lightcone-tunnel.py", "lightcone_tunnel.py"]:
            candidate = directory / fname
            if candidate.exists():
                return candidate
    return None


# ============================================================================
# Port selection with random fallback
# ============================================================================
def is_port_available(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is available for binding."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.bind((host, port))
            return True
    except OSError:
        return False


def pick_gui_port(preferred: int, host: str) -> int:
    """
    Return `preferred` if it is free, otherwise randomly pick an available
    port in [PORT_FALLBACK_MIN, PORT_FALLBACK_MAX]. Raises RuntimeError if no
    free port can be found within PORT_FALLBACK_ATTEMPTS tries.
    """
    if is_port_available(preferred, host):
        return preferred

    logger.warning(
        f"Preferred GUI port {preferred} on {host} is in use; "
        f"selecting a random fallback in [{PORT_FALLBACK_MIN}, {PORT_FALLBACK_MAX}]"
    )
    for _ in range(PORT_FALLBACK_ATTEMPTS):
        candidate = random.randint(PORT_FALLBACK_MIN, PORT_FALLBACK_MAX)
        if is_port_available(candidate, host):
            logger.info(f"Fallback GUI port selected: {candidate}")
            return candidate

    raise RuntimeError(
        f"Could not find a free GUI port after {PORT_FALLBACK_ATTEMPTS} attempts. "
        f"Free up port {preferred} or a port in the fallback range."
    )


# ============================================================================
# Global background task registry
# ============================================================================
# Retain strong references to fire-and-forget asyncio tasks. Without this the
# task may be garbage-collected before it completes (documented CPython
# behavior for asyncio.create_task).
_bg_tasks: Set[asyncio.Task] = set()


def spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return task


# ============================================================================
# Log broadcaster
# ============================================================================
class LogBroadcaster:
    """
    Shared log ring buffer with per-client cursors.

    The previous implementation used a single global `ui.log` object which
    meant only the most-recently-loaded browser tab received log lines and
    older tabs silently stopped updating. This class keeps one authoritative
    buffer and lets each client pull new lines on a timer.
    """

    def __init__(self, max_lines: int = MAX_LOG_LINES):
        self.buffer: deque = deque(maxlen=max_lines)
        self.counter: int = 0
        self.max_lines = max_lines

    def push(self, line: str) -> None:
        self.buffer.append(line)
        self.counter += 1

    def get_since(self, since: int) -> Tuple[int, List[str], bool]:
        """
        Return (new_counter, lines, must_resync).

        `since` is the counter value the client last observed. If the buffer
        has been trimmed or cleared past `since`, `must_resync` is True and
        the client should clear its view before appending `lines`.
        """
        if since > self.counter:
            # Buffer was reset (counter rolled back).
            return self.counter, list(self.buffer), True
        first_id = self.counter - len(self.buffer)
        if since < first_id:
            # Client fell behind the trim window.
            return self.counter, list(self.buffer), True
        offset = since - first_id
        return self.counter, list(self.buffer)[offset:], False

    def clear(self) -> None:
        self.buffer.clear()
        self.counter = 0


broadcaster = LogBroadcaster()


# ============================================================================
# Tunnel state manager
# ============================================================================
class TunnelStateManager:
    """Encapsulates process lifecycle and reactive UI language state."""

    def __init__(self, initial_lang: str = "zh-CN"):
        self._lock = asyncio.Lock()
        self.is_running: bool = False
        self.active_config: str = ""
        self.process: Optional[asyncio.subprocess.Process] = None
        self.log_task: Optional[asyncio.Task] = None
        self.lang: str = initial_lang

    async def get_state_snapshot(self) -> Tuple[bool, str]:
        async with self._lock:
            return self.is_running, self.active_config

    async def select_config(self, cfg_name: str) -> bool:
        async with self._lock:
            if self.is_running:
                return False
            self.active_config = cfg_name
            return True

    async def start(self, process: asyncio.subprocess.Process, cfg_name: str,
                    task: asyncio.Task) -> None:
        async with self._lock:
            self.process = process
            self.is_running = True
            self.active_config = cfg_name
            self.log_task = task

    async def stop(self) -> None:
        """
        Stop the running tunnel process and cancel its log task. Waits for
        both to fully settle so we don't leave zombie processes or dangling
        tasks behind.
        """
        # Grab references under the lock, then act outside of it.
        async with self._lock:
            if not self.is_running and self.process is None:
                self.is_running = False
                self.active_config = self.active_config
                return
            proc = self.process
            log_task = self.log_task
            self.process = None
            self.log_task = None
            self.is_running = False

        if proc is not None:
            try:
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=3.0)
                    except asyncio.TimeoutError:
                        logger.warning("Tunnel did not exit within 3s; killing it.")
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=2.0)
                        except asyncio.TimeoutError:
                            logger.error("Tunnel failed to die after kill(); leaving zombie.")
            except ProcessLookupError:
                pass
            except Exception as e:
                logger.warning(f"Error terminating tunnel process: {e}")

        if log_task is not None and not log_task.done():
            log_task.cancel()
            try:
                await log_task
            except (asyncio.CancelledError, Exception):
                pass


app_settings = load_settings()
state = TunnelStateManager(initial_lang=app_settings.get("language", "zh-CN"))


# ============================================================================
# i18n
# ============================================================================
I18N = {
    "en": {
        "title": "Lightcone Console",
        "configs": "Configurations",
        "logs": "Live System Logs",
        "settings": "Settings",
        "start": "Start Tunnel",
        "stop": "Stop Tunnel",
        "running": "Running",
        "stopped": "Stopped",
        "active": "Active",
        "switch_warn": "Tunnel is currently running. Please stop it before changing configuration.",
        "auto_start": "Auto-start tunnel on manager launch",
        "default_config": "Default Launch Config",
        "host": "Console Listen Host",
        "port": "Console Listen Port",
        "save": "Save Settings",
        "cancel": "Cancel",
        "delete": "Delete",
        "delete_config": "Delete Config",
        "delete_confirm": "Are you sure you want to delete configuration '{fname}'?",
        "restart_notice": "Host and Port changes require application restart.",
        "saved_toast": "Settings saved successfully.",
        "no_configs": "No configuration files found in ./configs",
        "refresh": "Refresh",
        "clear_logs": "Clear Logs",
        "status_label": "Status",
        "current_config": "Active Config",
        "add_config": "Add Config File",
        "config_name": "Configuration Name",
        "config_content": "YAML Configuration Content",
        "exit_app": "Exit Manager",
        "exit_confirm": "Are you sure you want to stop active processes and exit Lightcone Console?",
        "exiting_notice": "Shutting down services, please wait...",
        "invalid_filename": "Configuration name contains invalid characters.",
        "port_fallback": "Preferred port {p} was in use. Console is now listening on port {np}.",
    },
    "zh-CN": {
        "title": "Lightcone 控制台",
        "configs": "配置文件",
        "logs": "实时运行日志",
        "settings": "系统设置",
        "start": "启动隧道",
        "stop": "停止隧道",
        "running": "运行中",
        "stopped": "已停止",
        "active": "当前生效",
        "switch_warn": "隧道运行中，请先停止隧道再切换配置文件。",
        "auto_start": "开启程序时自动启动隧道",
        "default_config": "默认启动配置",
        "host": "控制台监听 IP",
        "port": "控制台监听端口",
        "save": "保存设置",
        "cancel": "取消",
        "delete": "删除",
        "delete_config": "删除配置文件",
        "delete_confirm": "确定要删除配置文件 '{fname}' 吗？",
        "restart_notice": "修改监听 IP 或端口需重启控制台后生效。",
        "saved_toast": "设置保存成功。",
        "no_configs": "未在 ./configs 目录找到配置文件。",
        "refresh": "刷新",
        "clear_logs": "清空日志",
        "status_label": "运行状态",
        "current_config": "当前配置",
        "add_config": "添加配置文件",
        "config_name": "配置文件名称",
        "config_content": "YAML 配置内容",
        "exit_app": "退出程序",
        "exit_confirm": "确定要停止运行并退出 Lightcone 控制台吗？",
        "exiting_notice": "正在停止服务并退出，请稍候...",
        "invalid_filename": "配置文件名称包含非法字符。",
        "port_fallback": "首选端口 {p} 已被占用，控制台已切换到端口 {np}。",
    },
    "zh-TW": {
        "title": "Lightcone 控制台",
        "configs": "設定檔列表",
        "logs": "即時運行日誌",
        "settings": "系統設定",
        "start": "啟動隧道",
        "stop": "停止隧道",
        "running": "運行中",
        "stopped": "已停止",
        "active": "當前生效",
        "switch_warn": "隧道運行中，請先停止隧道再切換設定檔。",
        "auto_start": "開啟程序時自動啟動隧道",
        "default_config": "預設啟動設定",
        "host": "控制台監聽 IP",
        "port": "控制台監聽埠",
        "save": "儲存設定",
        "cancel": "取消",
        "delete": "刪除",
        "delete_config": "刪除設定檔",
        "delete_confirm": "確定要刪除設定檔 '{fname}' 嗎？",
        "restart_notice": "修改監聽 IP 或埠需重啟控制台後生效。",
        "saved_toast": "設定儲存成功。",
        "no_configs": "未在 ./configs 目錄找到設定檔。",
        "refresh": "重新整理",
        "clear_logs": "清除日誌",
        "status_label": "運行狀態",
        "current_config": "當前設定",
        "add_config": "新增設定檔",
        "config_name": "設定檔名稱",
        "config_content": "YAML 設定內容",
        "exit_app": "退出程式",
        "exit_confirm": "確定要停止運行並退出 Lightcone 控制台嗎？",
        "exiting_notice": "正在停止服務並退出，請稍候...",
        "invalid_filename": "設定檔名稱包含非法字元。",
        "port_fallback": "首選埠 {p} 已被佔用，控制台已切換到埠 {np}。",
    },
}


def t(key: str) -> str:
    """Translate UI text key based on active language."""
    return I18N.get(state.lang, I18N["zh-CN"]).get(key, key)


def tf(key: str, **kwargs) -> str:
    """
    Translate and substitute placeholders. Uses str.replace instead of
    str.format so a missing placeholder in any translation cannot raise.
    """
    text = t(key)
    for k, v in kwargs.items():
        text = text.replace("{" + k + "}", str(v))
    return text


# ============================================================================
# Config helpers
# ============================================================================
def get_config_files() -> List[str]:
    """Retrieve list of configuration files without file extension."""
    if not CONFIGS_DIR.exists():
        CONFIGS_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(
        [f.stem for f in CONFIGS_DIR.glob("*.yaml")]
        + [f.stem for f in CONFIGS_DIR.glob("*.yml")]
    )
    return list(dict.fromkeys(files))


def validate_config_content(content: str) -> Tuple[bool, str]:
    """Return (ok, error_message). Checks YAML structure and required fields."""
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return False, f"Invalid YAML: {e}"
    if not isinstance(data, dict):
        return False, "Config root must be a mapping."
    if "role" not in data:
        return False, "Missing required field: role"
    if data["role"] not in ("client", "server"):
        return False, "Field 'role' must be 'client' or 'server'."
    if not data.get("psk"):
        return False, "Missing required field: psk"
    if "server_addr" not in data:
        return False, "Missing required field: server_addr"
    addr = str(data["server_addr"])
    if ":" not in addr:
        return False, "server_addr must be in 'host:port' form."
    host_part, port_part = addr.rsplit(":", 1)
    if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
        return False, f"Invalid port in server_addr: {port_part}"
    if not host_part:
        return False, "Missing host part in server_addr."
    return True, ""


available_configs = get_config_files()
if app_settings.get("default_config") in available_configs:
    state.active_config = app_settings["default_config"]
elif available_configs:
    state.active_config = available_configs[0]


# ============================================================================
# Tunnel lifecycle
# ============================================================================
async def select_config(cfg_name: str) -> None:
    """Handle configuration card click with validation against running state."""
    success = await state.select_config(cfg_name)
    if not success:
        ui.notify(t("switch_warn"), type="warning", position="top")
        return
    render_header.refresh()
    render_config_list.refresh()


async def start_tunnel() -> None:
    """Spawn the tunnel process and stream its output into the log buffer."""
    is_running, active_cfg = await state.get_state_snapshot()
    if is_running or not active_cfg:
        return

    config_path = CONFIGS_DIR / f"{active_cfg}.yaml"
    if not config_path.exists():
        config_path = CONFIGS_DIR / f"{active_cfg}.yml"
    if not config_path.exists():
        ui.notify(f"Config file for {active_cfg} not found!", type="negative")
        return

    if getattr(sys, 'frozen', False):
        cmd = [sys.executable, "--worker", str(config_path)]
    else:
        tunnel_script = get_tunnel_script_path()
        if tunnel_script is None:
            ui.notify("lightcone-tunnel.py not found!", type="negative")
            return
        cmd = [sys.executable, str(tunnel_script), str(config_path)]

    try:
        # asyncio subprocess gives us a native StreamReader on stdout, which
        # is fully cancellable. The previous thread-executor based reader
        # leaked threads because readline() cannot be interrupted.
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(BASE_DIR),
        )
    except Exception as e:
        ui.notify(f"Failed to start tunnel: {e}", type="negative")
        return

    log_task = spawn(read_tunnel_logs(proc))
    await state.start(proc, active_cfg, log_task)

    render_header.refresh()
    render_config_list.refresh()
    ui.notify(f"Tunnel started: [{active_cfg}]", type="positive")


async def stop_tunnel() -> None:
    """Stop the running tunnel process and wait for full teardown."""
    if not state.is_running and state.process is None:
        return
    await state.stop()
    render_header.refresh()
    render_config_list.refresh()
    ui.notify("Tunnel stopped", type="info")


async def read_tunnel_logs(proc: asyncio.subprocess.Process) -> None:
    """
    Stream the tunnel process's stdout into the shared log buffer until the
    process exits. asyncio's StreamReader.readline() is cancellable, which
    the previous thread-executor implementation was not.
    """
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip()
            if text:
                broadcaster.push(text)
    except asyncio.CancelledError:
        # Best-effort drain before propagating the cancellation.
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.2)
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    broadcaster.push(text)
        except (asyncio.TimeoutError, Exception):
            pass
        raise
    except Exception as e:
        broadcaster.push(f"[Manager] log reader error: {e}")
    finally:
        # Wait for exit code so we can log the reason for termination.
        try:
            returncode = await proc.wait()
            if returncode not in (0, None, -15, -9):
                broadcaster.push(f"[Manager] tunnel exited with code {returncode}")
        except Exception:
            pass

        # If this task ended because the process died on its own (not
        # because stop_tunnel() killed it), reflect that in the UI.
        if state.is_running and state.process is proc:
            await state.stop()
            render_header.refresh()
            render_config_list.refresh()


# ============================================================================
# Dialogs
# ============================================================================
DEFAULT_CONFIG_TEMPLATE = """# Lightcone Tunnel Client Configuration
role: "client"
server_addr: "127.0.0.1:8443"
psk: "YourStrongSecretPSKKeyHere"
socks_port: 1080
http_port: 8080
fec_data_shards: 12
fec_parity_shards: 4
max_concurrent_streams: 1024
log_level: "info"
"""


def open_add_config_dialog() -> None:
    """Render the dialog for adding a new YAML configuration file."""
    with ui.dialog() as dialog, ui.card().classes(
        "w-[500px] p-6 rounded-3xl bg-[#1d2026] text-gray-100 shadow-2xl border border-[#313745] gap-4"
    ):
        ui.label(t("add_config")).classes("text-xl font-bold tracking-tight text-[#a8c7fa] mb-1")

        name_input = ui.input(
            label=t("config_name"),
            placeholder="e.g. node_hk",
        ).classes("w-full").props("outlined dark rounded")

        content_input = ui.textarea(
            label=t("config_content"),
            value=DEFAULT_CONFIG_TEMPLATE,
        ).classes("w-full h-48 font-mono text-xs").props("outlined dark rounded")

        def save_file(target_path: Path, fname: str, raw_content: str, parent_dialog) -> None:
            ok, err = validate_config_content(raw_content)
            if not ok:
                ui.notify(err, type="negative")
                return
            try:
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(raw_content)
                ui.notify(f"Config '{fname}' saved.", type="positive")
                parent_dialog.close()
                render_config_list.refresh()
            except Exception as e:
                ui.notify(f"Failed to save file: {e}", type="negative")

        def create_file() -> None:
            fname = (name_input.value or "").strip()
            if not fname:
                ui.notify("Configuration name cannot be empty.", type="warning")
                return
            if re.search(r'[\/:*?"<>|]', fname):
                ui.notify(t("invalid_filename"), type="warning")
                return
            if not fname.endswith((".yaml", ".yml")):
                fname += ".yaml"
            target_path = CONFIGS_DIR / fname

            if target_path.exists():
                with ui.dialog() as confirm_dialog, ui.card().classes(
                    "p-5 gap-4 bg-[#1d2026] text-gray-100 border border-[#313745] rounded-3xl"
                ):
                    ui.label(f"File '{fname}' already exists. Overwrite?").classes(
                        "text-base font-medium text-gray-200"
                    )
                    with ui.row().classes("w-full justify-end gap-2"):
                        ui.button(t("cancel"), on_click=confirm_dialog.close).props("flat color=grey")

                        def do_overwrite():
                            confirm_dialog.close()
                            save_file(target_path, fname, content_input.value or "", dialog)

                        ui.button("Overwrite", on_click=do_overwrite).classes(
                            "bg-[#f2b8b5] text-[#601410] font-bold rounded-full px-4 py-1"
                        )
                confirm_dialog.open()
                return

            save_file(target_path, fname, content_input.value or "", dialog)

        with ui.row().classes("w-full justify-end gap-3 mt-2"):
            ui.button(t("cancel"), on_click=dialog.close).props("flat rounded color=grey")
            ui.button(t("save"), on_click=create_file).classes(
                "bg-[#a8c7fa] text-[#062e6f] font-medium rounded-full px-6 py-2"
            )

    dialog.open()


def open_delete_config_dialog(cfg_name: str) -> None:
    """Render a confirmation dialog to delete one or more config files."""
    if state.is_running:
        ui.notify(t("switch_warn"), type="warning")
        return

    with ui.dialog() as dialog, ui.card().classes(
        "w-[400px] p-6 rounded-3xl bg-[#1d2026] text-gray-100 shadow-2xl "
        "border border-[#313745] gap-4 text-center"
    ):
        ui.label(t("delete_config")).classes("text-xl font-bold text-[#f2b8b5] mb-1")
        ui.label(tf("delete_confirm", fname=cfg_name)).classes("text-sm text-gray-300")

        def confirm_delete() -> None:
            dialog.close()
            deleted_any = False
            target_files = [
                p for p in CONFIGS_DIR.iterdir()
                if p.is_file() and p.stem == cfg_name and p.suffix.lower() in (".yaml", ".yml")
            ]

            if not target_files:
                ui.notify(f"Config '{cfg_name}' not found on disk.", type="warning")
            else:
                for target_path in target_files:
                    try:
                        target_path.unlink()
                        deleted_any = True
                    except PermissionError:
                        ui.notify(
                            f"Config '{cfg_name}' is locked by another process. "
                            f"Please close any editor.",
                            type="negative",
                        )
                        return
                    except Exception as e:
                        ui.notify(f"Failed to delete config: {e}", type="negative")
                        return

            if deleted_any:
                ui.notify(f"Config '{cfg_name}' deleted.", type="positive")

            remaining = get_config_files()
            if state.active_config == cfg_name:
                state.active_config = remaining[0] if remaining else ""
            if app_settings.get("default_config") == cfg_name:
                app_settings["default_config"] = remaining[0] if remaining else ""
                save_settings(app_settings)

            render_header.refresh()
            render_config_list.refresh()

        with ui.row().classes("w-full justify-center gap-4 mt-2"):
            ui.button(t("cancel"), on_click=dialog.close).props("flat rounded color=grey")
            ui.button(t("delete"), on_click=confirm_delete).classes(
                "bg-[#f2b8b5] text-[#601410] font-bold rounded-full px-6 py-2"
            )

    dialog.open()


def open_exit_dialog() -> None:
    """Render a confirmation dialog to exit the application cleanly."""
    with ui.dialog() as dialog, ui.card().classes(
        "w-[400px] p-6 rounded-3xl bg-[#1d2026] text-gray-100 shadow-2xl "
        "border border-[#313745] gap-4 text-center"
    ):
        ui.label(t("exit_app")).classes("text-xl font-bold text-[#f2b8b5] mb-1")
        ui.label(t("exit_confirm")).classes("text-sm text-gray-300")

        async def confirm_exit() -> None:
            dialog.close()
            with ui.dialog() as loading_dialog, ui.card().classes(
                "p-6 rounded-3xl bg-[#1d2026] text-gray-100 border border-[#313745] text-center gap-2"
            ):
                ui.icon("hourglass_empty", size="2.5rem").classes(
                    "text-[#a8c7fa] mx-auto animate-spin"
                )
                ui.label(t("exit_app")).classes("text-lg font-bold text-center mt-2")
                ui.label(t("exiting_notice")).classes("text-sm text-gray-400 text-center")
            loading_dialog.open()

            # Give the browser a moment to render the loading dialog before
            # we block the loop on process teardown.
            await asyncio.sleep(0.3)

            try:
                await stop_tunnel()
            except Exception:
                pass

            release_instance_lock()

            # Graceful shutdown instead of os._exit(0): lets NiceGUI close
            # the websocket cleanly and lets atexit handlers run.
            try:
                app.shutdown()
            except Exception:
                pass

        with ui.row().classes("w-full justify-center gap-4 mt-2"):
            ui.button(t("cancel"), on_click=dialog.close).props("flat rounded color=grey")
            ui.button(t("exit_app"), on_click=confirm_exit).classes(
                "bg-[#f2b8b5] text-[#601410] font-bold rounded-full px-6 py-2"
            )

    dialog.open()


def open_settings_dialog() -> None:
    """Render the application settings dialog."""
    configs = get_config_files()
    cur_default = app_settings.get("default_config", state.active_config)
    selected_value = cur_default if cur_default in configs else (configs[0] if configs else None)

    with ui.dialog() as dialog, ui.card().classes(
        "w-[460px] p-6 rounded-3xl bg-[#1d2026] text-gray-100 shadow-2xl "
        "border border-[#313745] gap-4"
    ):
        ui.label(t("settings")).classes("text-xl font-bold tracking-tight text-[#a8c7fa] mb-1")

        host_input = ui.input(
            label=t("host"),
            value=app_settings.get("gui_host", "127.0.0.1"),
        ).classes("w-full").props("outlined dark rounded")

        port_input = ui.number(
            label=t("port"),
            value=app_settings.get("gui_port", 8000),
            format="%d",
        ).classes("w-full").props("outlined dark rounded")

        ui.label(t("restart_notice")).classes("text-xs text-amber-400 -mt-2 mb-2")

        auto_start_switch = ui.switch(
            t("auto_start"),
            value=app_settings.get("auto_start_enabled", False),
        ).classes("text-sm text-gray-200")

        default_config_select = ui.select(
            options=configs if configs else [],
            value=selected_value,
            label=t("default_config"),
        ).classes("w-full").props("outlined dark rounded")

        lang_select = ui.select(
            options={"zh-CN": "简体中文", "zh-TW": "繁體中文", "en": "English"},
            value=state.lang,
            label="Language / 语言",
        ).classes("w-full").props("outlined dark rounded")

        def save() -> None:
            app_settings["gui_host"] = str(host_input.value or "127.0.0.1").strip() or "127.0.0.1"
            try:
                app_settings["gui_port"] = int(port_input.value)
            except (TypeError, ValueError):
                app_settings["gui_port"] = 8000
            app_settings["auto_start_enabled"] = bool(auto_start_switch.value)
            app_settings["default_config"] = str(default_config_select.value) if default_config_select.value else ""
            state.lang = str(lang_select.value or "zh-CN")
            app_settings["language"] = state.lang

            save_settings(app_settings)
            dialog.close()
            ui.notify(t("saved_toast"), type="positive")

            render_header.refresh()
            render_config_list.refresh()

        with ui.row().classes("w-full justify-end gap-3 mt-4"):
            ui.button(t("cancel"), on_click=dialog.close).props("flat rounded color=grey")
            ui.button(t("save"), on_click=save).classes(
                "bg-[#a8c7fa] text-[#062e6f] font-medium rounded-full px-6 py-2"
            )

    dialog.open()


# ============================================================================
# Refreshable UI sections
# ============================================================================
@ui.refreshable
def render_header() -> None:
    """Render the Material You top navigation bar."""
    with ui.row().classes(
        "w-full bg-[#171c26] text-white px-6 py-4 rounded-3xl mb-6 "
        "border border-[#2b313e] items-center justify-between shadow-sm"
    ):
        with ui.row().classes("items-center gap-3"):
            ui.icon("hub").classes("text-3xl text-[#a8c7fa]")
            with ui.column().classes("gap-0"):
                ui.label(t("title")).classes("text-xl font-bold tracking-tight text-gray-100")
                ui.label(
                    f"{t('current_config')}: {state.active_config or 'N/A'}"
                ).classes("text-xs text-gray-400 font-mono")

        with ui.row().classes("items-center gap-3"):
            if state.is_running:
                with ui.row().classes(
                    "bg-[#81c995]/20 text-[#81c995] border border-[#81c995]/40 "
                    "rounded-full px-3.5 py-1.5 items-center gap-2"
                ):
                    ui.icon("sensors").classes("text-sm animate-pulse")
                    ui.label(t("running")).classes("font-semibold text-xs tracking-wide")
            else:
                with ui.row().classes(
                    "bg-[#f2b8b5]/20 text-[#f2b8b5] border border-[#f2b8b5]/40 "
                    "rounded-full px-3.5 py-1.5 items-center gap-2"
                ):
                    ui.icon("sensors_off").classes("text-sm")
                    ui.label(t("stopped")).classes("font-semibold text-xs tracking-wide")

            if state.is_running:
                ui.button(
                    t("stop"),
                    icon="power_settings_new",
                    on_click=stop_tunnel,
                ).classes(
                    "bg-[#f2b8b5] text-[#601410] font-semibold rounded-full "
                    "px-6 py-2 hover:bg-[#f9dada] transition-all"
                )
            else:
                ui.button(
                    t("start"),
                    icon="play_arrow",
                    on_click=start_tunnel,
                ).classes(
                    "bg-[#a8c7fa] text-[#062e6f] font-semibold rounded-full "
                    "px-6 py-2 hover:bg-[#bdcffc] transition-all"
                )

            ui.button(icon="settings", on_click=open_settings_dialog).props(
                "flat round text-color=white"
            ).classes("hover:bg-[#282f3d]").tooltip(t("settings"))
            ui.button(icon="logout", on_click=open_exit_dialog).props(
                "flat round text-color=red-4"
            ).classes("hover:bg-[#282f3d]").tooltip(t("exit_app"))


@ui.refreshable
def render_config_list() -> None:
    """Render the configuration card list."""
    configs = get_config_files()

    with ui.row().classes("w-full items-center justify-between mb-3 px-1"):
        ui.label(t("configs")).classes(
            "text-sm font-semibold tracking-wider text-gray-400 uppercase"
        )
        with ui.row().classes("items-center gap-1"):
            ui.button(icon="add", on_click=open_add_config_dialog).props(
                "flat round dense text-color=grey-4"
            ).tooltip(t("add_config"))
            ui.button(icon="refresh", on_click=render_config_list.refresh).props(
                "flat round dense text-color=grey-4"
            ).tooltip(t("refresh"))

    if not configs:
        ui.label(t("no_configs")).classes(
            "text-gray-400 text-sm italic p-4 bg-[#171c26] rounded-2xl "
            "border border-[#2b313e] w-full"
        )
        return

    with ui.column().classes("w-full gap-3"):
        for cfg in configs:
            is_active = (cfg == state.active_config)

            card_classes = (
                "w-full p-4 rounded-2xl transition-all duration-200 "
                "cursor-pointer flex items-center justify-between border "
            )
            if is_active:
                card_classes += "bg-[#252c3a] border-[#a8c7fa] shadow-md "
            else:
                card_classes += "bg-[#171c26] border-[#2b313e] hover:bg-[#202634] "

            if state.is_running and not is_active:
                card_classes += "opacity-50 cursor-not-allowed "

            with ui.card().classes(card_classes).on(
                "click", lambda _, c=cfg: spawn(select_config(c))
            ):
                with ui.row().classes("items-center gap-3"):
                    icon_name = "tune" if is_active else "description"
                    icon_color = "text-[#a8c7fa]" if is_active else "text-gray-400"
                    ui.icon(icon_name).classes(f"text-xl {icon_color}")
                    ui.label(cfg).classes("font-medium text-base text-gray-100")

                with ui.row().classes("items-center gap-2"):
                    if is_active:
                        ui.badge(t("active")).classes(
                            "bg-[#a8c7fa] text-[#062e6f] font-bold text-xs "
                            "px-3 py-1 rounded-full"
                        )

                    del_btn = ui.button(icon="delete").props(
                        "flat round dense text-color=grey-5"
                    ).classes("hover:text-red-400").tooltip(t("delete_config"))
                    if state.is_running:
                        del_btn.props("disabled")
                    else:
                        del_btn.on(
                            "click.stop",
                            lambda _, c=cfg: open_delete_config_dialog(c),
                        )


# ============================================================================
# Main page
# ============================================================================
@ui.page("/")
def main_page() -> None:
    """Main application layout page. Runs once per connected client."""

    ui.add_head_html("""
        <style>
            body {
                background-color: #0f131a;
                color: #e2e2e9;
                font-family: 'Roboto', -apple-system, BlinkMacSystemFont,
                             "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            }
            .q-field--outlined .q-field__control {
                border-radius: 12px !important;
            }
        </style>
    """)

    with ui.column().classes("w-full max-w-7xl mx-auto p-4 md:p-6 min-h-screen gap-0"):
        render_header()

        with ui.row().classes("w-full gap-6 items-start flex-col md:flex-row"):
            with ui.column().classes("w-full md:w-80 flex-shrink-0"):
                render_config_list()

            with ui.column().classes("w-full flex-1 gap-3"):
                with ui.row().classes("w-full items-center justify-between px-1"):
                    ui.label(t("logs")).classes(
                        "text-sm font-semibold tracking-wider text-gray-400 uppercase"
                    )

                    def clear_logs() -> None:
                        broadcaster.clear()
                        log_view.clear()

                    ui.button(icon="delete_sweep", on_click=clear_logs).props(
                        "flat dense text-color=grey-4"
                    ).classes("text-xs").tooltip(t("clear_logs"))

                with ui.card().classes(
                    "w-full p-3 bg-[#171c26] rounded-3xl border border-[#2b313e] shadow-sm"
                ):
                    log_view = ui.log(max_lines=MAX_LOG_LINES).classes(
                        "w-full h-[540px] bg-[#0c0e12] text-green-400 "
                        "font-mono text-xs p-4 rounded-2xl border border-[#202530]"
                    )

    # Per-client log cursor. The broadcaster's `counter` is a monotonic line
    # id; we pull new lines since the last observed id every sync tick.
    client_cursor = {"seen": broadcaster.counter}

    # Backfill any lines already in the buffer for this freshly loaded page.
    _, initial_lines, _ = broadcaster.get_since(0)
    for line in initial_lines:
        log_view.push(line)

    def sync_logs() -> None:
        counter, new_lines, must_resync = broadcaster.get_since(client_cursor["seen"])
        if must_resync:
            log_view.clear()
        for line in new_lines:
            log_view.push(line)
        client_cursor["seen"] = counter

    ui.timer(LOG_SYNC_INTERVAL, sync_logs)

    if app_settings.get("auto_start_enabled", False):
        # Delay slightly so the page finishes rendering before we spawn.
        ui.timer(0.5, start_tunnel, once=True)


# ============================================================================
# Entry point
# ============================================================================
def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    gui_host = app_settings.get("gui_host", "127.0.0.1")
    try:
        preferred_port = int(app_settings.get("gui_port", 8000))
    except (TypeError, ValueError):
        preferred_port = 8000

    try:
        gui_port = pick_gui_port(preferred_port, gui_host)
    except RuntimeError as e:
        logger.error(str(e))
        print(f"\n❌ Error: {e}\n")
        sys.exit(1)

    if gui_port != preferred_port:
        msg = tf("port_fallback", p=preferred_port, np=gui_port)
        logger.warning(msg)
        print(f"\n⚠  {msg}\n")
        broadcaster.push(f"[Manager] {msg}")

    ui.run(
        host=gui_host,
        port=gui_port,
        title="Lightcone Console",
        dark=True,
        reload=False,
        storage_secret=uuid.uuid4().hex,
        show=False,
    )


if __name__ == "__main__":
    main()
