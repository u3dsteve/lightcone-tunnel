#!/usr/bin/env python3
"""
Lightcone Tunnel GUI Manager v1.2.4 (i18n Exit Notice Fix)
Built with NiceGUI for Cross-Platform Desktop Management
"""

import asyncio
import importlib.util
import multiprocessing
import os
import re
import sys
from pathlib import Path
from typing import Dict, Any, Optional

import yaml

# ============================================================================
# PyInstaller Multi-processing Guard & Worker Entry Point
# ============================================================================
multiprocessing.freeze_support()

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
        print(f"Error: lightcone-tunnel.py core script not found in: {search_dirs}")
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

# ----------------------------------------------------------------------------
# Single Instance Lock
# ----------------------------------------------------------------------------
def acquire_single_instance_lock():
    lock_file = Path("/tmp/lightcone_manager.lock")
    try:
        fp = open(lock_file, "w")
        import fcntl
        fcntl.flock(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fp
    except (IOError, OSError):
        print("[Error] Another instance of Lightcone Manager is already running on this machine.")
        sys.exit(1)
    except ImportError:
        return None

_instance_lock = acquire_single_instance_lock()

from nicegui import ui, app

# ============================================================================
# i18n Dictionary Definition
# ============================================================================
I18N = {
    "en": {
        "title": "Lightcone Tunnel Manager",
        "configs": "Configurations",
        "add_config": "Add Config",
        "start": "Start Engine",
        "stop": "Stop Engine",
        "exit_app": "Exit App",
        "confirm_exit": "Are you sure you want to close the application?",
        "exit_notice": "Application closed. Please run again if needed.",
        "status_running": "RUNNING",
        "status_stopped": "STOPPED",
        "tab_config": "Configuration",
        "tab_logs": "Live Logs",
        "save": "Save Changes",
        "delete": "Delete",
        "cancel": "Cancel",
        "create": "Create",
        "role": "Node Role",
        "server_addr": "Server Address (Host:Port)",
        "psk": "Pre-Shared Key (PSK)",
        "socks_port": "Local SOCKS5 Port",
        "http_port": "Local HTTP Proxy Port",
        "fec_enable": "Enable RS-FEC Forward Error Correction",
        "fec_n": "FEC Data Shards (N)",
        "fec_m": "FEC Parity Shards (M)",
        "max_streams": "Max Concurrent Streams",
        "log_level": "Log Level",
        "clear_logs": "Clear Logs",
        "export_logs": "Export Logs",
        "dialog_name_placeholder": "Config Name (1-20 chars)",
        "err_max_configs": "Maximum 10 configurations allowed.",
        "err_name_len": "Name must be between 1 and 20 characters.",
        "err_invalid_chars": "Name contains invalid filename characters.",
        "err_name_exists": "Configuration name already exists.",
        "err_delete_running": "Cannot delete configuration while tunnel is running.",
        "msg_saved": "Configuration saved successfully.",
        "msg_deleted": "Configuration removed.",
        "confirm_delete": "Are you sure you want to delete this configuration?",
    },
    "zh-CN": {
        "title": "Lightcone Tunnel 控制台",
        "configs": "配置列表",
        "add_config": "新建配置",
        "start": "启动隧道",
        "stop": "停止隧道",
        "exit_app": "关闭程序",
        "confirm_exit": "确定要关闭程序吗？",
        "exit_notice": "程序已关闭，若需要请再次运行。",
        "status_running": "运行中",
        "status_stopped": "已停止",
        "tab_config": "配置参数",
        "tab_logs": "实时日志",
        "save": "保存配置",
        "delete": "删除配置",
        "cancel": "取消",
        "create": "创建",
        "role": "运行角色",
        "server_addr": "服务器地址 (IP/域名:端口)",
        "psk": "预共享密钥 (PSK)",
        "socks_port": "本地 SOCKS5 端口",
        "http_port": "本地 HTTP 代理端口",
        "fec_enable": "启用 RS-FEC 前向纠错保护",
        "fec_n": "FEC 数据分片 (N)",
        "fec_m": "FEC 校验分片 (M)",
        "max_streams": "最大并发流数",
        "log_level": "日志级别",
        "clear_logs": "清空日志",
        "export_logs": "导出日志",
        "dialog_name_placeholder": "配置名称 (1-20 字符)",
        "err_max_configs": "最多只能创建 10 个配置。",
        "err_name_len": "配置名称须为 1-20 个字符。",
        "err_invalid_chars": "配置名称不能包含非法路径字符 (\\ / : * ? \" < > |)。",
        "err_name_exists": "配置名称已存在。",
        "err_delete_running": "无法删除正在运行中的隧道配置，请先停止服务。",
        "msg_saved": "配置保存成功。",
        "msg_deleted": "配置已删除。",
        "confirm_delete": "确定要删除此配置吗？",
    },
    "zh-TW": {
        "title": "Lightcone Tunnel 控制台",
        "configs": "設定列表",
        "add_config": "新建設定",
        "start": "啟動隧道",
        "stop": "停止隧道",
        "exit_app": "關閉程式",
        "confirm_exit": "確定要關閉程式嗎？",
        "exit_notice": "程式已關閉，若需要請再次運行。",
        "status_running": "運行中",
        "status_stopped": "已停止",
        "tab_config": "設定參數",
        "tab_logs": "實時日誌",
        "save": "儲存設定",
        "delete": "刪除設定",
        "cancel": "取消",
        "create": "建立",
        "role": "運行角色",
        "server_addr": "伺服器地址 (IP/域名:通訊埠)",
        "psk": "預共享金鑰 (PSK)",
        "socks_port": "本地 SOCKS5 通訊埠",
        "http_port": "本地 HTTP 代理通訊埠",
        "fec_enable": "啟用 RS-FEC 前向糾錯保護",
        "fec_n": "FEC 資料分片 (N)",
        "fec_m": "FEC 校驗分片 (M)",
        "max_streams": "最大並發流數",
        "log_level": "日誌級別",
        "clear_logs": "清除日誌",
        "export_logs": "匯出日誌",
        "dialog_name_placeholder": "設定名稱 (1-20 字元)",
        "err_max_configs": "最多只能建立 10 個設定。",
        "err_name_len": "設定名稱須為 1-20 個字元。",
        "err_invalid_chars": "設定名稱不能包含非法路徑字元 (\\ / : * ? \" < > |)。",
        "err_name_exists": "設定名稱已存在。",
        "err_delete_running": "無法刪除正在運行中的隧道設定，請先停止服務。",
        "msg_saved": "設定儲存成功。",
        "msg_deleted": "設定已刪除。",
        "confirm_delete": "確定要刪除此設定嗎？",
    }
}

DEFAULT_CLIENT_CONFIG = {
    "role": "client",
    "server_addr": "127.0.0.1:8443",
    "psk": "YourStrongSecretPSKKeyHere",
    "socks_port": 1080,
    "http_port": 8080,
    "fec_data_shards": 12,
    "fec_parity_shards": 4,
    "max_concurrent_streams": 1024,
    "log_level": "info",
}

MAX_LOG_LINES = 2000
CONFIG_DIR = Path("configs")


# ============================================================================
# Tunnel Manager Core State & Lifecycle
# ============================================================================
class TunnelAppState:
    def __init__(self):
        self.lang = "en"
        self.active_config_name: Optional[str] = None
        self.configs: Dict[str, Dict[str, Any]] = {}
        self.process: Optional[asyncio.subprocess.Process] = None
        self.log_widget: Optional[ui.log] = None
        self.log_buffer = []
        self.load_configs()

    def t(self, key: str) -> str:
        return I18N.get(self.lang, I18N["en"]).get(key, key)

    def load_configs(self):
        CONFIG_DIR.mkdir(exist_ok=True)
        self.configs.clear()
        for p in CONFIG_DIR.glob("*.yaml"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    self.configs[p.stem] = data
            except Exception as e:
                print(f"Error loading {p}: {e}")

        if not self.configs:
            self.configs["default_client"] = DEFAULT_CLIENT_CONFIG.copy()
            self.save_config_file("default_client", DEFAULT_CLIENT_CONFIG)

        if not self.active_config_name or self.active_config_name not in self.configs:
            self.active_config_name = next(iter(self.configs.keys()))

    def save_config_file(self, name: str, data: Dict[str, Any]):
        CONFIG_DIR.mkdir(exist_ok=True)
        file_path = CONFIG_DIR / f"{name}.yaml"
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def delete_config_file(self, name: str):
        file_path = CONFIG_DIR / f"{name}.yaml"
        if file_path.exists():
            file_path.unlink()

    def append_log(self, text: str):
        self.log_buffer.append(text)
        if len(self.log_buffer) > MAX_LOG_LINES:
            self.log_buffer.pop(0)
        if self.log_widget:
            self.log_widget.push(text)

    @property
    def is_running(self) -> bool:
        return self.process is not None and self.process.returncode is None


state = TunnelAppState()


# ============================================================================
# Subprocess Management
# ============================================================================
async def start_tunnel_engine():
    if state.is_running or not state.active_config_name:
        return

    config_path = str((CONFIG_DIR / f"{state.active_config_name}.yaml").resolve())

    if getattr(sys, 'frozen', False):
        cmd = [sys.executable, "--worker", config_path]
    else:
        script_dir = Path(__file__).parent
        tunnel_script = script_dir / "lightcone-tunnel.py"
        if not tunnel_script.exists():
            tunnel_script = script_dir / "lightcone_tunnel.py"
        cmd = [sys.executable, "-u", str(tunnel_script), config_path]

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    try:
        state.process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env
        )
        state.append_log(f"[Manager] Engine started with config: '{state.active_config_name}'")
        ui.update()

        asyncio.create_task(read_process_output())
    except Exception as e:
        error_msg = str(e)
        if "Address already in use" in error_msg or "cannot bind" in error_msg or "Errno 98" in error_msg:
            state.append_log("[Manager] Port already in use. Please check local/remote binding conflict.")
        elif "Permission denied" in error_msg or "Errno 13" in error_msg:
            state.append_log("[Manager] Permission denied. Try running with elevated privileges.")
        else:
            state.append_log(f"[Manager Exception] Failed to start process: {e}")
        state.process = None
        ui.update()


async def read_process_output():
    proc = state.process
    if not proc or not proc.stdout:
        return

    while proc.returncode is None:
        line = await proc.stdout.readline()
        if not line:
            break
        text = line.decode('utf-8', errors='ignore').rstrip()
        if text:
            state.append_log(text)

    await proc.wait()
    state.append_log(f"[Manager] Engine stopped with exit code: {proc.returncode}")
    if state.process == proc:
        state.process = None
    ui.update()


async def stop_tunnel_engine():
    if not state.is_running or not state.process:
        return

    state.append_log("[Manager] Terminating engine...")
    try:
        state.process.terminate()
        await asyncio.wait_for(state.process.wait(), timeout=3.0)
    except asyncio.TimeoutError:
        state.process.kill()
        state.append_log("[Manager] Engine force killed.")
    except Exception as e:
        state.append_log(f"[Manager Error] Stop error: {e}")
    finally:
        state.process = None
        ui.update()


async def exit_application():
    await stop_tunnel_engine()
    notice = state.t("exit_notice")
    ui.run_javascript(f'''
        document.body.style.backgroundColor = "white";
        document.body.innerHTML = "<div style='display: flex; justify-content: center; align-items: center; height: 100vh; font-size: 20px; color: #333; font-family: sans-serif; font-weight: bold;'>{notice}</div>";
    ''')
    await asyncio.sleep(0.5)
    os._exit(0)


# ============================================================================
# Dynamic Refreshable UI Components
# ============================================================================
@ui.refreshable
def render_config_list():
    for cfg_name in list(state.configs.keys()):
        is_active = (cfg_name == state.active_config_name)
        
        with ui.row().classes(f'w-full items-center justify-between p-2 rounded cursor-pointer transition-colors {"bg-blue-50 dark:bg-slate-800" if is_active else "hover:bg-slate-200 dark:hover:bg-slate-800"}'):
            ui.label(cfg_name).classes('font-medium text-sm truncate max-w-[140px]') \
                .on('click', lambda _, name=cfg_name: select_config(name))
            
            with ui.row().classes('items-center gap-1'):
                if len(state.configs) > 1:
                    ui.button(icon='delete', on_click=lambda _, name=cfg_name: confirm_delete_config(name)) \
                        .props('flat round dense size=sm color=negative')


@ui.refreshable
def render_config_form():
    cfg = state.configs.get(state.active_config_name, DEFAULT_CLIENT_CONFIG.copy())

    ui.label().bind_text_from(state, 'active_config_name', lambda n: f"Config: {n}").classes('text-xl font-bold mb-2')

    with ui.grid(columns=2).classes('w-full gap-4'):
        role_select = ui.select(
            options=["client", "server"],
            value=cfg.get("role", "client"),
            label=state.t("role")
        ).classes('w-full').props('outlined')

        server_addr_input = ui.input(
            label=state.t("server_addr"),
            value=cfg.get("server_addr", "127.0.0.1:8443")
        ).classes('w-full').props('outlined')

        psk_input = ui.input(
            label=state.t("psk"),
            value=cfg.get("psk", ""),
            password=True,
            password_toggle_button=True
        ).classes('w-full').props('outlined')

        socks_port_input = ui.number(
            label=state.t("socks_port"),
            value=cfg.get("socks_port", 1080),
            format='%d'
        ).classes('w-full').props('outlined')

        http_port_input = ui.number(
            label=state.t("http_port"),
            value=cfg.get("http_port", 8080),
            format='%d'
        ).classes('w-full').props('outlined')

        fec_enabled_init = cfg.get("fec_data_shards", 0) > 0 and cfg.get("fec_parity_shards", 0) > 0
        fec_switch = ui.switch(
            text=state.t("fec_enable"),
            value=fec_enabled_init
        ).classes('col-span-2 font-medium')

        fec_n_input = ui.number(
            label=state.t("fec_n"),
            value=cfg.get("fec_data_shards", 12) if fec_enabled_init else 12,
            format='%d'
        ).classes('w-full').props('outlined')

        fec_m_input = ui.number(
            label=state.t("fec_m"),
            value=cfg.get("fec_parity_shards", 4) if fec_enabled_init else 4,
            format='%d'
        ).classes('w-full').props('outlined')

        max_streams_input = ui.number(
            label=state.t("max_streams"),
            value=cfg.get("max_concurrent_streams", 1024),
            format='%d'
        ).classes('w-full').props('outlined')

        log_level_select = ui.select(
            options=["debug", "info", "warning", "error"],
            value=cfg.get("log_level", "info"),
            label=state.t("log_level")
        ).classes('w-full').props('outlined')

    def handle_role_change(e):
        is_client = (e.value == "client")
        socks_port_input.set_visibility(is_client)
        http_port_input.set_visibility(is_client)

    def handle_fec_toggle(e):
        fec_n_input.set_visibility(e.value)
        fec_m_input.set_visibility(e.value)

    role_select.on_value_change(handle_role_change)
    handle_role_change(type('Ev', (), {'value': role_select.value}))

    fec_switch.on_value_change(handle_fec_toggle)
    handle_fec_toggle(type('Ev', (), {'value': fec_switch.value}))

    def save_action():
        updated_cfg = {
            "role": role_select.value,
            "server_addr": server_addr_input.value,
            "psk": psk_input.value,
            "fec_data_shards": int(fec_n_input.value or 0) if fec_switch.value else 0,
            "fec_parity_shards": int(fec_m_input.value or 0) if fec_switch.value else 0,
            "max_concurrent_streams": int(max_streams_input.value or 1024),
            "log_level": log_level_select.value,
        }
        if role_select.value == "client":
            updated_cfg["socks_port"] = int(socks_port_input.value or 1080)
            updated_cfg["http_port"] = int(http_port_input.value or 8080)

        state.configs[state.active_config_name] = updated_cfg
        state.save_config_file(state.active_config_name, updated_cfg)
        ui.notify(state.t("msg_saved"), type='positive')

    ui.button(icon='save', on_click=save_action) \
        .bind_text_from(state, 'lang', lambda _: state.t('save')) \
        .props('color=primary unelevated').classes('mt-4')


# ============================================================================
# GUI Layout & Actions
# ============================================================================
@ui.page('/')
def main_page():
    ui.colors(primary='#2563EB', secondary='#475569', accent='#10B981')

    # Header
    with ui.header().classes('items-center justify-between bg-slate-800 text-white px-6 py-3'):
        with ui.row().classes('items-center gap-3'):
            ui.icon('lan', size='md').classes('text-blue-400')
            ui.label().bind_text_from(state, 'lang', lambda _: state.t("title")).classes('text-lg font-bold')

            with ui.badge().bind_visibility_from(state, 'is_running').classes('bg-emerald-500 text-white px-2 py-1'):
                ui.label().bind_text_from(state, 'lang', lambda _: f"● {state.t('status_running')}")
            with ui.badge().bind_visibility_from(state, 'is_running', backward=lambda r: not r).classes('bg-rose-500 text-white px-2 py-1'):
                ui.label().bind_text_from(state, 'lang', lambda _: f"○ {state.t('status_stopped')}")

        with ui.row().classes('items-center gap-4'):
            def on_lang_change(e):
                state.lang = e.value
                render_config_list.refresh()
                render_config_form.refresh()

            ui.select(
                options={"en": "English", "zh-CN": "简体中文", "zh-TW": "繁體中文"},
                value=state.lang,
                on_change=on_lang_change
            ).props('dense options-dense dark').classes('w-32')

            ui.button(
                text="",
                icon="play_arrow",
                on_click=start_tunnel_engine
            ).bind_text_from(state, 'lang', lambda _: state.t('start')) \
             .bind_visibility_from(state, 'is_running', backward=lambda r: not r) \
             .props('color=emerald unelevated')

            ui.button(
                text="",
                icon="stop",
                on_click=stop_tunnel_engine
            ).bind_text_from(state, 'lang', lambda _: state.t('stop')) \
             .bind_visibility_from(state, 'is_running') \
             .props('color=rose unelevated')

            ui.button(
                text="",
                icon="power_settings_new",
                on_click=confirm_exit_app
            ).bind_text_from(state, 'lang', lambda _: state.t('exit_app')) \
             .props('color=grey-8 unelevated')

    # Main Grid
    with ui.row().classes('w-full h-[calc(100vh-65px)] no-wrap gap-0'):
        # Drawer
        with ui.column().classes('w-72 bg-slate-100 dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 p-4 gap-2 h-full'):
            with ui.row().classes('w-full items-center justify-between mb-2'):
                ui.label().bind_text_from(state, 'lang', lambda _: state.t('configs')).classes('font-semibold text-slate-700 dark:text-slate-300')
                ui.button(icon='add', on_click=open_add_config_dialog).props('flat round dense color=primary')

            with ui.column().classes('w-full gap-1 overflow-y-auto flex-grow'):
                render_config_list()

        # Content Area
        with ui.column().classes('flex-grow h-full p-6 bg-white dark:bg-slate-950 overflow-y-auto'):
            with ui.tabs().classes('w-full') as tabs:
                tab_config = ui.tab('cfg_tab', icon='settings').bind_label_from(state, 'lang', lambda _: state.t('tab_config'))
                tab_logs = ui.tab('log_tab', icon='terminal').bind_label_from(state, 'lang', lambda _: state.t('tab_logs'))

            with ui.tab_panels(tabs, value=tab_config).classes('w-full mt-4 flex-grow'):
                # Config Panel
                with ui.tab_panel(tab_config):
                    with ui.column().classes('w-full max-w-3xl gap-4'):
                        render_config_form()

                # Logs Panel
                with ui.tab_panel(tab_logs):
                    with ui.row().classes('w-full items-center justify-between mb-2'):
                        with ui.row().classes('gap-2'):
                            ui.button(icon='clear_all', on_click=clear_logs_action) \
                                .bind_text_from(state, 'lang', lambda _: state.t('clear_logs')) \
                                .props('outline dense color=secondary')
                            ui.button(icon='download', on_click=export_logs_action) \
                                .bind_text_from(state, 'lang', lambda _: state.t('export_logs')) \
                                .props('outline dense color=primary')
                        
                    log_widget = ui.log(max_lines=MAX_LOG_LINES).classes('w-full h-[calc(100vh-220px)] bg-slate-900 text-green-400 font-mono text-xs p-4 rounded')
                    state.log_widget = log_widget
                    for line in state.log_buffer:
                        log_widget.push(line)


def select_config(name: str):
    if state.is_running:
        ui.notify("Stop the tunnel before changing active config.", type='warning')
        return
    state.active_config_name = name
    render_config_list.refresh()
    render_config_form.refresh()


def clear_logs_action():
    state.log_buffer.clear()
    if state.log_widget:
        state.log_widget.clear()


def export_logs_action():
    if not state.log_buffer:
        ui.notify("Log buffer is empty.", type='warning')
        return
    content = "\n".join(state.log_buffer)
    ui.download(content.encode('utf-8'), "lightcone_export.log")


def open_add_config_dialog():
    if len(state.configs) >= 10:
        ui.notify(state.t("err_max_configs"), type='warning')
        return

    dialog = ui.dialog()
    with dialog, ui.card().classes('w-96 p-4 gap-4'):
        ui.label(state.t("add_config")).classes('text-lg font-bold')
        name_input = ui.input(label=state.t("dialog_name_placeholder")).classes('w-full').props('outlined')

        with ui.row().classes('w-full justify-end gap-2'):
            ui.button(state.t('cancel'), on_click=dialog.close).props('flat')
            
            def create_config():
                val = name_input.value.strip()
                if not val or len(val) > 20:
                    ui.notify(state.t("err_name_len"), type='negative')
                    return
                if re.search(r'[\\/:*?"<>|]', val):
                    ui.notify(state.t("err_invalid_chars"), type='negative')
                    return
                if val in state.configs:
                    ui.notify(state.t("err_name_exists"), type='warning')
                    return

                state.configs[val] = DEFAULT_CLIENT_CONFIG.copy()
                state.save_config_file(val, DEFAULT_CLIENT_CONFIG)
                state.active_config_name = val
                render_config_list.refresh()
                render_config_form.refresh()
                dialog.close()

            ui.button(state.t('create'), on_click=create_config).props('unelevated color=primary')

    dialog.open()


def confirm_delete_config(name: str):
    if state.is_running:
        ui.notify(state.t("err_delete_running"), type='warning')
        return

    dialog = ui.dialog()
    with dialog, ui.card().classes('p-4 gap-4'):
        ui.label(state.t("confirm_delete")).classes('text-base')
        with ui.row().classes('w-full justify-end gap-2'):
            ui.button(state.t('cancel'), on_click=dialog.close).props('flat')
            
            def do_delete():
                dialog.close()
                state.delete_config_file(name)
                state.configs.pop(name, None)
                if state.active_config_name == name:
                    state.active_config_name = next(iter(state.configs.keys()), "")
                render_config_list.refresh()
                render_config_form.refresh()
                ui.notify(state.t("msg_deleted"), type='info')

            ui.button(state.t('delete'), on_click=do_delete).props('unelevated color=negative')

    dialog.open()


def confirm_exit_app():
    dialog = ui.dialog()
    with dialog, ui.card().classes('p-4 gap-4'):
        ui.label(state.t("confirm_exit")).classes('text-base')
        with ui.row().classes('w-full justify-end gap-2'):
            ui.button(state.t('cancel'), on_click=dialog.close).props('flat')
            
            async def do_exit():
                dialog.close()
                await exit_application()

            ui.button(state.t('exit_app'), on_click=do_exit).props('unelevated color=negative')

    dialog.open()


# ============================================================================
# Application Entry Point (Browser Mode)
# ============================================================================
if __name__ in {"__main__", "__mp_main__"}:
    app.on_shutdown(stop_tunnel_engine)

    ui.run(
        title="Lightcone Tunnel Manager",
        port=8000,
        reload=False,
        show=True,
        native=False,
    )
