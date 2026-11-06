# -*- coding: utf-8 -*-
"""运维换机助手：查看/修改默认出网网卡静态 IP、主机名、本机账户名。"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk


APP_TITLE = "运维换机助手"
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9-]{1,15}$")
ACCOUNT_RE = re.compile(r"^[^\\/\"\[\]:;|=,+*?<>]{1,20}$")
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$"
)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_or_exit() -> None:
    if is_admin():
        return
    # 打包成 exe 时只传额外参数；源码运行时传脚本路径及参数
    if getattr(sys, "frozen", False):
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
    else:
        params = " ".join(f'"{a}"' for a in sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params or None, None, 1
    )
    if rc <= 32:
        # 提权失败时尚无主窗口，用 MessageBoxW
        ctypes.windll.user32.MessageBoxW(
            0, "未能获取管理员权限，程序退出。", APP_TITLE, 0x10
        )
    sys.exit(0)


def _decode_console(data: bytes) -> str:
    if not data:
        return ""
    for enc in ("utf-8", "gbk", "cp936", "mbcs"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def run_ps(script: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """用 -EncodedCommand 传 UTF-16 脚本，避免中文网卡名在命令行被截断/乱码。"""
    wrapped = (
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "$OutputEncoding = [Console]::OutputEncoding; "
        "$ErrorActionPreference = 'Stop'; "
        + script
    )
    encoded = base64.b64encode(wrapped.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        capture_output=True,
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW
        if hasattr(subprocess, "CREATE_NO_WINDOW")
        else 0,
    )
    return subprocess.CompletedProcess(
        args=result.args,
        returncode=result.returncode,
        stdout=_decode_console(result.stdout),
        stderr=_decode_console(result.stderr),
    )


def mask_to_prefix(mask: str) -> int:
    if not IPV4_RE.match(mask):
        raise ValueError("子网掩码格式无效")
    bits = "".join(f"{int(p):08b}" for p in mask.split("."))
    if "01" in bits:
        raise ValueError("子网掩码不是合法连续掩码")
    return bits.count("1")


def prefix_to_mask(prefix: int) -> str:
    if not 0 <= prefix <= 32:
        raise ValueError("前缀长度无效")
    value = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return ".".join(str((value >> s) & 0xFF) for s in (24, 16, 8, 0))


def clean_err(text: str) -> str:
    """把 PowerShell CLIXML / 冗长错误收成可读短句。"""
    if not text:
        return "未知错误"
    raw = text.strip()
    if "80070534" in raw or "账户名与安全标识符间无任何映射完成" in raw:
        return (
            "账户名与 SID 暂时无法映射（刚改过登录账户名时常见）。"
            "请注销重新登录后再打开本工具；一键应用时会先改网络、最后改账户名。"
        )
    if "#< CLIXML" in raw or "<Objs" in raw:
        msgs = re.findall(r'<S N="Message">(.*?)</S>', raw, flags=re.DOTALL)
        if msgs:
            msg = msgs[0]
            msg = (
                msg.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
                .replace("&#xA;", "\n")
            )
            return msg.strip()[:400]
        # 再试中文短句
        for key in ("未找到", "无法", "失败", "拒绝", "无效"):
            if key in raw:
                # 截一段非 XML 文本
                break
        return "操作失败（PowerShell 报错）。请重试或注销后重开。"
    return raw[:500]


def run_cmd(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        capture_output=True,
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW
        if hasattr(subprocess, "CREATE_NO_WINDOW")
        else 0,
    )
    return subprocess.CompletedProcess(
        args=result.args,
        returncode=result.returncode,
        stdout=_decode_console(result.stdout),
        stderr=_decode_console(result.stderr),
    )


def parse_netsh_config(text: str) -> dict:
    ip = ""
    mask = ""
    gateway = ""
    dns: list[str] = []
    prefix = 24
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("IP Address:") or s.startswith("IP 地址:"):
            ip = s.split(":", 1)[1].strip()
        elif s.startswith("Subnet Prefix:") or s.startswith("子网前缀:"):
            # e.g. 192.168.16.0/24 (mask 255.255.255.0)
            m = re.search(r"/(\d+)", s)
            if m:
                prefix = int(m.group(1))
            m2 = re.search(r"mask\s+(\d+\.\d+\.\d+\.\d+)", s, re.I)
            if m2:
                mask = m2.group(1)
            m3 = re.search(r"掩码\s+(\d+\.\d+\.\d+\.\d+)", s)
            if m3:
                mask = m3.group(1)
        elif s.startswith("Default Gateway:") or s.startswith("默认网关:"):
            gw = s.split(":", 1)[1].strip()
            if gw and gw.lower() not in ("none", "无"):
                gateway = gw
        elif re.match(r"^\d+\.\d+\.\d+\.\d+$", s):
            # DNS 列表行
            dns.append(s)
        elif "DNS" in s and ":" in s:
            part = s.split(":", 1)[1].strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", part):
                dns.append(part)
    if not mask and prefix:
        try:
            mask = prefix_to_mask(prefix)
        except ValueError:
            mask = "255.255.255.0"
    return {
        "ip": ip,
        "mask": mask,
        "prefix": prefix,
        "gateway": gateway,
        "dns1": dns[0] if len(dns) > 0 else "",
        "dns2": dns[1] if len(dns) > 1 else "",
    }


def get_network_info() -> dict:
    """优先已连接有线；有线未连接再用无线。读配置避开 Get-NetIPConfiguration（改账户名后会 0x80070534）。"""
    script = r"""
function Test-ExcludedAdapter([string]$name, [string]$desc) {
    $t = "$name $desc"
    return [bool]($t -match '蓝牙|Bluetooth|Virtual|vEthernet|Hyper-V|WSL|VPN|Loopback|Pseudo|TAP-Windows')
}
function Test-IsWifi($a) {
    if ([int]$a.InterfaceType -eq 71) { return $true }
    $t = "$($a.Name) $($a.InterfaceDescription)"
    return [bool]($t -match 'WLAN|Wi-?Fi|无线|802\.11|Wireless')
}
function Test-IsWired($a) {
    if (Test-ExcludedAdapter $a.Name $a.InterfaceDescription) { return $false }
    if (Test-IsWifi $a) { return $false }
    if ([int]$a.InterfaceType -eq 6) { return $true }
    $t = "$($a.Name) $($a.InterfaceDescription)"
    return [bool]($t -match '以太网|Ethernet|本地连接|Local Area')
}

$all = @(Get-NetAdapter -ErrorAction Stop)
$wiredUp = @($all | Where-Object { $_.Status -eq 'Up' -and (Test-IsWired $_) })
$wifiUp  = @($all | Where-Object { $_.Status -eq 'Up' -and (Test-IsWifi $_) })

if ($wiredUp.Count -gt 0) {
    $pool = $wiredUp
    $kind = '有线'
} elseif ($wifiUp.Count -gt 0) {
    $pool = $wifiUp
    $kind = '无线'
} else {
    throw '未找到已连接的有线或无线网卡（请先插网线或连上 Wi-Fi）'
}

$chosen = $pool | ForEach-Object {
    $hasGw = [bool](Get-NetRoute -InterfaceIndex $_.ifIndex -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1)
    $_ | Select-Object Name, ifIndex, Status, InterfaceMetric, @{n='HasGw';e={ $hasGw }}
} | Sort-Object @{e={ -not $_.HasGw }}, InterfaceMetric | Select-Object -First 1

[pscustomobject]@{
    Alias = $chosen.Name
    Index = [int]$chosen.ifIndex
    Kind = $kind
    Status = [string]$chosen.Status
} | ConvertTo-Json -Compress
"""
    result = run_ps(script)
    if result.returncode != 0:
        raise RuntimeError(clean_err(result.stderr or result.stdout or "读取网卡失败"))
    lines = [ln for ln in (result.stdout or "").splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError("读取网卡失败：无有效输出")
    meta = json.loads(lines[-1])
    if_index = int(meta.get("Index") or 0)
    alias = meta.get("Alias") or ""

    # 用 netsh 读 IP/网关/DNS，不走 Get-NetIPConfiguration
    cfg_text = ""
    for key in (str(if_index), alias):
        if not key:
            continue
        r = run_cmd(
            ["netsh", "interface", "ipv4", "show", "config", f"name={key}"],
            timeout=20,
        )
        if r.returncode == 0 and (r.stdout or "").strip():
            cfg_text = r.stdout
            break
    parsed = parse_netsh_config(cfg_text)
    prefix = int(parsed.get("prefix") or 24)
    mask = parsed.get("mask") or prefix_to_mask(prefix)
    return {
        "alias": alias,
        "index": if_index,
        "kind": meta.get("Kind") or "",
        "status": meta.get("Status") or "",
        "ip": parsed.get("ip") or "",
        "prefix": prefix,
        "mask": mask,
        "gateway": parsed.get("gateway") or "",
        "dns1": parsed.get("dns1") or "",
        "dns2": parsed.get("dns2") or "",
    }


def get_identity() -> dict:
    """用当前登录用户 SID 解析本地账户名，避免显示名/微软账户不一致。"""
    script = r"""
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $id.User.Value
$u = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid } | Select-Object -First 1
[pscustomobject]@{
    Account = if ($u) { $u.Name } else { $env:USERNAME }
    Sid = $sid
    PrincipalSource = if ($u) { [string]$u.PrincipalSource } else { '' }
    Hostname = $env:COMPUTERNAME
} | ConvertTo-Json -Compress
"""
    result = run_ps(script)
    if result.returncode == 0:
        lines = [ln for ln in (result.stdout or "").splitlines() if ln.strip().startswith("{")]
        if lines:
            data = json.loads(lines[-1])
            return {
                "hostname": data.get("Hostname") or socket.gethostname(),
                "account": data.get("Account") or os.environ.get("USERNAME") or "",
                "sid": data.get("Sid") or "",
                "principal_source": data.get("PrincipalSource") or "",
            }
    return {
        "hostname": socket.gethostname(),
        "account": os.environ.get("USERNAME") or os.getlogin(),
        "sid": "",
        "principal_source": "",
    }


def apply_static_ip(
    if_index: int, ip: str, mask: str, gateway: str, dns1: str, dns2: str, alias: str = ""
) -> None:
    """用 netsh 设静态 IP，避免 Rename-LocalUser 后 NetTCPIP 的 0x80070534。"""
    if if_index <= 0:
        raise RuntimeError("无效的网卡 Index")
    # name 优先用 Index（数字），失败再试网卡名
    names = [str(if_index)]
    if alias:
        names.append(alias)

    last_err = ""
    ok = False
    used = ""
    for name in names:
        r = run_cmd(
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "address",
                f"name={name}",
                "source=static",
                f"address={ip}",
                f"mask={mask}",
                f"gateway={gateway}",
            ],
            timeout=60,
        )
        if r.returncode == 0:
            ok = True
            used = name
            break
        # 兼容另一套语法
        r2 = run_cmd(
            [
                "netsh",
                "interface",
                "ip",
                "set",
                "address",
                f"name={name}",
                "static",
                ip,
                mask,
                gateway,
                "1",
            ],
            timeout=60,
        )
        if r2.returncode == 0:
            ok = True
            used = name
            break
        last_err = clean_err((r.stderr or r.stdout or "") + "\n" + (r2.stderr or r2.stdout or ""))

    if not ok:
        raise RuntimeError(last_err or "设置静态 IP 失败")

    # DNS
    if dns1:
        r = run_cmd(
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                f"name={used}",
                "source=static",
                f"address={dns1}",
                "register=primary",
                "validate=no",
            ],
            timeout=30,
        )
        if r.returncode != 0:
            r = run_cmd(
                [
                    "netsh",
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    f"name={used}",
                    "static",
                    dns1,
                    "primary",
                ],
                timeout=30,
            )
        if r.returncode != 0:
            raise RuntimeError(clean_err(r.stderr or r.stdout or "设置 DNS 失败"))
        if dns2:
            run_cmd(
                [
                    "netsh",
                    "interface",
                    "ipv4",
                    "add",
                    "dnsservers",
                    f"name={used}",
                    f"address={dns2}",
                    "index=2",
                    "validate=no",
                ],
                timeout=30,
            )
    else:
        run_cmd(
            [
                "netsh",
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                f"name={used}",
                "source=static",
                "address=none",
            ],
            timeout=30,
        )


def apply_hostname(new_name: str) -> None:
    script = f"""
$n = {json.dumps(new_name, ensure_ascii=False)}
Rename-Computer -NewName $n -Force -ErrorAction Stop
"""
    result = run_ps(script)
    if result.returncode != 0:
        raise RuntimeError(clean_err(result.stderr or result.stdout or "修改主机名失败"))


def apply_account_name(old_name: str, new_name: str, sid: str = "") -> None:
    """按 SID 改名；ADSI 兜底。微软关联账户直接提示。"""
    script = f"""
$old = {json.dumps(old_name, ensure_ascii=False)}
$new = {json.dumps(new_name, ensure_ascii=False)}
$sid = {json.dumps(sid or "", ensure_ascii=False)}

$user = $null
if ($sid) {{
    $user = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {{ $_.SID.Value -eq $sid }} | Select-Object -First 1
}}
if (-not $user -and $old) {{
    $user = Get-LocalUser -Name $old -ErrorAction SilentlyContinue
}}
if (-not $user) {{
    throw "找不到本地账户（SID=$sid, Name=$old）。域账户/微软账户登录无法用本工具改名。"
}}
$src = [string]$user.PrincipalSource
if ($src -eq 'MicrosoftAccount') {{
    throw "当前账户已关联 Microsoft 账户，无法直接改本地用户名。请先在 Windows 设置里改为纯本地账户。"
}}
if ($user.Name -eq $new) {{ return }}

$from = $user.Name
$err1 = $null
try {{
    Rename-LocalUser -InputObject $user -NewName $new -ErrorAction Stop
    return
}} catch {{
    $err1 = $_.Exception.Message
}}
try {{
    $acct = [ADSI]("WinNT://./$from,user")
    $null = $acct.psbase.Rename($new)
}} catch {{
    throw ("改账户名失败：" + $err1 + " / ADSI：" + $_.Exception.Message)
}}
"""
    result = run_ps(script)
    if result.returncode != 0:
        raise RuntimeError(clean_err(result.stderr or result.stdout or "修改账户名失败"))


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.resizable(False, False)
        self.configure(padx=12, pady=12)

        self.net: dict = {}
        self.identity: dict = {}
        self._busy = False

        self._build_ui()
        self.after(100, self.refresh_all)

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")

        frm = ttk.Frame(self)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="当前信息", font=("", 11, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 6)
        )

        self.lbl_adapter = ttk.Label(frm, text="目标网卡：-")
        self.lbl_adapter.grid(row=1, column=0, columnspan=3, sticky="w")

        self.cur_vars = {
            "ip": tk.StringVar(value="-"),
            "mask": tk.StringVar(value="-"),
            "gateway": tk.StringVar(value="-"),
            "dns": tk.StringVar(value="-"),
            "hostname": tk.StringVar(value="-"),
            "account": tk.StringVar(value="-"),
        }
        rows = [
            ("当前 IP", "ip"),
            ("当前掩码", "mask"),
            ("当前网关", "gateway"),
            ("当前 DNS", "dns"),
            ("主机设备名", "hostname"),
            ("Windows 账户", "account"),
        ]
        for i, (label, key) in enumerate(rows, start=2):
            ttk.Label(frm, text=label + "：").grid(row=i, column=0, sticky="w", pady=2)
            ttk.Label(frm, textvariable=self.cur_vars[key], width=36).grid(
                row=i, column=1, columnspan=2, sticky="w", pady=2
            )

        ttk.Separator(frm).grid(row=8, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(frm, text="修改为（静态 IP）", font=("", 11, "bold")).grid(
            row=9, column=0, columnspan=3, sticky="w", pady=(0, 6)
        )

        self.ent = {
            "ip": tk.StringVar(),
            "mask": tk.StringVar(),
            "gateway": tk.StringVar(),
            "dns1": tk.StringVar(),
            "dns2": tk.StringVar(),
            "hostname": tk.StringVar(),
            "account": tk.StringVar(),
        }
        edit_rows = [
            ("新 IP", "ip"),
            ("子网掩码", "mask"),
            ("网关", "gateway"),
            ("首选 DNS", "dns1"),
            ("备选 DNS", "dns2"),
            ("新主机名", "hostname"),
            ("新账户名", "account"),
        ]
        for i, (label, key) in enumerate(edit_rows, start=10):
            ttk.Label(frm, text=label + "：").grid(row=i, column=0, sticky="w", pady=2)
            ttk.Entry(frm, textvariable=self.ent[key], width=34).grid(
                row=i, column=1, columnspan=2, sticky="w", pady=2
            )

        btns = ttk.Frame(frm)
        btns.grid(row=17, column=0, columnspan=3, sticky="ew", pady=(12, 0))
        self.btn_refresh = ttk.Button(btns, text="刷新", command=self.refresh_all)
        self.btn_refresh.pack(side="left")
        self.btn_apply = ttk.Button(btns, text="一键应用", command=self.on_apply_all)
        self.btn_apply.pack(side="left", padx=8)

        self.status = tk.StringVar(value="就绪" if is_admin() else "未提权")
        ttk.Label(frm, textvariable=self.status, foreground="#555").grid(
            row=18, column=0, columnspan=3, sticky="w", pady=(10, 0)
        )

        tip = (
            "说明：优先改已连接有线网卡，未连接才用无线；"
            "一键顺序为网络→主机名→账户名；改主机名会问是否重启。"
        )
        ttk.Label(frm, text=tip, wraplength=420, foreground="#666").grid(
            row=19, column=0, columnspan=3, sticky="w", pady=(6, 0)
        )

    def set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for b in (self.btn_refresh, self.btn_apply):
            b.configure(state=state)
        if text:
            self.status.set(text)

    def refresh_all(self) -> None:
        if self._busy:
            return
        self.set_busy(True, "读取中…")

        def work() -> None:
            err = None
            net, ident = {}, {}
            try:
                net = get_network_info()
                ident = get_identity()
            except Exception as exc:  # noqa: BLE001
                err = clean_err(str(exc))
            self.after(0, lambda: self._apply_refresh(net, ident, err))

        threading.Thread(target=work, daemon=True).start()

    def _apply_refresh(self, net: dict, ident: dict, err: str | None) -> None:
        self.set_busy(False)
        if err:
            self.status.set("读取失败")
            messagebox.showerror(APP_TITLE, err)
            return
        self.net = net
        self.identity = ident
        kind = net.get("kind") or "-"
        self.lbl_adapter.configure(
            text=f"目标网卡：{net.get('alias', '-')}（{kind}，Index {net.get('index', '-')}）"
        )
        self.cur_vars["ip"].set(net.get("ip") or "-")
        self.cur_vars["mask"].set(net.get("mask") or "-")
        self.cur_vars["gateway"].set(net.get("gateway") or "-")
        dns = " / ".join(x for x in (net.get("dns1"), net.get("dns2")) if x) or "-"
        self.cur_vars["dns"].set(dns)
        self.cur_vars["hostname"].set(ident.get("hostname") or "-")
        self.cur_vars["account"].set(ident.get("account") or "-")

        # 预填当前值，方便改一两项
        self.ent["ip"].set(net.get("ip") or "")
        self.ent["mask"].set(net.get("mask") or "255.255.255.0")
        self.ent["gateway"].set(net.get("gateway") or "")
        self.ent["dns1"].set(net.get("dns1") or "")
        self.ent["dns2"].set(net.get("dns2") or "")
        self.ent["hostname"].set(ident.get("hostname") or "")
        self.ent["account"].set(ident.get("account") or "")
        self.status.set("已刷新")

    def _require_ipv4(self, value: str, label: str, optional: bool = False) -> str:
        value = value.strip()
        if not value:
            if optional:
                return ""
            raise ValueError(f"{label}不能为空")
        if not IPV4_RE.match(value):
            raise ValueError(f"{label}格式无效：{value}")
        return value

    def on_apply_all(self) -> None:
        if self._busy:
            return
        if_index = int(self.net.get("index") or 0)
        if if_index <= 0:
            messagebox.showwarning(APP_TITLE, "请先刷新，获取默认出网网卡。")
            return

        try:
            ip = self._require_ipv4(self.ent["ip"].get(), "IP")
            mask = self._require_ipv4(self.ent["mask"].get(), "子网掩码")
            mask_to_prefix(mask)
            gateway = self._require_ipv4(self.ent["gateway"].get(), "网关")
            dns1 = self._require_ipv4(self.ent["dns1"].get(), "首选 DNS", optional=True)
            dns2 = self._require_ipv4(self.ent["dns2"].get(), "备选 DNS", optional=True)

            new_host = self.ent["hostname"].get().strip()
            if not new_host:
                raise ValueError("新主机名不能为空")
            if (
                not HOSTNAME_RE.match(new_host)
                or new_host.startswith("-")
                or new_host.endswith("-")
            ):
                raise ValueError(
                    "主机名需 1–15 位字母/数字/连字符，且不能以连字符开头或结尾。"
                )

            old_account = self.identity.get("account") or ""
            new_account = self.ent["account"].get().strip()
            if not new_account:
                raise ValueError("新账户名不能为空")
            if not ACCOUNT_RE.match(new_account):
                raise ValueError("账户名包含非法字符或过长。")
        except ValueError as exc:
            messagebox.showwarning(APP_TITLE, str(exc))
            return

        old_host = self.identity.get("hostname") or ""
        change_net = (
            ip != (self.net.get("ip") or "")
            or mask != (self.net.get("mask") or "")
            or gateway != (self.net.get("gateway") or "")
            or dns1 != (self.net.get("dns1") or "")
            or dns2 != (self.net.get("dns2") or "")
        )
        change_host = new_host.upper() != old_host.upper()
        change_account = new_account.lower() != old_account.lower()

        if not (change_net or change_host or change_account):
            self.status.set("无变更")
            return

        account_sid = self.identity.get("sid") or ""
        alias = self.net.get("alias") or ""
        self.set_busy(True, "正在一键应用…")

        def work() -> None:
            done: list[str] = []
            errors: list[str] = []
            need_reboot = False
            renamed_account = False
            # 正确顺序：先网络 → 主机名 → 最后账户名
            # 先改账户会导致登录会话用户名与 SID 失配，NetTCPIP 报 0x80070534
            try:
                if change_net:
                    apply_static_ip(if_index, ip, mask, gateway, dns1, dns2, alias)
                    done.append("网络")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"网络：{exc}")
            try:
                if change_host:
                    apply_hostname(new_host)
                    done.append("主机名")
                    need_reboot = True
            except Exception as exc:  # noqa: BLE001
                errors.append(f"主机名：{exc}")
            try:
                if change_account:
                    apply_account_name(old_account, new_account, account_sid)
                    done.append("账户名")
                    renamed_account = True
            except Exception as exc:  # noqa: BLE001
                errors.append(f"账户名：{exc}")

            self.after(
                0,
                lambda: self._after_apply_all(
                    done, errors, need_reboot, renamed_account
                ),
            )

        threading.Thread(target=work, daemon=True).start()

    def _after_apply_all(
        self,
        done: list[str],
        errors: list[str],
        need_reboot: bool,
        renamed_account: bool = False,
    ) -> None:
        self.set_busy(False)
        if errors:
            self.status.set("部分失败" if done else "应用失败")
            msg = ""
            if done:
                msg += "已完成：" + "、".join(done) + "\n\n"
            msg += "失败：\n" + "\n".join(clean_err(e) for e in errors)
            messagebox.showerror(APP_TITLE, msg)
        else:
            self.status.set("已应用：" + "、".join(done) if done else "完成")

        if need_reboot and messagebox.askyesno(
            APP_TITLE, "主机名已修改，是否立即重启电脑？"
        ):
            subprocess.run(
                ["shutdown", "/r", "/t", "0"],
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0,
            )
            return

        # 账户已改名：改其实已成功。此时再调网卡 API 常报 SID 映射错误，
        # 那是刷新界面失败，不是刚才的修改失败。用表单值更新显示即可。
        if renamed_account:
            self._sync_ui_after_apply()
            if not errors:
                messagebox.showinfo(
                    APP_TITLE,
                    "已改好。\n\n"
                    "账户名变更后，当前登录会话暂时读不了网卡信息（正常现象），"
                    "注销重新登录即可。配置本身已经写入成功。",
                )
            return

        self.refresh_all()

    def _sync_ui_after_apply(self) -> None:
        """改账户名后无法安全刷新网卡 API，直接用已写入的表单值更新界面。"""
        ip = self.ent["ip"].get().strip()
        mask = self.ent["mask"].get().strip()
        gateway = self.ent["gateway"].get().strip()
        dns1 = self.ent["dns1"].get().strip()
        dns2 = self.ent["dns2"].get().strip()
        host = self.ent["hostname"].get().strip()
        account = self.ent["account"].get().strip()

        self.cur_vars["ip"].set(ip or "-")
        self.cur_vars["mask"].set(mask or "-")
        self.cur_vars["gateway"].set(gateway or "-")
        dns = " / ".join(x for x in (dns1, dns2) if x) or "-"
        self.cur_vars["dns"].set(dns)
        self.cur_vars["hostname"].set(host or "-")
        self.cur_vars["account"].set(account or "-")

        self.net.update(
            {
                "ip": ip,
                "mask": mask,
                "gateway": gateway,
                "dns1": dns1,
                "dns2": dns2,
            }
        )
        self.identity.update({"hostname": host, "account": account})
        self.status.set("已应用（请注销后重开以完整刷新）")


def main() -> None:
    # 先 stealth 提权：无窗口时仍可弹 UAC
    if not is_admin():
        elevate_or_exit()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
