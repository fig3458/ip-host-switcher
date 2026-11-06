# 运维换机助手（ip-host-switcher）

现场换机 / 装机常用的 Windows 小工具：查看并修改**默认出网网卡**的静态 IP、主机名、本机账户名。启动时自动请求管理员权限。

## 功能

| 能力 | 说明 |
|------|------|
| 识别网卡 | 识别默认出网网卡，显示当前 IP / 掩码 / 网关 / DNS |
| 改静态 IP | 一键写入 IPv4 配置 |
| 改主机名 | 修改计算机名（通常需重启生效） |
| 改账户名 | 修改本机用户账户名（常见运维场景） |

## 下载与使用

1. 到 [Releases](https://github.com/fig3458/ip-host-switcher/releases) 下载 `ip-host-switcher.exe`
2. 双击运行，UAC 点「是」
3. 按界面填写并应用

源码运行：

```bat
python app.py
```

需要 Python 3.10+（见 `requirements.txt`）。

## 自行打包

```bat
build.bat
```

或：

```powershell
.\build.ps1
```

产物：`dist\` 下单文件 exe（已带 UAC 清单）。

## 注意

修改网络与账户属于高权限操作，请确认目标机器与参数无误后再应用。

## 许可证

[MIT](LICENSE)
