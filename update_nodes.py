#!/usr/bin/env python3
"""
update_nodes.py
--------------
自动从机场订阅拉取节点，合并进本地 sing-box config 文件。
支持格式：sing-box JSON / Clash YAML / base64 URI 列表

用法：
    python3 update_nodes.py

依赖：
    pip3 install requests pyyaml
"""

import json
import base64
import re
import sys
import shutil
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# ── 配置区（按需修改） ─────────────────────────────────────────
SUB_URL = "https://12ba76293aa941395bbe0d821d1717fe.cdn-res-oss-cn-hongkong-aliyuncs-file.com/s?t=12ba76293aa941395bbe0d821d1717fe.jpg"

# 本地订阅文件路径（从浏览器下载后放这里）
# 设置后优先使用本地文件，留空则走网络请求
LOCAL_SUB_FILE = "SSRDOG"

# 你的本地 config 文件路径
CONFIG_PATH = "config_anytls.json"

# 备份目录
BACKUP_DIR = "backups"

# 请求超时（秒）
TIMEOUT = 15

# User-Agent
USER_AGENTS = [
    "clash-meta",
    "sing-box",
    "ClashForAndroid/2.5.12",
    "Mozilla/5.0",
]
# ─────────────────────────────────────────────────────────────


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def fetch_subscription(url):
    """尝试多个 UA 拉取订阅"""
    try:
        import requests
    except ImportError:
        print("请先安装依赖：pip3 install requests pyyaml")
        sys.exit(1)

    for ua in USER_AGENTS:
        try:
            log(f"尝试 UA: {ua}")
            resp = requests.get(url, headers={"User-Agent": ua}, timeout=TIMEOUT)
            if resp.status_code == 200 and len(resp.content) > 100:
                log(f"成功拉取，大小: {len(resp.content)} bytes")
                return resp.text, resp.content
        except Exception as e:
            log(f"  失败: {e}")
    raise RuntimeError("所有 User-Agent 均失败，请检查订阅链接或网络")


def detect_format(text, raw_bytes):
    """检测订阅格式"""
    text = text.strip()

    # sing-box JSON
    if text.startswith("{") or text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return "singbox_list", data
            if isinstance(data, dict) and "outbounds" in data:
                return "singbox_full", data
        except Exception:
            pass

    # Clash YAML
    if "proxies:" in text or "proxy-groups:" in text:
        return "clash", text

    # base64
    try:
        decoded = base64.b64decode(text + "==").decode("utf-8", errors="ignore")
        if any(decoded.startswith(p) for p in ("ss://", "vmess://", "trojan://",
                                                "vless://", "anytls://", "hy2://",
                                                "hysteria2://")):
            return "uri_list", decoded
    except Exception:
        pass

    # 直接 URI 列表
    if any(text.startswith(p) for p in ("ss://", "vmess://", "trojan://",
                                         "vless://", "anytls://", "hy2://")):
        return "uri_list", text

    return "unknown", text


def parse_clash_proxies(yaml_text):
    """从 Clash YAML 提取节点并转成 sing-box outbounds"""
    try:
        import yaml
    except ImportError:
        print("请先安装依赖：pip3 install pyyaml")
        sys.exit(1)

    data = yaml.safe_load(yaml_text)
    proxies = data.get("proxies", [])
    outbounds = []

    for p in proxies:
        ptype = p.get("type", "").lower()

        if ptype == "ss":
            outbounds.append({
                "type": "shadowsocks",
                "tag": p.get("name", "node"),
                "server": p.get("server"),
                "server_port": int(p.get("port", 443)),
                "method": p.get("cipher", "aes-256-gcm"),
                "password": str(p.get("password", "")),
            })

        elif ptype == "anytls":
            ob = {
                "type": "anytls",
                "tag": p.get("name", "node"),
                "server": p.get("server"),
                "server_port": int(p.get("port", 443)),
                "password": str(p.get("password", "")),
            }
            if p.get("sni"):
                ob["tls"] = {"enabled": True, "server_name": p["sni"],
                             "insecure": p.get("skip-cert-verify", False)}
            outbounds.append(ob)

        elif ptype == "vmess":
            ob = {
                "type": "vmess",
                "tag": p.get("name", "node"),
                "server": p.get("server"),
                "server_port": int(p.get("port", 443)),
                "uuid": p.get("uuid", ""),
                "security": p.get("cipher", "auto"),
                "alter_id": int(p.get("alterId", 0)),
            }
            outbounds.append(ob)

        elif ptype in ("trojan",):
            ob = {
                "type": "trojan",
                "tag": p.get("name", "node"),
                "server": p.get("server"),
                "server_port": int(p.get("port", 443)),
                "password": str(p.get("password", "")),
                "tls": {"enabled": True,
                        "server_name": p.get("sni", p.get("server", "")),
                        "insecure": p.get("skip-cert-verify", False)},
            }
            outbounds.append(ob)

        elif ptype in ("vless",):
            ob = {
                "type": "vless",
                "tag": p.get("name", "node"),
                "server": p.get("server"),
                "server_port": int(p.get("port", 443)),
                "uuid": p.get("uuid", ""),
            }
            outbounds.append(ob)

        elif ptype in ("hy2", "hysteria2"):
            ob = {
                "type": "hysteria2",
                "tag": p.get("name", "node"),
                "server": p.get("server"),
                "server_port": int(p.get("port", 443)),
                "password": str(p.get("password", "")),
                "tls": {"enabled": True,
                        "server_name": p.get("sni", p.get("server", "")),
                        "insecure": p.get("skip-cert-verify", False)},
            }
            outbounds.append(ob)

        else:
            log(f"  跳过不支持的协议: {ptype} ({p.get('name', '?')})")

    return outbounds


def parse_uri_list(uri_text):
    """解析 URI 列表（ss:// vmess:// anytls:// 等）"""
    outbounds = []
    for line in uri_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ob = parse_single_uri(line)
            if ob:
                outbounds.append(ob)
        except Exception as e:
            log(f"  跳过无法解析的行: {line[:60]}… ({e})")
    return outbounds


def parse_single_uri(uri):
    """解析单条 URI"""
    if uri.startswith("ss://"):
        # ss://BASE64(method:password)@host:port#name
        # or ss://BASE64@host:port#name
        name = ""
        if "#" in uri:
            uri, name = uri.rsplit("#", 1)
            name = urlparse("http://x/" + name).path.strip("/") or name

        parsed = urlparse(uri)
        host = parsed.hostname
        port = parsed.port

        userinfo = parsed.username or ""
        # 尝试 base64 decode
        try:
            decoded = base64.b64decode(userinfo + "==").decode()
            method, password = decoded.split(":", 1)
        except Exception:
            method = userinfo
            password = parsed.password or ""

        return {
            "type": "shadowsocks",
            "tag": name or f"ss-{host}:{port}",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password,
        }

    elif uri.startswith("anytls://"):
        parsed = urlparse(uri)
        name = ""
        if "#" in uri:
            name = uri.rsplit("#", 1)[1]
        params = parse_qs(parsed.query)
        ob = {
            "type": "anytls",
            "tag": name or f"anytls-{parsed.hostname}:{parsed.port}",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": parsed.password or parsed.username or "",
        }
        sni = params.get("sni", [None])[0] or params.get("peer", [None])[0]
        if sni:
            ob["tls"] = {"enabled": True, "server_name": sni,
                         "insecure": params.get("insecure", ["0"])[0] == "1"}
        return ob

    elif uri.startswith(("hy2://", "hysteria2://")):
        parsed = urlparse(uri)
        name = ""
        if "#" in uri:
            name = uri.rsplit("#", 1)[1]
        params = parse_qs(parsed.query)
        return {
            "type": "hysteria2",
            "tag": name or f"hy2-{parsed.hostname}:{parsed.port}",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": parsed.password or parsed.username or "",
            "tls": {
                "enabled": True,
                "server_name": params.get("sni", [parsed.hostname])[0],
                "insecure": params.get("insecure", ["0"])[0] == "1",
            },
        }

    elif uri.startswith("vmess://"):
        raw = uri[8:]
        if "#" in raw:
            raw = raw.rsplit("#", 1)[0]
        data = json.loads(base64.b64decode(raw + "==").decode())
        return {
            "type": "vmess",
            "tag": data.get("ps", data.get("add", "vmess")),
            "server": data.get("add"),
            "server_port": int(data.get("port", 443)),
            "uuid": data.get("id"),
            "security": data.get("scy", "auto"),
            "alter_id": int(data.get("aid", 0)),
        }

    elif uri.startswith("trojan://"):
        parsed = urlparse(uri)
        name = ""
        if "#" in uri:
            name = uri.rsplit("#", 1)[1]
        params = parse_qs(parsed.query)
        return {
            "type": "trojan",
            "tag": name or f"trojan-{parsed.hostname}",
            "server": parsed.hostname,
            "server_port": parsed.port or 443,
            "password": parsed.username or "",
            "tls": {
                "enabled": True,
                "server_name": params.get("sni", [parsed.hostname])[0],
                "insecure": params.get("allowInsecure", ["0"])[0] == "1",
            },
        }

    return None


def extract_node_outbounds(raw_outbounds):
    """从 sing-box outbounds 列表中提取节点（排除 selector/urltest/direct/block）"""
    skip_types = {"selector", "urltest", "direct", "block", "dns"}
    return [o for o in raw_outbounds if o.get("type") not in skip_types]


def get_node_tags(outbounds):
    return [o["tag"] for o in outbounds]


def update_config(config, new_nodes):
    """将新节点合并进 config，更新所有 selector/urltest 的 outbounds 列表"""
    node_tags = get_node_tags(new_nodes)
    log(f"新节点数量: {len(node_tags)}")

    # 地区过滤规则
    region_patterns = {
        "🇭🇰 香港节点": re.compile(r"HK|Hong Kong|香港|🇭🇰", re.I),
        "🇯🇵 日本节点": re.compile(r"JP|Japan|日本|🇯🇵", re.I),
        "🇺🇲 美国节点": re.compile(r"US|United States|美国|美國|🇺🇸|🇺🇲", re.I),
        "🇨🇳 台湾节点": re.compile(r"TW|Taiwan|台湾|台灣|🇹🇼", re.I),
        "🇸🇬 狮城节点": re.compile(r"SG|Singapore|新加坡|狮城|獅城|🇸🇬", re.I),
        "🇰🇷 韩国节点": re.compile(r"KR|Korea|韩国|韓國|🇰🇷", re.I),
    }

    # 保留原有的 selector/urltest/direct/block，移除旧节点
    keep_types = {"selector", "urltest", "direct", "block"}
    control_outbounds = [o for o in config["outbounds"] if o.get("type") in keep_types]

    # 更新各组的 outbounds 列表
    for o in control_outbounds:
        tag = o["tag"]
        otype = o["type"]

        if tag in ("🎯 全球直连", "🛑 广告拦截", "🍃 应用净化", "DIRECT", "REJECT"):
            continue  # 不改

        if tag in region_patterns:
            pat = region_patterns[tag]
            matched = [t for t in node_tags if pat.search(t)]
            o["outbounds"] = matched if matched else node_tags[:5]
            log(f"  {tag}: {len(matched)} 个节点")

        elif tag in ("🚀 手动切换", "♻️ 自动选择", "GLOBAL", "🎥 奈飞节点"):
            o["outbounds"] = node_tags.copy()
            if tag in ("🚀 手动切换", "GLOBAL"):
                o["outbounds"].insert(0, "DIRECT")

        elif otype == "selector" and tag not in ("🎯 全球直连", "🛑 广告拦截", "🍃 应用净化"):
            # 其他 selector（节点选择、各媒体/服务组）保持原有结构，只更新手动切换引用
            pass

    # 组合最终 outbounds：控制组 + 新节点
    config["outbounds"] = control_outbounds + new_nodes
    return config


def backup_config(path):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = os.path.join(BACKUP_DIR, f"config_{ts}.json")
    shutil.copy2(path, dst)
    log(f"已备份原配置至: {dst}")


def main():
    log("=== sing-box 订阅更新脚本 ===")

    # 读取本地 config
    if not os.path.exists(CONFIG_PATH):
        print(f"错误：找不到配置文件 {CONFIG_PATH}")
        print("请将此脚本和 config_1_13_fixed.json 放在同一目录")
        sys.exit(1)

    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
    log(f"已读取配置: {CONFIG_PATH}")

    # 备份
    backup_config(CONFIG_PATH)

    # 读取订阅（优先本地文件）
    if LOCAL_SUB_FILE and os.path.exists(LOCAL_SUB_FILE):
        log(f"使用本地订阅文件: {LOCAL_SUB_FILE}")
        with open(LOCAL_SUB_FILE, "r", encoding="utf-8") as f:
            text = f.read()
        raw = text.encode()
    else:
        log(f"拉取订阅: {SUB_URL[:60]}…")
        text, raw = fetch_subscription(SUB_URL)

    # 检测格式
    fmt, data = detect_format(text, raw)
    log(f"订阅格式: {fmt}")

    # 解析节点
    if fmt == "singbox_full":
        new_nodes = extract_node_outbounds(data.get("outbounds", []))
    elif fmt == "singbox_list":
        new_nodes = extract_node_outbounds(data)
    elif fmt == "clash":
        new_nodes = parse_clash_proxies(data)
    elif fmt == "uri_list":
        new_nodes = parse_uri_list(data)
    else:
        print(f"无法识别订阅格式，内容开头：\n{text[:200]}")
        sys.exit(1)

    if not new_nodes:
        print("警告：未解析到任何节点，已中止，配置未修改")
        sys.exit(1)

    log(f"解析到 {len(new_nodes)} 个节点")

    # 合并
    config = update_config(config, new_nodes)

    # 写回
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    log(f"✅ 配置已更新: {CONFIG_PATH}")
    log("请在 SFM 中重新加载配置文件生效")


if __name__ == "__main__":
    main()
