"""
VPN Gate Collector (CURL Edition)
Собирает список серверов через curl, проверяет TCP/UDP и сохраняет в JSON.
"""

import csv
import json
import time
import logging
import hashlib
import subprocess
import re
import base64
from typing import Tuple
from datetime import datetime, timezone
from pathlib import Path
import schedule # pip install schedule

# === НАСТРОЙКИ === # https://ifconfig.co/ #
OUTPUT_FILE = "vpngate_full_list.json"

MIRRORS = [
    "https://www.vpngate.net",
    "http://160.251.62.107:46080",
    "http://175.210.118.154:39744",
    "http://211.14.226.154:33477",
    "http://221.171.27.70:47201/",
    "http://118.106.179.107:12143",
    "http://p1371060-ipxg00e01okayamahigasi.okayama.ocn.ne.jp:37613/",
    "http://183.100.225.237:56531/",
    "http://220.57.84.30:62713/",
    "http://112.165.112.49:52818/",
    "http://124.18.179.190:39566/",
    "http://kd036012175158.ppp-bb.dion.ne.jp:64678/",
]

PROXY_BASE = None
PROXY_CRED = None

API_PATH = "/api/iphone/"
CURL_TIMEOUT = 30
ASQ_PERIOD = 1

# Regex patterns (аналог C# с RegexOptions.Multiline | IgnoreCase)
PORT_REGEX = re.compile(r'^remote\s+[\w\.:]+\s+(\d+)(?:\s+(tcp|udp))?', re.MULTILINE | re.IGNORECASE)
PORT_TCP_REGEX = re.compile(r'^\s*proto\s+tcp\s*$', re.MULTILINE | re.IGNORECASE)
PORT_UDP_REGEX = re.compile(r'^\s*proto\s+udp\s*$', re.MULTILINE | re.IGNORECASE)

# Настройка логирования
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("vpngate_curl.log", encoding="utf-8"),logging.StreamHandler()])
logger = logging.getLogger(__name__)


def generate_server_id(row: dict) -> str:
    key = f"{row.get('HostName', '')}:{row.get('IP', '')}"
    return hashlib.md5(key.encode()).hexdigest()


def run_curl_request(url: str) -> str:
    cmd = [
        "curl",                # curl.exe
        "-s",                  # Тихий режим
        "-f",                  # Не выводить ошибки HTTP 404/500 в stdout
        "-L",                  # Следовать за редиректами
        "--max-time", str(CURL_TIMEOUT),
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        url
    ]

    if PROXY_BASE: cmd.extend(["-x", PROXY_BASE])
    if PROXY_BASE and PROXY_CRED: cmd.extend(["-U", PROXY_CRED])

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Curl ошибка ({e.returncode}) для {url}: {e.stderr.decode('utf-8', errors='ignore').strip()}")
        return None
    except FileNotFoundError:
        logger.critical("Утилита 'curl' не найдена в системе! Установите её или добавьте в PATH.")
        return None


def parse_server_line(csv_line: str) -> Tuple[bool, bool, bool, int]:
    """
    Парсит строку CSV VPN Gate и извлекает информацию о протоколе/порте 
    из встроенного OpenVPN-конфига (base64).
    
    Args:
        csv_line: Строка CSV от VPN Gate API
        
    Returns:
        tuple: (parsed: bool, tcp: bool, udp: bool, port: int)
    """
    try:
        if len(csv_line) < 7: return (False, False, False, 0)
        base64_config = csv_line[len(csv_line)-1]

        tcp = False
        udp = False
        port = 0
        
        try:
            # Декодируем base64-конфиг
            config_bytes = base64.b64decode(base64_config)
            config = config_bytes.decode('utf-8')

            # 1. Ищем port/proto в директиве 'remote'
            match = PORT_REGEX.search(config)
            if match:
                port_str = match.group(1)
                proto = match.group(2)
                if port_str:
                    port = int(port_str)
                # Если в remote указан протокол — используем его как подсказку
                if proto and proto.lower() == 'udp':
                    udp = True
                elif proto and proto.lower() == 'tcp':
                    tcp = True

            # 2. Переопределяем по явным директивам proto (как в оригинале C#)
            # Примечание: в оригинале эти проверки перезаписывают результат выше
            if PORT_TCP_REGEX.search(config):
                tcp = True
            if PORT_UDP_REGEX.search(config):
                udp = True
                
        except (base64.binascii.Error, UnicodeDecodeError, ValueError):
            # Если не удалось распарсить конфиг — возвращаем то, что есть
            pass
            
        return (True, tcp, udp, port)
        
    except Exception:
        return (False, False, False, 0)


def parse_vpngate_csv(raw_data: bytes, source_url: str, fetched_at: str) -> list[dict]:
    """
    Парсит бинарные данные от curl.
    """
    servers = []
    
    # VPN Gate часто отдает в Shift-JIS, пробуем декодировать
    try: text_data = raw_data.decode('shift-jis')
    except UnicodeDecodeError:
        try: text_data = raw_data.decode('utf-8')
        except UnicodeDecodeError: text_data = raw_data.decode('latin-1') # Fallback

    lines = [line for line in text_data.splitlines() if not line.startswith('*')]    
    if len(lines) < 2: return servers
    reader = csv.reader(lines, delimiter=',')
    
    try:
        raw_headers = next(reader)
        headers = [h.strip('* #') for h in raw_headers]
    except StopIteration: return servers

    for row_data in reader:
        if not row_data or len(row_data) < len(headers): continue            
        server_data = dict(zip(headers, row_data))
        (parsed, tcp, udp, port) = parse_server_line(row_data)
        server_data['TcpPort'] = port or 0
        server_data['TCP'] = tcp
        server_data['UDP'] = udp
        server_data['_source_url'] = source_url
        server_data['_fetched_at'] = fetched_at
        server_data['_server_id'] = generate_server_id(server_data)                        
        servers.append(server_data)
    
    logger.info(f"Получено {len(servers)} серверов")
    return servers


def fetch_mirror(mirror_url: str) -> list[dict]:
    api_url = mirror_url.rstrip('/') + API_PATH
    fetched_at = datetime.now(timezone.utc).isoformat()
    logger.info(f"Загрузка {api_url}")
    raw_content = run_curl_request(api_url)
    if not raw_content: return []        
    return parse_vpngate_csv(raw_content, mirror_url, fetched_at)


def load_existing(filepath: str) -> dict[str, dict]:
    """Загружает базу"""
    if not Path(filepath).exists(): return {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)           
            result = {s['_server_id']: s for s in data}
            logger.info(f"Загружено {len(result)} серверов из {filepath}")
            return result
    except Exception as e:
        logger.error(f"Ошибка чтения файла: {e}")
        return {}


def save_data(servers: dict[str, dict], filepath: str):
    data = []
    
    ## JSON ##
    try:
        data = [v for k,v in servers.items()]
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"Сохранено {len(data)} серверов в {filepath}")
    except Exception as e:
        logger.error(f"Ошибка сохранения: {e}")

    ## CSV ##
    try:
        csvpath = filepath + ".csv"
        keys = list(data[0].keys())
        target_keys = ["Operator","Message","_source_url","_fetched_at","_server_id","OpenVPN_ConfigData_Base64"]
        for target_key in target_keys:
            if target_key in keys:
                keys.remove(target_key)
                keys.append(target_key)
        with open(csvpath, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        logger.info(f"Сохранено {len(data)} серверов в {csvpath}")
    except Exception as e:
        logger.error(f"Ошибка сохранения: {e}")

    ## CSV ##
    try:
        csvpath = filepath + "no_cfg.csv"
        keys = list(data[0].keys())
        target_keys = ["Operator","Message","_source_url","_fetched_at","_server_id","OpenVPN_ConfigData_Base64"]
        for target_key in target_keys:
            if target_key in keys:
                keys.remove(target_key)
                keys.append(target_key)
        if True:
            keys.remove("OpenVPN_ConfigData_Base64")
            for d in data: 
                del d["OpenVPN_ConfigData_Base64"]
                if not "." in d["HostName"]: d["HostName"] += ".opengw.net"
        with open(csvpath, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        logger.info(f"Сохранено {len(data)} серверов в {csvpath}")
    except Exception as e:
        logger.error(f"Ошибка сохранения: {e}")


def asq_mirrors():    
    logger.info("Начало сбора данных...")    
    db = load_existing(OUTPUT_FILE)    
    was = len(db)
    for mirror in MIRRORS:
        servers = fetch_mirror(mirror)
        if not servers: continue            
        for srv in servers:
            sid = srv['_server_id']
            db[sid] = srv 
        nww = len(db)
        logger.info(f" ... Добавлено {nww-was} серверов.")
    save_data(db, OUTPUT_FILE)
    nww = len(db)
    logger.info(f"Сбор завершен. Добавлено {nww-was} серверов.")


def run():
    logger.info(f"Планировщик запущен: каждые {ASQ_PERIOD}H")
    asq_mirrors() # Первый запуск
    schedule.every(ASQ_PERIOD).hours.do(asq_mirrors)    
    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    try: run()
    except KeyboardInterrupt: logger.info("Остановка.")