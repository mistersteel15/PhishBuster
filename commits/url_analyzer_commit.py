#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
PhishBuster – Этап 2: Анализатор URL и веб-страниц (без проверки длины)
Принимает URL через ввод в консоли и выдаёт JSON с вердиктом, признаками и списком «красных флагов».
Использование:
    python3 url_analyzer.py
"""

import json                                                     # Сериализация результатов в JSON
import re                                                       # Регулярные выражения для поиска шаблонов в URL и HTML
import socket                                                   # Низкоуровневая работа с сетью (TCP-соединения)
import ssl                                                      # Проверка SSL-сертификатов
import sys                                                      # Завершение программы, вывод в stderr
from datetime import datetime                                   # Работа с датами (возраст домена)
from urllib.parse import urlparse                               # Разбор URL на компоненты

# Внешние зависимости (устанавливаются через pip)
DEPS_AVAILABLE = True                                           # Флаг наличия всех библиотек
try:                                                            # Пробуем импортировать сторонние библиотеки
    import requests                                             # HTTP-запросы для загрузки страниц
    from bs4 import BeautifulSoup                               # Парсинг HTML
    import whois                                                # WHOIS-запросы для получения информации о домене
    import dns.resolver                                         # DNS-запросы для проверки записей домена
    import tldextract                                           # Извлечение зарегистрированного домена и публичного суффикса
except ImportError as e:                                        # Если хотя бы одна библиотека не установлена
    DEPS_AVAILABLE = False                                      # Сбрасываем флаг доступности
    if __name__ == '__main__':                                  # Только при запуске напрямую, а не импорте
        print(f"Ошибка: не установлена библиотека {e.name}. "
              f"Установите её через 'pip install {e.name}'",
              file=sys.stderr)
        sys.exit(1)                                             # Завершаем с кодом ошибки

# ─────────────────────────────────────────────────────────
# Доверенные домены – для них не применяются некоторые проверки
# ─────────────────────────────────────────────────────────
TRUSTED_DOMAINS = {
    'google.com', 'google.ru', 'googleapis.com', 'youtube.com', 'g.co',
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazon.ru', 'amazon.co.uk',
    'paypal.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'github.com', 'dropbox.com',
    'whatsapp.com', 'tiktok.com', 'yahoo.com', 'protonmail.com',
    'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'chase.com',
    'alibaba.com', 'ebay.com', 'reddit.com', 'pinterest.com',
    'snapchat.com', 'discord.com', 'telegram.org', 'yandex.ru', 'mail.ru',
    'cloudfront.net',
    'd2h7jmc5kw17oy.cloudfront.net', 'x.com',
    'notifications.googleapis.com',  't.me',  'bsky.app', 'duolingo.com', 'geoguessr.com',
    'url3138.geoguessr.com', 'dashastat.ru', 'mckw.ru',
}

# Список популярных брендов и их официальных доменов (для анти-спуфинга)
BRAND_OFFICIAL = {
    'google': ['google.com', 'google.ru', 'googleapis.com', 'youtube.com', 'ggpht.com',
               'googleusercontent.com', 'goo.gl', 'g.co'],
    'facebook': ['facebook.com', 'fb.com', 'facebook.net'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'],
    'amazon': ['amazon.com', 'amazon.ru', 'amazon.co.uk', 'amazon.de'],
    'paypal': ['paypal.com', 'paypal.me'],
    'instagram': ['instagram.com'],
    'twitter': ['twitter.com', 't.co'],
    'linkedin': ['linkedin.com'],
    'netflix': ['netflix.com'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'github': ['github.com', 'github.io'],
    'dropbox': ['dropbox.com'],
    'whatsapp': ['whatsapp.com', 'whatsapp.net'],
    'tiktok': ['tiktok.com'],
    'yahoo': ['yahoo.com'],
    'outlook': ['outlook.com'],
    'protonmail': ['protonmail.com', 'proton.me'],
    'bankofamerica': ['bankofamerica.com'],
    'wellsfargo': ['wellsfargo.com'],
    'citibank': ['citibank.com', 'citi.com'],
    'chase': ['chase.com'],
    'alibaba': ['alibaba.com', 'aliexpress.com'],
    'ebay': ['ebay.com'],
    'reddit': ['reddit.com', 'redd.it'],
    'pinterest': ['pinterest.com'],
    'snapchat': ['snapchat.com'],
    'discord': ['discord.com', 'discord.gg'],
    'telegram': ['telegram.org', 't.me'],
    'yandex': ['yandex.ru', 'ya.ru'],
    'mail': ['mail.ru'],
}

POPULAR_BRANDS = list(BRAND_OFFICIAL.keys())                    # Список названий брендов для быстрого перебора

# ─────────────────────────────────────────────────────────
# Простая реализация расстояния Левенштейна
# ─────────────────────────────────────────────────────────
def levenshtein_distance(s1: str, s2: str) -> int:              # Вычисляет расстояние Левенштейна между двумя строками
    if len(s1) < len(s2):                                       # Чтобы s1 была длиннее (оптимизация памяти)
        return levenshtein_distance(s2, s1)                     # Меняем местами
    if len(s2) == 0:                                            # Если вторая строка пустая
        return len(s1)                                          # Расстояние равно длине первой
    previous_row = range(len(s2) + 1)                           # Начальная строка: 0,1,2,...len(s2)
    for i, c1 in enumerate(s1):                                 # Для каждого символа в s1
        current_row = [i + 1]                                   # Первый элемент новой строки — i+1
        for j, c2 in enumerate(s2):                             # Для каждого символа в s2
            insertions = previous_row[j + 1] + 1                # Вставка
            deletions = current_row[j] + 1                      # Удаление
            substitutions = previous_row[j] + (c1 != c2)        # Замена (0 если равны, иначе 1)
            current_row.append(min(insertions, deletions, substitutions))  # Берём минимум
        previous_row = current_row                              # Переходим к следующей строке
    return previous_row[-1]                                     # Последний элемент — искомое расстояние

# ─────────────────────────────────────────────────────────
# Безопасное получение порта из объекта ParseResult
# ─────────────────────────────────────────────────────────
def safe_port(parsed):                                          # Извлекает порт, избегая ошибок при некорректном значении
    """Возвращает номер порта как int или None, если порт не указан или некорректен."""
    try:
        return parsed.port
    except ValueError:                                          # Если порт не является целым числом (например, "void(0)")
        return None

# ─────────────────────────────────────────────────────────
# 1. Парсинг URL (возвращает словарь)
# ─────────────────────────────────────────────────────────
def parse_url(url: str) -> dict:                                # Разбирает URL на составные части
    if not url.startswith('http'):                              # Если нет схемы
        url = 'http://' + url                                   # Добавляем http://
    parsed = urlparse(url)                                      # Стандартный разбор URL
    ext = tldextract.extract(url)                               # Извлекаем зарегистрированный домен и суффикс
    domain = '.'.join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)  # Полный домен
    return {
        'original': url,
        'scheme': parsed.scheme,
        'netloc': parsed.netloc,
        'hostname': parsed.hostname or '',
        'port': safe_port(parsed),                              # Безопасное получение порта
        'path': parsed.path,
        'query': parsed.query,
        'fragment': parsed.fragment,
        'domain': domain.lower() if domain else '',
        'registered_domain': ext.registered_domain or '',       # Например, example.com
        'subdomain': ext.subdomain or '',                       # Например, www
    }

def check_url_syntax(url: str) -> list:                         # Проверяет синтаксические признаки подозрительности
    """
    Возвращает список подозрительных синтаксических признаков URL.
    Проверка длины полностью исключена.
    """
    flags = []                                                  # Список обнаруженных флагов
    parsed = urlparse(url)                                      # Разбираем URL

    if parsed.hostname and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', parsed.hostname):  # Если хост — IPv4
        flags.append(f"URL содержит IP-адрес: {parsed.hostname}")

    if '@' in url:                                              # Символ @ может маскировать реальный домен
        flags.append("URL содержит символ @ (возможна маскировка)")
    if url.count('//') > 2:                                     # Множественные // могут быть признаком обфускации
        flags.append("Множественные // в URL")
    percent_encoded = url.count('%')                            # Считаем количество %-кодирования
    if percent_encoded > len(url) * 0.3:                       # Если более 30% символов — подозрительно
        flags.append("Слишком много %-кодирования в URL")
    port = safe_port(parsed)                                    # Получаем порт безопасно
    if port is not None and port not in {80, 443, 8080, 8443}: # Нестандартный порт
        flags.append(f"Нестандартный порт: {port}")
    if 'xn--' in url.lower():                                   # Punycode может скрывать омографы
        flags.append("Обнаружен Punycode (xn--), возможна омографная атака")
    return flags

# ─────────────────────────────────────────────────────────
# 2. DNS и WHOIS (без изменений)
# ─────────────────────────────────────────────────────────
def get_dns_records(domain: str) -> dict:                       # Получает DNS-записи для домена
    result = {}
    if not domain:
        return result
    for rtype in ['A', 'MX', 'NS', 'TXT']:                     # Основные типы записей
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=3)  # Запрос с таймаутом 3 сек
            result[rtype] = [str(r) for r in answers]          # Сохраняем текстовые представления
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            result[rtype] = None                                # Нет данных
        except Exception:
            result[rtype] = None                                # Общая ошибка
    return result

def whois_info(domain: str) -> dict:                            # Получает данные WHOIS о домене
    if not domain:
        return {}
    try:
        w = whois.whois(domain)                                 # Запрос WHOIS
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        if isinstance(creation_date, list):                     # Иногда возвращается список дат
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return {
            'creation_date': creation_date.strftime('%Y-%m-%d') if isinstance(creation_date, datetime) else str(creation_date),
            'expiration_date': expiration_date.strftime('%Y-%m-%d') if isinstance(expiration_date, datetime) else str(expiration_date),
            'registrar': w.registrar,
            'country': w.country,
        }
    except Exception as e:
        return {'error': str(e)}                                # Возвращаем ошибку, если WHOIS не доступен

# ─────────────────────────────────────────────────────────
# 3. SSL-сертификат (без изменений)
# ─────────────────────────────────────────────────────────
def check_ssl_cert(hostname: str, port: int = 443) -> dict:     # Проверяет SSL-сертификат
    ctx = ssl.create_default_context()                          # Контекст SSL по умолчанию
    ctx.check_hostname = True                                   # Проверять соответствие имени хоста
    ctx.verify_mode = ssl.CERT_REQUIRED                         # Требовать валидный сертификат
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:  # TCP-соединение
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:    # Оборачиваем в SSL
                cert = ssock.getpeercert()                      # Получаем сертификат
                subject = dict(x[0] for x in cert.get('subject', []))
                san = cert.get('subjectAltName', [])
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                return {
                    'valid': True,
                    'subject': subject,
                    'san': san,
                    'not_before': not_before,
                    'not_after': not_after,
                    'hostname_match': True,                     # Если исключения не было, значит имя совпало
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                }
    except ssl.SSLCertVerificationError as e:
        return {'valid': False, 'error': f'SSL-сертификат недействителен: {e}'}
    except Exception as e:
        return {'valid': False, 'error': str(e)}                # Общая ошибка (сеть, таймаут)

# ─────────────────────────────────────────────────────────
# 4. Анализ веб-страницы (без изменений)
# ─────────────────────────────────────────────────────────
def fetch_page(url: str, timeout: int = 8) -> requests.Response:  # Загружает страницу по HTTP(S)
    headers = {'User-Agent': 'PhishBuster/1.0 (Security Scanner)'}  # Идентификатор сканера
    try:
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        return resp
    except Exception:
        return None                                             # При любой ошибке возвращаем None

def html_analysis(html: str, base_url: str) -> list:            # Ищет фишинговые индикаторы в HTML-коде
    flags = []
    if not html:
        return flags
    soup = BeautifulSoup(html, 'html.parser')                   # Парсим HTML
    base_domain = parse_url(base_url)['registered_domain']      # Домен страницы

    forms = soup.find_all('form')                               # Ищем все формы
    for form in forms:
        inputs = form.find_all('input')
        input_names = [inp.get('name', '').lower() for inp in inputs]
        if any('password' in name or 'pass' in name for name in input_names):
            flags.append("Обнаружена HTML-форма с полем 'password' (возможен сбор учётных данных)")
            break                                                # Достаточно одной формы

    iframes = soup.find_all('iframe', src=True)                 # Ищем все iframe с атрибутом src
    for iframe in iframes:
        style = (iframe.get('style') or '').lower()
        width = iframe.get('width', '')
        height = iframe.get('height', '')
        if width == '0' or height == '0' or 'hidden' in style or 'none' in style:
            flags.append("Обнаружен скрытый iframe")            # Скрытый iframe
        else:
            src_url = iframe.get('src')
            src_domain = parse_url(src_url)['registered_domain']
            if src_domain and src_domain != base_domain:
                flags.append(f"iframe загружает внешний ресурс: {src_url}")

    meta_refresh = soup.find('meta', attrs={'http-equiv': lambda v: v and v.lower() == 'refresh'})  # Мета-редирект
    if meta_refresh:
        flags.append(f"Обнаружен META refresh: {meta_refresh.get('content', '')}")

    scripts = soup.find_all('script')                           # Ищем все теги script
    for script in scripts:
        if not script.string:
            continue
        redirect_calls = re.findall(
            r'window\.location\.(?:href|assign|replace)\s*\(\s*["\']([^"\']+)["\']',
            script.string
        )
        for target_url in redirect_calls:                       # Если есть присваивание location
            target_domain = parse_url(target_url)['registered_domain']
            if target_domain and target_domain != base_domain:
                flags.append(f"JavaScript редирект на внешний домен: {target_url}")
                break

    for a in soup.find_all('a', href=True):                     # Анализ ссылок
        href = a.get('href')
        text = a.get_text(strip=True)
        if not text or not href:
            continue
        href_reg_domain = parse_url(href)['registered_domain']
        if not href_reg_domain:                                 # Относительная ссылка – пропускаем
            continue
        text_lower = text.lower()
        for brand in POPULAR_BRANDS:
            if brand in text_lower and len(text) < 50:          # Текст ссылки содержит бренд
                if brand not in href_reg_domain:
                    official = BRAND_OFFICIAL.get(brand, [])
                    if href_reg_domain not in official:         # Домен не официальный
                        flags.append(f"Ссылка с текстом '{text}' ведёт на домен {href_reg_domain}, не связанный с {brand}")
                        break
    return flags

# ─────────────────────────────────────────────────────────
# 5. Тайпсквоттинг (без изменений)
# ─────────────────────────────────────────────────────────
def check_typosquatting(domain: str) -> list:                   # Проверяет, похож ли домен на популярный бренд
    if not domain:
        return []
    ext = tldextract.extract(domain)                            # Извлекаем составляющие домена
    base = ext.domain.lower() if ext.domain else domain.lower() # Домен второго уровня
    flags = []
    for brand in POPULAR_BRANDS:
        if len(base) >= 4:
            distance = levenshtein_distance(base, brand.lower()) # Расстояние Левенштейна
            if 0 < distance <= 2:                                # Похож, но не точное совпадение
                official_domains = BRAND_OFFICIAL.get(brand, [])
                if domain not in official_domains:               # И не является официальным
                    flags.append(f"Возможный тайпсквоттинг: домен '{domain}' похож на '{brand}'")
                    break
    return flags

# ─────────────────────────────────────────────────────────
# 6. Чёрные списки (без изменений)
# ─────────────────────────────────────────────────────────
def check_blacklists(domain: str) -> list:                      # Проверяет домен по локальному файлу blacklist.txt
    try:
        with open('data/blacklist.txt', 'r') as f:
            blacklist = set(line.strip() for line in f if line.strip())
        if domain in blacklist:
            return ['local_blacklist']
    except FileNotFoundError:
        pass
    return []

# ─────────────────────────────────────────────────────────
# 7. Главная функция анализа
# ─────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict:                              # Комплексный анализ URL: синтаксис, DNS, WHOIS, SSL, контент
    if not DEPS_AVAILABLE:                                      # Если библиотеки не установлены
        return {'url': url, 'verdict': 'clean', 'score': 0,
                'flags': ['Библиотеки для анализа URL не установлены'],
                'details': {}}
    parsed = parse_url(url)                                     # Разбираем URL
    flags = []
    score = 0

    # Синтаксические признаки (без проверки длины)
    syntax_flags = check_url_syntax(url)
    for f in syntax_flags:
        if "Множественные //" in f:                             # Этот признак только предупреждает
            flags.append(f)                                     # Не добавляем баллы
        else:
            flags.append(f)
            score += 5

    domain = parsed['registered_domain']                        # Зарегистрированный домен
    dns = get_dns_records(domain)

    if dns.get('A') is None or len(dns.get('A', [])) == 0:     # Нет A-записи — домен не резолвится
        flags.append(f"Домен {domain} не разрешается в IP-адрес (нет A-записи)")
        score += 20

    if domain and ('mail' in domain or 'login' in domain or 'account' in domain) and not dns.get('MX'):
        flags.append(f"Домен {domain} не имеет MX-записи, хотя похож на почтовый сервис")
        score += 10

    whois_data = whois_info(domain)
    if 'error' not in whois_data:
        creation_str = whois_data.get('creation_date')
        if creation_str:
            try:
                creation_date = datetime.strptime(creation_str, '%Y-%m-%d')
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:                                # Домену меньше месяца
                    flags.append(f"Домен зарегистрирован менее 30 дней назад ({creation_str})")
                    score += 15
            except ValueError:
                pass

    # --- SSL (только для недоверенных доменов) ---
    ssl_result = {}
    if parsed['scheme'] == 'https' and parsed['hostname'] \
       and parsed.get('registered_domain') not in TRUSTED_DOMAINS:  # Проверяем только недоверенные домены
        port = parsed.get('port') or 443
        ssl_result = check_ssl_cert(parsed['hostname'], port)
        if not ssl_result.get('valid'):
            flags.append(f"Проблема с SSL: {ssl_result.get('error')}")
            score += 10

    # --- Загрузка страницы (только для недоверенных доменов) ---
    page_loaded = False
    final_url = url
    if parsed['scheme'] in ('http', 'https') and parsed.get('registered_domain') not in TRUSTED_DOMAINS:
        resp = fetch_page(url)
        if resp is not None:
            page_loaded = True
            final_url = resp.url
            if final_url == url or parse_url(final_url)['registered_domain'] == domain:
                page_flags = html_analysis(resp.text, url)      # Анализируем HTML
                for f in page_flags:
                    if "Скрытый iframe" in f or "Ссылка с текстом" in f:
                        score += 10                              # Повышенный вес для опасных элементов
                    else:
                        score += 5
                flags.extend(page_flags)
            else:                                                # Перенаправление на другой домен
                target_report = analyze_url(final_url)            # Рекурсивная проверка конечного URL
                if target_report['verdict'] == 'phishing':
                    flags.append(f"Перенаправление на ФИШИНГОВЫЙ сайт: {final_url}")
                    score += 25
                else:
                    flags.append(f"Перенаправление на другой домен (безопасный): {final_url}")
        else:
            flags.append("Не удалось загрузить страницу (сайт не отвечает)")
            score += 20

    typo_flags = check_typosquatting(domain)
    flags.extend(typo_flags)
    score += len(typo_flags) * 25                                # Тайпсквоттинг – серьёзный признак

    blacklisted = check_blacklists(domain)
    for bl in blacklisted:
        flags.append(f"Домен найден в чёрном списке: {bl}")
        score += 25

    score = min(score, 100)                                      # Ограничиваем максимальный балл
    verdict = 'phishing' if score >= 30 else 'clean'            # Порог 30

    return {
        'url': url,
        'verdict': verdict,
        'score': score,
        'flags': flags,
        'details': {
            'parsed': parsed,
            'dns': dns,
            'whois': whois_data,
            'ssl': ssl_result,
            'page_loaded': page_loaded,
            'final_url': final_url,
        }
    }

# ─────────────────────────────────────────────────────────
# 8. CLI-интерфейс (без изменений)
# ─────────────────────────────────────────────────────────
def is_valid_url(url: str) -> bool:                             # Проверка, что строка является валидным HTTP(S) URL
    if not url.startswith(('http://', 'https://')):              # Должна быть схема
        return False
    parsed = urlparse(url)
    return bool(parsed.netloc)                                   # Должен быть домен

def main():                                                      # Точка входа при запуске скрипта
    try:
        print("=" * 60)
        print("PhishBuster URL Analyzer")
        print("=" * 60)
        while True:                                               # Запрашиваем URL, пока не будет введён корректный
            url = input("Введи URL адрес полностью (http://example.com): ").strip()
            if not url:
                print("URL не введён. Завершение.")
                sys.exit(0)
            if not is_valid_url(url):
                print("Ошибка: введена некорректная ссылка. Попробуйте снова.")
                continue
            break

        report = analyze_url(url)

        print("\n" + "=" * 60)
        print("PhishBuster Url Analyzer – Результат")
        print("=" * 60)
        print(f"URL: {report['url']}")
        print(f"Вердикт: {report['verdict'].upper()} (score: {report['score']}/100)")
        if report['flags']:
            print("\nОбнаруженные признаки:")
            for flag in report['flags']:
                print(f"  • {flag}")
        else:
            print("\nПодозрительных признаков не найдено.")
        print("=" * 60)
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем (Ctrl+C).")
        print("=" * 60)
        sys.exit(0)
    except Exception as e:
        print(f"Ошибка анализа: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()