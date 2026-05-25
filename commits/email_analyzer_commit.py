#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
PhishBuster Email Analyzer (с белым списком CloudFront, TikTok и фильтром bounce)
Расширенный анализ .eml-файлов с балльной системой (0–100).
- Исключает bounce-адреса Google, Duolingo и любые другие с 'bounces.' в домене.
- Усилены веса реальных фишинговых признаков.
- Добавлены проверки: IP-ссылки, mismatch текст/HREF, короткие ссылки, подозрительные TLD.
- Новые правила для русскоязычных фишинговых писем (налоги, компенсации, ZIP-вложения).
- Интеграция с url_analyzer: проверка ссылок с таймаутом 10 секунд (не проверяются изображения и другие статические файлы).
Вердикт: PHISHING / CLEAN (порог >= 30). Score: 0–100.
Запуск: python3 email_analyzer.py
"""

import os                                                       # Работа с файловой системой
import sys                                                      # Завершение программы
import re                                                       # Регулярные выражения
import email                                                    # Парсинг .eml-файлов
import email.policy                                             # Политика разбора email
import concurrent.futures                                       # Потоки для таймаута анализа URL
from email.header import decode_header                          # Декодирование заголовков
from urllib.parse import urlparse                               # Разбор URL на компоненты
from url_analyzer import analyze_url as is_phishing_url         # Глубокий анализ URL

# ============================================================
# Каталог с .eml файлами
# ============================================================
CHECK_EMAIL_DIR = "/home/zakhar/phishbuster/phishbuster/check_email"  # Папка с письмами для проверки

# ============================================================
# Конфигурация баллов
# ============================================================
SCORE_PHISHING_URL = 35                                         # Балл за фишинговую ссылку
SCORE_SPOOF_RETURN_PATH = 25                                    # Балл за спуфинг Return-Path
SCORE_SPOOF_REPLY_TO = 20                                       # Балл за подмену Reply-To
SCORE_SUSPICIOUS_DOMAIN = 25                                    # Балл за подозрительный домен отправителя
SCORE_IMPERSONATION = 20                                        # Балл за имперсонацию компании
SCORE_SUBJECT_KEYWORDS = 15                                     # Балл за ключевые слова в теме
SCORE_URGENCY_SUBJECT = 15                                      # Балл за срочность в теме
SCORE_PHISHING_BODY_PHRASE = 25                                 # Балл за фишинговую фразу в теле
SCORE_DANGEROUS_ATTACHMENT = 30                                 # Балл за опасное вложение
SCORE_HIDDEN_TEXT = 15                                          # Балл за скрытый текст
SCORE_SPF_FAIL = 20                                             # Балл за провал SPF
SCORE_DMARC_FAIL = 20                                           # Балл за провал DMARC
SCORE_IP_URL = 25                                               # Балл за IP-ссылку
SCORE_MISMATCH_HREF = 30                                        # Балл за несовпадение текст/HREF
SCORE_SHORTENER_URL = 15                                        # Балл за сокращённую ссылку
SCORE_SUSPICIOUS_TLD = 20                                       # Балл за подозрительную доменную зону
SCORE_SUSPICIOUS_ARCHIVE = 20                                   # Балл за подозрительный архив
SCORE_FINANCIAL_BAIT = 20                                       # Балл за финансовую приманку
SCORE_URGENCY_BODY = 15                                         # Балл за срочность в теле
SCORE_FAKE_GOVERNMENT = 25                                      # Балл за выдачу за госорган

PHISHING_THRESHOLD = 30                                         # Порог баллов для вердикта PHISHING

# Доверенные домены (CloudFront, Google APIs, TikTok и др.)
TRUSTED_DOMAINS = {
    'google.com', 'google.ru', 'microsoft.com', 'office.com', 'apple.com',
    'amazon.com', 'paypal.com', 'facebook.com', 'instagram.com', 'twitter.com',
    'yandex.ru', 'mail.ru', 'vk.com', 'ok.ru',
    'nalog.ru', 'government.ru', 'pfr.gov.ru', 'rosminzdrav.gov.ru',
    'mil.ru', 'fssp.gov.ru', 'mchs.gov.ru', 'gosuslugi.ru',
    'cbr.ru', 'minfin.gov.ru', 'fsb.ru', 'mvd.gov.ru',
    'cloudfront.net', 'd2h7jmc5kw17oy.cloudfront.net', 'x.com',
    'notifications.googleapis.com', 'tiktok.com',
    'duolingo.com', 'geoguessr.com',
    'amazonaws.com',   'dashastat.ru', 'mbx-sender-02.ru',     'skillfactory.ru',
    'mckw.ru',
}

TRUSTED_HIDDEN_TEXT_SENDERS = {'google.com'}                     # Отправители, которым разрешён скрытый текст
TRUSTED_BOUNCE_PATTERNS = ['bounces.google.com', 'bounces.duolingo.com', 'bounce.']  # Шаблоны bounce-адресов

SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.bar', '.rest', '.wang', '.club', '.work', '.local', '.test',
}                                                                 # Подозрительные доменные зоны

URL_SHORTENERS = {                                               # Сервисы сокращения ссылок
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'shorte.st',
    'is.gd', 'buff.ly', 'adf.ly', 'bc.vc', 'rebrand.ly', 'tiny.cc',
    'clicky.me', 'shorturl.at', 'rb.gy', 'soo.gd', 's2r.co'
}

SUSPICIOUS_SUBJECT_WORDS = [                                     # Список подозрительных слов в теме
    'urgent', 'verify', 'account', 'suspend', 'limited', 'confirm',
    'password', 'credit', 'unusual activity', 'login attempt', 'click here',
    'update your', 'deactivation', 'expire', 'security alert', 'action required',
    'ваш аккаунт', 'подтвердит', 'подтвержден', 'срочно', 'блокировк',
    'верификаци', 'ограничен', 'доступ', 'безопасност',
    'компенсация', 'возврат', 'налог', 'выплата', 'реквизиты',
    'аннулирован', 'заполните форму', 'скачайте', 'деактивац',
    'задолженность', 'штраф', 'суд', 'прокуратура', 'мвд',
    'инвойс', 'invoice',
]

PHISHING_BODY_PHRASES = [                                        # Регулярки фишинговых фраз в теле
    r'click\s*here\s*to\s*verify',
    r'verify\s*your\s*account',
    r'your\s*account\s*has\s*been\s*limited',
    r'update\s*your\s*information',
    r'suspicious\s*activity',
    r'reset\s*your\s*password',
    r'log\s*in\s*immediately',
    r'ваш\s*аккаунт\s*заблокирован',
    r'подтвердит\w*\s*парол',
    r'срочно\s*обновит',
    r'начислена\s+компенсация',
    r'скачайте\s+и\s+заполните\s+форму',
    r'верните\s+(её|их)\s+нам',
    r'подтвердит\w*\s+реквизиты',
    r'в\s+течение\s+\d+\s+(дня|дней|часа|часов)',
    r'выплата\s+будет\s+аннулирована',
    r'заполните\s+прилагаемую\s+форму',
    r'форма\s+возврата',
    r'возврат\s+ндфл',
    r'компенсация\s+в\s+размере',
    r'требуется\s+подтверждение',
    r'ваш\s*идентификатор\s*был\s*заблокирован',
    r'ваш\s*счет\s*будет\s*заблокирован',
]

DANGEROUS_EXTENSIONS = {'.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1', '.hta', '.docm', '.xlsm'}  # Опасные расширения
SUSPICIOUS_ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.gz', '.tar', '.bz2'}  # Подозрительные архивы

FINANCIAL_BAIT_WORDS = [                                         # Слова финансовой приманки
    r'компенсация', r'выплата', r'возврат\s+средств', r'переплата',
    r'налоговый\s+вычет', r'субсидия', r'пособие', r'выигрыш',
    r'пени', r'поставк', r'налог', r'просрочк', r'задолженност',
]
GOVERNMENT_NAMES = [                                             # Названия госорганов для обнаружения имперсонации
    'фнс', 'налоговая', 'федеральная налоговая', 'мвд', 'прокуратура',
    'суд', 'пенсионный фонд', 'пфр', 'банк', 'центробанк', 'цб',
    'минфин', 'правительство', 'госуслуги', 'следственный комитет',
    'фсб', 'мчс', 'роскомнадзор', 'таможня', 'санэпидемстанция',
]

# ============================================================
# Вспомогательные функции
# ============================================================

def extract_urls_from_html(html_content):                       # Извлекает URL из атрибутов href в HTML
    urls = set()                                                # Множество для уникальных URL
    href_regex = r'href\s*=\s*["\'](https?://[^"\']+)["\']'    # Регулярное выражение для href
    matches = re.findall(href_regex, html_content, re.IGNORECASE)  # Поиск всех совпадений
    for url in matches:                                         # По найденным URL
        url = url.replace('&amp;', '&')                         # Заменяем HTML-сущность &amp; на &
        urls.add(url)                                           # Добавляем в множество
    return urls                                                 # Возвращаем множество URL

def extract_urls_from_text(text):                               # Извлекает URL из обычного текста
    url_regex = r'https?://[^\s<>"\'\)]+'                       # Регулярка для ссылок
    return set(re.findall(url_regex, text, re.IGNORECASE))      # Возвращаем множество найденных URL

def decode_email_part(part):                                    # Декодирует часть письма в строку
    charset = part.get_content_charset() or 'utf-8'             # Кодировка из заголовка или utf-8
    try:                                                        # Пробуем декодировать
        payload = part.get_payload(decode=True)                 # Получаем байты
        return payload.decode(charset, errors='replace')        # Преобразуем в строку, заменяя ошибки
    except Exception:                                            # Если ошибка
        return str(part.get_payload())                           # Возвращаем строковое представление

def get_header_value(msg, header_name):                         # Получает декодированное значение заголовка
    value = msg.get(header_name, '')                            # Берём сырое значение
    if not value:                                                # Если пусто – возвращаем пустую строку
        return ''
    decoded_parts = []                                           # Список для декодированных частей
    for part, encoding in decode_header(value):                 # Разбираем заголовок
        if isinstance(part, bytes):                              # Если часть байтовая
            try:                                                 # Пробуем декодировать
                decoded_parts.append(part.decode(encoding or 'utf-8', errors='replace'))
            except Exception:                                    # При ошибке
                decoded_parts.append(part.decode('utf-8', errors='replace'))
        else:                                                    # Если строка
            decoded_parts.append(str(part))                      # Просто добавляем
    return ' '.join(decoded_parts)                               # Склеиваем через пробел

def extract_email_address(full_header):                         # Извлекает email из заголовка вида "Имя <addr>"
    match = re.search(r'<([^>]+)>', full_header)                # Ищем адрес в угловых скобках
    if match:                                                    # Если нашли
        return match.group(1).lower()                           # Возвращаем нижним регистром
    if '@' in full_header:                                      # Если скобок нет, но есть @
        return full_header.strip().lower()                       # Возвращаем как есть
    return ''                                                    # Иначе пусто

def display_name(full_header):                                  # Извлекает отображаемое имя из заголовка From
    match = re.match(r'([^<]+)<', full_header)                  # Берём текст до угловой скобки
    if match:                                                    # Если нашли
        return match.group(1).strip().strip('"')                # Убираем пробелы и кавычки
    return ''                                                    # Иначе пусто

def get_email_domain(addr):                                     # Извлекает домен из email-адреса
    """Извлекает домен из email-адреса (часть после '@')."""
    if '@' in addr:                                              # Если есть @
        return addr.split('@', 1)[1]                            # Берём часть после @
    return ''                                                    # Иначе пусто

def is_ip_url(url):                                              # Проверяет, является ли хост IP-адресом
    try:                                                         # Пытаемся получить hostname
        host = urlparse(url).hostname                           # Хост из URL
        if host:                                                 # Если хост есть
            parts = host.split('.')                              # Разбиваем на части
            return len(parts) == 4 and all(p.isdigit() for p in parts)  # Проверяем формат IPv4
    except Exception:                                            # При ошибке
        pass
    return False                                                 # Не IP

def get_domain(url):                                             # Извлекает netloc (домен) из URL
    try:                                                         # Пробуем разобрать
        return urlparse(url).netloc.lower()                     # Возвращаем netloc в нижнем регистре
    except Exception:                                            # При ошибке
        return ''                                                # Пусто

def is_suspicious_tld(domain):                                   # Проверяет, входит ли домен в подозрительные зоны
    for tld in SUSPICIOUS_TLDS:                                  # По всем подозрительным TLD
        if domain.endswith(tld):                                 # Если домен заканчивается на TLD
            return True                                          # Возвращаем True
    return False                                                 # Ни одна не подошла

def analyze_url_with_timeout(url, timeout=5):                   # Вызывает url_analyzer с ограничением по времени
    """Вызывает url_analyzer с ограничением по времени. Возвращает словарь или None при ошибке/таймауте."""
    try:                                                         # Пробуем выполнить в потоке
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(is_phishing_url, url)       # Запускаем анализ URL
            return future.result(timeout=timeout)                # Ждём не более timeout секунд
    except (concurrent.futures.TimeoutError, Exception):         # Таймаут или ошибка
        return None                                              # Возвращаем None

# ============================================================
# Основная функция анализа
# ============================================================
def analyze_eml(filepath):                                      # Главная функция: анализ письма
    signs = []                                                   # Список обнаруженных признаков
    score = 0                                                    # Общий балл подозрительности

    with open(filepath, 'rb') as f:                              # Открываем .eml-файл в бинарном режиме
        msg = email.message_from_binary_file(f, policy=email.policy.default)  # Парсим письмо

    # --- Основные заголовки ---
    subject = get_header_value(msg, 'Subject')                  # Тема письма
    from_header = get_header_value(msg, 'From')                 # Заголовок From
    from_addr = extract_email_address(from_header)              # Email отправителя
    from_display = display_name(from_header)                    # Отображаемое имя
    return_path = get_header_value(msg, 'Return-Path')          # Return-Path
    reply_to = get_header_value(msg, 'Reply-To')                # Reply-To

    # --- 1. Проверка отправителя ---
    # Спуфинг Return-Path (пропускаем bounce‑адреса и поддомены)
    if return_path:                                              # Если Return-Path есть
        rp_addr = extract_email_address(return_path)             # Извлекаем адрес
        if rp_addr and from_addr and rp_addr != from_addr:       # Если адреса разные
            rp_domain = get_email_domain(rp_addr)                # Домен Return-Path
            from_domain_temp = get_email_domain(from_addr)       # Домен From
            # Пропускаем, если домены совпадают или один является поддоменом другого
            if rp_domain == from_domain_temp or \
               rp_domain.endswith('.' + from_domain_temp) or \
               from_domain_temp.endswith('.' + rp_domain):
                pass                                             # Не спуфинг
            else:
                # Пропускаем bounce‑адреса (локальная часть содержит 'bounce')
                local_part = rp_addr.split('@')[0] if '@' in rp_addr else ''
                if 'bounce' not in local_part and not any(rp_addr.endswith(pattern) for pattern in TRUSTED_BOUNCE_PATTERNS):
                    signs.append(f"Return-Path ({rp_addr}) ≠ From ({from_addr}) – спуфинг.")
                    score += SCORE_SPOOF_RETURN_PATH

    if reply_to:                                                 # Если Reply-To задан
        rt_addr = extract_email_address(reply_to)                # Извлекаем адрес
        if rt_addr and rt_addr != from_addr:                     # Если отличается от From
            signs.append(f"Reply-To ({rt_addr}) ≠ From ({from_addr}) – подмена.")
            score += SCORE_SPOOF_REPLY_TO

    from_domain = from_addr.split('@')[-1] if from_addr else ''  # Домен отправителя
    lookalike_markers = ['-secure', 'login-', 'account-', 'verify-', 'secure-', 'support-', 'service-',
                         '-pro', '-vendor', '-invoice', '-payment', '-billing', '-accounting']
    # Домен отправителя содержит финансовые/фишинговые ключевые слова
    financial_domain_keywords = ['invoice', 'vendor', 'payment', 'billing', 'accounting', 'finance', 'tax']
    if from_domain and any(kw in from_domain.lower() for kw in financial_domain_keywords):
        # проверяем, что это не официальный домен (не в TRUSTED_DOMAINS)
        if not any(from_domain.endswith('.' + td) or from_domain == td for td in TRUSTED_DOMAINS):
            signs.append(f"Подозрительный домен отправителя (финансовый контекст): {from_domain}")
            score += 15                                           # вес можно настроить

    commercial_names = ['microsoft', 'google', 'facebook', 'paypal', 'apple', 'amazon', 'сбербанк', 'яндекс', 'yandex']
    if from_display and any(comp in from_display.lower() for comp in commercial_names):
        if not any(comp in from_domain for comp in commercial_names):
            signs.append(f"Имя '{from_display}' похоже на компанию, но домен {from_domain} – не её.")
            score += SCORE_IMPERSONATION

    if from_display:                                             # Если есть отображаемое имя
        display_lower = from_display.lower()                    # Приводим к нижнему регистру
        for gov_name in GOVERNMENT_NAMES:                       # Проверяем на госорганы
            if gov_name in display_lower:                        # Найдено название госоргана
                if not any(from_domain.endswith('.' + td) or from_domain == td for td in TRUSTED_DOMAINS):
                    signs.append(f"Выдача за госорган ({from_display}), но домен {from_domain} не является официальным.")
                    score += SCORE_FAKE_GOVERNMENT
                break                                            # Достаточно одного совпадения

    # --- 2. Анализ темы ---
    if subject:                                                  # Если тема не пуста
        subj_lower = subject.lower()                             # Нижний регистр для поиска
        found_kw = [w for w in SUSPICIOUS_SUBJECT_WORDS if w in subj_lower]  # Ищем ключевые слова
        if found_kw:                                             # Если нашли
            signs.append(f"Тема содержит подозрительные слова: {', '.join(found_kw)}")
            score += SCORE_SUBJECT_KEYWORDS
        if re.search(r'(urgent|срочно|immediately|limited|action required|в течение \d+ (дней|часов)|до \d{1,2}:\d{2} сегодня|до конца (дня|недели))', subj_lower):
            signs.append("Тема создаёт давление (срочность/угроза).")
            score += SCORE_URGENCY_SUBJECT

    # --- 3. Разбор тела письма ---
    body_text = ""                                               # Текстовое содержимое
    html_text = ""                                               # HTML-содержимое
    all_urls = set()                                             # Множество всех URL
    href_text_pairs = []                                         # Пары (текст ссылки, href)
    has_suspicious_archives = False                              # Флаг подозрительного архива
    attachment_names = []                                        # Имена вложений

    if msg.is_multipart():                                       # Если письмо состоит из нескольких частей
        for part in msg.walk():                                  # Обходим все части
            ct = part.get_content_type()                         # Content-Type части
            if part.get_content_disposition() == 'attachment':   # Если это вложение
                fname = part.get_filename()                      # Имя файла
                if fname:                                        # Если имя есть
                    attachment_names.append(fname)               # Добавляем в список
                    ext = os.path.splitext(fname)[1].lower()    # Расширение
                    if ext in DANGEROUS_EXTENSIONS:              # Опасное расширение
                        signs.append(f"Опасное вложение: {fname} ({ext})")
                        score += SCORE_DANGEROUS_ATTACHMENT
                    if ext in SUSPICIOUS_ARCHIVE_EXTENSIONS:     # Архивное расширение
                        has_suspicious_archives = True           # Запоминаем
                continue                                         # К следующей части
            if ct == 'text/plain':                               # Текстовая часть
                text = decode_email_part(part)                   # Декодируем
                body_text += text + "\n"                         # Накапливаем текст
                all_urls.update(extract_urls_from_text(text))    # Извлекаем URL из текста
            elif ct == 'text/html':                              # HTML-часть
                html = decode_email_part(part)                   # Декодируем
                html_text += html + "\n"                         # Накапливаем HTML
                all_urls.update(extract_urls_from_html(html))    # Извлекаем URL из href
                all_urls.update(extract_urls_from_text(html))    # Извлекаем URL, просто написанные в HTML
                for match in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', html, re.IGNORECASE):
                    href = match.group(1).replace('&amp;', '&')  # Убираем &amp;
                    link_text = match.group(2).strip().lower()   # Текст ссылки
                    href_text_pairs.append((link_text, href))    # Сохраняем пару
    else:                                                        # Письмо состоит из одной части
        ct = msg.get_content_type()                              # Content-Type
        raw = decode_email_part(msg)                             # Декодируем тело
        if ct == 'text/plain':                                   # Только текст
            body_text = raw
            all_urls.update(extract_urls_from_text(raw))
        elif ct == 'text/html':                                  # Только HTML
            html_text = raw
            all_urls.update(extract_urls_from_html(raw))
            all_urls.update(extract_urls_from_text(raw))
            for match in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', raw, re.IGNORECASE):
                href = match.group(1).replace('&amp;', '&')
                link_text = match.group(2).strip().lower()
                href_text_pairs.append((link_text, href))

    # --- 4. Проверка фишинговых фраз ---
    combined_body = body_text + " " + re.sub(r'<[^>]+>', '', html_text)  # Объединённый текст без тегов
    for phrase in PHISHING_BODY_PHRASES:                         # По всем фишинговым фразам
        if re.search(phrase, combined_body, re.IGNORECASE):      # Если фраза найдена
            signs.append(f"Тело содержит фишинговую фразу: '{phrase}'")
            score += SCORE_PHISHING_BODY_PHRASE
            break                                                # Достаточно одной фразы

    for bait in FINANCIAL_BAIT_WORDS:                            # По финансовым приманкам
        if re.search(bait, combined_body, re.IGNORECASE):        # Найдена
            signs.append(f"Обнаружена финансовая приманка: '{bait}'")
            score += SCORE_FINANCIAL_BAIT
            break

    if re.search(r'в\s+течение\s+\d+\s+(дня|дней|часа|часов)|до\s+\d{1,2}:\d{2}\s+сегодня|до\s+конца\s+(дня|недели)', combined_body, re.IGNORECASE):
        signs.append("Ограничение по времени в теле письма (срочность).")
        score += SCORE_URGENCY_BODY

    # --- 5. Подозрительные архивы ---
    if has_suspicious_archives:                                  # Если есть архивы во вложениях
        bait_triggers = [                                        # Побудительные фразы
            r'скачайте', r'откройте', r'запустите', r'распакуйте', r'заполните форму',
            r'ознакомьтесь', r'установите', r'отправьте', r'верните',
        ]
        if any(re.search(trig, combined_body + ' ' + subject.lower(), re.IGNORECASE) for trig in bait_triggers):
            signs.append(f"Подозрительное вложение-архив: {', '.join(attachment_names)} (с побудительными фразами).")
            score += SCORE_SUSPICIOUS_ARCHIVE

    # --- 6. Анализ ссылок ---
    # Расширения файлов, которые не нужно проверять как веб-страницы
    skip_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.ico', '.css', '.js', '.pdf', '.zip', '.rar', '.doc', '.docx', '.xls', '.xlsx')
    for url in sorted(all_urls):                                 # Обходим все URL
        if not url.startswith(('http://', 'https://')):          # Если не http
            if 'www.w3.org/' in url:                             # XML-пространство имён
                continue                                         # Пропускаем
        # Пропускаем статические ресурсы (изображения, документы)
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            continue

        domain = get_domain(url)                                 # Домен ссылки
        if is_ip_url(url):                                       # IP вместо домена
            signs.append(f"Ссылка с IP-адресом: {url}")
            score += SCORE_IP_URL
        if domain in URL_SHORTENERS:                             # Сокращалка ссылок
            signs.append(f"Сокращатель ссылок: {url}")
            score += SCORE_SHORTENER_URL
        if is_suspicious_tld(domain):                            # Подозрительная зона
            signs.append(f"Подозрительная доменная зона: {url}")
            score += SCORE_SUSPICIOUS_TLD

        # Пропускаем доверенные домены – не проверяем их url_analyzer
        if any(domain.endswith('.' + td) or domain == td for td in TRUSTED_DOMAINS):
            continue

        # Проверка через url_analyzer с таймаутом
        report = analyze_url_with_timeout(url, timeout=10)
        if report is None:                                       # Таймаут или ошибка
            signs.append(f"Неопознанный сайт: {url}")
        elif isinstance(report, dict) and report.get('score', 0) >= 30:  # Фишинг по мнению url_analyzer
            signs.append(f"Фишинговая ссылка (url_analyzer): {url}")
            score += SCORE_PHISHING_URL

    # --- 7. Mismatch текст/HREF ---
    for link_text, href in href_text_pairs:                     # По всем ссылкам
        if link_text and re.search(r'(google|facebook|paypal|amazon|apple|microsoft|сбербанк|яндекс)', link_text):
            href_domain = get_domain(href)                       # Реальный домен
            # Пропускаем, если ссылка ведёт на тот же домен, что и отправитель (или его поддомен)
            if from_domain and (href_domain == from_domain or href_domain.endswith('.' + from_domain)):
                continue
            if not any(comp in href_domain for comp in commercial_names):
                signs.append(f"Несовпадение: текст ссылки «{link_text}», реальный домен {href_domain}")
                score += SCORE_MISMATCH_HREF
                break

    # --- 8. Заголовки безопасности ---
    spf = msg.get('Received-SPF', '')                            # Проверка SPF
    if spf and 'fail' in spf.lower():                            # SPF fail
        signs.append("SPF fail")
        score += SCORE_SPF_FAIL
    dmarc = msg.get('DMARC-Result', msg.get('Authentication-Results', ''))  # Проверка DMARC
    if dmarc and 'fail' in dmarc.lower():                        # DMARC fail
        signs.append("DMARC fail")
        score += SCORE_DMARC_FAIL

    # --- 9. Скрытый мелкий текст ---
    if 'font-size: 1px' in html_text or 'font-size:1px' in html_text:  # Есть скрытый текст
        if from_domain not in TRUSTED_HIDDEN_TEXT_SENDERS:        # Отправитель не в белом списке
            signs.append("Обнаружен скрытый мелкий текст (font-size:1px)")
            score += SCORE_HIDDEN_TEXT

    score = min(score, 100)                                      # Ограничиваем балл до 100

    if score >= PHISHING_THRESHOLD:                              # Сравниваем с порогом
        verdict = "PHISHING"
    else:
        verdict = "CLEAN"

    if not signs:                                                # Если признаков не обнаружено
        signs.append("Фишинговые признаки не обнаружены.")

    return {                                                     # Возвращаем результат
        'filepath': filepath,
        'subject': subject,
        'from': from_header,
        'verdict': verdict,
        'score': score,
        'signs': signs
    }

# ============================================================
# Интерфейс запуска
# ============================================================
def main():                                                      # Точка входа при запуске скрипта
    try:                                                         # Обрабатываем Ctrl+C
        print("=" * 60)
        print("PhishBuster Email Analyzer")
        print("=" * 60)
        print("Сохраните .eml в папку:")
        print(f"  {CHECK_EMAIL_DIR}\n")

        filename = input("Имя файла: ").strip()                 # Запрашиваем имя файла
        if not filename:                                         # Если пусто
            print("Ошибка: имя файла не введено.")
            sys.exit(1)

        filepath = os.path.join(CHECK_EMAIL_DIR, filename)       # Полный путь
        if not os.path.isfile(filepath):                         # Файл не существует
            print(f"Ошибка: файл '{filepath}' не найден.")
            sys.exit(1)

        print("\n" + "=" * 60)
        result = analyze_eml(filepath)                           # Анализируем письмо
        print("PhishBuster Email Analyzer - Результат")
        print("=" * 60)
        print(f"Файл: {result['filepath']}")
        print(f"Тема: {result['subject']}")
        print(f"От: {result['from']}")
        print(f"Вердикт: {result['verdict']} (Score: {result['score']}/100)")
        print("\nОбнаруженные признаки фишинга:")
        for sign in result['signs']:                             # Выводим все признаки
            print(f" • {sign}")
    except KeyboardInterrupt:                                    # Нажали Ctrl+C
        print("\nПрограмма прервана пользователем (Ctrl+C).")
        print("=" * 60)
        sys.exit(0)

if __name__ == "__main__":
    main()
