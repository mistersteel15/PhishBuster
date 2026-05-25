#!/usr/bin/env python3
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

import os
import sys
import re
import email
import email.policy
import concurrent.futures
from email.header import decode_header
from urllib.parse import urlparse
from url_analyzer import analyze_url as is_phishing_url

# ============================================================
# Каталог с .eml файлами
# ============================================================
CHECK_EMAIL_DIR = "/home/zakhar/phishbuster/phishbuster/check_email"

# ============================================================
# Конфигурация баллов
# ============================================================
SCORE_PHISHING_URL = 35
SCORE_SPOOF_RETURN_PATH = 25
SCORE_SPOOF_REPLY_TO = 20
SCORE_SUSPICIOUS_DOMAIN = 25
SCORE_IMPERSONATION = 20
SCORE_SUBJECT_KEYWORDS = 15
SCORE_URGENCY_SUBJECT = 15
SCORE_PHISHING_BODY_PHRASE = 25
SCORE_DANGEROUS_ATTACHMENT = 30
SCORE_HIDDEN_TEXT = 15
SCORE_SPF_FAIL = 20
SCORE_DMARC_FAIL = 20
SCORE_IP_URL = 25
SCORE_MISMATCH_HREF = 30
SCORE_SHORTENER_URL = 15
SCORE_SUSPICIOUS_TLD = 20
SCORE_SUSPICIOUS_ARCHIVE = 20
SCORE_FINANCIAL_BAIT = 20
SCORE_URGENCY_BODY = 15
SCORE_FAKE_GOVERNMENT = 25

PHISHING_THRESHOLD = 30

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

TRUSTED_HIDDEN_TEXT_SENDERS = {'google.com'}
TRUSTED_BOUNCE_PATTERNS = ['bounces.google.com', 'bounces.duolingo.com', 'bounce.']

SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.bar', '.rest', '.wang', '.club', '.work', '.local', '.test', 
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'shorte.st',
    'is.gd', 'buff.ly', 'adf.ly', 'bc.vc', 'rebrand.ly', 'tiny.cc',
    'clicky.me', 'shorturl.at', 'rb.gy', 'soo.gd', 's2r.co'
}

SUSPICIOUS_SUBJECT_WORDS = [
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

PHISHING_BODY_PHRASES = [
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

DANGEROUS_EXTENSIONS = {'.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1', '.hta', '.docm', '.xlsm'}
SUSPICIOUS_ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.gz', '.tar', '.bz2'}

FINANCIAL_BAIT_WORDS = [
    r'компенсация', r'выплата', r'возврат\s+средств', r'переплата',
    r'налоговый\s+вычет', r'субсидия', r'пособие', r'выигрыш',
    r'пени', r'поставк', r'налог', r'просрочк', r'задолженност',
]
GOVERNMENT_NAMES = [
    'фнс', 'налоговая', 'федеральная налоговая', 'мвд', 'прокуратура',
    'суд', 'пенсионный фонд', 'пфр', 'банк', 'центробанк', 'цб',
    'минфин', 'правительство', 'госуслуги', 'следственный комитет',
    'фсб', 'мчс', 'роскомнадзор', 'таможня', 'санэпидемстанция',
]

# ============================================================
# Вспомогательные функции
# ============================================================

def extract_urls_from_html(html_content):
    urls = set()
    href_regex = r'href\s*=\s*["\'](https?://[^"\']+)["\']'
    matches = re.findall(href_regex, html_content, re.IGNORECASE)
    for url in matches:
        url = url.replace('&amp;', '&')
        urls.add(url)
    return urls

def extract_urls_from_text(text):
    url_regex = r'https?://[^\s<>"\'\)]+'
    return set(re.findall(url_regex, text, re.IGNORECASE))

def decode_email_part(part):
    charset = part.get_content_charset() or 'utf-8'
    try:
        payload = part.get_payload(decode=True)
        return payload.decode(charset, errors='replace')
    except Exception:
        return str(part.get_payload())

def get_header_value(msg, header_name):
    value = msg.get(header_name, '')
    if not value:
        return ''
    decoded_parts = []
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            try:
                decoded_parts.append(part.decode(encoding or 'utf-8', errors='replace'))
            except Exception:
                decoded_parts.append(part.decode('utf-8', errors='replace'))
        else:
            decoded_parts.append(str(part))
    return ' '.join(decoded_parts)

def extract_email_address(full_header):
    match = re.search(r'<([^>]+)>', full_header)
    if match:
        return match.group(1).lower()
    if '@' in full_header:
        return full_header.strip().lower()
    return ''

def display_name(full_header):
    match = re.match(r'([^<]+)<', full_header)
    if match:
        return match.group(1).strip().strip('"')
    return ''

def get_email_domain(addr):
    """Извлекает домен из email-адреса (часть после '@')."""
    if '@' in addr:
        return addr.split('@', 1)[1]
    return ''

def is_ip_url(url):
    try:
        host = urlparse(url).hostname
        if host:
            parts = host.split('.')
            return len(parts) == 4 and all(p.isdigit() for p in parts)
    except Exception:
        pass
    return False

def get_domain(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ''

def is_suspicious_tld(domain):
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False

def analyze_url_with_timeout(url, timeout=5):
    """Вызывает url_analyzer с ограничением по времени. Возвращает словарь или None при ошибке/таймауте."""
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(is_phishing_url, url)
            return future.result(timeout=timeout)
    except (concurrent.futures.TimeoutError, Exception):
        return None

# ============================================================
# Основная функция анализа
# ============================================================
def analyze_eml(filepath):
    signs = []
    score = 0

    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    # --- Основные заголовки ---
    subject = get_header_value(msg, 'Subject')
    from_header = get_header_value(msg, 'From')
    from_addr = extract_email_address(from_header)
    from_display = display_name(from_header)
    return_path = get_header_value(msg, 'Return-Path')
    reply_to = get_header_value(msg, 'Reply-To')

    # --- 1. Проверка отправителя ---
    # Спуфинг Return-Path (пропускаем bounce‑адреса и поддомены)
    if return_path:
        rp_addr = extract_email_address(return_path)
        if rp_addr and from_addr and rp_addr != from_addr:
            rp_domain = get_email_domain(rp_addr)
            from_domain_temp = get_email_domain(from_addr)
            # Пропускаем, если домены совпадают или один является поддоменом другого
            if rp_domain == from_domain_temp or \
               rp_domain.endswith('.' + from_domain_temp) or \
               from_domain_temp.endswith('.' + rp_domain):
                pass  # не спуфинг
            else:
                # Пропускаем bounce‑адреса
                local_part = rp_addr.split('@')[0] if '@' in rp_addr else ''
                if 'bounce' not in local_part and not any(rp_addr.endswith(pattern) for pattern in TRUSTED_BOUNCE_PATTERNS):
                    signs.append(f"Return-Path ({rp_addr}) ≠ From ({from_addr}) – спуфинг.")
                    score += SCORE_SPOOF_RETURN_PATH

    if reply_to:
        rt_addr = extract_email_address(reply_to)
        if rt_addr and rt_addr != from_addr:
            signs.append(f"Reply-To ({rt_addr}) ≠ From ({from_addr}) – подмена.")
            score += SCORE_SPOOF_REPLY_TO

    from_domain = from_addr.split('@')[-1] if from_addr else ''
    lookalike_markers = ['-secure', 'login-', 'account-', 'verify-', 'secure-', 'support-', 'service-',
                         '-pro', '-vendor', '-invoice', '-payment', '-billing', '-accounting']
    # Домен отправителя содержит финансовые/фишинговые ключевые слова
    financial_domain_keywords = ['invoice', 'vendor', 'payment', 'billing', 'accounting', 'finance', 'tax']
    if from_domain and any(kw in from_domain.lower() for kw in financial_domain_keywords):
        # проверяем, что это не официальный домен (не в TRUSTED_DOMAINS)
        if not any(from_domain.endswith('.' + td) or from_domain == td for td in TRUSTED_DOMAINS):
            signs.append(f"Подозрительный домен отправителя (финансовый контекст): {from_domain}")
            score += 15   # вес можно настроить

    commercial_names = ['microsoft', 'google', 'facebook', 'paypal', 'apple', 'amazon', 'сбербанк', 'яндекс', 'yandex']
    if from_display and any(comp in from_display.lower() for comp in commercial_names):
        if not any(comp in from_domain for comp in commercial_names):
            signs.append(f"Имя '{from_display}' похоже на компанию, но домен {from_domain} – не её.")
            score += SCORE_IMPERSONATION

    if from_display:
        display_lower = from_display.lower()
        for gov_name in GOVERNMENT_NAMES:
            if gov_name in display_lower:
                if not any(from_domain.endswith('.' + td) or from_domain == td for td in TRUSTED_DOMAINS):
                    signs.append(f"Выдача за госорган ({from_display}), но домен {from_domain} не является официальным.")
                    score += SCORE_FAKE_GOVERNMENT
                break

    # --- 2. Анализ темы ---
    if subject:
        subj_lower = subject.lower()
        found_kw = [w for w in SUSPICIOUS_SUBJECT_WORDS if w in subj_lower]
        if found_kw:
            signs.append(f"Тема содержит подозрительные слова: {', '.join(found_kw)}")
            score += SCORE_SUBJECT_KEYWORDS
        if re.search(r'(urgent|срочно|immediately|limited|action required|в течение \d+ (дней|часов)|до \d{1,2}:\d{2} сегодня|до конца (дня|недели))', subj_lower):
            signs.append("Тема создаёт давление (срочность/угроза).")
            score += SCORE_URGENCY_SUBJECT

    # --- 3. Разбор тела письма ---
    body_text = ""
    html_text = ""
    all_urls = set()
    href_text_pairs = []
    has_suspicious_archives = False
    attachment_names = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if part.get_content_disposition() == 'attachment':
                fname = part.get_filename()
                if fname:
                    attachment_names.append(fname)
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in DANGEROUS_EXTENSIONS:
                        signs.append(f"Опасное вложение: {fname} ({ext})")
                        score += SCORE_DANGEROUS_ATTACHMENT
                    if ext in SUSPICIOUS_ARCHIVE_EXTENSIONS:
                        has_suspicious_archives = True
                continue

            if ct == 'text/plain':
                text = decode_email_part(part)
                body_text += text + "\n"
                all_urls.update(extract_urls_from_text(text))
            elif ct == 'text/html':
                html = decode_email_part(part)
                html_text += html + "\n"
                all_urls.update(extract_urls_from_html(html))
                all_urls.update(extract_urls_from_text(html))
                for match in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', html, re.IGNORECASE):
                    href = match.group(1).replace('&amp;', '&')
                    link_text = match.group(2).strip().lower()
                    href_text_pairs.append((link_text, href))
    else:
        ct = msg.get_content_type()
        raw = decode_email_part(msg)
        if ct == 'text/plain':
            body_text = raw
            all_urls.update(extract_urls_from_text(raw))
        elif ct == 'text/html':
            html_text = raw
            all_urls.update(extract_urls_from_html(raw))
            all_urls.update(extract_urls_from_text(raw))
            for match in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', raw, re.IGNORECASE):
                href = match.group(1).replace('&amp;', '&')
                link_text = match.group(2).strip().lower()
                href_text_pairs.append((link_text, href))

    # --- 4. Проверка фишинговых фраз ---
    combined_body = body_text + " " + re.sub(r'<[^>]+>', '', html_text)
    for phrase in PHISHING_BODY_PHRASES:
        if re.search(phrase, combined_body, re.IGNORECASE):
            signs.append(f"Тело содержит фишинговую фразу: '{phrase}'")
            score += SCORE_PHISHING_BODY_PHRASE
            break

    for bait in FINANCIAL_BAIT_WORDS:
        if re.search(bait, combined_body, re.IGNORECASE):
            signs.append(f"Обнаружена финансовая приманка: '{bait}'")
            score += SCORE_FINANCIAL_BAIT
            break

    if re.search(r'в\s+течение\s+\d+\s+(дня|дней|часа|часов)|до\s+\d{1,2}:\d{2}\s+сегодня|до\s+конца\s+(дня|недели)', combined_body, re.IGNORECASE):
        signs.append("Ограничение по времени в теле письма (срочность).")
        score += SCORE_URGENCY_BODY

    # --- 5. Подозрительные архивы ---
    if has_suspicious_archives:
        bait_triggers = [
            r'скачайте', r'откройте', r'запустите', r'распакуйте', r'заполните форму',
            r'ознакомьтесь', r'установите', r'отправьте', r'верните',
        ]
        if any(re.search(trig, combined_body + ' ' + subject.lower(), re.IGNORECASE) for trig in bait_triggers):
            signs.append(f"Подозрительное вложение-архив: {', '.join(attachment_names)} (с побудительными фразами).")
            score += SCORE_SUSPICIOUS_ARCHIVE

    # --- 6. Анализ ссылок ---
    # Расширения файлов, которые не нужно проверять как веб-страницы
    skip_extensions = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp', '.ico', '.css', '.js', '.pdf', '.zip', '.rar', '.doc', '.docx', '.xls', '.xlsx')
    for url in sorted(all_urls):
        if not url.startswith(('http://', 'https://')):
            if 'www.w3.org/' in url:
                continue
        # Пропускаем статические ресурсы (изображения, документы)
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            continue

        domain = get_domain(url)
        if is_ip_url(url):
            signs.append(f"Ссылка с IP-адресом: {url}")
            score += SCORE_IP_URL
        if domain in URL_SHORTENERS:
            signs.append(f"Сокращатель ссылок: {url}")
            score += SCORE_SHORTENER_URL
        if is_suspicious_tld(domain):
            signs.append(f"Подозрительная доменная зона: {url}")
            score += SCORE_SUSPICIOUS_TLD

        # Пропускаем доверенные домены – не проверяем их url_analyzer
        if any(domain.endswith('.' + td) or domain == td for td in TRUSTED_DOMAINS):
            continue

        # Проверка через url_analyzer с таймаутом
        report = analyze_url_with_timeout(url, timeout=10)
        if report is None:
            signs.append(f"Неопознанный сайт: {url}")
        elif isinstance(report, dict) and report.get('score', 0) >= 30:
            signs.append(f"Фишинговая ссылка (url_analyzer): {url}")
            score += SCORE_PHISHING_URL

    # --- 7. Mismatch текст/HREF ---
    for link_text, href in href_text_pairs:
        if link_text and re.search(r'(google|facebook|paypal|amazon|apple|microsoft|сбербанк|яндекс)', link_text):
            href_domain = get_domain(href)
            # Пропускаем, если ссылка ведёт на тот же домен, что и отправитель (или его поддомен)
            if from_domain and (href_domain == from_domain or href_domain.endswith('.' + from_domain)):
                continue
            if not any(comp in href_domain for comp in commercial_names):
                signs.append(f"Несовпадение: текст ссылки «{link_text}», реальный домен {href_domain}")
                score += SCORE_MISMATCH_HREF
                break

    # --- 8. Заголовки безопасности ---
    spf = msg.get('Received-SPF', '')
    if spf and 'fail' in spf.lower():
        signs.append("SPF fail")
        score += SCORE_SPF_FAIL
    dmarc = msg.get('DMARC-Result', msg.get('Authentication-Results', ''))
    if dmarc and 'fail' in dmarc.lower():
        signs.append("DMARC fail")
        score += SCORE_DMARC_FAIL

    # --- 9. Скрытый мелкий текст ---
    if 'font-size: 1px' in html_text or 'font-size:1px' in html_text:
        if from_domain not in TRUSTED_HIDDEN_TEXT_SENDERS:
            signs.append("Обнаружен скрытый мелкий текст (font-size:1px)")
            score += SCORE_HIDDEN_TEXT

    score = min(score, 100)

    if score >= PHISHING_THRESHOLD:
        verdict = "PHISHING"
    else:
        verdict = "CLEAN"

    if not signs:
        signs.append("Фишинговые признаки не обнаружены.")

    return {
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
def main():
    try:
        print("=" * 60)
        print("PhishBuster Email Analyzer")
        print("=" * 60)
        print("Сохраните .eml в папку:")
        print(f"  {CHECK_EMAIL_DIR}\n")

        filename = input("Имя файла: ").strip()
        if not filename:
            print("Ошибка: имя файла не введено.")
            sys.exit(1)

        filepath = os.path.join(CHECK_EMAIL_DIR, filename)
        if not os.path.isfile(filepath):
            print(f"Ошибка: файл '{filepath}' не найден.")
            sys.exit(1)

        print("\n" + "=" * 60)
        result = analyze_eml(filepath)
        print("PhishBuster Email Analyzer - Результат")
        print("=" * 60)
        print(f"Файл: {result['filepath']}")
        print(f"Тема: {result['subject']}")
        print(f"От: {result['from']}")
        print(f"Вердикт: {result['verdict']} (Score: {result['score']}/100)")
        print("\nОбнаруженные признаки фишинга:")
        for sign in result['signs']:
            print(f" • {sign}")
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем (Ctrl+C).")
        print("=" * 60)
        sys.exit(0)

if __name__ == "__main__":
    main()
