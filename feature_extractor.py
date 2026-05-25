#!/usr/bin/env python3
"""
PhishBuster – Этап 3: Извлечение признаков (Feature Extractor)
Совместим с email_analyzer.py и url_analyzer.py.
Извлекает числовые признаки из .eml-файлов или URL.
Использование:
    python3 feature_extractor.py          # интерактивный ввод
    python3 feature_extractor.py письмо.eml   # JSON для письма
    python3 feature_extractor.py https://example.com # JSON для URL
"""

import os
import sys
import re
import email
import email.policy
from urllib.parse import urlparse
from email.header import decode_header
from datetime import datetime



# ----------------------------------------------
# Попытка импорта анализаторов из текущей папки
# ----------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from email_analyzer import analyze_eml
    EMAIL_ANALYZER = True
except ImportError:
    EMAIL_ANALYZER = False
    # Без вывода, чтобы не засорять консоль при интерактиве

try:
    from url_analyzer import analyze_url as url_analyzer_func
    URL_ANALYZER = True
except ImportError:
    URL_ANALYZER = False

# ----------------------------------------------
# Константы
# ----------------------------------------------
SUSPICIOUS_SUBJECT_WORDS = [
    'urgent', 'verify', 'account', 'suspend', 'limited', 'confirm',
    'password', 'credit', 'unusual activity', 'login attempt', 'click here',
    'update your', 'deactivation', 'expire', 'security alert', 'action required',
    'ваш аккаунт', 'подтвердит', 'подтвержден', 'срочно', 'блокировк', 'парол',
    'верификаци', 'ограничен', 'доступ', 'безопасност',
    'компенсация', 'возврат', 'налог', 'выплата', 'реквизиты',
    'аннулирован', 'заполните форму', 'скачайте', 'деактивац',
    'задолженность', 'штраф', 'суд', 'прокуратура', 'мвд',
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
SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.bar', '.rest', '.wang', '.club', '.work'}
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'shorte.st',
    'is.gd', 'buff.ly', 'adf.ly', 'bc.vc', 'rebrand.ly', 'tiny.cc',
    'clicky.me', 'shorturl.at', 'rb.gy', 'soo.gd', 's2r.co'
}

# ----------------------------------------------
# Вспомогательные функции
# ----------------------------------------------
def _decode_part(part):
    charset = part.get_content_charset() or 'utf-8'
    try:
        payload = part.get_payload(decode=True)
        return payload.decode(charset, errors='replace')
    except Exception:
        return str(part.get_payload())

def _decode_header_val(msg, name):
    value = msg.get(name, '')
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

def _extract_urls_from_html(html):
    urls = set()
    for m in re.finditer(r'href\s*=\s*["\'](https?://[^"\']+)["\']', html, re.IGNORECASE):
        url = m.group(1).replace('&amp;', '&')
        urls.add(url)
    return urls

def _extract_urls_from_text(text):
    return set(re.findall(r'https?://[^\s<>"\'\)]+', text, re.IGNORECASE))

def _get_domain(url):
    try:
        return urlparse(url).netloc.lower()
    except:
        return ''

def _is_ip_url(url):
    try:
        host = urlparse(url).hostname
        if host:
            parts = host.split('.')
            return len(parts) == 4 and all(p.isdigit() for p in parts)
    except:
        pass
    return False

def _email_domain(addr):
    if '@' in addr:
        return addr.split('@', 1)[1]
    return ''

# ----------------------------------------------
# Извлечение признаков из письма
# ----------------------------------------------
def extract_email_features(filepath):
    features = {}
    if EMAIL_ANALYZER:
        try:
            report = analyze_eml(filepath)
            features['score_from_analyzer'] = report['score']
            features['verdict_code'] = 1 if report['verdict'] == 'PHISHING' else 0
        except Exception:
            features['score_from_analyzer'] = -1
            features['verdict_code'] = -1
    else:
        features['score_from_analyzer'] = -1
        features['verdict_code'] = -1

    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    subject = _decode_header_val(msg, 'Subject')
    from_header = _decode_header_val(msg, 'From')
    from_addr = re.search(r'<([^>]+)>', from_header)
    from_addr = from_addr.group(1) if from_addr else from_header.strip()
    from_domain = _email_domain(from_addr) if '@' in from_addr else ''

    features['subject_length'] = len(subject)
    features['from_domain'] = from_domain

    body_text = ""
    html_text = ""
    all_urls = set()
    href_text_pairs = []
    attachment_names = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if part.get_content_disposition() == 'attachment':
                fname = part.get_filename()
                if fname:
                    attachment_names.append(fname)
                continue
            if ct == 'text/plain':
                text = _decode_part(part)
                body_text += text + "\n"
                all_urls.update(_extract_urls_from_text(text))
            elif ct == 'text/html':
                html = _decode_part(part)
                html_text += html + "\n"
                all_urls.update(_extract_urls_from_html(html))
                all_urls.update(_extract_urls_from_text(html))
                for m in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', html, re.IGNORECASE):
                    href = m.group(1).replace('&amp;', '&')
                    link_text = m.group(2).strip().lower()
                    href_text_pairs.append((link_text, href))
    else:
        ct = msg.get_content_type()
        raw = _decode_part(msg)
        if ct == 'text/plain':
            body_text = raw
            all_urls.update(_extract_urls_from_text(raw))
        elif ct == 'text/html':
            html_text = raw
            all_urls.update(_extract_urls_from_html(raw))
            all_urls.update(_extract_urls_from_text(raw))
            for m in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', raw, re.IGNORECASE):
                href = m.group(1).replace('&amp;', '&')
                link_text = m.group(2).strip().lower()
                href_text_pairs.append((link_text, href))

    combined_body = body_text + " " + re.sub(r'<[^>]+>', '', html_text)
    features['body_length'] = len(combined_body)
    url_list = list(all_urls)
    features['url_count'] = len(url_list)
    features['ip_url_count'] = sum(1 for u in url_list if _is_ip_url(u))
    features['shortener_url_count'] = sum(1 for u in url_list if _get_domain(u) in URL_SHORTENERS)
    features['suspicious_tld_url_count'] = sum(1 for u in url_list if any(_get_domain(u).endswith(tld) for tld in SUSPICIOUS_TLDS))
    features['phishing_phrase_count'] = sum(1 for phrase in PHISHING_BODY_PHRASES if re.search(phrase, combined_body, re.IGNORECASE))
    subj_lower = subject.lower()
    features['subject_suspicious_keywords'] = sum(1 for w in SUSPICIOUS_SUBJECT_WORDS if w in subj_lower)
    features['dangerous_attachment'] = 1 if any(os.path.splitext(f)[1].lower() in DANGEROUS_EXTENSIONS for f in attachment_names) else 0
    features['suspicious_archive'] = 1 if any(os.path.splitext(f)[1].lower() in SUSPICIOUS_ARCHIVE_EXTENSIONS for f in attachment_names) else 0

    mismatch_count = 0
    for link_text, href in href_text_pairs:
        if link_text and re.search(r'(google|facebook|paypal|amazon|apple|microsoft|сбербанк|яндекс)', link_text):
            href_domain = _get_domain(href)
            if not any(comp in href_domain for comp in ['google','facebook','paypal','amazon','apple','microsoft','сбербанк','яндекс']):
                mismatch_count += 1
    features['mismatch_href_count'] = mismatch_count

    spf = msg.get('Received-SPF', '')
    features['spf_fail'] = 1 if spf and 'fail' in spf.lower() else 0
    dmarc = msg.get('DMARC-Result', msg.get('Authentication-Results', ''))
    features['dmarc_fail'] = 1 if dmarc and 'fail' in dmarc.lower() else 0

    features['hidden_text'] = 1 if ('font-size: 1px' in html_text or 'font-size:1px' in html_text) else 0
    features['urgency_body'] = 1 if re.search(r'в\s+течение\s+\d+\s+(дня|дней|часа|часов)', combined_body, re.IGNORECASE) else 0
    financial = ['компенсация', 'выплата', 'возврат средств', 'переплата', 'налоговый вычет', 'субсидия', 'пособие', 'выигрыш']
    features['financial_bait'] = 1 if any(re.search(w, combined_body, re.IGNORECASE) for w in financial) else 0

    from_display = re.match(r'([^<]+)<', from_header)
    from_display = from_display.group(1).strip().strip('"') if from_display else ''
    gov_names = ['фнс', 'налоговая', 'федеральная налоговая', 'мвд', 'прокуратура', 'суд', 'пенсионный фонд', 'пфр', 'банк', 'центробанк', 'цб', 'минфин', 'правительство', 'госуслуги', 'следственный комитет', 'фсб', 'мчс', 'роскомнадзор', 'таможня', 'санэпидемстанция']
    features['government_impersonation'] = 1 if any(g in from_display.lower() for g in gov_names) else 0

    free_domains = {'gmail.com', 'yandex.ru', 'mail.ru', 'outlook.com', 'hotmail.com', 'yahoo.com', 'protonmail.com'}
    features['free_email_sender'] = 1 if from_domain in free_domains else 0
    markers = ['-secure', 'login-', 'account-', 'verify-', 'secure-', 'support-', 'service-']
    features['suspicious_domain_marker'] = 1 if any(m in from_domain for m in markers) else 0
    features['sender_suspicious_tld'] = 1 if any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
    features['sender_domain_age_days'] = -1

    return features

# ----------------------------------------------
# Извлечение признаков из URL
# ----------------------------------------------
def extract_url_features(url):
    features = {}
    if URL_ANALYZER:
        try:
            report = url_analyzer_func(url)
            features['url_score_from_analyzer'] = report.get('score', 0)
            features['url_flags_count'] = len(report.get('flags', []))
            parsed = report.get('details', {}).get('parsed', {})
            features['url_length'] = len(url)
            features['has_ip'] = 1 if (parsed.get('hostname') and re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed['hostname'])) else 0
            features['has_at'] = 1 if '@' in url else 0
            features['non_standard_port'] = 1 if parsed.get('port') and parsed['port'] not in {80, 443, 8080, 8443} else 0
            features['path_length'] = len(parsed.get('path', ''))
            features['query_length'] = len(parsed.get('query', ''))
            ssl = report.get('details', {}).get('ssl', {})
            features['has_ssl'] = 1 if ssl.get('valid') else 0
            features['ssl_hostname_match'] = 1 if ssl.get('hostname_match') else 0
            dns = report.get('details', {}).get('dns', {})
            features['dns_has_a'] = 1 if dns.get('A') else 0
            features['dns_has_mx'] = 1 if dns.get('MX') else 0
            whois_data = report.get('details', {}).get('whois', {})
            age = -1
            if 'creation_date' in whois_data:
                try:
                    creation_str = whois_data['creation_date']
                    creation_date = datetime.strptime(creation_str, '%Y-%m-%d')
                    age = (datetime.now() - creation_date).days
                except:
                    pass
            features['domain_age_days'] = age
            flags = report.get('flags', [])
            features['has_form_flag'] = 1 if any('форма' in f or 'form' in f.lower() for f in flags) else 0
            features['has_hidden_iframe'] = 1 if any('скрытый iframe' in f or 'hidden iframe' in f.lower() for f in flags) else 0
            features['has_meta_refresh'] = 1 if any('META refresh' in f for f in flags) else 0
            features['has_js_redirect'] = 1 if any('JavaScript редирект' in f for f in flags) else 0
            features['typosquatting'] = 1 if any('тайпсквоттинг' in f or 'typosquatting' in f.lower() for f in flags) else 0
            features['in_blacklist'] = 1 if any('черном списке' in f or 'blacklist' in f.lower() for f in flags) else 0
        except Exception:
            features['url_length'] = len(url)
            features['has_ip'] = 1 if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url) else 0
            features['has_at'] = 1 if '@' in url else 0
            for key in ['non_standard_port', 'path_length', 'query_length', 'has_ssl', 'ssl_hostname_match',
                        'dns_has_a', 'dns_has_mx', 'domain_age_days', 'has_form_flag', 'has_hidden_iframe',
                        'has_meta_refresh', 'has_js_redirect', 'typosquatting', 'in_blacklist']:
                features.setdefault(key, 0)
    else:
        features['url_length'] = len(url)
        features['has_ip'] = 1 if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url) else 0
        features['has_at'] = 1 if '@' in url else 0
        for key in ['non_standard_port', 'path_length', 'query_length', 'has_ssl', 'ssl_hostname_match',
                    'dns_has_a', 'dns_has_mx', 'domain_age_days', 'has_form_flag', 'has_hidden_iframe',
                    'has_meta_refresh', 'has_js_redirect', 'typosquatting', 'in_blacklist']:
            features[key] = 0
    return features

# ----------------------------------------------
# Универсальная функция
# ----------------------------------------------
def extract_features(source, source_type=None):
    if source_type is None:
        if os.path.isfile(source):
            source_type = 'email'
        elif source.startswith(('http://', 'https://')):
            source_type = 'url'
        else:
            raise ValueError("Не удалось определить тип источника. Укажите source_type='email' или 'url'")
    if source_type == 'email':
        return extract_email_features(source)
    elif source_type == 'url':
        return extract_url_features(source)
    else:
        raise ValueError("source_type должен быть 'email' или 'url'")

# ----------------------------------------------
# Красивый вывод признаков
# ----------------------------------------------
def display_email_features(feats):
    print("\n" + "=" * 60)
    print("PhishBuster Feature Extractor - Результат (email)")
    print("=" * 60)
    score = feats.get('score_from_analyzer', -1)
    if score != -1:
        verdict = "PHISHING" if score >= 30 else "CLEAN"
        print(f"Вердикт (по email_analyzer): {verdict} (Score: {score}/100)")
    else:
        print("Вердикт: нет данных от email_analyzer, только признаки.")

    print(f"\nТема (длина): {feats['subject_length']} символов")
    print(f"Домен отправителя: {feats['from_domain']}")
    print(f"Длина тела: {feats['body_length']} символов")
    print(f"Количество URL: {feats['url_count']}")
    print(f"IP-адреса в URL: {feats['ip_url_count']}")
    print(f"Сокращённые ссылки: {feats['shortener_url_count']}")
    print(f"Подозрительные TLD: {feats['suspicious_tld_url_count']}")
    print(f"Фишинговые фразы: {feats['phishing_phrase_count']}")
    print(f"Ключевые слова в теме: {feats['subject_suspicious_keywords']}")
    print(f"Опасные вложения: {'Да' if feats['dangerous_attachment'] else 'Нет'}")
    print(f"Подозрительные архивы: {'Да' if feats['suspicious_archive'] else 'Нет'}")
    print(f"Несовпадение текст/HREF: {feats['mismatch_href_count']}")
    print(f"SPF fail: {'Да' if feats['spf_fail'] else 'Нет'}")
    print(f"DMARC fail: {'Да' if feats['dmarc_fail'] else 'Нет'}")
    print(f"Скрытый текст (1px): {'Да' if feats['hidden_text'] else 'Нет'}")
    print(f"Срочность в теле: {'Да' if feats['urgency_body'] else 'Нет'}")
    print(f"Финансовая приманка: {'Да' if feats['financial_bait'] else 'Нет'}")
    print(f"Выдача за госорган: {'Да' if feats['government_impersonation'] else 'Нет'}")
    print(f"Бесплатный почтовый домен: {'Да' if feats['free_email_sender'] else 'Нет'}")
    print(f"Подозрительный маркер домена: {'Да' if feats['suspicious_domain_marker'] else 'Нет'}")
    print(f"Подозрительный TLD отправителя: {'Да' if feats['sender_suspicious_tld'] else 'Нет'}")
    print(f"Возраст домена отправителя: {feats['sender_domain_age_days']} дней (заглушка)")
    print("=" * 60)

def display_url_features(feats):
    print("\n" + "=" * 60)
    print("PhishBuster Feature Extractor - Результат (URL)")
    print("=" * 60)
    score = feats.get('url_score_from_analyzer', 0)
    verdict = "PHISHING" if score >= 30 else "CLEAN"
    print(f"Вердикт (url_analyzer): {verdict} (Score: {score}/100)")
    print(f"Флагов url_analyzer: {feats.get('url_flags_count', 0)}")
    print(f"\nДлина URL: {feats['url_length']}")
    print(f"IP-адрес: {'Да' if feats['has_ip'] else 'Нет'}")
    print(f"Символ @: {'Да' if feats['has_at'] else 'Нет'}")
    print(f"Нестандартный порт: {'Да' if feats['non_standard_port'] else 'Нет'}")
    print(f"Длина пути: {feats['path_length']}")
    print(f"Длина запроса: {feats['query_length']}")
    print(f"SSL валиден: {'Да' if feats['has_ssl'] else 'Нет'}")
    print(f"SSL hostname match: {'Да' if feats['ssl_hostname_match'] else 'Нет'}")
    print(f"DNS A-запись: {'Да' if feats['dns_has_a'] else 'Нет'}")
    print(f"DNS MX-запись: {'Да' if feats['dns_has_mx'] else 'Нет'}")
    print(f"Возраст домена: {feats['domain_age_days']} дней")
    print(f"HTML-форма: {'Да' if feats['has_form_flag'] else 'Нет'}")
    print(f"Скрытый iframe: {'Да' if feats['has_hidden_iframe'] else 'Нет'}")
    print(f"META refresh: {'Да' if feats['has_meta_refresh'] else 'Нет'}")
    print(f"JavaScript редирект: {'Да' if feats['has_js_redirect'] else 'Нет'}")
    print(f"Тайпсквоттинг: {'Да' if feats['typosquatting'] else 'Нет'}")
    print(f"В чёрном списке: {'Да' if feats['in_blacklist'] else 'Нет'}")
    print("=" * 60)

# ----------------------------------------------
# CLI
# ----------------------------------------------
if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            # Режим командной строки – вывод JSON
            import json
            src = sys.argv[1]
            try:
                feats = extract_features(src)
                print(json.dumps(feats, indent=2, ensure_ascii=False, default=str))
            except Exception as e:
                print(f"Ошибка: {e}")
        else:
            # Интерактивный режим с выбором типа проверки
            EMAIL_DIR = "/home/zakhar/phishbuster/phishbuster/check_email"

            def is_valid_url(url: str) -> bool:
                if not url.startswith(('http://', 'https://')):
                    return False
                parsed = urlparse(url)
                return bool(parsed.netloc)

            print("=" * 60)
            print("PhishBuster Feature Extractor")
            print("=" * 60)
            print("Выберите тип проверки:")
            print("  1 – Проверка письма (.eml)")
            print("  2 – Проверка URL")
            choice = input("Ваш выбор (1/2): ").strip()

            while choice not in ('1', '2'):
                choice = input("Пожалуйста, введите 1 или 2: ").strip()

            if choice == '1':
                print(f"\nСохраните .eml в папку: {EMAIL_DIR}")
                while True:
                    fname = input("Введите имя .eml файла: ").strip()
                    if not fname:
                        print("Имя файла не может быть пустым. Попробуйте снова.")
                        continue
                    if not fname.lower().endswith('.eml'):
                        print("Ошибка: файл должен иметь расширение .eml. Попробуйте снова.")
                        continue
                    filepath = os.path.join(EMAIL_DIR, fname)
                    if not os.path.isfile(filepath):
                        print(f"Ошибка: файл '{fname}' не найден в {EMAIL_DIR}. Попробуйте снова.")
                        continue
                    src = filepath
                    break
            else:  # choice == '2'
                while True:
                    url = input("Введите URL (начинается с http:// или https://): ").strip()
                    if not url:
                        print("URL не может быть пустым. Попробуйте снова.")
                        continue
                    if not is_valid_url(url):
                        print("Ошибка: введена некорректная ссылка. Попробуйте снова.")
                        continue
                    src = url
                    break

            try:
                feats = extract_features(src)
                if 'score_from_analyzer' in feats:
                    display_email_features(feats)
                else:
                    display_url_features(feats)
            except Exception as e:
                print(f"Ошибка при извлечении признаков: {e}")
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем (Ctrl+C).")
        sys.exit(0)
