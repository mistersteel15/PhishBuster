#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
PhishBuster – Этап 3: Извлечение признаков (Feature Extractor)
Совместим с email_analyzer.py и url_analyzer.py.
Извлекает числовые признаки из .eml-файлов или URL.
Использование:
    python3 feature_extractor.py          # интерактивный ввод
    python3 feature_extractor.py письмо.eml   # JSON для письма
    python3 feature_extractor.py https://example.com # JSON для URL
"""

import os                                                       # Работа с файловой системой
import sys                                                      # Завершение программы и пути импорта
import re                                                       # Регулярные выражения
import email                                                    # Парсинг .eml-файлов
import email.policy                                             # Политика разбора email
from urllib.parse import urlparse                               # Разбор URL на компоненты
from email.header import decode_header                          # Декодирование заголовков писем
from datetime import datetime                                   # Работа с датами для возраста домена

# ----------------------------------------------
# Добавляем текущую папку в пути импорта, чтобы находить модули проекта
# ----------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # Вставляем путь в начало списка импорта

# ----------------------------------------------
# Попытка импорта анализаторов из текущей папки
# ----------------------------------------------
try:                                                            # Пробуем импортировать email_analyzer
    from email_analyzer import analyze_eml                      # Импортируем функцию анализа писем
    EMAIL_ANALYZER = True                                       # Модуль доступен
except ImportError:                                             # Модуль не найден
    EMAIL_ANALYZER = False                                      # Модуль недоступен

try:                                                            # Пробуем импортировать url_analyzer
    from url_analyzer import analyze_url as url_analyzer_func   # Импортируем функцию анализа URL
    URL_ANALYZER = True                                         # Модуль доступен
except ImportError:                                             # Модуль не найден
    URL_ANALYZER = False                                        # Модуль недоступен

# ----------------------------------------------
# Константы (скопированы из email_analyzer / url_analyzer для независимости)
# ----------------------------------------------
# Список подозрительных слов в теме (русские и английские)
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

# Регулярные выражения для фишинговых фраз в теле письма
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

# Опасные расширения вложений (исполняемые файлы, скрипты)
DANGEROUS_EXTENSIONS = {'.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1', '.hta', '.docm', '.xlsm'}

# Подозрительные расширения архивов
SUSPICIOUS_ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.gz', '.tar', '.bz2'}

# Подозрительные доменные зоны, часто используемые в фишинге
SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.bar', '.rest', '.wang', '.club', '.work'}

# Сервисы сокращения ссылок
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'shorte.st',
    'is.gd', 'buff.ly', 'adf.ly', 'bc.vc', 'rebrand.ly', 'tiny.cc',
    'clicky.me', 'shorturl.at', 'rb.gy', 'soo.gd', 's2r.co'
}

# ----------------------------------------------
# Вспомогательные функции (дублируют логику парсинга, чтобы не зависеть от других модулей)
# ----------------------------------------------
def _decode_part(part):                                         # Декодирует часть письма в строку
    charset = part.get_content_charset() or 'utf-8'             # Определяет кодировку
    try:                                                        # Пытается декодировать
        payload = part.get_payload(decode=True)                  # Получает байты содержимого
        return payload.decode(charset, errors='replace')         # Преобразует в строку с заменой ошибок
    except Exception:                                            # Если ошибка
        return str(part.get_payload())                           # Возвращает строковое представление

def _decode_header_val(msg, name):                              # Получает и декодирует значение заголовка
    value = msg.get(name, '')                                   # Берёт сырое значение заголовка
    if not value:                                                # Если пусто
        return ''                                                # Возвращает пустую строку
    decoded_parts = []                                           # Список для декодированных частей
    for part, encoding in decode_header(value):                 # Разбирает заголовок на части
        if isinstance(part, bytes):                              # Если часть – байты
            try:                                                 # Пробует декодировать
                decoded_parts.append(part.decode(encoding or 'utf-8', errors='replace'))
            except Exception:                                    # При ошибке декодирования
                decoded_parts.append(part.decode('utf-8', errors='replace'))
        else:                                                    # Если часть – строка
            decoded_parts.append(str(part))                      # Просто добавляет строку
    return ' '.join(decoded_parts)                               # Склеивает все части через пробел

def _extract_urls_from_html(html):                              # Извлекает URL из HTML-кода
    urls = set()                                                 # Множество для уникальных URL
    for m in re.finditer(r'href\s*=\s*["\'](https?://[^"\']+)["\']', html, re.IGNORECASE):
        url = m.group(1).replace('&amp;', '&')                  # Берёт URL из группы, заменяет &amp;
        urls.add(url)                                            # Добавляет в множество
    return urls                                                  # Возвращает множество URL

def _extract_urls_from_text(text):                              # Извлекает URL из обычного текста
    return set(re.findall(r'https?://[^\s<>"\'\)]+', text, re.IGNORECASE))  # Поиск всех ссылок

def _get_domain(url):                                            # Извлекает домен из URL
    try:                                                         # Пытается разобрать URL
        return urlparse(url).netloc.lower()                     # Возвращает netloc в нижнем регистре
    except:                                                      # При ошибке
        return ''                                                # Возвращает пустую строку

def _is_ip_url(url):                                             # Проверяет, является ли хост IP-адресом
    try:                                                         # Пытается получить hostname
        host = urlparse(url).hostname                           # Берёт hostname из URL
        if host:                                                 # Если hostname есть
            parts = host.split('.')                              # Разбивает на части
            return len(parts) == 4 and all(p.isdigit() for p in parts)  # Проверяет формат IPv4
    except:                                                      # При ошибке
        pass                                                     # Ничего не делает
    return False                                                 # Возвращает False

def _email_domain(addr):                                         # Извлекает домен из email-адреса
    if '@' in addr:                                              # Если в адресе есть @
        return addr.split('@', 1)[1]                            # Возвращает часть после @
    return ''                                                    # Возвращает пустую строку

# ----------------------------------------------
# Извлечение признаков из письма
# ----------------------------------------------
def extract_email_features(filepath):                            # Главная функция для признаков письма
    features = {}                                                # Пустой словарь для признаков

    if EMAIL_ANALYZER:                                           # Если email_analyzer доступен
        try:                                                     # Пытаемся получить отчёт
            report = analyze_eml(filepath)                       # Вызывает анализ письма
            features['score_from_analyzer'] = report['score']   # Сохраняет скоринговый балл
            features['verdict_code'] = 1 if report['verdict'] == 'PHISHING' else 0  # Бинарный вердикт
        except Exception:                                        # Если ошибка
            features['score_from_analyzer'] = -1                 # Помечаем как недоступный
            features['verdict_code'] = -1                        # Помечаем как недоступный
    else:                                                        # Если email_analyzer не найден
        features['score_from_analyzer'] = -1                     # Балл неизвестен
        features['verdict_code'] = -1                            # Вердикт неизвестен

    with open(filepath, 'rb') as f:                              # Открываем файл в бинарном режиме
        msg = email.message_from_binary_file(f, policy=email.policy.default)  # Парсим письмо

    subject = _decode_header_val(msg, 'Subject')                 # Получаем тему письма
    from_header = _decode_header_val(msg, 'From')                # Получаем заголовок From
    from_addr = re.search(r'<([^>]+)>', from_header)            # Ищем email в угловых скобках
    from_addr = from_addr.group(1) if from_addr else from_header.strip()  # Извлекаем адрес
    from_domain = _email_domain(from_addr) if '@' in from_addr else ''  # Домен отправителя

    features['subject_length'] = len(subject)                    # Длина темы
    features['from_domain'] = from_domain                        # Сохраняем домен отправителя

    # Разбор тела письма
    body_text = ""                                               # Текстовое содержимое
    html_text = ""                                               # HTML-содержимое
    all_urls = set()                                             # Множество всех URL
    href_text_pairs = []                                         # Пары (текст ссылки, href)
    attachment_names = []                                        # Имена файлов-вложений

    if msg.is_multipart():                                       # Если письмо multipart
        for part in msg.walk():                                  # Обходим все части
            ct = part.get_content_type()                         # Content-Type части
            if part.get_content_disposition() == 'attachment':   # Если это вложение
                fname = part.get_filename()                      # Получаем имя файла
                if fname:                                        # Если имя есть
                    attachment_names.append(fname)               # Добавляем в список
                continue                                         # Переходим к следующей части
            if ct == 'text/plain':                               # Если текстовая часть
                text = _decode_part(part)                        # Декодируем текст
                body_text += text + "\n"                         # Накапливаем текст
                all_urls.update(_extract_urls_from_text(text))   # Извлекаем URL из текста
            elif ct == 'text/html':                              # Если HTML-часть
                html = _decode_part(part)                        # Декодируем HTML
                html_text += html + "\n"                         # Накапливаем HTML
                all_urls.update(_extract_urls_from_html(html))   # Извлекаем URL из href
                all_urls.update(_extract_urls_from_text(html))   # Извлекаем URL из текста
                for m in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', html, re.IGNORECASE):
                    href = m.group(1).replace('&amp;', '&')      # Получаем href, убираем &amp;
                    link_text = m.group(2).strip().lower()       # Видимый текст ссылки
                    href_text_pairs.append((link_text, href))    # Сохраняем пару
    else:                                                        # Письмо не multipart
        ct = msg.get_content_type()                              # Content-Type всего письма
        raw = _decode_part(msg)                                  # Декодируем тело
        if ct == 'text/plain':                                   # Если текст
            body_text = raw                                      # Сохраняем текст
            all_urls.update(_extract_urls_from_text(raw))        # Извлекаем URL
        elif ct == 'text/html':                                  # Если HTML
            html_text = raw                                      # Сохраняем HTML
            all_urls.update(_extract_urls_from_html(raw))        # Извлекаем URL из href
            all_urls.update(_extract_urls_from_text(raw))        # Извлекаем URL из текста
            for m in re.finditer(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']+)["\'][^>]*>([^<]*)</a>', raw, re.IGNORECASE):
                href = m.group(1).replace('&amp;', '&')          # Убираем &amp;
                link_text = m.group(2).strip().lower()           # Текст ссылки
                href_text_pairs.append((link_text, href))        # Сохраняем пару

    combined_body = body_text + " " + re.sub(r'<[^>]+>', '', html_text)  # Объединённый текст без тегов
    features['body_length'] = len(combined_body)                 # Длина тела письма

    url_list = list(all_urls)                                    # Превращаем множество в список
    features['url_count'] = len(url_list)                        # Количество URL
    features['ip_url_count'] = sum(1 for u in url_list if _is_ip_url(u))  # Количество IP-ссылок
    features['shortener_url_count'] = sum(1 for u in url_list if _get_domain(u) in URL_SHORTENERS)  # Сокращённых ссылок
    features['suspicious_tld_url_count'] = sum(1 for u in url_list if any(_get_domain(u).endswith(tld) for tld in SUSPICIOUS_TLDS))  # Ссылок с подозрительной зоной

    # Фишинговые фразы в теле
    features['phishing_phrase_count'] = sum(1 for phrase in PHISHING_BODY_PHRASES if re.search(phrase, combined_body, re.IGNORECASE))

    subj_lower = subject.lower()                                 # Тема в нижнем регистре
    features['subject_suspicious_keywords'] = sum(1 for w in SUSPICIOUS_SUBJECT_WORDS if w in subj_lower)  # Ключевых слов в теме

    # Признаки вложений
    features['dangerous_attachment'] = 1 if any(os.path.splitext(f)[1].lower() in DANGEROUS_EXTENSIONS for f in attachment_names) else 0
    features['suspicious_archive'] = 1 if any(os.path.splitext(f)[1].lower() in SUSPICIOUS_ARCHIVE_EXTENSIONS for f in attachment_names) else 0

    # Mismatch текст/HREF
    mismatch_count = 0                                           # Счётчик несовпадений
    for link_text, href in href_text_pairs:                     # Проходим по всем парам
        if link_text and re.search(r'(google|facebook|paypal|amazon|apple|microsoft|сбербанк|яндекс)', link_text):
            href_domain = _get_domain(href)                      # Домен из реального URL
            if not any(comp in href_domain for comp in ['google','facebook','paypal','amazon','apple','microsoft','сбербанк','яндекс']):
                mismatch_count += 1                              # Увеличиваем счётчик
    features['mismatch_href_count'] = mismatch_count            # Сохраняем количество

    # Заголовки безопасности
    spf = msg.get('Received-SPF', '')                            # Получаем SPF
    features['spf_fail'] = 1 if spf and 'fail' in spf.lower() else 0  # Флаг провала SPF
    dmarc = msg.get('DMARC-Result', msg.get('Authentication-Results', ''))  # Пытаемся получить DMARC
    features['dmarc_fail'] = 1 if dmarc and 'fail' in dmarc.lower() else 0  # Флаг провала DMARC

    # Скрытый текст
    features['hidden_text'] = 1 if ('font-size: 1px' in html_text or 'font-size:1px' in html_text) else 0

    # Срочность в теле
    features['urgency_body'] = 1 if re.search(r'в\s+течение\s+\d+\s+(дня|дней|часа|часов)', combined_body, re.IGNORECASE) else 0

    # Финансовая приманка
    financial = ['компенсация', 'выплата', 'возврат средств', 'переплата', 'налоговый вычет', 'субсидия', 'пособие', 'выигрыш']
    features['financial_bait'] = 1 if any(re.search(w, combined_body, re.IGNORECASE) for w in financial) else 0

    # Имперсонация госоргана
    from_display = re.match(r'([^<]+)<', from_header)            # Ищем отображаемое имя
    from_display = from_display.group(1).strip().strip('"') if from_display else ''  # Извлекаем имя
    gov_names = ['фнс', 'налоговая', 'федеральная налоговая', 'мвд', 'прокуратура', 'суд', 'пенсионный фонд', 'пфр', 'банк', 'центробанк', 'цб', 'минфин', 'правительство', 'госуслуги', 'следственный комитет', 'фсб', 'мчс', 'роскомнадзор', 'таможня', 'санэпидемстанция']
    features['government_impersonation'] = 1 if any(g in from_display.lower() for g in gov_names) else 0

    # Бесплатный почтовый ящик
    free_domains = {'gmail.com', 'yandex.ru', 'mail.ru', 'outlook.com', 'hotmail.com', 'yahoo.com', 'protonmail.com'}
    features['free_email_sender'] = 1 if from_domain in free_domains else 0

    # Подозрительные маркеры в домене отправителя
    markers = ['-secure', 'login-', 'account-', 'verify-', 'secure-', 'support-', 'service-']
    features['suspicious_domain_marker'] = 1 if any(m in from_domain for m in markers) else 0

    # Подозрительная зона отправителя
    features['sender_suspicious_tld'] = 1 if any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0

    # Возраст домена (заглушка)
    features['sender_domain_age_days'] = -1                      # Не запрашиваем WHOIS

    return features                                              # Возвращаем словарь признаков

# ----------------------------------------------
# Извлечение признаков из URL
# ----------------------------------------------
def extract_url_features(url):                                   # Функция для признаков URL
    features = {}                                                # Пустой словарь
    if URL_ANALYZER:                                             # Если url_analyzer доступен
        try:                                                     # Пытаемся получить отчёт
            report = url_analyzer_func(url)                      # Анализируем URL
            features['url_score_from_analyzer'] = report.get('score', 0)  # Балл от анализатора
            features['url_flags_count'] = len(report.get('flags', []))  # Количество флагов
            parsed = report.get('details', {}).get('parsed', {})  # Разобранный URL
            features['url_length'] = len(url)                    # Длина URL
            features['has_ip'] = 1 if (parsed.get('hostname') and re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed['hostname'])) else 0  # IP в URL
            features['has_at'] = 1 if '@' in url else 0         # Есть ли @ в URL
            features['non_standard_port'] = 1 if parsed.get('port') and parsed['port'] not in {80, 443, 8080, 8443} else 0  # Нестандартный порт
            features['path_length'] = len(parsed.get('path', ''))  # Длина пути
            features['query_length'] = len(parsed.get('query', ''))  # Длина query-строки
            ssl = report.get('details', {}).get('ssl', {})       # Данные SSL
            features['has_ssl'] = 1 if ssl.get('valid') else 0  # Валидный SSL
            features['ssl_hostname_match'] = 1 if ssl.get('hostname_match') else 0  # Совпадение hostname
            dns = report.get('details', {}).get('dns', {})       # DNS-записи
            features['dns_has_a'] = 1 if dns.get('A') else 0    # Есть A-запись
            features['dns_has_mx'] = 1 if dns.get('MX') else 0  # Есть MX-запись
            whois_data = report.get('details', {}).get('whois', {})  # WHOIS-данные
            age = -1                                              # Возраст домена по умолчанию
            if 'creation_date' in whois_data:                    # Если есть дата создания
                try:                                              # Пробуем разобрать дату
                    creation_str = whois_data['creation_date']   # Берём дату
                    creation_date = datetime.strptime(creation_str, '%Y-%m-%d')  # Парсим дату
                    age = (datetime.now() - creation_date).days  # Считаем возраст в днях
                except:                                           # При ошибке
                    pass                                          # Оставляем -1
            features['domain_age_days'] = age                    # Сохраняем возраст
            flags = report.get('flags', [])                      # Список флагов анализатора
            features['has_form_flag'] = 1 if any('форма' in f or 'form' in f.lower() for f in flags) else 0  # Есть форма
            features['has_hidden_iframe'] = 1 if any('скрытый iframe' in f or 'hidden iframe' in f.lower() for f in flags) else 0  # Скрытый iframe
            features['has_meta_refresh'] = 1 if any('META refresh' in f for f in flags) else 0  # META refresh
            features['has_js_redirect'] = 1 if any('JavaScript редирект' in f for f in flags) else 0  # JS редирект
            features['typosquatting'] = 1 if any('тайпсквоттинг' in f or 'typosquatting' in f.lower() for f in flags) else 0  # Тайпсквоттинг
            features['in_blacklist'] = 1 if any('черном списке' in f or 'blacklist' in f.lower() for f in flags) else 0  # В чёрном списке
        except Exception:                                        # Если url_analyzer упал
            features['url_length'] = len(url)                    # Длина URL
            features['has_ip'] = 1 if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url) else 0  # Проверка IP
            features['has_at'] = 1 if '@' in url else 0         # Наличие @
            for key in ['non_standard_port', 'path_length', 'query_length', 'has_ssl', 'ssl_hostname_match',
                        'dns_has_a', 'dns_has_mx', 'domain_age_days', 'has_form_flag', 'has_hidden_iframe',
                        'has_meta_refresh', 'has_js_redirect', 'typosquatting', 'in_blacklist']:
                features.setdefault(key, 0)                      # Заполняем остальные признаки нулями
    else:                                                        # Если url_analyzer отсутствует
        features['url_length'] = len(url)                        # Длина URL
        features['has_ip'] = 1 if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url) else 0  # Проверка IP
        features['has_at'] = 1 if '@' in url else 0             # Наличие @
        for key in ['non_standard_port', 'path_length', 'query_length', 'has_ssl', 'ssl_hostname_match',
                    'dns_has_a', 'dns_has_mx', 'domain_age_days', 'has_form_flag', 'has_hidden_iframe',
                    'has_meta_refresh', 'has_js_redirect', 'typosquatting', 'in_blacklist']:
            features[key] = 0                                    # Заполняем нулями
    return features                                              # Возвращаем словарь признаков

# ----------------------------------------------
# Универсальная функция – автоматическое определение типа источника
# ----------------------------------------------
def extract_features(source, source_type=None):                 # Универсальная точка входа
    if source_type is None:                                     # Если тип не указан
        if os.path.isfile(source):                              # Проверяем, существует ли файл
            source_type = 'email'                               # Считаем письмом
        elif source.startswith(('http://', 'https://')):        # Если начинается с http
            source_type = 'url'                                 # Считаем URL
        else:                                                    # Не удалось определить
            raise ValueError("Не удалось определить тип источника. Укажите source_type='email' или 'url'")
    if source_type == 'email':                                   # Если письмо
        return extract_email_features(source)                    # Извлекаем признаки письма
    elif source_type == 'url':                                   # Если URL
        return extract_url_features(source)                      # Извлекаем признаки URL
    else:                                                        # Некорректный тип
        raise ValueError("source_type должен быть 'email' или 'url'")

# ----------------------------------------------
# Красивый вывод признаков (не обязательны для ML, но удобны при тестировании)
# ----------------------------------------------
def display_email_features(feats):                               # Вывод признаков письма
    print("\n" + "=" * 60)                                      # Заголовок
    print("PhishBuster Feature Extractor - Результат (email)")
    print("=" * 60)
    score = feats.get('score_from_analyzer', -1)                # Балл анализатора
    if score != -1:                                              # Если балл известен
        verdict = "PHISHING" if score >= 30 else "CLEAN"         # Определяем вердикт
        print(f"Вердикт (по email_analyzer): {verdict} (Score: {score}/100)")
    else:                                                        # Если балл не получен
        print("Вердикт: нет данных от email_analyzer, только признаки.")
    # Вывод каждого признака
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

def display_url_features(feats):                                 # Вывод признаков URL
    print("\n" + "=" * 60)                                      # Заголовок
    print("PhishBuster Feature Extractor - Результат (URL)")
    print("=" * 60)
    score = feats.get('url_score_from_analyzer', 0)             # Балл анализатора
    verdict = "PHISHING" if score >= 30 else "CLEAN"             # Вердикт
    print(f"Вердикт (url_analyzer): {verdict} (Score: {score}/100)")
    print(f"Флагов url_analyzer: {feats.get('url_flags_count', 0)}")
    # Вывод каждого признака
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
# CLI – интерактивный и командный режим
# ----------------------------------------------
if __name__ == "__main__":                                       # Точка входа при запуске скрипта
    try:                                                         # Оборачиваем в try для обработки Ctrl+C
        if len(sys.argv) > 1:                                    # Если передан аргумент командной строки
            import json                                           # Импортируем json
            src = sys.argv[1]                                     # Берём первый аргумент
            try:                                                  # Пробуем извлечь признаки
                feats = extract_features(src)                     # Извлекаем признаки
                print(json.dumps(feats, indent=2, ensure_ascii=False, default=str))  # Выводим JSON
            except Exception as e:                                # Если ошибка
                print(f"Ошибка: {e}")                             # Печатаем ошибку
        else:                                                     # Интерактивный режим
            EMAIL_DIR = "/home/zakhar/phishbuster/phishbuster/check_email"  # Папка с письмами

            def is_valid_url(url: str) -> bool:                  # Проверка валидности URL
                if not url.startswith(('http://', 'https://')):   # Должен начинаться с http
                    return False
                parsed = urlparse(url)                            # Разбираем URL
                return bool(parsed.netloc)                        # Проверяем наличие домена

            print("=" * 60)                                      # Вывод меню
            print("PhishBuster Feature Extractor")
            print("=" * 60)
            print("Выберите тип проверки:")
            print("  1 – Проверка письма (.eml)")
            print("  2 – Проверка URL")
            choice = input("Ваш выбор (1/2): ").strip()          # Считываем выбор

            while choice not in ('1', '2'):                      # Пока ввод некорректен
                choice = input("Пожалуйста, введите 1 или 2: ").strip()

            if choice == '1':                                     # Выбрано письмо
                print(f"\nСохраните .eml в папку: {EMAIL_DIR}")
                while True:                                       # Цикл ввода имени файла
                    fname = input("Введите имя .eml файла: ").strip()
                    if not fname:                                 # Пустой ввод
                        print("Имя файла не может быть пустым. Попробуйте снова.")
                        continue
                    if not fname.lower().endswith('.eml'):        # Проверка расширения
                        print("Ошибка: файл должен иметь расширение .eml. Попробуйте снова.")
                        continue
                    filepath = os.path.join(EMAIL_DIR, fname)     # Полный путь к файлу
                    if not os.path.isfile(filepath):              # Файл не существует
                        print(f"Ошибка: файл '{fname}' не найден в {EMAIL_DIR}. Попробуйте снова.")
                        continue
                    src = filepath                                # Сохраняем путь
                    break                                         # Выходим из цикла
            else:                                                  # Выбрано URL
                while True:                                       # Цикл ввода URL
                    url = input("Введите URL (начинается с http:// или https://): ").strip()
                    if not url:                                   # Пустой ввод
                        print("URL не может быть пустым. Попробуйте снова.")
                        continue
                    if not is_valid_url(url):                     # Невалидный URL
                        print("Ошибка: введена некорректная ссылка. Попробуйте снова.")
                        continue
                    src = url                                     # Сохраняем URL
                    break                                         # Выходим из цикла

            try:                                                  # Извлекаем признаки
                feats = extract_features(src)                     # Вызов универсальной функции
                if 'score_from_analyzer' in feats:               # Если это признаки письма
                    display_email_features(feats)                 # Показываем признаки письма
                else:                                             # Иначе это признаки URL
                    display_url_features(feats)                   # Показываем признаки URL
            except Exception as e:                                # Ошибка при извлечении
                print(f"Ошибка при извлечении признаков: {e}")
                sys.exit(1)

    except KeyboardInterrupt:                                    # Пользователь нажал Ctrl+C
        print("\n\nПрограмма прервана пользователем (Ctrl+C).")
        sys.exit(0)                                              # Выход без ошибки
