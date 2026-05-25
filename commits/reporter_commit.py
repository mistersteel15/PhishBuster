#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
PhishBuster – Этап 6: Генератор отчётов (Reporter)
Формирует HTML-отчёт на основе результатов гибридного анализа.
"""
from datetime import datetime                                   # Для отметки времени создания отчёта
import os                                                       # Для работы с путями и создания папок

def generate_html_report(result, is_email=True):                # Генерирует HTML-код отчёта
    """
    Возвращает строку с HTML-отчётом.
    result – словарь, возвращаемый hybrid_analyze_email/URL.
    is_email – True, если анализировалось письмо, False – URL.
    """
    verdict = result.get('verdict', 'CLEAN')                    # Извлекаем итоговый вердикт (по умолчанию CLEAN)
    if verdict == 'PHISHING':                                   # Если вердикт PHISHING
        verdict_color = '#e74c3c'                               # Цвет для фишинга — красный
        verdict_icon = '⚠️'                                     # Иконка предупреждения
    elif verdict == 'INVALID_URL':                              # Если URL невалидный
        verdict_color = '#95a5a6'                               # Серый цвет
        verdict_icon = '❓'                                     # Вопросительный знак
    else:                                                       # Для CLEAN
        verdict_color = '#2ecc71'                               # Зелёный цвет
        verdict_icon = '✅'                                     # Галочка

    hybrid_score = result.get('hybrid_score', 0)                # Итоговый гибридный балл
    heuristic_score = result.get('heuristic_score', 0)          # Эвристический балл
    heuristic_verdict = result.get('heuristic_verdict', '')     # Вердикт эвристики
    ml_confidence = result.get('ml_confidence')                 # Уверенность ML (может быть None)
    ml_verdict = result.get('ml_verdict', '')                   # Вердикт ML
    signs = result.get('signs', []) + result.get('ml_signs', [])  # Все признаки (эвристика + ML)

    # Блок информации об источнике
    if is_email:                                                # Если это письмо
        source_label = 'Письмо'                                 # Метка источника
        source_value = f"{result.get('file', '')}<br>Тема: {result.get('subject', '')}<br>От: {result.get('from', '')}"
        # Собираем путь к файлу, тему и отправителя через <br>
    else:                                                       # Если URL
        source_label = 'URL'                                    # Метка источника
        source_value = result.get('url', '')                    # Сам URL

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')          # Текущие дата и время в красивом формате

    # f-строка с HTML-шаблоном, в которую подставляются переменные
    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishBuster Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f4f6f9;
            margin: 0;
            padding: 20px;
            color: #2c3e50;
        }}
        .container {{
            max-width: 700px;
            margin: auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.05);
            overflow: hidden;
        }}
        .header {{
            background: {verdict_color};                        # Цвет шапки зависит от вердикта
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.2em;
        }}
        .header .subtitle {{
            opacity: 0.9;
            margin-top: 10px;
            font-size: 1.1em;
        }}
        .content {{
            padding: 30px;
        }}
        .section {{
            margin-bottom: 25px;
        }}
        .section h2 {{
            font-size: 1.3em;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 5px;
            margin-top: 0;
        }}
        .score-badge {{
            display: inline-block;
            background: #ecf0f1;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
        }}
        .score-value {{
            font-size: 1.2em;
        }}
        .signs-list {{
            list-style: none;
            padding: 0;
        }}
        .signs-list li {{
            padding: 8px 12px;
            margin: 5px 0;
            background: #f8f9fa;
            border-left: 4px solid {verdict_color};             # Цвет полосы слева = цвет вердикта
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #95a5a6;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{verdict_icon} {verdict}</h1>                   <!-- Иконка и вердикт крупно -->
            <div class="subtitle">PhishBuster Hybrid Engine</div>
        </div>
        <div class="content">
            <div class="section">
                <h2>Источник</h2>
                <p><strong>{source_label}:</strong><br>{source_value}</p>
            </div>
            <div class="section">
                <h2>Скоринг</h2>
                <p>🔍 Эвристический анализ: <span class="score-badge">{heuristic_score}/100</span> ({heuristic_verdict})</p>
                <p>🧠 ML-модель: {f"<span class='score-badge'>{ml_confidence}</span> ({ml_verdict})" if ml_confidence is not None else "не загружена"}</p>
                <p>⚡ Итоговый гибридный балл: <span class="score-badge score-value">{hybrid_score}/100</span></p>
            </div>
            <div class="section">
                <h2>Обнаруженные признаки</h2>
                {f'<ul class="signs-list">{"".join(f"<li>{s}</li>" for s in signs)}</ul>' if signs else '<p>Подозрительных признаков не найдено.</p>'}
                <!-- Если есть признаки – выводим список, иначе сообщение -->
            </div>
        </div>
        <div class="footer">
            Отчёт создан {now} · PhishBuster
        </div>
    </div>
</body>
</html>"""
    return html                                                  # Возвращаем готовую HTML-строку

def save_report(result, is_email=True, output_dir=None):        # Сохраняет HTML-отчёт в файл
    """
    Сохраняет HTML-отчёт в файл.
    Если output_dir не указан, сохраняет в папку reports/email/ или reports/url/
    рядом со скриптом (в зависимости от типа анализа).
    Возвращает путь к сохранённому файлу.
    """
    if output_dir is None:                                      # Если папка не указана
        script_dir = os.path.dirname(os.path.abspath(__file__)) # Определяем папку скрипта
        base_dir = os.path.join(script_dir, 'reports')          # Базовая папка reports
        sub = 'email' if is_email else 'url'                    # Выбор подпапки по типу анализа
        output_dir = os.path.join(base_dir, sub)                # Полный путь к подпапке

    os.makedirs(output_dir, exist_ok=True)                      # Создаём папку, если её нет

    timestamp = datetime.now().strftime('%Y.%m.%d_%H:%M:%S')    # Временная метка для имени файла
    filename = f"phishbuster_report_{timestamp}.html"            # Имя файла с меткой
    filepath = os.path.join(output_dir, filename)                # Полный путь к файлу

    html = generate_html_report(result, is_email)               # Генерируем HTML-отчёт
    with open(filepath, 'w', encoding='utf-8') as f:            # Открываем файл для записи
        f.write(html)                                            # Записываем HTML-код
    return filepath                                              # Возвращаем путь к сохранённому файлу
