#!/usr/bin/env python3
"""
PhishBuster – Этап 6: Генератор отчётов (Reporter)
Формирует HTML-отчёт на основе результатов гибридного анализа.
"""

from datetime import datetime
import os

def generate_html_report(result, is_email=True):
    """
    Возвращает строку с HTML-отчётом.
    result – словарь, возвращаемый hybrid_analyze_email/URL.
    is_email – True, если анализировалось письмо, False – URL.
    """
    verdict = result.get('verdict', 'CLEAN')
    if verdict == 'PHISHING':
        verdict_color = '#e74c3c'  # красный
        verdict_icon = '⚠️'
    elif verdict == 'INVALID_URL':
        verdict_color = '#95a5a6'  # серый
        verdict_icon = '❓'
    else:
        verdict_color = '#2ecc71'  # зелёный
        verdict_icon = '✅'

    hybrid_score = result.get('hybrid_score', 0)
    heuristic_score = result.get('heuristic_score', 0)
    heuristic_verdict = result.get('heuristic_verdict', '')
    ml_confidence = result.get('ml_confidence')
    ml_verdict = result.get('ml_verdict', '')
    signs = result.get('signs', []) + result.get('ml_signs', [])

    # Источник
    if is_email:
        source_label = 'Письмо'
        source_value = f"{result.get('file', '')}<br>Тема: {result.get('subject', '')}<br>От: {result.get('from', '')}"
    else:
        source_label = 'URL'
        source_value = result.get('url', '')

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

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
            background: {verdict_color};
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
            border-left: 4px solid {verdict_color};
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
            <h1>{verdict_icon} {verdict}</h1>
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
            </div>
        </div>
        <div class="footer">
            Отчёт создан {now} · PhishBuster
        </div>
    </div>
</body>
</html>"""
    return html

def save_report(result, is_email=True, output_dir=None):
    """
    Сохраняет HTML-отчёт в файл.
    Если output_dir не указан, сохраняет в папку reports/email/ или reports/url/
    рядом со скриптом (в зависимости от типа анализа).
    Возвращает путь к сохранённому файлу.
    """
    if output_dir is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.join(script_dir, 'reports')
        sub = 'email' if is_email else 'url'
        output_dir = os.path.join(base_dir, sub)

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y.%m.%d_%H:%M:%S')
    filename = f"phishbuster_report_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    html = generate_html_report(result, is_email)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html)
    return filepath
