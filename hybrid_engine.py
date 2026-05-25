#!/usr/bin/env python3
"""
PhishBuster – Этап 5: Гибридный движок (Rule Engine + ML)
Объединяет эвристический анализ и машинное обучение.
Использование:
    python3 hybrid_engine.py --file письмо.eml
    python3 hybrid_engine.py --url http://example.com
    python3 hybrid_engine.py                    # интерактивный режим
"""

import os
import sys
import pickle
import math
import argparse
import json
from urllib.parse import urlparse as urlparse_check
from reporter import save_report

EMAIL_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'phish_model.pkl')
URL_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'url_model.pkl')

# Добавляем текущую папку в пути импорта
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ----------------------------------------------
# Импорт наших модулей (с мягкой обработкой ошибок)
# ----------------------------------------------
try:
    from email_analyzer import analyze_eml
    EMAIL_OK = True
except ImportError:
    EMAIL_OK = False
    print("[!] email_analyzer не найден", file=sys.stderr)

try:
    from url_analyzer import analyze_url as url_analyzer_func
    URL_OK = True
except ImportError:
    URL_OK = False
    print("[!] url_analyzer не найден", file=sys.stderr)

try:
    from feature_extractor import extract_email_features, extract_url_features
    FE_OK = True
except ImportError:
    FE_OK = False
    print("[!] feature_extractor не найден", file=sys.stderr)

# ----------------------------------------------
# Загрузка ML-модели (k-NN)
# ----------------------------------------------
def load_model(model_type='email'):
    """Загружает модель k-NN. model_type = 'email' или 'url'."""
    path = EMAIL_MODEL_PATH if model_type == 'email' else URL_MODEL_PATH
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        model = pickle.load(f)
    return model

# ----------------------------------------------
# Предсказание с вероятностью (k-NN)
# ----------------------------------------------
def predict_with_confidence(model, features_dict):
    """
    Возвращает (predicted_label, confidence) для одного примера.
    confidence – доля голосов за класс 1 среди k ближайших соседей (от 0 до 1).
    """
    train_data = model['train_data']
    feature_keys = model['feature_keys']
    min_vals = model['min_vals']
    range_vals = model['range_vals']
    k = model['k']

    # Нормализация входного вектора
    norm = {}
    for key in feature_keys:
        raw = features_dict.get(key, 0.0)
        if key in min_vals and range_vals.get(key, 0) != 0:
            norm[key] = (raw - min_vals[key]) / range_vals[key]
        else:
            norm[key] = 0.0

    # Вычисление расстояний до всех обучающих примеров
    distances = []
    for train_row in train_data:
        dist = 0.0
        for key in feature_keys:
            diff = norm[key] - train_row.get(key, 0.0)
            dist += diff * diff
        distances.append((math.sqrt(dist), train_row['label']))
    distances.sort(key=lambda x: x[0])

    # k ближайших
    k_nearest = distances[:k]
    votes_phishing = sum(1 for _, label in k_nearest if label == 1)
    confidence = votes_phishing / len(k_nearest)   # от 0 до 1
    predicted_label = 1 if votes_phishing > k // 2 else 0
    return predicted_label, confidence

# ----------------------------------------------
# Проверка корректности URL
# ----------------------------------------------
def is_valid_url(url: str) -> bool:
    """Простая проверка: URL должен содержать схему и домен."""
    try:
        parsed = urlparse_check(url)
        return all([parsed.scheme in ('http', 'https'), parsed.netloc])
    except Exception:
        return False

# ----------------------------------------------
# Гибридный анализ письма (исправлен)
# ----------------------------------------------
def hybrid_analyze_email(filepath):
    """Анализирует .eml файл с помощью эвристик и ML."""
    result = {
        'file': filepath,
        'subject': '',
        'from': '',
        'heuristic_score': 0,
        'heuristic_verdict': 'CLEAN',
        'ml_confidence': None,
        'ml_verdict': None,
        'hybrid_score': 0,
        'verdict': 'CLEAN',
        'signs': [],
        'ml_signs': [],
    }

    # 1. Эвристический анализ
    if EMAIL_OK:
        try:
            report = analyze_eml(filepath)
            result['subject'] = report.get('subject', '')
            result['from'] = report.get('from', '')
            result['heuristic_score'] = report.get('score', 0)
            result['heuristic_verdict'] = report.get('verdict', 'CLEAN')
            result['signs'] = report.get('signs', [])
        except Exception as e:
            result['signs'].append(f"Ошибка эвристического анализа: {e}")

    # 2. Извлечение признаков и предсказание ML
    model = load_model('email')
    if model and FE_OK:
        try:
            features = extract_email_features(filepath)
            pred_label, confidence = predict_with_confidence(model, features)
            result['ml_confidence'] = round(confidence, 3)
            result['ml_verdict'] = 'PHISHING' if pred_label == 1 else 'CLEAN'
            if pred_label == 1:
                result['ml_signs'].append(f"ML-модель: фишинг (confidence={confidence:.2f})")
            else:
                result['ml_signs'].append(f"ML-модель: легитимное (confidence={confidence:.2f})")
        except Exception as e:
            result['ml_signs'].append(f"Ошибка ML: {e}")

    # 3. Гибридный скоринг
    # 3. Гибридный скоринг (защита от слабого ML)
    heuristic = result['heuristic_score']
    ml_confidence = result['ml_confidence'] if result['ml_confidence'] is not None else 0.0
    if heuristic >= 30:
        hybrid_score = heuristic
    else:
        ml_boost = int(ml_confidence * 20)          # максимум +20 баллов
        hybrid_score = min(heuristic + ml_boost, 29) # не даём подняться выше 29
    result['hybrid_score'] = min(hybrid_score, 100)
    result['verdict'] = 'PHISHING' if result['hybrid_score'] >= 30 else 'CLEAN'

    return result   # <-- ОБЯЗАТЕЛЬНО ВЕРНУТЬ

# ----------------------------------------------
# Гибридный анализ URL (без изменений)
# ----------------------------------------------
def hybrid_analyze_url(url):
    """Анализирует URL с помощью эвристик url_analyzer и ML."""
    if not is_valid_url(url):
        return {
            'url': url,
            'heuristic_score': 0,
            'heuristic_verdict': 'INVALID',
            'ml_confidence': None,
            'ml_verdict': None,
            'hybrid_score': 0,
            'verdict': 'INVALID_URL',
            'signs': ['Некорректный URL. Убедитесь, что адрес начинается с http:// или https:// и содержит домен.'],
            'ml_signs': [],
        }

    result = {
        'url': url,
        'heuristic_score': 0,
        'heuristic_verdict': 'CLEAN',
        'ml_confidence': None,
        'ml_verdict': None,
        'hybrid_score': 0,
        'verdict': 'CLEAN',
        'signs': [],
        'ml_signs': [],
    }

    # 1. Эвристический анализ URL
    if URL_OK:
        try:
            report = url_analyzer_func(url)
            result['heuristic_score'] = report.get('score', 0)
            result['heuristic_verdict'] = report.get('verdict', 'CLEAN')
            result['signs'] = report.get('flags', [])
        except Exception as e:
            result['signs'].append(f"Ошибка анализа URL: {e}")

    # 2. ML (если есть модель)
    model = load_model('url')
    if model and FE_OK:
        try:
            features = extract_url_features(url)
            pred_label, confidence = predict_with_confidence(model, features)
            result['ml_confidence'] = round(confidence, 3)
            result['ml_verdict'] = 'PHISHING' if pred_label == 1 else 'CLEAN'
            if pred_label == 1:
                result['ml_signs'].append(f"ML-модель: фишинг (confidence={confidence:.2f})")
            else:
                result['ml_signs'].append(f"ML-модель: легитимное (confidence={confidence:.2f})")
        except Exception as e:
            result['ml_signs'].append(f"Ошибка ML: {e}")

    # 3. Гибридный скоринг
    heuristic = result['heuristic_score']
    ml_confidence = result['ml_confidence'] if result['ml_confidence'] is not None else 0.0
    if heuristic >= 30:
        hybrid_score = heuristic
    else:
        # ограничиваем влияние ML, чтобы не перебить эвристику
        ml_boost = int(ml_confidence * 20)
        hybrid_score = min(heuristic + ml_boost, 29)
    result['hybrid_score'] = hybrid_score
    result['verdict'] = 'PHISHING' if hybrid_score >= 30 else 'CLEAN'
    return result

# ----------------------------------------------
# Вывод результатов
# ----------------------------------------------
def print_result(result, is_email=True):
    """Выводит результат анализа в человекочитаемом формате."""
    if not result:
        print("Ошибка: пустой результат.")
        return

    print("\n" + "=" * 60)
    print("PhishBuster Hybrid Engine – Результат")
    print("=" * 60)

    if result.get('verdict') == 'INVALID_URL':
        print(f"URL: {result.get('url', '')}")
        print("Ошибка: введён некорректный URL.")
        print("Убедитесь, что адрес начинается с http:// или https:// и содержит домен.")
        print("=" * 60)
        return

    if is_email:
        print(f"Файл: {result.get('file', '')}")
        print(f"Тема: {result.get('subject', '')}")
        print(f"От: {result.get('from', '')}")
    else:
        print(f"URL: {result.get('url', '')}")
    print(f"Эвристический скоринг: {result['heuristic_score']}/100 ({result['heuristic_verdict']})")
    if result.get('ml_confidence') is not None:
        print(f"ML confidence: {result['ml_confidence']} ({result['ml_verdict']})")
    else:
        print("ML модель не загружена – используется только эвристика.")
    print(f"Гибридный скоринг: {result['hybrid_score']}/100")
    print(f"Итоговый вердикт: {result['verdict']}")
    signs = result.get('signs', []) + result.get('ml_signs', [])
    if signs:
        print("\nОбнаруженные признаки:")
        for s in signs:
            print(f"  • {s}")
    print("=" * 60)

# ----------------------------------------------
# CLI (интерактивный + командный режим)
# ----------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='PhishBuster Hybrid Engine')
    parser.add_argument('--file', help='Путь к .eml файлу')
    parser.add_argument('--url', help='URL для проверки')
    parser.add_argument('--raw', action='store_true', help='Вывести результат в JSON')
    parser.add_argument('--report', choices=['html'], help='Сохранить отчёт в указанном формате (html)')
    args = parser.parse_args()

    # Командный режим с аргументами
    if args.file or args.url:
        if args.file:
            if not os.path.exists(args.file):
                print(f"Файл {args.file} не найден")
                sys.exit(1)
            result = hybrid_analyze_email(args.file)
            is_email = True
        else:
            result = hybrid_analyze_url(args.url)
            is_email = False

        if result is None:
            print("Ошибка: анализ не вернул результат.")
            sys.exit(1)

        if args.raw:
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:
            print_result(result, is_email=is_email)

        if args.report == 'html':
            path = save_report(result, is_email=is_email)
            print(f"\nHTML-отчёт сохранён: {path}")
        return

    # Интерактивный режим
    check_email_dir = "/home/zakhar/phishbuster/phishbuster/check_email"
    last_result = None
    last_is_email = True

    try:
        while True:
            print('\n' + "=" * 60)
            print("PhishBuster Hybrid Engine – Главное меню")
            print("=" * 60)
            print("1 – Проверить письмо (из папки check_email)")
            print("2 – Проверить URL")
            print("3 – Показать последний результат в JSON")
            print("4 – Сохранить HTML-отчёт последнего анализа")
            print("Нажмите Ctrl+C для выхода")
            choice = input("Ваш выбор: ").strip()

            if choice == '1':
                filename = input("Введите имя файла (например, phishing.eml): ").strip()
                if not filename:
                    print("Ошибка: имя файла не может быть пустым.")
                    continue
                filepath = os.path.join(check_email_dir, filename)
                if not os.path.exists(filepath):
                    print(f"Файл '{filename}' не найден в папке {check_email_dir}")
                    continue
                result = hybrid_analyze_email(filepath)
                if result is None:
                    print("Ошибка анализа письма.")
                    continue
                last_result = result
                last_is_email = True
                print_result(result, is_email=True)

            elif choice == '2':
                url = input("Введите URL полностью (начиная с http:// или https://): ").strip()
                if not url:
                    print("Ошибка: URL не может быть пустым.")
                    continue
                if not is_valid_url(url):
                    print("Ошибка: введён некорректный URL. Убедитесь, что он начинается с http:// или https:// и содержит домен.")
                    continue
                result = hybrid_analyze_url(url)
                if result is None:
                    print("Ошибка анализа URL.")
                    continue
                last_result = result
                last_is_email = False
                print_result(result, is_email=False)

            elif choice == '3':
                if last_result is None:
                    print("Нет результатов для отображения. Сначала выполните анализ.")
                else:
                    print(json.dumps(last_result, ensure_ascii=False, indent=2, default=str))

            elif choice == '4':
                if last_result is None:
                    print("Нет результатов для сохранения. Сначала выполните анализ.")
                else:
                    path = save_report(last_result, is_email=last_is_email)
                    print(f"HTML-отчёт сохранён: {path}")

            else:
                print("Неверный выбор. Пожалуйста, введите 1, 2, 3, 4 или нажмите Ctrl+C для выхода.")
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем (Ctrl+C).")
        print("=" * 60)
        sys.exit(0)

if __name__ == '__main__':
    main()
