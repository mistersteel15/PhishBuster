#!/usr/bin/env python3                                          # Шебанг для Unix
"""
PhishBuster – Этап 5: Гибридный движок (Rule Engine + ML)
Объединяет эвристический анализ и машинное обучение.
Использование:
    python3 hybrid_engine.py --file письмо.eml
    python3 hybrid_engine.py --url http://example.com
    python3 hybrid_engine.py                    # интерактивный режим
"""

import os                                                       # Работа с файловой системой
import sys                                                      # Завершение программы
import pickle                                                   # Загрузка/сохранение модели
import math                                                     # Математические операции (sqrt)
import argparse                                                 # Разбор аргументов командной строки
import json                                                     # Работа с JSON
from urllib.parse import urlparse as urlparse_check             # Проверка валидности URL
from reporter import save_report                                # Функция сохранения HTML-отчёта

EMAIL_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'phish_model.pkl')  # Путь к модели для писем
URL_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'url_model.pkl')      # Путь к модели для URL

# Добавляем текущую папку в пути импорта
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # Чтобы Python видел модули проекта

# ----------------------------------------------
# Импорт наших модулей (с мягкой обработкой ошибок)
# ----------------------------------------------
try:                                                            # Пробуем импортировать email_analyzer
    from email_analyzer import analyze_eml                      # Функция анализа письма
    EMAIL_OK = True                                             # Модуль доступен
except ImportError:                                             # Модуль не найден
    EMAIL_OK = False                                            # Флаг недоступности
    print("[!] email_analyzer не найден", file=sys.stderr)      # Сообщение об ошибке

try:                                                            # Пробуем импортировать url_analyzer
    from url_analyzer import analyze_url as url_analyzer_func   # Функция анализа URL
    URL_OK = True                                               # Модуль доступен
except ImportError:                                             # Модуль не найден
    URL_OK = False                                              # Флаг недоступности
    print("[!] url_analyzer не найден", file=sys.stderr)        # Сообщение об ошибке

try:                                                            # Пробуем импортировать feature_extractor
    from feature_extractor import extract_email_features, extract_url_features  # Функции извлечения признаков
    FE_OK = True                                                # Модуль доступен
except ImportError:                                             # Модуль не найден
    FE_OK = False                                               # Флаг недоступности
    print("[!] feature_extractor не найден", file=sys.stderr)   # Сообщение об ошибке

# ----------------------------------------------
# Загрузка ML-модели (k-NN)
# ----------------------------------------------
def load_model(model_type='email'):                             # Загрузка модели по типу
    """Загружает модель k-NN. model_type = 'email' или 'url'."""
    path = EMAIL_MODEL_PATH if model_type == 'email' else URL_MODEL_PATH  # Выбор пути
    if not os.path.exists(path):                                # Если файла нет
        return None                                             # Возвращаем None
    with open(path, 'rb') as f:                                 # Открываем файл в бинарном режиме
        model = pickle.load(f)                                  # Загружаем модель через pickle
    return model                                                # Возвращаем модель

# ----------------------------------------------
# Предсказание с вероятностью (k-NN)
# ----------------------------------------------
def predict_with_confidence(model, features_dict):              # Предсказание метки и уверенности
    """
    Возвращает (predicted_label, confidence) для одного примера.
    confidence – доля голосов за класс 1 среди k ближайших соседей (от 0 до 1).
    """
    train_data = model['train_data']                            # Обучающие данные
    feature_keys = model['feature_keys']                        # Имена признаков
    min_vals = model['min_vals']                                # Минимумы для нормализации
    range_vals = model['range_vals']                            # Диапазоны для нормализации
    k = model['k']                                              # Число соседей

    # Нормализация входного вектора
    norm = {}                                                   # Пустой словарь для нормализованных значений
    for key in feature_keys:                                    # Для каждого признака
        raw = features_dict.get(key, 0.0)                       # Берём сырое значение или 0
        if key in min_vals and range_vals.get(key, 0) != 0:     # Если есть параметры нормализации
            norm[key] = (raw - min_vals[key]) / range_vals[key] # Нормализуем
        else:                                                   # Иначе
            norm[key] = 0.0                                     # Присваиваем 0

    # Вычисление расстояний до всех обучающих примеров
    distances = []                                              # Список расстояний
    for train_row in train_data:                                # Для каждой строки обучения
        dist = 0.0                                              # Начальное расстояние
        for key in feature_keys:                                # По всем признакам
            diff = norm[key] - train_row.get(key, 0.0)         # Разница нормализованных значений
            dist += diff * diff                                 # Квадрат разницы
        distances.append((math.sqrt(dist), train_row['label'])) # Добавляем расстояние и метку
    distances.sort(key=lambda x: x[0])                          # Сортируем по расстоянию

    # k ближайших
    k_nearest = distances[:k]                                   # Берём первых k
    votes_phishing = sum(1 for _, label in k_nearest if label == 1)  # Считаем голоса за фишинг
    confidence = votes_phishing / len(k_nearest)                # Доля голосов (от 0 до 1)
    predicted_label = 1 if votes_phishing > k // 2 else 0       # Большинство голосов
    return predicted_label, confidence                          # Возвращаем метку и уверенность

# ----------------------------------------------
# Проверка корректности URL
# ----------------------------------------------
def is_valid_url(url: str) -> bool:                             # Проверка валидности URL
    """Простая проверка: URL должен содержать схему и домен."""
    try:                                                        # Пробуем разобрать
        parsed = urlparse_check(url)                            # Разбираем URL
        return all([parsed.scheme in ('http', 'https'), parsed.netloc])  # Должны быть схема и домен
    except Exception:                                           # Ошибка разбора
        return False                                            # Считаем невалидным

# ----------------------------------------------
# Гибридный анализ письма (исправлен)
# ----------------------------------------------
def hybrid_analyze_email(filepath):                             # Гибридный анализ письма
    """Анализирует .eml файл с помощью эвристик и ML."""
    result = {                                                  # Инициализация словаря результата
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
    if EMAIL_OK:                                                # Если email_analyzer доступен
        try:                                                    # Пытаемся выполнить анализ
            report = analyze_eml(filepath)                      # Вызываем функцию анализа
            result['subject'] = report.get('subject', '')       # Забираем тему
            result['from'] = report.get('from', '')             # Забираем отправителя
            result['heuristic_score'] = report.get('score', 0)  # Эвристический балл
            result['heuristic_verdict'] = report.get('verdict', 'CLEAN')  # Вердикт эвристики
            result['signs'] = report.get('signs', [])           # Признаки эвристики
        except Exception as e:                                  # Ошибка при анализе
            result['signs'].append(f"Ошибка эвристического анализа: {e}")  # Сохраняем ошибку

    # 2. Извлечение признаков и предсказание ML
    model = load_model('email')                                 # Загружаем модель для писем
    if model and FE_OK:                                         # Если модель и feature_extractor доступны
        try:                                                    # Пытаемся извлечь признаки и предсказать
            features = extract_email_features(filepath)         # Извлекаем признаки письма
            pred_label, confidence = predict_with_confidence(model, features)  # Предсказание
            result['ml_confidence'] = round(confidence, 3)      # Сохраняем уверенность
            result['ml_verdict'] = 'PHISHING' if pred_label == 1 else 'CLEAN'  # Вердикт ML
            if pred_label == 1:                                 # Если ML считает фишингом
                result['ml_signs'].append(f"ML-модель: фишинг (confidence={confidence:.2f})")
            else:                                               # Если легитимное
                result['ml_signs'].append(f"ML-модель: легитимное (confidence={confidence:.2f})")
        except Exception as e:                                  # Ошибка ML
            result['ml_signs'].append(f"Ошибка ML: {e}")

    # 3. Гибридный скоринг (защита от слабого ML)
    heuristic = result['heuristic_score']                      # Эвристический балл
    ml_confidence = result['ml_confidence'] if result['ml_confidence'] is not None else 0.0  # Уверенность ML
    if heuristic >= 30:                                         # Если эвристика уже считает фишингом
        hybrid_score = heuristic                               # Доверяем эвристике
    else:                                                       # Иначе ограничиваем влияние ML
        ml_boost = int(ml_confidence * 20)                      # Бонус от ML не более 20
        hybrid_score = min(heuristic + ml_boost, 29)            # Не даём подняться выше 29
    result['hybrid_score'] = min(hybrid_score, 100)             # Ограничиваем максимум 100
    result['verdict'] = 'PHISHING' if result['hybrid_score'] >= 30 else 'CLEAN'  # Итоговый вердикт

    return result                                               # Возвращаем результат

# ----------------------------------------------
# Гибридный анализ URL (без изменений)
# ----------------------------------------------
def hybrid_analyze_url(url):                                    # Гибридный анализ URL
    """Анализирует URL с помощью эвристик url_analyzer и ML."""
    if not is_valid_url(url):                                   # Если URL некорректен
        return {                                                # Возвращаем сообщение об ошибке
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

    result = {                                                  # Инициализация словаря результата
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
    if URL_OK:                                                  # Если url_analyzer доступен
        try:                                                    # Пытаемся проанализировать
            report = url_analyzer_func(url)                     # Вызываем анализатор URL
            result['heuristic_score'] = report.get('score', 0)  # Эвристический балл
            result['heuristic_verdict'] = report.get('verdict', 'CLEAN')  # Вердикт
            result['signs'] = report.get('flags', [])           # Признаки
        except Exception as e:                                  # Ошибка
            result['signs'].append(f"Ошибка анализа URL: {e}")

    # 2. ML (если есть модель)
    model = load_model('url')                                   # Загружаем модель для URL
    if model and FE_OK:                                         # Если модель и фичи доступны
        try:                                                    # Извлекаем признаки и предсказываем
            features = extract_url_features(url)                # Извлекаем признаки URL
            pred_label, confidence = predict_with_confidence(model, features)  # Предсказание
            result['ml_confidence'] = round(confidence, 3)      # Уверенность
            result['ml_verdict'] = 'PHISHING' if pred_label == 1 else 'CLEAN'  # Вердикт ML
            if pred_label == 1:
                result['ml_signs'].append(f"ML-модель: фишинг (confidence={confidence:.2f})")
            else:
                result['ml_signs'].append(f"ML-модель: легитимное (confidence={confidence:.2f})")
        except Exception as e:
            result['ml_signs'].append(f"Ошибка ML: {e}")

    # 3. Гибридный скоринг
    heuristic = result['heuristic_score']                      # Эвристический балл
    ml_confidence = result['ml_confidence'] if result['ml_confidence'] is not None else 0.0
    if heuristic >= 30:                                         # Если эвристика бьёт тревогу
        hybrid_score = heuristic                               # Доверяем ей
    else:                                                       # Иначе ограничиваем ML
        ml_boost = int(ml_confidence * 20)
        hybrid_score = min(heuristic + ml_boost, 29)
    result['hybrid_score'] = hybrid_score
    result['verdict'] = 'PHISHING' if hybrid_score >= 30 else 'CLEAN'
    return result

# ----------------------------------------------
# Вывод результатов
# ----------------------------------------------
def print_result(result, is_email=True):                        # Вывод результата в консоль
    """Выводит результат анализа в человекочитаемом формате."""
    if not result:                                              # Если результат пуст
        print("Ошибка: пустой результат.")
        return

    print("\n" + "=" * 60)                                      # Заголовок
    print("PhishBuster Hybrid Engine – Результат")
    print("=" * 60)

    if result.get('verdict') == 'INVALID_URL':                  # Обработка невалидного URL
        print(f"URL: {result.get('url', '')}")
        print("Ошибка: введён некорректный URL.")
        print("Убедитесь, что адрес начинается с http:// или https:// и содержит домен.")
        print("=" * 60)
        return

    if is_email:                                                # Вывод для письма
        print(f"Файл: {result.get('file', '')}")
        print(f"Тема: {result.get('subject', '')}")
        print(f"От: {result.get('from', '')}")
    else:                                                       # Вывод для URL
        print(f"URL: {result.get('url', '')}")
    print(f"Эвристический скоринг: {result['heuristic_score']}/100 ({result['heuristic_verdict']})")
    if result.get('ml_confidence') is not None:                 # Если ML-уверенность известна
        print(f"ML confidence: {result['ml_confidence']} ({result['ml_verdict']})")
    else:                                                       # Если модель не загружена
        print("ML модель не загружена – используется только эвристика.")
    print(f"Гибридный скоринг: {result['hybrid_score']}/100")
    print(f"Итоговый вердикт: {result['verdict']}")
    signs = result.get('signs', []) + result.get('ml_signs', [])  # Объединяем признаки
    if signs:                                                   # Если есть признаки
        print("\nОбнаруженные признаки:")
        for s in signs:                                         # Выводим каждый
            print(f"  • {s}")
    print("=" * 60)

# ----------------------------------------------
# CLI (интерактивный + командный режим)
# ----------------------------------------------
def main():                                                     # Главная функция CLI
    parser = argparse.ArgumentParser(description='PhishBuster Hybrid Engine')  # Парсер аргументов
    parser.add_argument('--file', help='Путь к .eml файлу')     # Аргумент для файла
    parser.add_argument('--url', help='URL для проверки')       # Аргумент для URL
    parser.add_argument('--raw', action='store_true', help='Вывести результат в JSON')  # Флаг JSON
    parser.add_argument('--report', choices=['html'], help='Сохранить отчёт в указанном формате (html)')  # Сохранение отчёта
    args = parser.parse_args()                                  # Разбираем аргументы

    # Командный режим с аргументами
    if args.file or args.url:                                   # Если передан файл или URL
        if args.file:                                           # Обработка файла
            if not os.path.exists(args.file):                   # Проверка существования
                print(f"Файл {args.file} не найден")
                sys.exit(1)
            result = hybrid_analyze_email(args.file)            # Гибридный анализ письма
            is_email = True
        else:                                                   # Обработка URL
            result = hybrid_analyze_url(args.url)               # Гибридный анализ URL
            is_email = False

        if result is None:                                      # Если результат None
            print("Ошибка: анализ не вернул результат.")
            sys.exit(1)

        if args.raw:                                            # Вывод в JSON
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        else:                                                   # Человекочитаемый вывод
            print_result(result, is_email=is_email)

        if args.report == 'html':                               # Сохранение HTML-отчёта
            path = save_report(result, is_email=is_email)
            print(f"\nHTML-отчёт сохранён: {path}")
        return

    # Интерактивный режим
    check_email_dir = "/home/zakhar/phishbuster/phishbuster/check_email"  # Папка с письмами
    last_result = None                                          # Последний результат для JSON и сохранения
    last_is_email = True                                        # Тип последнего анализа

    try:                                                        # Обработка Ctrl+C
        while True:                                             # Бесконечный цикл меню
            print('\n' + "=" * 60)
            print("PhishBuster Hybrid Engine – Главное меню")
            print("=" * 60)
            print("1 – Проверить письмо (из папки check_email)")
            print("2 – Проверить URL")
            print("3 – Показать последний результат в JSON")
            print("4 – Сохранить HTML-отчёт последнего анализа")
            print("Нажмите Ctrl+C для выхода")
            choice = input("Ваш выбор: ").strip()               # Считываем выбор

            if choice == '1':                                   # Проверка письма
                filename = input("Введите имя файла (например, phishing.eml): ").strip()
                if not filename:                                # Пустой ввод
                    print("Ошибка: имя файла не может быть пустым.")
                    continue
                filepath = os.path.join(check_email_dir, filename)  # Полный путь
                if not os.path.exists(filepath):                # Файл не существует
                    print(f"Файл '{filename}' не найден в папке {check_email_dir}")
                    continue
                result = hybrid_analyze_email(filepath)         # Анализируем письмо
                if result is None:                              # Если результат None
                    print("Ошибка анализа письма.")
                    continue
                last_result = result                            # Сохраняем для истории
                last_is_email = True
                print_result(result, is_email=True)             # Выводим результат

            elif choice == '2':                                 # Проверка URL
                url = input("Введите URL полностью (начиная с http:// или https://): ").strip()
                if not url:                                     # Пустой ввод
                    print("Ошибка: URL не может быть пустым.")
                    continue
                if not is_valid_url(url):                       # Невалидный URL
                    print("Ошибка: введён некорректный URL. Убедитесь, что он начинается с http:// или https:// и содержит домен.")
                    continue
                result = hybrid_analyze_url(url)                # Анализируем URL
                if result is None:
                    print("Ошибка анализа URL.")
                    continue
                last_result = result
                last_is_email = False
                print_result(result, is_email=False)

            elif choice == '3':                                 # Показать JSON последнего результата
                if last_result is None:
                    print("Нет результатов для отображения. Сначала выполните анализ.")
                else:
                    print(json.dumps(last_result, ensure_ascii=False, indent=2, default=str))

            elif choice == '4':                                 # Сохранить HTML-отчёт
                if last_result is None:
                    print("Нет результатов для сохранения. Сначала выполните анализ.")
                else:
                    path = save_report(last_result, is_email=last_is_email)
                    print(f"HTML-отчёт сохранён: {path}")

            else:                                               # Неверный ввод
                print("Неверный выбор. Пожалуйста, введите 1, 2, 3, 4 или нажмите Ctrl+C для выхода.")
    except KeyboardInterrupt:                                   # Обработка Ctrl+C
        print("\nПрограмма прервана пользователем (Ctrl+C).")
        print("=" * 60)
        sys.exit(0)

if __name__ == '__main__':
    main()
