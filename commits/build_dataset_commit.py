#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
Сбор датасета из .eml-файлов для обучения модели.
Использование:
    python3 build_dataset.py
"""

import os                                                       # Работа с путями и папками
import sys                                                      # Выход из программы и пути импорта
import pandas as pd                                             # Работа с табличными данными (DataFrame)

# Убедимся, что feature_extractor доступен
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # Добавляем текущую папку в пути импорта
from feature_extractor import extract_email_features            # Импортируем функцию извлечения признаков писем

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data', 'emails')   # Папка с исходными .eml-файлами
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), 'data', 'dataset.csv')  # Путь для сохранения датасета

def collect_samples():                                           # Сбор признаков из всех .eml в папках phishing/legit
    samples = []                                                 # Список для собранных образцов
    for label, subdir in [(1, 'phishing'), (0, 'legit')]:       # 1 – фишинг, 0 – легитимные
        folder = os.path.join(DATA_DIR, subdir)                  # Полный путь к папке категории
        if not os.path.isdir(folder):                            # Если папка не существует
            print(f"Папка {folder} не найдена, создайте её и поместите .eml файлы.")
            continue                                             # Переходим к следующей категории
        for fname in sorted(os.listdir(folder)):                 # Обходим файлы в алфавитном порядке
            if fname.endswith('.eml'):                           # Берём только .eml-файлы
                filepath = os.path.join(folder, fname)           # Полный путь к файлу
                try:                                             # Пробуем извлечь признаки
                    features = extract_email_features(filepath)  # Вызываем извлечение признаков
                    features['label'] = label                    # Добавляем метку класса
                    samples.append(features)                     # Сохраняем образец
                    print(f"[OK] {fname}")                       # Успешная обработка
                except Exception as e:                           # Ошибка при извлечении
                    print(f"[ERR] {fname}: {e}")                 # Выводим ошибку
    return samples                                               # Возвращаем список образцов

if __name__ == '__main__':                                       # Точка входа при запуске скрипта
    print("=" * 60)                                              # Вывод заголовка
    print("PhishBuster Build Dataset")
    print("=" * 60)
    samples = collect_samples()                                  # Запускаем сбор образцов
    if not samples:                                              # Если ничего не собрали
        print("Нет данных. Поместите .eml в data/emails/phishing/ и data/emails/legit/")
        sys.exit(0)                                              # Выходим

    df = pd.DataFrame(samples)                                   # Превращаем список словарей в таблицу
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)      # Создаём выходную папку, если нужно
    df.to_csv(OUTPUT_CSV, index=False)                           # Сохраняем таблицу в CSV без индекса
    print(f"Датасет сохранён в {OUTPUT_CSV} ({len(df)} записей)")  # Сообщаем результат
