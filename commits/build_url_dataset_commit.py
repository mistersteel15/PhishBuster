#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
Сбор датасета URL для обучения модели.
Использование:
    python3 build_url_dataset.py
"""

import os                                                       # Работа с путями и файловой системой
import sys                                                      # Завершение программы и пути импорта
import csv                                                      # Запись CSV-файла
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # Добавляем текущую папку в пути импорта
from feature_extractor import extract_url_features              # Функция извлечения признаков URL

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data', 'urls')        # Папка с исходными списками URL
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), 'data', 'url_dataset.csv')  # Путь для сохранения датасета

def load_urls_from_folder(folder):                              # Загружает все URL из текстовых файлов в папке
    urls = []                                                   # Список для URL
    if not os.path.isdir(folder):                               # Если папка не существует
        return urls                                             # Возвращаем пустой список
    for fname in sorted(os.listdir(folder)):                    # Обходим файлы в алфавитном порядке
        path = os.path.join(folder, fname)                      # Полный путь к файлу
        if os.path.isfile(path):                                # Если это файл (а не вложенная папка)
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:  # Открываем для чтения
                for line in f:                                  # Построчно читаем
                    line = line.strip()                         # Убираем пробелы и переносы строк
                    if line and line.startswith(('http://', 'https://')):  # Если это URL
                        urls.append(line)                       # Добавляем в список
    return urls                                                 # Возвращаем собранные URL

def collect_samples():                                          # Собирает признаки для всех URL и формирует список образцов
    samples = []                                                # Список для образцов
    for label, subdir in [(1, 'phishing'), (0, 'legit')]:      # 1 – фишинг, 0 – легитимные
        folder = os.path.join(DATA_DIR, subdir)                 # Полный путь к папке категории
        urls = load_urls_from_folder(folder)                    # Загружаем URL из папки
        for url in urls:                                        # По каждому URL
            try:                                                # Пытаемся извлечь признаки
                features = extract_url_features(url)            # Извлекаем числовые признаки
                features['label'] = label                       # Добавляем метку класса
                samples.append(features)                        # Сохраняем образец
                print(f"[OK] {url[:60]}...")                   # Сообщение об успехе (первые 60 символов)
            except Exception as e:                              # Ошибка извлечения
                print(f"[ERR] {url}: {e}")                      # Выводим ошибку
    return samples                                              # Возвращаем список образцов

if __name__ == '__main__':                                      # Точка входа при запуске скрипта
    samples = collect_samples()                                 # Запускаем сбор образцов
    if not samples:                                             # Если ничего не собрали
        print("Нет данных. Поместите списки URL в data/urls/phishing/ и data/urls/legit/")
        sys.exit(0)                                             # Выходим

    # Определяем все возможные ключи (названия признаков)
    all_keys = set()                                            # Множество для имён признаков
    for s in samples:                                           # По всем собранным образцам
        all_keys.update(s.keys())                               # Добавляем ключи словаря
    all_keys.discard('label')                                   # Убираем 'label' из признаков
    fieldnames = sorted(all_keys) + ['label']                   # Список столбцов: сначала признаки, потом метка

    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)     # Создаём папку для выходного файла
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:  # Открываем CSV для записи
        writer = csv.DictWriter(f, fieldnames=fieldnames)       # Создаём писатель с заданными столбцами
        writer.writeheader()                                    # Записываем строку заголовков
        for row in samples:                                     # Для каждой строки данных
            writer.writerow(row)                                # Записываем строку в CSV
    print(f"Датасет сохранён в {OUTPUT_CSV} ({len(samples)} записей)")  # Сообщаем о результате
