#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
Обучение k-NN модели для URL.
Использование:
    python3 train_url_model.py
"""

import os                                                       # Работа с путями и файловой системой
import sys                                                      # Завершение программы
import csv                                                      # Чтение CSV-файла с датасетом URL
import pickle                                                   # Сохранение обученной модели
import random                                                   # Перемешивание данных перед разбиением
import math                                                     # Математическая функция sqrt

DATA_CSV = os.path.join(os.path.dirname(__file__), 'data', 'url_dataset.csv')   # Путь к датасету URL
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'url_model.pkl')   # Путь для сохранения модели

def load_data(csv_path):                                        # Загрузка данных из CSV-файла
    rows = []                                                   # Список для обработанных строк
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:  # Открываем CSV
        reader = csv.DictReader(f)                              # Читаем как словарь
        for row in reader:                                      # По каждой строке
            new_row = {}                                        # Новый словарь для числовых значений
            for key, val in row.items():                        # По каждой колонке
                if key == 'label':                              # Если это целевая метка
                    new_row[key] = int(val)                     # Преобразуем в целое
                else:                                           # Иначе — признак
                    try:                                        # Пробуем преобразовать в float
                        new_row[key] = float(val)
                    except (ValueError, TypeError):             # Если не число — пропускаем (например, домен)
                        continue
            rows.append(new_row)                                # Добавляем обработанную строку
    all_keys = set()                                            # Множество для названий признаков
    for row in rows:                                            # Обходим все строки
        all_keys.update(row.keys())                             # Собираем все ключи
    all_keys.discard('label')                                   # Убираем 'label' — это не признак
    return rows, sorted(all_keys)                               # Возвращаем строки и отсортированные имена признаков

def min_max_normalize(data, feature_keys):                      # Min-max нормализация признаков в [0,1]
    # Вычисляем минимумы и максимумы для каждого признака
    min_vals = {k: min(row[k] for row in data if k in row) for k in feature_keys}
    max_vals = {k: max(row[k] for row in data if k in row) for k in feature_keys}
    # Диапазон (max - min), если равен 0 — заменяем на 1.0, чтобы избежать деления на ноль
    range_vals = {k: (max_vals[k] - min_vals[k]) if max_vals[k] != min_vals[k] else 1.0 for k in feature_keys}
    normalized = []                                              # Список для нормализованных данных
    for row in data:                                             # Для каждой строки
        new_row = {}                                             # Новый словарь
        for k in feature_keys:                                   # Для каждого признака
            raw = row.get(k, 0.0)                                # Берём значение (или 0, если отсутствует)
            new_row[k] = (raw - min_vals[k]) / range_vals[k]    # Нормализуем
        new_row['label'] = row['label']                         # Сохраняем метку
        normalized.append(new_row)                               # Добавляем нормализованную строку
    return normalized, min_vals, range_vals                      # Возвращаем данные и параметры

def euclidean_distance(a, b, keys):                              # Евклидово расстояние между двумя точками
    dist = 0.0                                                   # Начальное расстояние
    for k in keys:                                               # По всем признакам
        dist += (a.get(k, 0.0) - b.get(k, 0.0)) ** 2           # Квадрат разницы
    return math.sqrt(dist)                                       # Квадратный корень

def knn_predict(train_data, test_point, k, keys):               # Предсказание метки методом k-NN
    distances = []                                               # Список расстояний до обучающих точек
    for train_row in train_data:                                 # По всем обучающим примерам
        dist = euclidean_distance(test_point, train_row, keys)  # Вычисляем расстояние
        distances.append((dist, train_row['label']))             # Сохраняем пару (расстояние, метка)
    distances.sort(key=lambda x: x[0])                           # Сортируем по расстоянию
    k_nearest = distances[:k]                                    # Берём k ближайших соседей
    votes = sum(1 for _, label in k_nearest if label == 1)      # Считаем голоса за фишинг (1)
    return 1 if votes > k // 2 else 0                            # Возвращаем 1, если голосов больше половины

def evaluate(y_true, y_pred):                                    # Оценка качества классификации
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)  # True Positive
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)  # True Negative
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)  # False Positive
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)  # False Negative
    acc = (tp + tn) / len(y_true) if y_true else 0               # Доля правильных ответов
    prec = tp / (tp + fp) if (tp + fp) else 0                    # Точность (precision)
    rec = tp / (tp + fn) if (tp + fn) else 0                     # Полнота (recall)
    return acc, prec, rec

def main():                                                      # Главная функция обучения модели
    if not os.path.exists(DATA_CSV):                             # Проверяем, существует ли датасет
        print(f"Файл {DATA_CSV} не найден. Сначала запустите build_url_dataset.py")
        sys.exit(1)

    data, feature_keys = load_data(DATA_CSV)                    # Загружаем данные и имена признаков
    if len(data) < 4:                                            # Минимум 4 записи для разделения
        print("Слишком мало данных для обучения (минимум 4 записи).")
        sys.exit(1)

    random.seed(42)                                              # Фиксируем генератор случайных чисел
    shuffled = data[:]                                           # Копируем список
    random.shuffle(shuffled)                                     # Перемешиваем
    split_idx = int(len(shuffled) * 0.7)                         # Индекс разделения 70% / 30%
    train_data = shuffled[:split_idx]                            # Обучающая выборка
    test_data = shuffled[split_idx:]                             # Тестовая выборка

    # Нормализуем обучающую выборку и получаем параметры
    train_norm, min_vals, range_vals = min_max_normalize(train_data, feature_keys)
    # Нормализуем тестовую выборку с теми же параметрами (но пока без коррекции)
    test_norm, _, _ = min_max_normalize(test_data, feature_keys)

    # Корректируем тестовую нормализацию, чтобы она точно соответствовала параметрам train
    for row in test_norm:                                        # По каждой строке теста
        for k in feature_keys:                                   # По каждому признаку
            if k in min_vals:                                    # Если для признака есть минимум/диапазон
                raw = row.get(k, 0.0) * range_vals[k] + min_vals[k]  # Восстанавливаем исходное значение
                row[k] = (raw - min_vals[k]) / range_vals[k] if range_vals[k] != 0 else 0.0  # Нормализуем заново

    # Выбираем k (количество соседей)
    k = min(3, len(train_norm))                                  # k = 3, но не больше числа обучающих примеров
    if k % 2 == 0:                                               # Если k чётное
        k -= 1                                                   # Делаем нечётным
    if k < 1:                                                    # Если k < 1
        k = 1                                                    # Берём 1

    # Истинные и предсказанные метки
    y_true = [row['label'] for row in test_norm]                # Истинные метки
    y_pred = [knn_predict(train_norm, row, k, feature_keys) for row in test_norm]  # Предсказанные метки

    # Оценка качества
    acc, prec, rec = evaluate(y_true, y_pred)
    print("=== Метрики качества (URL k-NN) ===")
    print(f"K = {k}")
    print(f"Точность (accuracy): {acc:.3f}")
    print(f"Точность (precision): {prec:.3f}")
    print(f"Полнота (recall): {rec:.3f}")

    # Сохраняем модель
    model = {
        'train_data': train_norm,                                # Нормализованные обучающие данные
        'feature_keys': feature_keys,                            # Имена признаков
        'min_vals': min_vals,                                    # Минимумы для нормализации
        'range_vals': range_vals,                                # Диапазоны для нормализации
        'k': k,                                                  # Число соседей
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)     # Создаём папку, если её нет
    with open(MODEL_PATH, 'wb') as f:                            # Открываем файл для записи в бинарном режиме
        pickle.dump(model, f)                                    # Сохраняем модель через pickle
    print(f"Модель сохранена в {MODEL_PATH}")

if __name__ == '__main__':
    main()
