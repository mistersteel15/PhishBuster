#!/usr/bin/env python3                                          # Шебанг для Unix-систем
"""
Простой k-NN классификатор для PhishBuster.
Не требует scikit-learn, joblib – только стандартная библиотека Python.
Использование:
    python3 train_model.py
"""

import csv                                                       # Чтение CSV-файла с признаками
import os                                                       # Работа с путями и файлами
import sys                                                      # Выход из программы
import pickle                                                   # Сохранение и загрузка модели
import random                                                   # Перемешивание данных перед разбиением
import math                                                     # Математическая функция sqrt

DATA_CSV = os.path.join(os.path.dirname(__file__), 'data', 'dataset.csv')   # Путь к датасету писем
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'phish_model.pkl')  # Путь для сохранения модели

def load_data(csv_path):                                        # Загрузка данных из CSV
    """Загружает CSV, возвращает список словарей и множество всех ключей (признаков)."""
    rows = []                                                   # Список для строк
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:  # Открываем CSV
        reader = csv.DictReader(f)                              # Читаем как словарь
        for row in reader:                                      # По каждой строке
            new_row = {}                                        # Новый словарь для преобразованных значений
            for key, val in row.items():                        # По каждой колонке
                if key == 'label':                              # Если это целевая метка
                    new_row[key] = int(val)                     # Преобразуем в целое
                else:                                           # Иначе это признак
                    try:                                        # Пробуем преобразовать в float
                        new_row[key] = float(val)
                    except (ValueError, TypeError):             # Если не число – пропускаем (например, from_domain)
                        continue
            rows.append(new_row)                                # Добавляем обработанную строку
    # Собираем все числовые ключи (кроме label)
    all_keys = set()                                            # Множество для названий признаков
    for row in rows:                                            # Обходим все строки
        all_keys.update(row.keys())                             # Добавляем ключи
    all_keys.discard('label')                                   # Удаляем 'label' из признаков
    return rows, sorted(all_keys)                               # Возвращаем строки и отсортированные имена признаков

def min_max_normalize(data, feature_keys):                      # Min-max нормализация признаков
    """Нормализует признаки в интервал [0,1] и возвращает параметры."""
    # Вычисляем минимум и максимум для каждого признака по всем строкам
    min_vals = {k: min(row[k] for row in data if k in row) for k in feature_keys}
    max_vals = {k: max(row[k] for row in data if k in row) for k in feature_keys}
    # Диапазон (max - min), если 0 – заменяем на 1.0, чтобы избежать деления на ноль
    range_vals = {k: (max_vals[k] - min_vals[k]) if max_vals[k] != min_vals[k] else 1.0 for k in feature_keys}
    normalized = []                                              # Список для нормализованных данных
    for row in data:                                             # Для каждой строки данных
        new_row = {}                                             # Новый словарь
        for k in feature_keys:                                   # Для каждого признака
            if k in row:                                         # Если признак есть в строке
                new_row[k] = (row[k] - min_vals[k]) / range_vals[k]  # Нормализуем
            else:                                                # Если отсутствует
                new_row[k] = 0.0                                 # Заполняем нулём
        new_row['label'] = row['label']                         # Сохраняем метку
        normalized.append(new_row)                               # Добавляем нормализованную строку
    return normalized, min_vals, range_vals                      # Возвращаем данные и параметры

def euclidean_distance(a, b, keys):                              # Евклидово расстояние между двумя точками
    """Евклидово расстояние между двумя точками по заданным ключам."""
    dist = 0.0                                                   # Начальное расстояние
    for k in keys:                                               # По всем признакам
        dist += (a.get(k, 0.0) - b.get(k, 0.0)) ** 2           # Квадрат разницы
    return math.sqrt(dist)                                       # Квадратный корень

def knn_predict(train_data, test_point, k, keys):               # Предсказание метки для одной точки
    """Предсказывает метку (0 или 1) для test_point на основе k ближайших соседей."""
    distances = []                                               # Список расстояний
    for train_row in train_data:                                 # По всем обучающим примерам
        dist = euclidean_distance(test_point, train_row, keys)  # Считаем расстояние
        distances.append((dist, train_row['label']))             # Добавляем пару (расстояние, метка)
    distances.sort(key=lambda x: x[0])                           # Сортируем по расстоянию
    # Голосование k ближайших
    k_nearest = distances[:k]                                    # Берём k ближайших
    votes = sum(1 for _, label in k_nearest if label == 1)      # Считаем голоса за фишинг (1)
    return 1 if votes > k // 2 else 0                            # Возвращаем 1, если больше половины

def evaluate(y_true, y_pred):                                    # Расчёт метрик качества
    """Вычисляет accuracy, precision, recall для бинарной классификации."""
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)  # True Positive
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)  # True Negative
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)  # False Positive
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)  # False Negative
    accuracy = (tp + tn) / len(y_true) if y_true else 0          # Доля правильных ответов
    precision = tp / (tp + fp) if (tp + fp) else 0               # Точность предсказаний фишинга
    recall = tp / (tp + fn) if (tp + fn) else 0                  # Полнота обнаружения фишинга
    return accuracy, precision, recall

def main():                                                      # Главная функция обучения
    if not os.path.exists(DATA_CSV):                             # Проверяем наличие датасета
        print(f"Файл {DATA_CSV} не найден. Сначала запустите build_dataset.py")
        sys.exit(1)

    # Загрузка данных
    data, feature_keys = load_data(DATA_CSV)                    # Читаем CSV и получаем имена признаков
    if len(data) < 4:                                            # Минимум 4 записи для разбиения
        print("Слишком мало данных для обучения (нужно минимум 4).")
        sys.exit(1)

    # Перемешиваем и разделяем на train/test (70/30)
    random.seed(42)                                              # Фиксируем генератор для воспроизводимости
    shuffled = data[:]                                           # Копируем список данных
    random.shuffle(shuffled)                                     # Перемешиваем случайным образом
    split_idx = int(len(shuffled) * 0.7)                         # Индекс разделения: 70% в обучение
    train_data = shuffled[:split_idx]                            # Обучающая выборка
    test_data = shuffled[split_idx:]                             # Тестовая выборка

    # Нормализация (обучаем параметры на train, применяем к test)
    train_norm, min_vals, range_vals = min_max_normalize(train_data, feature_keys)  # Нормализуем train
    test_norm, _, _ = min_max_normalize(test_data, feature_keys)                  # Нормализуем test (с теми же параметрами)
    # Корректируем test_norm, чтобы он использовал min/range от train
    for row in test_norm:                                        # Для каждой строки теста
        for k in feature_keys:                                   # По признакам
            if k in min_vals:                                    # Если параметры есть
                raw = row.get(k, 0.0) * range_vals[k] + min_vals[k]  # Восстанавливаем исходное значение
                row[k] = (raw - min_vals[k]) / range_vals[k] if range_vals[k] != 0 else 0.0  # Нормализуем заново

    # k-NN: выберем k (не более количества обучающих примеров, нечётное)
    k = min(3, len(train_norm))                                  # k = 3 или меньше, если данных мало
    if k % 2 == 0:                                               # Если k чётное
        k -= 1                                                   # Делаем нечётным для избежания ничьей
    if k < 1:                                                    # Если k меньше 1
        k = 1                                                    # Минимум 1

    # Предсказания на тесте
    y_true = [row['label'] for row in test_norm]                # Истинные метки тестовой выборки
    y_pred = [knn_predict(train_norm, row, k, feature_keys) for row in test_norm]  # Предсказанные метки

    # Оценка качества
    acc, prec, rec = evaluate(y_true, y_pred)                   # Считаем метрики
    print("=== Метрики качества (k-NN) ===")
    print(f"K = {k}")
    print(f"Точность (accuracy): {acc:.3f}")
    print(f"Точность (precision): {prec:.3f}")
    print(f"Полнота (recall): {rec:.3f}")

    # Сохраняем модель (обучающие данные + параметры нормализации)
    model = {
        'train_data': train_norm,
        'feature_keys': feature_keys,
        'min_vals': min_vals,
        'range_vals': range_vals,
        'k': k,
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)     # Создаём папку, если её нет
    with open(MODEL_PATH, 'wb') as f:                            # Открываем файл для записи в бинарном режиме
        pickle.dump(model, f)                                    # Сохраняем модель через pickle
    print(f"Модель сохранена в {MODEL_PATH}")

if __name__ == '__main__':
    print("=" * 60)
    print("PhishBuster Train Model")
    print("=" * 60)
    main()
