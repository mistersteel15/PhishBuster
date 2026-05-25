#!/usr/bin/env python3
"""
Простой k-NN классификатор для PhishBuster.
Не требует scikit-learn, joblib – только стандартная библиотека Python.
Использование:
    python3 train_model.py
"""

import csv
import os
import sys
import pickle
import random
import math

DATA_CSV = os.path.join(os.path.dirname(__file__), 'data', 'dataset.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'phish_model.pkl')

def load_data(csv_path):
    """Загружает CSV, возвращает список словарей и множество всех ключей (признаков)."""
    rows = []
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Преобразуем значения в float, кроме метки
            new_row = {}
            for key, val in row.items():
                if key == 'label':
                    new_row[key] = int(val)
                else:
                    try:
                        new_row[key] = float(val)
                    except (ValueError, TypeError):
                        # Пропускаем нечисловые столбцы (например, from_domain)
                        continue
            rows.append(new_row)
    # Собираем все числовые ключи (исключая label)
    all_keys = set()
    for row in rows:
        all_keys.update(row.keys())
    all_keys.discard('label')
    return rows, sorted(all_keys)

def min_max_normalize(data, feature_keys):
    """Нормализует признаки в интервал [0,1] и возвращает параметры."""
    min_vals = {k: min(row[k] for row in data if k in row) for k in feature_keys}
    max_vals = {k: max(row[k] for row in data if k in row) for k in feature_keys}
    range_vals = {k: (max_vals[k] - min_vals[k]) if max_vals[k] != min_vals[k] else 1.0 for k in feature_keys}
    normalized = []
    for row in data:
        new_row = {}
        for k in feature_keys:
            if k in row:
                new_row[k] = (row[k] - min_vals[k]) / range_vals[k]
            else:
                new_row[k] = 0.0  # отсутствующий признак → 0
        new_row['label'] = row['label']
        normalized.append(new_row)
    return normalized, min_vals, range_vals

def euclidean_distance(a, b, keys):
    """Евклидово расстояние между двумя точками по заданным ключам."""
    dist = 0.0
    for k in keys:
        dist += (a.get(k, 0.0) - b.get(k, 0.0)) ** 2
    return math.sqrt(dist)

def knn_predict(train_data, test_point, k, keys):
    """Предсказывает метку (0 или 1) для test_point на основе k ближайших соседей."""
    distances = []
    for train_row in train_data:
        dist = euclidean_distance(test_point, train_row, keys)
        distances.append((dist, train_row['label']))
    distances.sort(key=lambda x: x[0])
    # Голосование k ближайших
    k_nearest = distances[:k]
    votes = sum(1 for _, label in k_nearest if label == 1)
    return 1 if votes > k // 2 else 0

def evaluate(y_true, y_pred):
    """Вычисляет accuracy, precision, recall для бинарной классификации."""
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    accuracy = (tp + tn) / len(y_true) if y_true else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    return accuracy, precision, recall

def main():
    if not os.path.exists(DATA_CSV):
        print(f"Файл {DATA_CSV} не найден. Сначала запустите build_dataset.py")
        sys.exit(1)

    # Загрузка данных
    data, feature_keys = load_data(DATA_CSV)
    if len(data) < 4:
        print("Слишком мало данных для обучения (нужно минимум 4).")
        sys.exit(1)

    # Перемешиваем и разделяем на train/test (70/30)
    random.seed(42)
    shuffled = data[:]
    random.shuffle(shuffled)
    split_idx = int(len(shuffled) * 0.7)
    train_data = shuffled[:split_idx]
    test_data = shuffled[split_idx:]

    # Нормализация (обучаем на train, применяем ко всем)
    train_norm, min_vals, range_vals = min_max_normalize(train_data, feature_keys)
    test_norm, _, _ = min_max_normalize(test_data, feature_keys)
    # Применяем те же min/range к test
    for row in test_norm:
        for k in feature_keys:
            if k in min_vals:
                raw = row.get(k, 0.0) * range_vals[k] + min_vals[k]
                row[k] = (raw - min_vals[k]) / range_vals[k] if range_vals[k] != 0 else 0.0

    # k-NN: выберем k (не более количества обучающих примеров, нечётное)
    k = min(3, len(train_norm))
    if k % 2 == 0:
        k -= 1
    if k < 1:
        k = 1

    # Предсказания на тесте
    y_true = [row['label'] for row in test_norm]
    y_pred = [knn_predict(train_norm, row, k, feature_keys) for row in test_norm]

    # Оценка
    acc, prec, rec = evaluate(y_true, y_pred)
    print("=== Метрики качества (k-NN) ===")
    print(f"K = {k}")
    print(f"Точность (accuracy): {acc:.3f}")
    print(f"Точность (precision): {prec:.3f}")
    print(f"Полнота (recall): {rec:.3f}")

    # Сохраняем модель (обучающие данные + параметры)
    model = {
        'train_data': train_norm,
        'feature_keys': feature_keys,
        'min_vals': min_vals,
        'range_vals': range_vals,
        'k': k,
    }
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    print(f"Модель сохранена в {MODEL_PATH}")

if __name__ == '__main__':
    print("=" * 60)
    print("PhishBuster Train Model")
    print("=" * 60)
    main()
