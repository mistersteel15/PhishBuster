#!/usr/bin/env python3
"""
Обучение k-NN модели для URL.
Использование:
    python3 train_url_model.py
"""

import os
import sys
import csv
import pickle
import random
import math

DATA_CSV = os.path.join(os.path.dirname(__file__), 'data', 'url_dataset.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'url_model.pkl')

def load_data(csv_path):
    rows = []
    with open(csv_path, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            new_row = {}
            for key, val in row.items():
                if key == 'label':
                    new_row[key] = int(val)
                else:
                    try:
                        new_row[key] = float(val)
                    except (ValueError, TypeError):
                        continue
            rows.append(new_row)
    all_keys = set()
    for row in rows:
        all_keys.update(row.keys())
    all_keys.discard('label')
    return rows, sorted(all_keys)

def min_max_normalize(data, feature_keys):
    min_vals = {k: min(row[k] for row in data if k in row) for k in feature_keys}
    max_vals = {k: max(row[k] for row in data if k in row) for k in feature_keys}
    range_vals = {k: (max_vals[k] - min_vals[k]) if max_vals[k] != min_vals[k] else 1.0 for k in feature_keys}
    normalized = []
    for row in data:
        new_row = {}
        for k in feature_keys:
            raw = row.get(k, 0.0)
            new_row[k] = (raw - min_vals[k]) / range_vals[k]
        new_row['label'] = row['label']
        normalized.append(new_row)
    return normalized, min_vals, range_vals

def euclidean_distance(a, b, keys):
    dist = 0.0
    for k in keys:
        dist += (a.get(k, 0.0) - b.get(k, 0.0)) ** 2
    return math.sqrt(dist)

def knn_predict(train_data, test_point, k, keys):
    distances = []
    for train_row in train_data:
        dist = euclidean_distance(test_point, train_row, keys)
        distances.append((dist, train_row['label']))
    distances.sort(key=lambda x: x[0])
    k_nearest = distances[:k]
    votes = sum(1 for _, label in k_nearest if label == 1)
    return 1 if votes > k // 2 else 0

def evaluate(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    acc = (tp + tn) / len(y_true) if y_true else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    return acc, prec, rec

def main():
    if not os.path.exists(DATA_CSV):
        print(f"Файл {DATA_CSV} не найден. Сначала запустите build_url_dataset.py")
        sys.exit(1)

    data, feature_keys = load_data(DATA_CSV)
    if len(data) < 4:
        print("Слишком мало данных для обучения (минимум 4 записи).")
        sys.exit(1)

    random.seed(42)
    shuffled = data[:]
    random.shuffle(shuffled)
    split_idx = int(len(shuffled) * 0.7)
    train_data = shuffled[:split_idx]
    test_data = shuffled[split_idx:]

    train_norm, min_vals, range_vals = min_max_normalize(train_data, feature_keys)
    test_norm, _, _ = min_max_normalize(test_data, feature_keys)

    for row in test_norm:
        for k in feature_keys:
            if k in min_vals:
                raw = row.get(k, 0.0) * range_vals[k] + min_vals[k]
                row[k] = (raw - min_vals[k]) / range_vals[k] if range_vals[k] != 0 else 0.0

    k = min(3, len(train_norm))
    if k % 2 == 0:
        k -= 1
    if k < 1:
        k = 1

    y_true = [row['label'] for row in test_norm]
    y_pred = [knn_predict(train_norm, row, k, feature_keys) for row in test_norm]

    acc, prec, rec = evaluate(y_true, y_pred)
    print("=== Метрики качества (URL k-NN) ===")
    print(f"K = {k}")
    print(f"Точность (accuracy): {acc:.3f}")
    print(f"Точность (precision): {prec:.3f}")
    print(f"Полнота (recall): {rec:.3f}")

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
    main()
