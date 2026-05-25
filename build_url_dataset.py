#!/usr/bin/env python3
"""
Сбор датасета URL для обучения модели.
Использование:
    python3 build_url_dataset.py
"""

import os
import sys
import csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_url_features

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data', 'urls')
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), 'data', 'url_dataset.csv')

def load_urls_from_folder(folder):
    urls = []
    if not os.path.isdir(folder):
        return urls
    for fname in sorted(os.listdir(folder)):
        path = os.path.join(folder, fname)
        if os.path.isfile(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and line.startswith(('http://', 'https://')):
                        urls.append(line)
    return urls

def collect_samples():
    samples = []
    for label, subdir in [(1, 'phishing'), (0, 'legit')]:
        folder = os.path.join(DATA_DIR, subdir)
        urls = load_urls_from_folder(folder)
        for url in urls:
            try:
                features = extract_url_features(url)
                features['label'] = label
                samples.append(features)
                print(f"[OK] {url[:60]}...")
            except Exception as e:
                print(f"[ERR] {url}: {e}")
    return samples

if __name__ == '__main__':
    samples = collect_samples()
    if not samples:
        print("Нет данных. Поместите списки URL в data/urls/phishing/ и data/urls/legit/")
        sys.exit(0)

    # Определяем все возможные ключи
    all_keys = set()
    for s in samples:
        all_keys.update(s.keys())
    all_keys.discard('label')
    fieldnames = sorted(all_keys) + ['label']

    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in samples:
            writer.writerow(row)
    print(f"Датасет сохранён в {OUTPUT_CSV} ({len(samples)} записей)")
