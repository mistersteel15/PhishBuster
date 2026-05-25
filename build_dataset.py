#!/usr/bin/env python3
"""
Сбор датасета из .eml-файлов для обучения модели.
Использование:
    python3 build_dataset.py
"""

import os
import sys
import pandas as pd

# Убедимся, что feature_extractor доступен
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_extractor import extract_email_features

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data', 'emails')
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), 'data', 'dataset.csv')

def collect_samples():
    samples = []
    for label, subdir in [(1, 'phishing'), (0, 'legit')]:
        folder = os.path.join(DATA_DIR, subdir)
        if not os.path.isdir(folder):
            print(f"Папка {folder} не найдена, создайте её и поместите .eml файлы.")
            continue
        for fname in sorted(os.listdir(folder)):
            if fname.endswith('.eml'):
                filepath = os.path.join(folder, fname)
                try:
                    features = extract_email_features(filepath)
                    features['label'] = label
                    samples.append(features)
                    print(f"[OK] {fname}")
                except Exception as e:
                    print(f"[ERR] {fname}: {e}")
    return samples

if __name__ == '__main__':
    print("=" * 60)
    print("PhishBuster Build Dataset")
    print("=" * 60)
    samples = collect_samples()
    if not samples:
        print("Нет данных. Поместите .eml в data/emails/phishing/ и data/emails/legit/")
        sys.exit(0)

    df = pd.DataFrame(samples)
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Датасет сохранён в {OUTPUT_CSV} ({len(df)} записей)")
