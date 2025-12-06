import os
import csv
import random


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def generate_dataset(path: str, n: int):
    headers = [
        "patient_id",
        "name",
        "age",
        "heart_rate",
        "blood_pressure_sys",
        "blood_pressure_dia",
        "temperature",
        "glucose",
    ]

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for i in range(1, n + 1):
            patient_id = i
            name = f"Patient {i}"
            age = random.randint(18, 90)
            heart_rate = random.randint(50, 110)
            bp_sys = random.randint(90, 160)
            bp_dia = random.randint(60, 100)
            temperature = round(random.uniform(96.0, 103.0), 1)
            glucose = round(random.uniform(70.0, 180.0), 1)
            w.writerow([
                patient_id,
                name,
                age,
                heart_rate,
                bp_sys,
                bp_dia,
                temperature,
                glucose,
            ])


if __name__ == "__main__":
    base = os.path.join("data", "synthetic")
    ensure_dir(base)
    generate_dataset(os.path.join(base, "patients_1k.csv"), 1000)
    generate_dataset(os.path.join(base, "patients_10k.csv"), 10000)
    generate_dataset(os.path.join(base, "patients_100k.csv"), 100000)

