import os
import io
import sys
import numpy as np
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.api.app import create_app


def test_full_workflow_integration():
    app = create_app()
    client = app.test_client()

    r = client.post('/auth/register', json={'username': 'int_user', 'password': 'p1'})
    assert r.status_code in (201, 409)
    r = client.post('/auth/login', json={'username': 'int_user', 'password': 'p1'})
    assert r.status_code == 200
    token = r.get_json()['access_token']

    path = os.path.join('data', 'synthetic', 'patients_1k.csv')
    with open(path, 'rb') as f:
        data = {'file': (io.BytesIO(f.read()), 'patients_1k.csv')}
    r = client.post('/encrypt/dataset', data=data, content_type='multipart/form-data')
    assert r.status_code == 200
    dsid = r.get_json()['dataset_id']

    r = client.post('/analytics/mean', json={'dataset_id': dsid, 'field_name': 'heart_rate'})
    assert r.status_code == 200
    result_obj = r.get_json()['result']

    r = client.post('/analytics/decrypt/result', headers={'Authorization': f'Bearer {token}'}, json={'dataset_id': dsid, 'result': result_obj})
    assert r.status_code == 200
    value = r.get_json()['value']

    df = pd.read_csv(path)
    mean_plain = float(np.mean(df['heart_rate'].astype(float)))
    assert abs(value - mean_plain) / mean_plain < 0.01

