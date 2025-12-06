import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.api.app import create_app


def test_ui_routes_status_codes():
    app = create_app()
    client = app.test_client()
    assert client.get('/').status_code == 200
    assert client.get('/upload').status_code == 200
    assert client.get('/ui/analytics').status_code == 200
    r = client.get('/ui/datasets')
    assert r.status_code == 200
    assert 'datasets' in r.get_json()
    assert client.get('/results').status_code == 200

