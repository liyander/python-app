# quick test: exercise admin login flow for app_clean
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app_clean import app

app.testing = True
c = app.test_client()

r = c.get('/admin')
print('GET /admin ->', r.status_code)

r = c.get('/admin/login')
print('GET /admin/login ->', r.status_code)
print(r.get_data(as_text=True)[:600])

# attempt login with configured creds
resp = c.post('/admin/login', data={'username': 'thiru', 'password': '_THIRU@4690'}, follow_redirects=False)
print('POST /admin/login ->', resp.status_code, 'Location:', resp.headers.get('Location'))

# now try to access /admin/scans (should redirect to login if not logged in, or show scans if session persisted in client)
r2 = c.get('/admin/scans')
print('GET /admin/scans ->', r2.status_code)
print(r2.get_data(as_text=True)[:800])
