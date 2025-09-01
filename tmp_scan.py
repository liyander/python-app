import requests, base64, json, time, sys

# Wait for server to be ready
for i in range(10):
    try:
        requests.get('http://127.0.0.1:5000', timeout=2)
        break
    except Exception:
        time.sleep(0.5)
else:
    print('Server unreachable on http://127.0.0.1:5000', file=sys.stderr)
    sys.exit(2)

try:
    r = requests.post('http://127.0.0.1:5000/scan', json={'type': 'url', 'input': 'https://www.example.com'}, timeout=15)
except Exception as e:
    print('Error posting to /scan:', e, file=sys.stderr)
    sys.exit(1)

print('scan status', r.status_code)
try:
    obj = r.json()
    print(json.dumps(obj, indent=2))
except Exception:
    print('Non-JSON response:', r.text)
    sys.exit(1)

data = base64.b64encode(json.dumps(obj).encode('utf-8')).decode('ascii')
print('\nOpen this URL in your browser to see the result page:')
print('http://127.0.0.1:5000/result?data=' + data)
