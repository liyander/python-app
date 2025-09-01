import requests, sys
try:
    r = requests.get('http://127.0.0.1:5000', timeout=3)
    print('ROOT_OK', r.status_code)
except Exception as e:
    print('ROOT_ERR', repr(e))
    sys.exit(2)
