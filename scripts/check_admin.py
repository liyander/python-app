import requests, sys
try:
    r = requests.get('http://127.0.0.1:5000/admin', timeout=5)
    print('STATUS', r.status_code)
    print('HEADERS:\n', r.headers)
    print('\nBODY:\n')
    print(r.text)
except Exception as e:
    print('ERR', repr(e))
    sys.exit(2)
