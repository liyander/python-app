import requests
r = requests.post('http://127.0.0.1:5000/scan', json={'type':'url','input':'https://www.google.com'}, headers={'Content-Type':'application/json'})
print(r.status_code)
print(r.text)
