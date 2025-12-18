import json
import http.cookiejar
import urllib.request

BASE = 'http://127.0.0.1:5000'

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, data):
    url = BASE + path
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type':'application/json'})
    resp = opener.open(req)
    return resp.read().decode('utf-8')

def get(path):
    url = BASE + path
    resp = opener.open(url)
    return resp.read().decode('utf-8')

if __name__ == '__main__':
    print('Registering user alice...')
    print(post('/register', {'username':'alice','password':'password123'}))

    print('Logging in alice...')
    print(post('/login', {'username':'alice','password':'password123'}))

    print('Applying for loan...')
    print(post('/apply_loan', {'amount':10000, 'income':4000}))

    print('Listing loans...')
    print(get('/loans'))
