from app import app, init_db

def run():
    # Ensure DB/tables exist
    init_db()
    with app.test_client() as c:
        print('Registering alice')
        r = c.post('/register', json={'username':'alice','password':'password123'})
        print(r.status_code, r.get_json())

        print('Logging in alice')
        r = c.post('/login', json={'username':'alice','password':'password123'})
        print(r.status_code, r.get_json())

        print('Applying for loan')
        r = c.post('/apply_loan', json={'amount':5000, 'income':3000})
        print(r.status_code, r.get_json())

        print('Listing loans')
        r = c.get('/loans')
        print(r.status_code, r.get_json())

if __name__ == '__main__':
    run()
