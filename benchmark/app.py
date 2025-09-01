from flask import Flask, request, g
import sqlite3
import json

app = Flask(__name__)
DATABASE = 'benchmark.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.route('/')
def index():
    return '<h1>Welcome to the vulnerable benchmark app!</h1><a href="/user?id=1">View user 1</a><br><a href="/search">Search</a>'

@app.route('/user')
def get_user():
    user_id = request.args.get('id', '1')
    db = get_db()
    try:
        # VULNERABLE to SQLi
        query = f"SELECT name, description FROM users WHERE id = {user_id}"
        cur = db.execute(query)
        user = cur.fetchone()
        if user:
            return f"User: {user[0]}, Description: {user[1]}"
        else:
            return "User not found."
    except sqlite3.Error as e:
        return f"Database error: {e}"

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        term = request.form['term']
        # VULNERABLE to SQLi
        query = f"SELECT name, description FROM users WHERE description LIKE '%{term}%'"
        db = get_db()
        cur = db.execute(query)
        results = cur.fetchall()
        return f"<h2>Search Results for '{term}':</h2><ul>{''.join(f'<li>{r[0]}</li>' for r in results)}</ul>"

    return """
        <h1>Search for a user</h1>
        <form method="POST">
            <input name="term" type="text" />
            <input type="submit" value="Search" />
        </form>
    """

@app.route('/api/user', methods=['POST'])
def create_user():
    data = request.get_json()
    name = data.get('name')
    # VULNERABLE to SQLi in JSON
    query = f"UPDATE users SET description = 'updated' WHERE name = '{name}'"
    db = get_db()
    db.execute(query)
    db.commit()
    return json.dumps({'status': 'ok'})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
