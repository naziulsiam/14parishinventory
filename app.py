from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
import hashlib
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '14parish-secret-key-change-in-production')


# === DECORATOR: Login Required ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# === DATABASE INIT ===
def init_db():
    conn = sqlite3.connect('/app/data/stock.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            current_stock INTEGER DEFAULT 0,
            min_stock INTEGER DEFAULT 5,
            unit TEXT,
            category TEXT NOT NULL CHECK(category IN ('kitchen', 'front_house'))
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS stock_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER,
            change_amount INTEGER,
            reason TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(item_id) REFERENCES items(id)
        )
    ''')

    # Add missing columns if DB existed before
    try:
        c.execute('ALTER TABLE items ADD COLUMN min_stock INTEGER DEFAULT 5')
    except:
        pass

    try:
        c.execute('ALTER TABLE items ADD COLUMN category TEXT DEFAULT "kitchen"')
        c.execute('UPDATE items SET category = "kitchen"')
    except:
        pass

    conn.commit()
    conn.close()

# === PASSWORD HELPERS ===
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# === AUTH ROUTES ===
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if username and password:
            conn = sqlite3.connect('/app/data/stock.db')
            try:
                conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                             (username, hash_password(password)))
                conn.commit()
                flash('Account created! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'danger')
            finally:
                conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('/app/data/stock.db')
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password_hash = ?',
                            (username, hash_password(password))).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# === MAIN STOCK ROUTES ===
def get_items():
    conn = sqlite3.connect('/app/data/stock.db')
    conn.row_factory = sqlite3.Row
    items = conn.execute('SELECT * FROM items ORDER BY category, name').fetchall()
    conn.close()
    return items

@app.route('/')
@login_required
def index():
    items = get_items()
    return render_template('index.html', items=items)

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form['name'].strip()
        unit = request.form['unit'].strip()
        min_stock = int(request.form.get('min_stock', 5))
        category = request.form.get('category', 'kitchen')
        if name and category in ['kitchen', 'front_house']:
            conn = sqlite3.connect('/app/data/stock.db')
            try:
                conn.execute('INSERT INTO items (name, unit, min_stock, category) VALUES (?, ?, ?, ?)',
                             (name, unit, min_stock, category))
                conn.commit()
            except sqlite3.IntegrityError:
                flash('Item already exists!', 'warning')
            finally:
                conn.close()
        return redirect(url_for('index'))
    return render_template('add_item.html')

@app.route('/log/<int:item_id>', methods=['GET', 'POST'])
@login_required
def log_transaction(item_id):
    conn = sqlite3.connect('/app/data/stock.db')
    conn.row_factory = sqlite3.Row
    item = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    if not item:
        conn.close()
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            amount = int(request.form['amount'])
            reason = request.form['reason'].strip()
            new_stock = item['current_stock'] + amount

            # Update stock
            conn.execute('UPDATE items SET current_stock = ? WHERE id = ?', (new_stock, item_id))
            conn.execute('INSERT INTO stock_log (item_id, change_amount, reason) VALUES (?, ?, ?)',
                         (item_id, amount, reason))
            conn.commit()

            # Optional: Just print low-stock to console (no email)
            if new_stock < item['min_stock']:
                print(f"⚠️ LOW STOCK: {item['name']} = {new_stock} (min: {item['min_stock']})")

        except Exception as e:
            flash('Invalid input', 'danger')
        finally:
            conn.close()
        return redirect(url_for('index'))
    
    conn.close()
    return render_template('log_transaction.html', item=item)

# === STOCK HISTORY ===
@app.route('/history/<int:item_id>')
@login_required
def stock_history(item_id):
    conn = sqlite3.connect('/app/data/stock.db')
    conn.row_factory = sqlite3.Row
    item = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    if not item:
        conn.close()
        return redirect(url_for('index'))
    
    logs = conn.execute('''
        SELECT 
            date(timestamp) as day,
            SUM(change_amount) as daily_change
        FROM stock_log 
        WHERE item_id = ? 
        AND timestamp >= datetime('now', '-30 days')
        GROUP BY day
        ORDER BY day
    ''', (item_id,)).fetchall()
    conn.close()

    dates = [log['day'] for log in logs]
    changes = [log['daily_change'] for log in logs]

    return render_template('history.html', item=item, dates=dates, changes=changes)

# === EDIT ITEM ===
@app.route('/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    conn = sqlite3.connect('/app/data/stock.db')
    conn.row_factory = sqlite3.Row
    item = conn.execute('SELECT * FROM items WHERE id = ?', (item_id,)).fetchone()
    if not item:
        conn.close()
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        unit = request.form['unit'].strip()
        min_stock = int(request.form['min_stock'])
        category = request.form['category']
        if name and category in ['kitchen', 'front_house']:
            conn.execute('''
                UPDATE items 
                SET name = ?, unit = ?, min_stock = ?, category = ?
                WHERE id = ?
            ''', (name, unit, min_stock, category, item_id))
            conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    conn.close()
    return render_template('edit_item.html', item=item)

# === DELETE ITEM ===
@app.route('/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    conn = sqlite3.connect('/app/data/stock.db')
    conn.execute('DELETE FROM stock_log WHERE item_id = ?', (item_id,))
    conn.execute('DELETE FROM items WHERE id = ?', (item_id,))
    conn.commit()
    conn.close()
    flash('Item deleted successfully.', 'success')
    return redirect(url_for('index'))

# === RUN APP ===
if __name__ == '__main__':
    os.makedirs('/app/data', exist_ok=True)
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
