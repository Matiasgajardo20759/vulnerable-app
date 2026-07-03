from flask import Flask, request, render_template_string, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os
import hashlib
import bcrypt

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = 'mi_clave_secreta_4576'


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


@app.route('/')
def index():
    return 'Welcome to the Task Manager Application!'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()

        # Inyección de SQL solo si se detecta un payload de inyección de SQL

        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        hashed_password = hash_password(password)
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid credentials!'
        
    return '''
        <form method="post">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    '''


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    tasks = conn.execute(
        "SELECT * FROM tasks WHERE user_id = ?", (user_id,)).fetchall()
    conn.close()

    return render_template_string('''
        <h1>Welcome, user {{ user_id }}!</h1>
        <form action="/add_task" method="post">
            <input type="text" name="task" placeholder="New task"><br>
            <input type="submit" value="Add Task">
        </form>
        <h2>Your Tasks</h2>
        <ul>
        {% for task in tasks %}
            <li>{{ task['task'] }} <a href="/delete_task/{{ task['id'] }}">Delete</a></li>
        {% endfor %}
        </ul>
    ''', user_id=user_id, tasks=tasks)


@app.route('/add_task', methods=['POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    task = request.form['task']
    user_id = session['user_id']

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO tasks (user_id, task) VALUES (?, ?)", (user_id, task))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    task = conn.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", 
                       (task_id, session['user_id'])).fetchone()
    
    if task is None:
        conn.close()
        return 'No tienes permiso para borrar esta tarea!'

    conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('dashboard'))


@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    return 'Welcome to the admin panel!'


if __name__ == '__main__':
    app.run(debug=False)
