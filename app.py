from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'Mudar@123'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Usuario(UserMixin):
    def __init__(self, id, email, senha):
        self.id = id
        self.email = email
        self.senha = senha


def buscar_usuario_por_email(email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return Usuario(id=user[0], email=user[1], senha=user[2])
    return None


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return Usuario(id=user[0], email=user[1], senha=user[2])
    return None


@app.route('/calendario')
@login_required
def calendario():
    return render_template('calendario.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM usuarios WHERE email = ? AND senha = ?", (email, senha))
            user_data = cursor.fetchone()

            if user_data:
                user_obj = Usuario(
                    id=user_data[0], email=user_data[1], senha=user_data[2])
                login_user(user_obj)
                return redirect(url_for('calendario'))

            else:
                flash('Email ou senha incorretos.')
                return redirect('/login')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agendamentos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                data TEXT NOT NULL,
                tipo TEXT NOT NULL,
                unidade TEXT NOT NULL,
                empreendimento TEXT NOT NULL
            )
        ''')
        conn.commit()


def criar_usuario_inicial():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO usuarios (email, senha) VALUES (?, ?)', ('admin@admin.com', '123456'))
            conn.commit()
            print("Usuário inicial criado com sucesso!")
        except sqlite3.IntegrityError:
            print("Usuário inicial já existe.")


# Executa inicialização
init_db()
criar_usuario_inicial()

# ... Resto do seu código ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
