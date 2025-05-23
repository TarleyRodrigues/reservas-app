from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

# 🔧 Configuração do app
app = Flask(__name__)
app.secret_key = 'Mudar@123'

# 🔑 Configuração do Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# 🔗 Classe de usuário
class Usuario(UserMixin):
    def __init__(self, id, email, senha_hash):
        self.id = id
        self.email = email
        self.senha_hash = senha_hash


# 🔍 Busca usuário por e-mail
def buscar_usuario_por_email(email):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return Usuario(id=user[0], email=user[1], senha_hash=user[2])
    return None


# 🔄 Carrega usuário pela sessão
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return Usuario(id=user[0], email=user[1], senha_hash=user[2])
    return None


# 🏠 Página inicial
@app.route('/')
def index():
    return render_template('index.html')


# 📅 Página do calendário (protegida)
@app.route('/calendario')
@login_required
def calendario():
    return render_template('calendario.html')


# 🔐 Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']

        user = buscar_usuario_por_email(email)

        if user and check_password_hash(user.senha_hash, senha):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Email ou senha incorretos.')
            return redirect(url_for('login'))

    return render_template('login.html')


# 🚪 Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')
        confirmar_senha = request.form.get('confirmar_senha', '')

        # Validações
        if not nome or not email or not senha or not confirmar_senha:
            flash('Todos os campos são obrigatórios', 'error')
            return redirect(url_for('cadastro'))

        if senha != confirmar_senha:
            flash('As senhas não coincidem', 'error')
            return redirect(url_for('cadastro'))

        if len(senha) < 6:
            flash('A senha deve ter pelo menos 6 caracteres', 'error')
            return redirect(url_for('cadastro'))

        # Verifica se usuário já existe
        usuario_existente = buscar_usuario_por_email(email)
        if usuario_existente:
            flash('Este email já está cadastrado', 'error')
            return redirect(url_for('cadastro'))

        # Cria o novo usuário
        senha_hash = generate_password_hash(senha)
        try:
            with sqlite3.connect('database.db') as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
                    (nome, email, senha_hash)
                )
                conn.commit()

            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Erro ao cadastrar usuário. Tente novamente.', 'error')
            app.logger.error(f'Erro no cadastro: {str(e)}')
            return redirect(url_for('cadastro'))

    return render_template('cadastro.html')

# 🔗 Retorna eventos no calendário


@app.route('/eventos')
@login_required
def eventos():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute(
        'SELECT id, nome, data, tipo, unidade, empreendimento FROM agendamentos')
    rows = cursor.fetchall()
    conn.close()

    eventos = []
    for row in rows:
        evento = {
            "id": row[0],
            "title": f"{row[1]} ({row[3]})",
            "start": row[2]
        }
        eventos.append(evento)

    return jsonify(eventos)


# 📅 Agendamento
@app.route('/agendar', methods=['GET', 'POST'])
@login_required
def agendar():
    if request.method == 'GET':
        return render_template('agendar.html')
    elif request.method == 'POST':
        nome = request.form['nome']
        data = request.form['data']
        tipo = request.form['tipo']
        unidade = request.form['unidade']
        empreendimento = request.form['empreendimento']

        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO agendamentos (nome, data, tipo, unidade, empreendimento)
                VALUES (?, ?, ?, ?, ?)
            ''', (nome, data, tipo, unidade, empreendimento))
            conn.commit()

        return redirect(url_for('index'))


# 🏗️ Criação do banco de dados
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


# 👤 Criação do usuário inicial (com senha criptografada)
def criar_usuario_inicial():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        senha_hash = generate_password_hash('123456')

        try:
            cursor.execute(
                'INSERT INTO usuarios (email, senha) VALUES (?, ?)',
                ('admin@admin.com', senha_hash)
            )
            conn.commit()
            print("Usuário inicial criado com sucesso!")
        except sqlite3.IntegrityError:
            print("Usuário inicial já existe.")

# Adicione isso antes do init_db()


def atualizar_tabela_usuarios():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("ALTER TABLE usuarios ADD COLUMN nome TEXT")
            conn.commit()
            print("Coluna nome adicionada à tabela usuarios")
        except sqlite3.OperationalError:
            print("Coluna nome já existe ou erro ao adicionar")


# 🚀 Execução inicial
init_db()
atualizar_tabela_usuarios()
criar_usuario_inicial()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
