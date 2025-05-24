# Certifique-se de que eventos.py está no mesmo diretório ou no path correto
from eventos import eventos_bp
import os
import sqlite3
import logging
from flask import (
    Flask, abort, jsonify, render_template, request,
    redirect, url_for, flash
)
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

# 📋 Configuração de logs
logging.basicConfig(level=logging.DEBUG)

# 🔧 Inicialização do app
app = Flask(__name__)
# Use variável de ambiente em produção
app.secret_key = os.environ.get('SECRET_KEY', 'Mudar@123')

# 🔐 Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 🔗 Registro dos Blueprints
app.register_blueprint(eventos_bp)


# 🔗 Classe de usuário


class Usuario(UserMixin):
    def __init__(self, id, nome, email, senha_hash):
        self.id = id
        self.nome = nome
        self.email = email
        self.senha_hash = senha_hash

# 🔍 Funções auxiliares


def buscar_usuario_por_email(email):
    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
        if row:
            return Usuario(row["id"], row["nome"], row["email"], row["senha"])
    return None


@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect('database.db') as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM usuarios WHERE id = ?", (user_id,)).fetchone()
        if row:
            return Usuario(row["id"], row["nome"], row["email"], row["senha"])
    return None

# 🏠 Página inicial


@app.route('/')
def index():
    return render_template('index.html')

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

        flash('Email ou senha incorretos.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 👤 Cadastro


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')
        confirmar_senha = request.form.get('confirmar_senha', '')

        if not all([nome, email, senha, confirmar_senha]):
            flash('Todos os campos são obrigatórios', 'error')
            return redirect(url_for('cadastro'))

        if senha != confirmar_senha:
            flash('As senhas não coincidem', 'error')
            return redirect(url_for('cadastro'))

        if len(senha) < 6:
            flash('A senha deve ter pelo menos 6 caracteres', 'error')
            return redirect(url_for('cadastro'))

        if buscar_usuario_por_email(email):
            flash('Este email já está cadastrado', 'error')
            return redirect(url_for('cadastro'))

        try:
            senha_hash = generate_password_hash(senha)
            with sqlite3.connect('database.db') as conn:
                conn.execute(
                    'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
                    (nome, email, senha_hash)
                )
                conn.commit()
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Erro ao cadastrar usuário.', 'error')
            app.logger.error(f'Erro no cadastro: {e}')

    return render_template('cadastro.html')

# 📅 Calendário e eventos


@app.route('/calendario')
@login_required
def calendario():
    return render_template('calendario.html')


@app.route('/eventos')
@login_required
def eventos():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
        SELECT a.id, u.nome, a.data, t.nome AS tipo_nome
        FROM agendamentos a
        JOIN usuarios u ON a.usuario_id = u.id
        JOIN tipos_agendamento t ON a.tipo_id = t.id
    ''')
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


@app.route('/debug-user')
@login_required
def debug_user():
    return jsonify({
        'email': current_user.email,
        'is_authenticated': current_user.is_authenticated,
        'is_admin': current_user.email == 'admin@admin.com'
    })


@app.route('/toggle_empreendimento')
def toggle_empreendimento():
    # lógica para alternar algo no empreendimento
    return redirect(url_for('alguma_rota'))


@app.route('/remover_empreendimento/<int:emp_id>', methods=['POST'])
@login_required
def remover_empreendimento(emp_id):
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))
    try:
        with sqlite3.connect('database.db') as conn:
            conn.execute('DELETE FROM empreendimentos WHERE id = ?', (emp_id,))
            conn.commit()
        flash('Empreendimento removido com sucesso!', 'success')
    except Exception as e:
        flash('Erro ao remover empreendimento', 'error')
        app.logger.error(f'Erro ao remover empreendimento: {e}')
    return redirect(url_for('configuracoes'))


@app.route('/toggle_unidade/<int:unidade_id>', methods=['POST'])
@login_required
def toggle_unidade(unidade_id):
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))
    try:
        with sqlite3.connect('database.db') as conn:
            # Pega o status atual
            cur = conn.execute(
                'SELECT ativo FROM unidades WHERE id = ?', (unidade_id,))
            row = cur.fetchone()
            if row:
                novo_status = 0 if row[0] == 1 else 1
                conn.execute(
                    'UPDATE unidades SET ativo = ? WHERE id = ?', (novo_status, unidade_id))
                conn.commit()
                flash('Status da unidade atualizado.', 'success')
            else:
                flash('Unidade não encontrada.', 'error')
    except Exception as e:
        flash('Erro ao atualizar status da unidade.', 'error')
        app.logger.error(f'Erro em toggle_unidade: {e}')
    return redirect(url_for('configuracoes'))


@app.route('/agendar', methods=['GET', 'POST'])
@login_required
def agendar():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row

    try:
        if request.method == 'POST':
            # [Mantém a lógica existente de POST]
            pass
        else:
            # Carrega tipos ativos
            tipos = conn.execute(
                'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1'
            ).fetchall()

            # Carrega empreendimentos ativos
            empreendimentos = conn.execute(
                'SELECT id, nome FROM empreendimentos WHERE ativo = 1'
            ).fetchall()

            # Carrega unidades ativas (sem filtro inicial)
            unidades = conn.execute('''
                SELECT u.id, u.nome, e.nome as empreendimento 
                FROM unidades u
                JOIN empreendimentos e ON u.empreendimento_id = e.id
                WHERE u.ativo = 1
            ''').fetchall()

            return render_template(
                'agendar.html',
                tipos=tipos,          # Lista de tipos com id e nome
                empreendimentos=empreendimentos,  # Lista de empreendimentos com id e nome
                unidades=unidades     # Lista de unidades com id, nome e empreendimento_id
            )

    except Exception as e:
        flash('Erro ao carregar dados para agendamento', 'error')
        app.logger.error(f'Erro em /agendar: {str(e)}')
        return redirect(url_for('index'))
    finally:
        conn.close()


# ⚙️ Configurações


@app.route('/configuracoes')
@login_required
def configuracoes():
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))

    try:
        with sqlite3.connect('database.db') as conn:
            conn.row_factory = sqlite3.Row
            tipos = conn.execute('SELECT * FROM tipos_agendamento').fetchall()
            empreendimentos = conn.execute(
                'SELECT * FROM empreendimentos').fetchall()
            unidades = conn.execute('''
                SELECT u.id, u.nome, u.ativo, e.nome as empreendimento
                FROM unidades u
                JOIN empreendimentos e ON u.empreendimento_id = e.id
            ''').fetchall()

        return render_template('configuracoes.html', tipos=tipos, empreendimentos=empreendimentos, unidades=unidades)

    except sqlite3.DatabaseError as e:
        flash('Erro de banco ao carregar configurações', 'error')
        app.logger.error(f'Erro de banco em configuracoes: {e}')
    except Exception as e:
        flash('Erro inesperado ao carregar configurações', 'error')
        app.logger.error(f'Erro inesperado em configuracoes: {e}')

    return render_template('configuracoes.html', tipos=[], empreendimentos=[], unidades=[])


# ➕ Adicionar tipo


@app.route('/adicionar_empreendimento', methods=['POST'])
@login_required
def adicionar_empreendimento():
    nome = request.form.get('nome', '').strip()
    app.logger.debug(f"Nome recebido para empreendimento: '{nome}'")
    if nome:
        try:
            with sqlite3.connect('database.db') as conn:
                conn.execute(
                    'INSERT INTO empreendimentos (nome) VALUES (?)', (nome,))
                conn.commit()
            flash('Empreendimento adicionado com sucesso!', 'success')
        except sqlite3.IntegrityError:
            flash('Este empreendimento já existe!', 'error')
    else:
        flash('Nome do empreendimento é obrigatório.', 'error')

    return redirect(url_for('configuracoes'))


@app.route('/adicionar_unidade', methods=['POST'])
@login_required
def adicionar_unidade():
    nome = request.form.get('nome', '').strip()
    empreendimento_id = request.form.get('empreendimento_id')

    if not nome or not empreendimento_id:
        flash('Nome da unidade e empreendimento são obrigatórios.', 'error')
        return redirect(url_for('configuracoes'))

    try:
        with sqlite3.connect('database.db') as conn:
            conn.execute(
                'INSERT INTO unidades (nome, empreendimento_id) VALUES (?, ?)',
                (nome, empreendimento_id)
            )
            conn.commit()
        flash('Unidade adicionada com sucesso!', 'success')
    except sqlite3.IntegrityError:
        flash('Essa unidade já existe nesse empreendimento.', 'error')
    except Exception as e:
        app.logger.error(f'Erro ao adicionar unidade: {str(e)}')
        flash('Erro ao adicionar unidade.', 'error')

    return redirect(url_for('configuracoes'))


@app.route('/adicionar_tipo', methods=['POST'])
@login_required
def adicionar_tipo():
    novo_tipo = request.form['novo_tipo'].strip()
    if novo_tipo:
        try:
            with sqlite3.connect('database.db') as conn:
                conn.execute(
                    'INSERT INTO tipos_agendamento (nome) VALUES (?)', (novo_tipo,))
                conn.commit()
            flash('Tipo adicionado com sucesso!', 'success')
        except sqlite3.IntegrityError:
            flash('Este tipo já existe!', 'error')
    return redirect(url_for('configuracoes'))


@app.route('/remover_tipo/<int:tipo_id>', methods=['POST'])
@login_required
def remover_tipo(tipo_id):
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))

    try:
        with sqlite3.connect('database.db') as conn:
            conn.execute(
                'DELETE FROM tipos_agendamento WHERE id = ?', (tipo_id,))
            conn.commit()
            flash('Tipo removido com sucesso!', 'success')
    except Exception as e:
        flash('Erro ao remover tipo', 'error')
        app.logger.error(f'Erro ao remover tipo: {e}')
    return redirect(url_for('configuracoes'))


# Listar todas as rotas
@app.route('/listar_rotas')
def listar_rotas():
    return jsonify({
        'rotas': [str(rule) for rule in app.url_map.iter_rules()]
    })


@app.route('/teste_insert')
def teste_insert():
    try:
        with sqlite3.connect('database.db') as conn:
            conn.execute(
                "INSERT INTO empreendimentos (nome) VALUES (?)", ("Teste Inserção",))
            conn.commit()
        return "Inserido com sucesso!"
    except Exception as e:
        return f"Erro: {e}"

# 🧱 Banco de dados


def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tipos_agendamento (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT UNIQUE NOT NULL,
                ativo BOOLEAN DEFAULT 1
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS empreendimentos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT UNIQUE NOT NULL,
                ativo BOOLEAN DEFAULT 1
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS unidades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                empreendimento_id INTEGER NOT NULL,
                ativo BOOLEAN DEFAULT 1,
                FOREIGN KEY (empreendimento_id) REFERENCES empreendimentos(id),
                UNIQUE(nome, empreendimento_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT,
                email TEXT UNIQUE NOT NULL,
                senha TEXT NOT NULL
            )
        ''')

        # ✅ Tabela que estava faltando
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agendamentos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                tipo_id INTEGER NOT NULL,
                unidade_id INTEGER NOT NULL,
                data TEXT NOT NULL,
                hora TEXT NOT NULL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
                FOREIGN KEY (tipo_id) REFERENCES tipos_agendamento(id),
                FOREIGN KEY (unidade_id) REFERENCES unidades(id)
            )
        ''')


def criar_usuario_inicial():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        senha_hash = generate_password_hash('123456')
        try:
            cursor.execute(
                'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
                ('Administrador', 'admin@admin.com', senha_hash)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            print("Usuário inicial já existe.")


def atualizar_tabela_usuarios():
    with sqlite3.connect('database.db') as conn:
        try:
            conn.execute("ALTER TABLE usuarios ADD COLUMN nome TEXT")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Coluna já existe


# 🚀 Execução
if __name__ == '__main__':
    init_db()
    atualizar_tabela_usuarios()
    criar_usuario_inicial()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
