# app.py
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask import (
    Flask, abort, jsonify, render_template, request,
    redirect, url_for, flash
)
import logging
import sqlite3
import os
from datetime import datetime

# ... (resto das suas importações e configurações iniciais) ...
# Certifique-se de que eventos.py está no mesmo diretório ou no path correto
# from eventos import eventos_bp # Deixe descomentado se você tiver este blueprint

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
# app.register_blueprint(eventos_bp) # Deixe descomentado se você tiver este blueprint

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
    ''')  # Adicionar JOIN com unidades e empreendimentos se necessário
    rows = cursor.fetchall()
    conn.close()

    eventos_lista = []  # Renomeado para evitar conflito com a função 'eventos'
    for row in rows:
        evento = {
            "id": row[0],
            "title": f"{row[1]} ({row[3]})",
            # Ajustar se a data incluir hora e for para o FullCalendar
            "start": row[2]
        }
        eventos_lista.append(evento)

    return jsonify(eventos_lista)


@app.route('/debug-user')
@login_required
def debug_user():
    return jsonify({
        'email': current_user.email,
        'is_authenticated': current_user.is_authenticated,
        'is_admin': current_user.email == 'admin@admin.com'
    })

# --- INÍCIO DA ALTERAÇÃO/IMPLEMENTAÇÃO ---


# Especificar methods=['POST']
@app.route('/toggle_empreendimento', methods=['POST'])
@login_required
def toggle_empreendimento():
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('index'))

    empreendimento_id = request.form.get('empreendimento_id')
    if not empreendimento_id:
        flash('ID do empreendimento não fornecido.', 'error')
        return redirect(url_for('configuracoes'))

    try:
        with sqlite3.connect('database.db') as conn:
            conn.row_factory = sqlite3.Row  # Para acessar colunas pelo nome
            cursor = conn.cursor()

            # Buscar o empreendimento e seu status atual
            empreendimento = cursor.execute(
                'SELECT id, ativo FROM empreendimentos WHERE id = ?',
                (empreendimento_id,)
            ).fetchone()

            if empreendimento:
                # Inverter o status (0 para 1, 1 para 0)
                novo_status = 0 if empreendimento['ativo'] == 1 else 1

                cursor.execute(
                    'UPDATE empreendimentos SET ativo = ? WHERE id = ?',
                    (novo_status, empreendimento_id)
                )
                conn.commit()

                # Se desativar um empreendimento, também desativar suas unidades
                if novo_status == 0:
                    cursor.execute(
                        'UPDATE unidades SET ativo = 0 WHERE empreendimento_id = ?',
                        (empreendimento_id,)
                    )
                    conn.commit()
                    flash(
                        f'Empreendimento e suas unidades foram desativados.', 'success')
                else:
                    flash(
                        f'Empreendimento foi ativado. Você pode precisar reativar unidades individualmente se desejar.', 'success')

            else:
                flash('Empreendimento não encontrado.', 'error')

    except sqlite3.Error as e:
        flash(
            f'Erro no banco de dados ao tentar alterar o status do empreendimento: {e}', 'error')
        app.logger.error(f"Erro DB em toggle_empreendimento: {e}")
    except Exception as e:
        flash(f'Ocorreu um erro inesperado: {e}', 'error')
        app.logger.error(f"Erro inesperado em toggle_empreendimento: {e}")

    return redirect(url_for('configuracoes'))
# --- FIM DA ALTERAÇÃO/IMPLEMENTAÇÃO ---


@app.route('/remover_empreendimento/<int:emp_id>', methods=['POST'])
@login_required
def remover_empreendimento(emp_id):
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))
    try:
        with sqlite3.connect('database.db') as conn:
            # Antes de remover o empreendimento, verificar se existem unidades associadas
            # Ou definir uma política (ex: remover unidades associadas ou impedir remoção)
            # Por simplicidade, vamos remover. Cuidado com ON DELETE CASCADE se definido no DB.
            conn.execute(
                'DELETE FROM unidades WHERE empreendimento_id = ?', (emp_id,))
            conn.execute('DELETE FROM empreendimentos WHERE id = ?', (emp_id,))
            conn.commit()
        flash('Empreendimento e suas unidades foram removidos com sucesso!', 'success')
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
            conn.row_factory = sqlite3.Row  # Para acessar colunas pelo nome
            cur = conn.cursor()  # Usar cursor para executar e depois commitar

            unidade = cur.execute(
                'SELECT ativo FROM unidades WHERE id = ?', (unidade_id,)
            ).fetchone()

            if unidade:
                novo_status = 0 if unidade['ativo'] == 1 else 1
                cur.execute(
                    'UPDATE unidades SET ativo = ? WHERE id = ?', (
                        novo_status, unidade_id)
                )
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
            # Este campo 'nome' parece ser para o título do agendamento, não do usuário
            nome = request.form['nome']
            data_str = request.form['data']
            hora_str = request.form['hora']
            tipo_id = request.form['tipo_id']
            unidade_id = request.form['unidade_id']

            app.logger.debug(
                f"Dados recebidos para agendamento (POST): Nome do evento={nome}, Data={data_str}, Hora={hora_str}, Tipo ID={tipo_id}, Unidade ID={unidade_id}")

            try:
                data_agendamento_obj = datetime.strptime(
                    data_str, '%Y-%m-%d').date()
                hora_agendamento_obj = datetime.strptime(
                    hora_str, '%H:%M').time()
                data_para_db = data_agendamento_obj.strftime('%Y-%m-%d')
                hora_para_db = hora_agendamento_obj.strftime('%H:%M')
                tipo_id = int(tipo_id)
                unidade_id = int(unidade_id)
                usuario_id = current_user.id

            except ValueError as ve:
                flash(
                    f'Erro de formato nos dados: {str(ve)}. Verifique a data e a hora.', 'error')
                app.logger.error(
                    f'Erro de conversão de dados em /agendar (POST): {str(ve)}', exc_info=True)
                # Recarregar dados para os selects
                tipos_refresh = conn.execute(
                    'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1').fetchall()
                empreendimentos_refresh = conn.execute(
                    'SELECT id, nome FROM empreendimentos WHERE ativo = 1').fetchall()
                unidades_refresh = conn.execute('''
                    SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                    FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id
                    WHERE u.ativo = 1 AND e.ativo = 1
                ''').fetchall()
                return render_template('agendar.html', tipos=tipos_refresh, empreendimentos=empreendimentos_refresh, unidades=unidades_refresh,
                                       form_data=request.form)  # Passa o form data para repopular

            # Verificar se a unidade e o tipo selecionados estão ativos
            unidade_selecionada = conn.execute('''
                SELECT u.*, e.ativo as empreendimento_ativo 
                FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id 
                WHERE u.id = ?
            ''', (unidade_id,)).fetchone()

            tipo_selecionado = conn.execute(
                'SELECT * FROM tipos_agendamento WHERE id = ?', (tipo_id,)).fetchone()

            if not (unidade_selecionada and unidade_selecionada['ativo'] and unidade_selecionada['empreendimento_ativo']):
                flash(
                    'A unidade selecionada (ou seu empreendimento) não está ativa.', 'error')
                # Recarregar dados para os selects
                tipos_refresh = conn.execute(
                    'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1').fetchall()
                empreendimentos_refresh = conn.execute(
                    'SELECT id, nome FROM empreendimentos WHERE ativo = 1').fetchall()
                unidades_refresh = conn.execute('''
                    SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                    FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id
                    WHERE u.ativo = 1 AND e.ativo = 1
                ''').fetchall()
                return render_template('agendar.html', tipos=tipos_refresh, empreendimentos=empreendimentos_refresh, unidades=unidades_refresh,
                                       form_data=request.form)

            if not (tipo_selecionado and tipo_selecionado['ativo']):
                flash('O tipo de agendamento selecionado não está ativo.', 'error')
                # Recarregar dados para os selects
                tipos_refresh = conn.execute(
                    'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1').fetchall()
                empreendimentos_refresh = conn.execute(
                    'SELECT id, nome FROM empreendimentos WHERE ativo = 1').fetchall()
                unidades_refresh = conn.execute('''
                    SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                    FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id
                    WHERE u.ativo = 1 AND e.ativo = 1
                ''').fetchall()
                return render_template('agendar.html', tipos=tipos_refresh, empreendimentos=empreendimentos_refresh, unidades=unidades_refresh,
                                       form_data=request.form)

            try:
                # Se o campo 'nome' do formulário for para um título específico do agendamento,
                # você precisará adicionar uma coluna na tabela 'agendamentos' para armazená-lo.
                # Por enquanto, vou assumir que 'nome' no formulário não é para ser salvo diretamente
                # ou que será usado para compor o título do evento no calendário (como já faz).
                # Se for para salvar, a query INSERT precisa ser ajustada.
                conn.execute(
                    '''INSERT INTO agendamentos (usuario_id, tipo_id, unidade_id, data, hora)
                       VALUES (?, ?, ?, ?, ?)''',
                    (usuario_id, tipo_id, unidade_id, data_para_db, hora_para_db)
                )
                conn.commit()
                flash('Agendamento realizado com sucesso!', 'success')
                app.logger.info(
                    f"Novo agendamento criado por {current_user.nome} (ID: {usuario_id}) para {data_para_db} às {hora_para_db} na unidade ID {unidade_id}.")
                return redirect(url_for('calendario'))

            except sqlite3.Error as db_error:
                flash(
                    f'Erro ao salvar agendamento no banco de dados: {str(db_error)}', 'error')
                app.logger.error(
                    f'Erro de DB em /agendar (POST): {str(db_error)}', exc_info=True)
                # Recarregar dados para os selects
                tipos_refresh = conn.execute(
                    'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1').fetchall()
                empreendimentos_refresh = conn.execute(
                    'SELECT id, nome FROM empreendimentos WHERE ativo = 1').fetchall()
                unidades_refresh = conn.execute('''
                    SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                    FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id
                    WHERE u.ativo = 1 AND e.ativo = 1
                ''').fetchall()
                return render_template('agendar.html', tipos=tipos_refresh, empreendimentos=empreendimentos_refresh, unidades=unidades_refresh,
                                       form_data=request.form)

        else:  # request.method == 'GET'
            tipos = conn.execute(
                'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1').fetchall()
            empreendimentos = conn.execute(
                'SELECT id, nome FROM empreendimentos WHERE ativo = 1').fetchall()
            # Mostrar apenas unidades ativas de empreendimentos ativos
            unidades = conn.execute('''
                SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                FROM unidades u
                JOIN empreendimentos e ON u.empreendimento_id = e.id
                WHERE u.ativo = 1 AND e.ativo = 1 
            ''').fetchall()
            app.logger.debug(f"Unidades carregadas para GET: {unidades}")
            return render_template('agendar.html', tipos=tipos, empreendimentos=empreendimentos, unidades=unidades)

    except Exception as e:
        flash(f'Erro interno ao processar agendamento: {str(e)}', 'error')
        app.logger.error(
            f'Erro inesperado em /agendar: {str(e)}', exc_info=True)
        # Ou uma página de erro mais específica
        return redirect(url_for('index'))
    finally:
        if conn:  # Garante que a conexão só é fechada se foi aberta
            conn.close()

# ⚙️ Configurações


# app.py - Rota configuracoes ajustada
@app.route('/configuracoes')
@login_required
def configuracoes():
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))

    conn = None
    tipos_data = []
    empreendimentos_data = []
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        tipos_data = conn.execute('SELECT * FROM tipos_agendamento').fetchall()
        empreendimentos_data = conn.execute(
            'SELECT * FROM empreendimentos').fetchall()
        # Não carregamos mais todas as unidades aqui
    except sqlite3.DatabaseError as e:
        flash('Erro de banco ao carregar configurações', 'error')
        app.logger.error(f'Erro de banco em configuracoes: {e}')
    except Exception as e:
        flash('Erro inesperado ao carregar configurações', 'error')
        app.logger.error(f'Erro inesperado em configuracoes: {e}')
    finally:
        if conn:
            conn.close()

    return render_template('configuracoes.html',
                           tipos=tipos_data,
                           empreendimentos=empreendimentos_data)

# ➕ Adicionar tipo, empreendimento, unidade

# app.py (adicionar esta nova rota)

# ... (suas outras rotas) ...


@app.route('/api/empreendimento/<int:empreendimento_id>/unidades')
@login_required  # Proteger a API
def api_get_unidades_por_empreendimento(empreendimento_id):
    if current_user.email != 'admin@admin.com':  # Apenas admin pode ver
        return jsonify({"error": "Acesso não autorizado"}), 403

    conn = None
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row

        # Verificar se o empreendimento existe
        empreendimento = conn.execute(
            "SELECT id FROM empreendimentos WHERE id = ?", (empreendimento_id,)).fetchone()
        if not empreendimento:
            return jsonify({"error": "Empreendimento não encontrado"}), 404

        unidades = conn.execute(
            "SELECT id, nome, ativo FROM unidades WHERE empreendimento_id = ?",
            (empreendimento_id,)
        ).fetchall()

        # Converter para uma lista de dicionários para jsonify
        lista_unidades = [dict(unidade) for unidade in unidades]
        return jsonify(lista_unidades)

    except sqlite3.Error as e:
        app.logger.error(
            f"Erro DB em api_get_unidades_por_empreendimento: {e}")
        return jsonify({"error": "Erro no banco de dados"}), 500
    except Exception as e:
        app.logger.error(
            f"Erro inesperado em api_get_unidades_por_empreendimento: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        if conn:
            conn.close()

# ... (resto do app.py)


@app.route('/adicionar_empreendimento', methods=['POST'])
@login_required
def adicionar_empreendimento():
    if current_user.email != 'admin@admin.com':  # Verificação de admin
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))

    nome = request.form.get('nome', '').strip()
    app.logger.debug(f"Nome recebido para empreendimento: '{nome}'")
    if nome:
        try:
            with sqlite3.connect('database.db') as conn:
                # Por padrão, um novo empreendimento é ativo (definido no CREATE TABLE)
                conn.execute(
                    'INSERT INTO empreendimentos (nome) VALUES (?)', (nome,))
                conn.commit()
            flash('Empreendimento adicionado com sucesso!', 'success')
        except sqlite3.IntegrityError:  # Nome do empreendimento é UNIQUE
            flash('Este empreendimento já existe!', 'error')
        except Exception as e:
            flash('Erro ao adicionar empreendimento.', 'error')
            app.logger.error(f"Erro ao adicionar empreendimento: {e}")
    else:
        flash('Nome do empreendimento é obrigatório.', 'error')
    return redirect(url_for('configuracoes'))


@app.route('/adicionar_unidade', methods=['POST'])
@login_required
def adicionar_unidade():
    if current_user.email != 'admin@admin.com':  # Verificação de admin
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))

    nome = request.form.get('nome', '').strip()
    empreendimento_id = request.form.get('empreendimento_id')

    if not nome or not empreendimento_id:
        flash('Nome da unidade e empreendimento são obrigatórios.', 'error')
        return redirect(url_for('configuracoes'))

    try:
        with sqlite3.connect('database.db') as conn:
            # Verificar se o empreendimento pai está ativo antes de adicionar unidade
            empreendimento_pai = conn.execute(
                "SELECT ativo FROM empreendimentos WHERE id = ?", (empreendimento_id,)).fetchone()
            # Se não encontrado ou inativo
            if not empreendimento_pai or not empreendimento_pai[0]:
                flash(
                    'Não é possível adicionar unidade a um empreendimento inativo.', 'error')
                return redirect(url_for('configuracoes'))

            # Por padrão, uma nova unidade é ativa (definido no CREATE TABLE)
            conn.execute(
                'INSERT INTO unidades (nome, empreendimento_id) VALUES (?, ?)',
                # Garantir que empreendimento_id é int
                (nome, int(empreendimento_id))
            )
            conn.commit()
        flash('Unidade adicionada com sucesso!', 'success')
    except sqlite3.IntegrityError:  # UNIQUE(nome, empreendimento_id)
        flash('Essa unidade já existe nesse empreendimento.', 'error')
    except ValueError:  # Erro ao converter empreendimento_id para int
        flash('ID do empreendimento inválido.', 'error')
    except Exception as e:
        app.logger.error(f'Erro ao adicionar unidade: {str(e)}')
        flash('Erro ao adicionar unidade.', 'error')
    return redirect(url_for('configuracoes'))


@app.route('/adicionar_tipo', methods=['POST'])
@login_required
def adicionar_tipo():
    if current_user.email != 'admin@admin.com':  # Verificação de admin
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))

    # Usar get para evitar KeyError
    novo_tipo = request.form.get('novo_tipo', '').strip()
    if novo_tipo:
        try:
            with sqlite3.connect('database.db') as conn:
                # Por padrão, um novo tipo é ativo (definido no CREATE TABLE)
                conn.execute(
                    'INSERT INTO tipos_agendamento (nome) VALUES (?)', (novo_tipo,))
                conn.commit()
            flash('Tipo de agendamento adicionado com sucesso!', 'success')
        except sqlite3.IntegrityError:  # Nome do tipo é UNIQUE
            flash('Este tipo de agendamento já existe!', 'error')
        except Exception as e:
            flash('Erro ao adicionar tipo de agendamento.', 'error')
            app.logger.error(f"Erro ao adicionar tipo: {e}")
    else:
        flash('Nome do tipo de agendamento é obrigatório.', 'error')
    return redirect(url_for('configuracoes'))


@app.route('/remover_tipo/<int:tipo_id>', methods=['POST'])
@login_required
def remover_tipo(tipo_id):
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores', 'error')
        return redirect(url_for('index'))
    try:
        with sqlite3.connect('database.db') as conn:
            # Adicionar verificação se o tipo está em uso antes de deletar, se necessário
            conn.execute(
                'DELETE FROM tipos_agendamento WHERE id = ?', (tipo_id,))
            conn.commit()
            flash('Tipo removido com sucesso!', 'success')
    except Exception as e:
        flash('Erro ao remover tipo', 'error')
        app.logger.error(f'Erro ao remover tipo: {e}')
    return redirect(url_for('configuracoes'))

# app.py (adicione esta nova rota)

# ... (outras rotas) ...


@app.route('/remover_unidade/<int:unidade_id>', methods=['POST'])
@login_required
def remover_unidade(unidade_id):
    if current_user.email != 'admin@admin.com':
        flash('Acesso restrito a administradores.', 'error')
        return redirect(url_for('index'))

    try:
        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()

            # Verificar se a unidade existe antes de tentar deletar
            unidade = cursor.execute(
                'SELECT id FROM unidades WHERE id = ?', (unidade_id,)
            ).fetchone()

            if not unidade:
                flash('Unidade não encontrada.', 'error')
                return redirect(url_for('configuracoes'))

            # Considerar o que acontece com agendamentos ligados a esta unidade.
            # A foreign key em 'agendamentos' para 'unidade_id' está como ON DELETE RESTRICT.
            # Isso significa que o SQLite impedirá a deleção da unidade se houver agendamentos
            # referenciando-a. Você precisa decidir como lidar com isso:
            # 1. Manter o RESTRICT e mostrar um erro se estiver em uso.
            # 2. Alterar para ON DELETE CASCADE na tabela agendamentos (deleta agendamentos associados).
            # 3. Alterar para ON DELETE SET NULL (define unidade_id como NULL nos agendamentos).
            # 4. Deletar manualmente os agendamentos antes de deletar a unidade.

            # Por enquanto, vamos tentar deletar e capturar a exceção de integridade.
            try:
                cursor.execute(
                    'DELETE FROM unidades WHERE id = ?', (unidade_id,))
                conn.commit()
                flash('Unidade removida com sucesso!', 'success')
            except sqlite3.IntegrityError:
                # Isso acontecerá se ON DELETE RESTRICT estiver ativo e a unidade estiver em uso.
                flash(
                    'Erro: Esta unidade não pode ser removida pois está associada a agendamentos existentes.', 'error')
                app.logger.warning(
                    f"Tentativa de remover unidade {unidade_id} em uso.")

    except sqlite3.Error as e:
        flash(f'Erro no banco de dados ao remover unidade: {e}', 'error')
        app.logger.error(f"Erro DB em remover_unidade: {e}")
    except Exception as e:
        flash(f'Ocorreu um erro inesperado ao remover unidade: {e}', 'error')
        app.logger.error(f"Erro inesperado em remover_unidade: {e}")

    return redirect(url_for('configuracoes'))

# ... (resto do app.py) ...

# ... (suas rotas de debug e init_db) ...

# 🧱 Banco de dados


def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tipos_agendamento (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT UNIQUE NOT NULL,
                ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1)) -- Usar INTEGER para booleano
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS empreendimentos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT UNIQUE NOT NULL,
                ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1)) -- Usar INTEGER para booleano
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS unidades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL,
                empreendimento_id INTEGER NOT NULL,
                ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1)), -- Usar INTEGER para booleano
                FOREIGN KEY (empreendimento_id) REFERENCES empreendimentos(id) ON DELETE CASCADE, -- Adicionado ON DELETE CASCADE
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

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agendamentos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                tipo_id INTEGER NOT NULL,
                unidade_id INTEGER NOT NULL,
                data TEXT NOT NULL,
                hora TEXT NOT NULL,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL, -- Ou CASCADE, dependendo da regra
                FOREIGN KEY (tipo_id) REFERENCES tipos_agendamento(id) ON DELETE RESTRICT, -- Impedir deleção se em uso
                FOREIGN KEY (unidade_id) REFERENCES unidades(id) ON DELETE RESTRICT -- Impedir deleção se em uso
            )
        ''')
        conn.commit()  # Commit após todas as criações de tabela


def criar_usuario_inicial():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        # Verificar se o usuário admin já existe
        admin_exists = cursor.execute(
            "SELECT id FROM usuarios WHERE email = ?", ('admin@admin.com',)).fetchone()
        if not admin_exists:
            # Use uma senha mais forte em produção
            senha_hash = generate_password_hash('123456')
            try:
                cursor.execute(
                    'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
                    ('Administrador', 'admin@admin.com', senha_hash)
                )
                conn.commit()
                app.logger.info("Usuário administrador inicial criado.")
            except sqlite3.IntegrityError:
                app.logger.info(
                    "Usuário administrador inicial já existe (verificação de concorrência).")
        else:
            app.logger.info("Usuário administrador inicial já existe.")

# Remover atualizar_tabela_usuarios() se a coluna 'nome' já está no CREATE TABLE
# def atualizar_tabela_usuarios():
#     with sqlite3.connect('database.db') as conn:
#         try:
#             # Verificar se a coluna 'nome' já existe antes de tentar adicioná-la
#             cursor = conn.cursor()
#             cursor.execute("PRAGMA table_info(usuarios)")
#             columns = [info[1] for info in cursor.fetchall()]
#             if 'nome' not in columns:
#                 conn.execute("ALTER TABLE usuarios ADD COLUMN nome TEXT")
#                 conn.commit()
#                 app.logger.info("Coluna 'nome' adicionada à tabela 'usuarios'.")
#             else:
#                 app.logger.info("Coluna 'nome' já existe na tabela 'usuarios'.")
#         except sqlite3.OperationalError as e:
#             app.logger.warning(f"Possível erro ao tentar adicionar coluna 'nome' (pode já existir): {e}")


# 🚀 Execução
if __name__ == '__main__':
    with app.app_context():  # Necessário para operações de DB fora de uma requisição, se usar extensões Flask
        init_db()
        # atualizar_tabela_usuarios() # Descomente se precisar rodar uma vez
        criar_usuario_inicial()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
