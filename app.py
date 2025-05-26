# app.py
from functools import wraps
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

# 📋 Configuração de logs
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# 🔧 Inicialização do app
app = Flask(__name__)
app.secret_key = os.environ.get(
    'SECRET_KEY', 'DevSecretKeyForReservasApp')

# 🔐 Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, realize o login para acessar esta página."
login_manager.login_message_category = "info"

# 🔗 Classe de usuário


class Usuario(UserMixin):
    def __init__(self, id, nome, email, senha_hash, is_admin=0):
        self.id = id
        self.nome = nome
        self.email = email
        self.senha_hash = senha_hash
        self.is_admin = is_admin

# 🔍 Funções auxiliares


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def buscar_usuario_por_email(email):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, nome, email, senha, is_admin FROM usuarios WHERE email = ?", (
            email,)
    ).fetchone()
    conn.close()
    if row:
        return Usuario(row["id"], row["nome"], row["email"], row["senha"], row["is_admin"])
    return None


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, nome, email, senha, is_admin FROM usuarios WHERE id = ?", (
            user_id,)
    ).fetchone()
    conn.close()
    if row:
        return Usuario(row["id"], row["nome"], row["email"], row["senha"], row["is_admin"])
    return None

# 🏠 Página inicial


@app.route('/')
def index():
    return render_template('index.html')

# 🔐 Login


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')

        if not email or not senha:
            flash('Email e senha são obrigatórios.', 'error')
            return render_template('login.html', email=email)

        user = buscar_usuario_por_email(email)

        if user and check_password_hash(user.senha_hash, senha):
            login_user(user)
            flash('Login realizado com sucesso!', 'success')
            next_page = request.args.get('next')
            app.logger.info(f"Usuário {user.email} logado com sucesso.")
            return redirect(next_page or url_for('index'))
        else:
            flash('Email ou senha incorretos.', 'error')
            app.logger.warning(f"Falha de login para o email: {email}")
            return render_template('login.html', email=email)

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"Usuário {current_user.email} deslogado.")
    logout_user()
    flash('Você saiu da sua conta.', 'success')
    return redirect(url_for('login'))

# 👤 Cadastro


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        nome = request.form.get('nome', '').strip()
        email = request.form.get('email', '').strip()
        senha = request.form.get('senha', '')
        confirmar_senha = request.form.get('confirmar_senha', '')

        errors = []
        if not nome:
            errors.append('O nome é obrigatório.')
        if not email:
            errors.append('O email é obrigatório.')
        if not senha:
            errors.append('A senha é obrigatória.')
        if not confirmar_senha:
            errors.append('A confirmação de senha é obrigatória.')

        if senha != confirmar_senha:
            errors.append('As senhas não coincidem.')
        if len(senha) < 6:
            errors.append('A senha deve ter pelo menos 6 caracteres.')

        if not errors and buscar_usuario_por_email(email):
            errors.append('Este email já está cadastrado.')

        if errors:
            for error_msg in errors:
                flash(error_msg, 'error')
            return render_template('cadastro.html', nome=nome, email=email)

        try:
            senha_hash = generate_password_hash(senha)
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO usuarios (nome, email, senha, is_admin) VALUES (?, ?, ?, ?)',
                (nome, email, senha_hash, 0)
            )
            conn.commit()
            conn.close()
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            app.logger.info(f"Novo usuário cadastrado: {email}")
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(
                'Erro ao cadastrar usuário no banco de dados. Tente novamente.', 'error')
            app.logger.error(f'Erro DB no cadastro: {e}')
        except Exception as e:
            flash(
                'Ocorreu um erro inesperado durante o cadastro. Por favor, tente mais tarde.', 'error')
            app.logger.error(
                f'Erro inesperado no cadastro: {e}', exc_info=True)
        return render_template('cadastro.html', nome=nome, email=email)

    return render_template('cadastro.html')


@app.route('/agendar', methods=['GET', 'POST'])
@login_required
def agendar():
    conn = get_db_connection()
    try:
        if request.method == 'POST':
            titulo_evento = request.form.get('nome', '').strip()
            data_str = request.form.get('data')
            hora_str = request.form.get('hora')
            tipo_id_str = request.form.get('tipo_id')
            empreendimento_id_str = request.form.get(
                'empreendimento_id')  # Adicionado empreendimento_id
            unidade_id_str = request.form.get('unidade_id')
            # --- NOVO: Pegar as observações ---
            # Pega o campo, remove espaços extras
            observacoes = request.form.get('observacoes', '').strip()
            # --- FIM NOVO ---

            app.logger.debug(
                f"Agendamento (POST): Título={titulo_evento}, Data={data_str}, Hora={hora_str}, Tipo ID={tipo_id_str}, Empreendimento ID={empreendimento_id_str}, Unidade ID={unidade_id_str}, Observações={observacoes}")

            # Validação e conversão de dados
            form_data_for_repopulation = {
                'nome': titulo_evento, 'data': data_str, 'hora': hora_str,
                'tipo_id': tipo_id_str, 'empreendimento_id': empreendimento_id_str, 'unidade_id': unidade_id_str,
                'observacoes': observacoes  # Adicionado para repopular em caso de erro
            }

            errors = []
            if not data_str:
                errors.append("A data é obrigatória.")
            if not hora_str:
                errors.append("A hora é obrigatória.")
            if not tipo_id_str:
                errors.append("O tipo de agendamento é obrigatório.")
            if not empreendimento_id_str:  # Adicionado validação para empreendimento
                errors.append("O empreendimento é obrigatório.")
            if not unidade_id_str:
                errors.append("A unidade é obrigatória.")

            if errors:
                for error in errors:
                    flash(error, 'error')
                # Recarregar dados para o formulário para exibir erros
                tipos_refresh = conn.execute(
                    'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1 ORDER BY nome').fetchall()
                empreendimentos_refresh = conn.execute(
                    'SELECT id, nome FROM empreendimentos WHERE ativo = 1 ORDER BY nome').fetchall()
                unidades_refresh = conn.execute('''
                    SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                    FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id
                    WHERE u.ativo = 1 AND e.ativo = 1 ORDER BY e.nome, u.nome
                ''').fetchall()
                return render_template('agendar.html', tipos=tipos_refresh, empreendimentos=empreendimentos_refresh, unidades=unidades_refresh,
                                       form_data=form_data_for_repopulation)

            try:
                data_agendamento_obj = datetime.strptime(
                    data_str, '%Y-%m-%d').date()
                hora_agendamento_obj = datetime.strptime(
                    hora_str, '%H:%M').time()
                data_para_db = data_agendamento_obj.strftime('%Y-%m-%d')
                hora_para_db = hora_agendamento_obj.strftime('%H:%M')
                tipo_id = int(tipo_id_str)
                empreendimento_id = int(
                    empreendimento_id_str)  # Converte para int
                unidade_id = int(unidade_id_str)
                usuario_id = current_user.id
            except ValueError as ve:
                flash(
                    f'Erro de formato nos dados: {str(ve)}. Verifique a data e a hora.', 'error')
                app.logger.error(
                    f'Erro de conversão em /agendar (POST): {str(ve)}', exc_info=True)
                # Recarregar dados para o formulário para exibir erros
                tipos_refresh = conn.execute(
                    'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1 ORDER BY nome').fetchall()
                empreendimentos_refresh = conn.execute(
                    'SELECT id, nome FROM empreendimentos WHERE ativo = 1 ORDER BY nome').fetchall()
                unidades_refresh = conn.execute('''
                    SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                    FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id
                    WHERE u.ativo = 1 AND e.ativo = 1 ORDER BY e.nome, u.nome
                ''').fetchall()
                return render_template('agendar.html', tipos=tipos_refresh, empreendimentos=empreendimentos_refresh, unidades=unidades_refresh,
                                       form_data=form_data_for_repopulation)

            # Verificar se a unidade e o tipo selecionados estão ativos
            unidade_selecionada = conn.execute('''
                SELECT u.id, u.ativo as unidade_ativa, u.nome as unidade_nome, e.ativo as empreendimento_ativo 
                FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id 
                WHERE u.id = ?
            ''', (unidade_id,)).fetchone()

            tipo_selecionado = conn.execute(
                'SELECT id, ativo, nome FROM tipos_agendamento WHERE id = ?', (tipo_id,)).fetchone()

            if not (unidade_selecionada and unidade_selecionada['unidade_ativa'] and unidade_selecionada['empreendimento_ativo']):
                flash(
                    'A unidade selecionada ou seu empreendimento não estão ativos.', 'error')
            elif not (tipo_selecionado and tipo_selecionado['ativo']):
                flash('O tipo de agendamento selecionado não está ativo.', 'error')
            else:
                try:
                    # --- ALTERAÇÃO AQUI: Adicionar 'observacoes' no INSERT ---
                    conn.execute(
                        '''INSERT INTO agendamentos (usuario_id, tipo_id, unidade_id, data, hora, observacoes) 
                           VALUES (?, ?, ?, ?, ?, ?)''',
                        (usuario_id, tipo_id, unidade_id,
                         data_para_db, hora_para_db, observacoes)  # Adicionado observacoes
                    )
                    # --- FIM DA ALTERAÇÃO ---
                    conn.commit()
                    flash('Agendamento realizado com sucesso!', 'success')
                    app.logger.info(
                        f"Novo agendamento por {current_user.email} (ID: {usuario_id}) para {data_para_db} às {hora_para_db}, tipo '{tipo_selecionado['nome']}', unidade '{unidade_selecionada['unidade_nome']}', Obs: '{observacoes}'.")
                    return redirect(url_for('calendario'))
                except sqlite3.Error as db_error:
                    flash(
                        f'Erro ao salvar agendamento no banco de dados: {str(db_error)}', 'error')
                    app.logger.error(
                        f'Erro de DB em /agendar (POST): {str(db_error)}', exc_info=True)

            # Se chegou aqui, houve erro de validação ou DB, recarregar dados para o form
            tipos_refresh = conn.execute(
                'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1 ORDER BY nome').fetchall()
            empreendimentos_refresh = conn.execute(
                'SELECT id, nome FROM empreendimentos WHERE ativo = 1 ORDER BY nome').fetchall()
            unidades_refresh = conn.execute('''
                SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id
                WHERE u.ativo = 1 AND e.ativo = 1 ORDER BY e.nome, u.nome
            ''').fetchall()
            return render_template('agendar.html', tipos=tipos_refresh, empreendimentos=empreendimentos_refresh, unidades=unidades_refresh,
                                   form_data=form_data_for_repopulation)

        else:  # request.method == 'GET'
            tipos = conn.execute(
                'SELECT id, nome FROM tipos_agendamento WHERE ativo = 1 ORDER BY nome').fetchall()
            empreendimentos = conn.execute(
                'SELECT id, nome FROM empreendimentos WHERE ativo = 1 ORDER BY nome').fetchall()
            unidades = conn.execute('''
                SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento 
                FROM unidades u
                JOIN empreendimentos e ON u.empreendimento_id = e.id
                WHERE u.ativo = 1 AND e.ativo = 1 ORDER BY e.nome, u.nome
            ''').fetchall()
            app.logger.debug(
                f"Dados para GET /agendar: Tipos={len(tipos)}, Empreendimentos={len(empreendimentos)}, Unidades={len(unidades)}")
            return render_template('agendar.html', tipos=tipos, empreendimentos=empreendimentos, unidades=unidades)

    except Exception as e:
        flash(
            f'Erro interno ao processar a página de agendamento: {str(e)}', 'error')
        app.logger.error(
            f'Erro inesperado em /agendar: {str(e)}', exc_info=True)
        return redirect(url_for('index'))
    finally:
        if conn:
            conn.close()

# 📅 Calendário e eventos


@app.route('/calendario')
@login_required
def calendario():
    return render_template('calendario.html')

# 🗓️ Eventos para o calendário


@app.route('/eventos')
@login_required
def eventos():
    conn = get_db_connection()
    eventos_db = conn.execute('''
        SELECT a.id, u.nome as usuario_nome, a.data, a.hora, a.observacoes, -- Adicionado 'a.observacoes'
                t.nome AS tipo_nome, un.nome as unidade_nome, e.nome as empreendimento_nome
        FROM agendamentos a
        JOIN usuarios u ON a.usuario_id = u.id
        JOIN tipos_agendamento t ON a.tipo_id = t.id
        JOIN unidades un ON a.unidade_id = un.id
        JOIN empreendimentos e ON un.empreendimento_id = e.id
        WHERE t.ativo = 1 AND un.ativo = 1 AND e.ativo = 1
    ''').fetchall()
    conn.close()

    eventos_lista = []
    for row in eventos_db:
        try:
            start_datetime_str = f"{row['data']}T{row['hora']}"
            datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M')
            evento = {
                "id": row["id"],
                "title": f"{row['tipo_nome']} - {row['unidade_nome']} ({row['empreendimento_nome']})",
                "start": start_datetime_str,
                "extendedProps": {
                    "usuario": row['usuario_nome'],
                    "tipo": row['tipo_nome'],
                    "unidade": row['unidade_nome'],
                    "empreendimento": row['empreendimento_nome'],
                    # Adicionado observacoes, com fallback para string vazia
                    "observacoes": row['observacoes'] or ""
                }
            }
            eventos_lista.append(evento)
        except ValueError:
            app.logger.error(
                f"Formato de data/hora inválido para agendamento ID {row['id']}: data='{row['data']}', hora='{row['hora']}'")

    return jsonify(eventos_lista)

# 🛠️ Rota de depuração do usuário


@app.route('/debug-user')
@login_required
def debug_user():
    return jsonify({
        'id': current_user.id,
        'nome': current_user.nome,
        'email': current_user.email,
        'is_authenticated': current_user.is_authenticated,
        'is_admin': current_user.is_admin
    })

# --- ROTAS DE ADMINISTRAÇÃO ---


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not hasattr(current_user, 'is_admin') or not current_user.is_admin:
            flash('Acesso restrito a administradores.', 'error')
            app.logger.warning(
                f"Tentativa de acesso não autorizado à rota admin por: {current_user.email}")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/toggle_empreendimento', methods=['POST'])
@admin_required
def toggle_empreendimento():
    empreendimento_id = request.form.get('empreendimento_id')
    if not empreendimento_id:
        flash('ID do empreendimento não fornecido.', 'error')
        return redirect(url_for('configuracoes', tab='empreendimentos'))

    conn = get_db_connection()
    try:
        empreendimento = conn.execute(
            'SELECT id, ativo, nome FROM empreendimentos WHERE id = ?', (empreendimento_id,)).fetchone()
        if empreendimento:
            novo_status = 0 if empreendimento['ativo'] == 1 else 1
            conn.execute('UPDATE empreendimentos SET ativo = ? WHERE id = ?',
                         (novo_status, empreendimento_id))
            status_texto = "desativado" if novo_status == 0 else "ativado"

            if novo_status == 0:
                conn.execute(
                    'UPDATE unidades SET ativo = 0 WHERE empreendimento_id = ?', (empreendimento_id,))
                flash(
                    f"Empreendimento '{empreendimento['nome']}' e suas unidades foram {status_texto}s.", 'success')
            else:
                flash(
                    f"Empreendimento '{empreendimento['nome']}' foi {status_texto}. Unidades precisam ser ativadas individualmente.", 'success')
            conn.commit()
            app.logger.info(
                f"Empreendimento ID {empreendimento_id} alterado para ativo={novo_status} por {current_user.email}")
        else:
            flash('Empreendimento não encontrado.', 'error')
    except sqlite3.Error as e:
        flash(f'Erro no banco de dados: {e}', 'error')
        app.logger.error(
            f"Erro DB em toggle_empreendimento: {e}", exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='empreendimentos'))


@app.route('/remover_empreendimento/<int:emp_id>', methods=['POST'])
@admin_required
def remover_empreendimento(emp_id):
    conn = get_db_connection()
    try:
        emp = conn.execute(
            "SELECT nome FROM empreendimentos WHERE id = ?", (emp_id,)).fetchone()
        if not emp:
            flash("Empreendimento não encontrado.", "error")
            return redirect(url_for('configuracoes', tab='empreendimentos'))

        agendamentos_existentes = conn.execute("""
            SELECT COUNT(a.id) as count 
            FROM agendamentos a 
            JOIN unidades u ON a.unidade_id = u.id 
            WHERE u.empreendimento_id = ?
        """, (emp_id,)).fetchone()

        if agendamentos_existentes and agendamentos_existentes['count'] > 0:
            flash(
                f"Não é possível remover o empreendimento '{emp['nome']}' pois existem agendamentos associados às suas unidades.", 'error')
            return redirect(url_for('configuracoes', tab='empreendimentos'))

        conn.execute('DELETE FROM empreendimentos WHERE id = ?', (emp_id,))
        conn.commit()
        flash(
            f"Empreendimento '{emp['nome']}' e suas unidades foram removidos com sucesso!", 'success')
        app.logger.info(
            f"Empreendimento ID {emp_id} removido por {current_user.email}")
    except sqlite3.Error as e:
        flash(
            f"Erro ao remover empreendimento: {e}. Verifique se há dados dependentes.", 'error')
        app.logger.error(
            f'Erro DB ao remover empreendimento {emp_id}: {e}', exc_info=True)
    except Exception as e:
        flash('Erro inesperado ao remover empreendimento.', 'error')
        app.logger.error(
            f'Erro inesperado ao remover empreendimento {emp_id}: {e}', exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='empreendimentos'))


@app.route('/toggle_unidade/<int:unidade_id>', methods=['POST'])
@admin_required
def toggle_unidade(unidade_id):
    source_emp_id = request.form.get('source_empreendimento_id')
    conn = get_db_connection()
    try:
        unidade = conn.execute(
            'SELECT u.id, u.ativo, u.nome, u.empreendimento_id, e.ativo as emp_ativo FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id WHERE u.id = ?', (unidade_id,)).fetchone()
        if unidade:
            novo_status = 0 if unidade['ativo'] == 1 else 1
            status_texto = "desativada" if novo_status == 0 else "ativada"

            if novo_status == 1 and not unidade['emp_ativo']:
                flash(
                    f"Não é possível ativar a unidade '{unidade['nome']}' pois seu empreendimento está inativo.", 'error')
            else:
                conn.execute(
                    'UPDATE unidades SET ativo = ? WHERE id = ?', (novo_status, unidade_id))
                conn.commit()
                flash(
                    f"Status da unidade '{unidade['nome']}' atualizado para {status_texto}.", 'success')
                app.logger.info(
                    f"Unidade ID {unidade_id} alterada para ativo={novo_status} por {current_user.email}")
        else:
            flash('Unidade não encontrada.', 'error')
    except sqlite3.Error as e:
        flash(f'Erro no banco de dados: {e}', 'error')
        app.logger.error(f"Erro DB em toggle_unidade: {e}", exc_info=True)
    finally:
        conn.close()

    if source_emp_id:
        return redirect(url_for('configuracoes', tab='empreendimentos', active_emp_id=source_emp_id))
    return redirect(url_for('configuracoes', tab='empreendimentos'))


@app.route('/remover_unidade/<int:unidade_id>', methods=['POST'])
@admin_required
def remover_unidade(unidade_id):
    source_emp_id = request.form.get('source_empreendimento_id')
    conn = get_db_connection()
    unidade_info_for_redirect = None  # Para guardar o empreendimento_id
    try:
        unidade = conn.execute(
            'SELECT nome, empreendimento_id FROM unidades WHERE id = ?', (unidade_id,)).fetchone()
        if not unidade:
            flash('Unidade não encontrada.', 'error')
        else:
            unidade_info_for_redirect = unidade  # Guardar antes de deletar
            agendamentos_count = conn.execute(
                "SELECT COUNT(id) as count FROM agendamentos WHERE unidade_id = ?", (unidade_id,)).fetchone()
            if agendamentos_count and agendamentos_count['count'] > 0:
                flash(
                    f"Erro: A unidade '{unidade['nome']}' não pode ser removida pois está associada a agendamentos existentes.", 'error')
            else:
                conn.execute(
                    'DELETE FROM unidades WHERE id = ?', (unidade_id,))
                conn.commit()
                flash(
                    f"Unidade '{unidade['nome']}' removida com sucesso!", 'success')
                app.logger.info(
                    f"Unidade ID {unidade_id} removida por {current_user.email}")
    except sqlite3.Error as e:
        flash(f"Erro ao remover unidade: {e}", 'error')
        app.logger.error(f"Erro DB em remover_unidade: {e}", exc_info=True)
    finally:
        conn.close()

    if source_emp_id:
        return redirect(url_for('configuracoes', tab='empreendimentos', active_emp_id=source_emp_id))
    elif unidade_info_for_redirect:
        return redirect(url_for('configuracoes', tab='empreendimentos', active_emp_id=unidade_info_for_redirect['empreendimento_id']))
    return redirect(url_for('configuracoes', tab='empreendimentos'))

# ⚙️ Configurações


@app.route('/configuracoes')
@admin_required
def configuracoes():
    conn = get_db_connection()
    tipos_data = []
    empreendimentos_data = []
    admin_users_data = []
    normal_users_data = []
    try:
        tipos_data = conn.execute(
            'SELECT * FROM tipos_agendamento ORDER BY nome').fetchall()
        empreendimentos_data = conn.execute(
            'SELECT * FROM empreendimentos ORDER BY nome').fetchall()
        admin_users_data = conn.execute(
            # Removido is_admin desnecessário aqui
            "SELECT id, nome, email FROM usuarios WHERE is_admin = 1 ORDER BY nome").fetchall()
        normal_users_data = conn.execute(
            # Removido is_admin
            "SELECT id, nome, email FROM usuarios WHERE is_admin = 0 ORDER BY nome").fetchall()
    except sqlite3.Error as e:
        flash("Erro ao carregar dados de configuração.", "error")
        app.logger.error(
            f"Erro DB ao carregar /configuracoes: {e}", exc_info=True)
    finally:
        conn.close()

    return render_template('configuracoes.html',
                           tipos=tipos_data,
                           empreendimentos=empreendimentos_data,
                           admin_users=admin_users_data,
                           normal_users=normal_users_data)


@app.route('/api/empreendimento/<int:empreendimento_id>/unidades')
@admin_required
def api_get_unidades_por_empreendimento(empreendimento_id):
    conn = get_db_connection()
    empreendimento = conn.execute(
        "SELECT id FROM empreendimentos WHERE id = ?", (empreendimento_id,)).fetchone()
    if not empreendimento:
        conn.close()
        return jsonify({"error": "Empreendimento não encontrado"}), 404

    unidades = conn.execute(
        "SELECT id, nome, ativo FROM unidades WHERE empreendimento_id = ? ORDER BY nome",
        (empreendimento_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(unidade) for unidade in unidades])

# Adicionar itens


@app.route('/adicionar_empreendimento', methods=['POST'])
@admin_required
def adicionar_empreendimento():
    nome = request.form.get('nome', '').strip()
    if not nome:
        flash('Nome do empreendimento é obrigatório.', 'error')
    else:
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO empreendimentos (nome) VALUES (?)', (nome,))
            conn.commit()
            flash('Empreendimento adicionado com sucesso!', 'success')
            app.logger.info(
                f"Empreendimento '{nome}' adicionado por {current_user.email}")
        except sqlite3.IntegrityError:
            flash('Este empreendimento já existe!', 'error')
        except sqlite3.Error as e:
            flash('Erro ao adicionar empreendimento.', 'error')
            app.logger.error(
                f"Erro DB ao adicionar empreendimento: {e}", exc_info=True)
        finally:
            conn.close()
    return redirect(url_for('configuracoes', tab='empreendimentos'))


@app.route('/adicionar_unidade', methods=['POST'])
@admin_required
def adicionar_unidade():
    nome = request.form.get('nome', '').strip()
    empreendimento_id = request.form.get('empreendimento_id')
    active_emp_id_for_redirect = empreendimento_id

    if not nome or not empreendimento_id:
        flash('Nome da unidade e seleção de empreendimento são obrigatórios.', 'error')
        return redirect(url_for('configuracoes', tab='empreendimentos', active_emp_id=active_emp_id_for_redirect))

    conn = get_db_connection()
    try:
        empreendimento_pai = conn.execute(
            "SELECT ativo, nome FROM empreendimentos WHERE id = ?", (empreendimento_id,)).fetchone()
        if not empreendimento_pai:
            flash('Empreendimento pai não encontrado.', 'error')
        elif not empreendimento_pai['ativo']:
            flash(
                f"Não é possível adicionar unidade ao empreendimento inativo '{empreendimento_pai['nome']}'.", 'error')
        else:
            conn.execute('INSERT INTO unidades (nome, empreendimento_id) VALUES (?, ?)',
                         (nome, int(empreendimento_id)))
            conn.commit()
            flash(
                f"Unidade '{nome}' adicionada ao empreendimento '{empreendimento_pai['nome']}' com sucesso!", 'success')
            app.logger.info(
                f"Unidade '{nome}' adicionada ao emp ID {empreendimento_id} por {current_user.email}")
    except sqlite3.IntegrityError:
        flash('Essa unidade já existe nesse empreendimento.', 'error')
    except ValueError:
        flash('ID do empreendimento inválido.', 'error')
    except sqlite3.Error as e:
        flash('Erro ao adicionar unidade.', 'error')
        app.logger.error(f'Erro DB ao adicionar unidade: {e}', exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='empreendimentos', active_emp_id=active_emp_id_for_redirect))


@app.route('/adicionar_tipo', methods=['POST'])
@admin_required
def adicionar_tipo():
    novo_tipo = request.form.get('novo_tipo', '').strip()
    if not novo_tipo:
        flash('Nome do tipo de agendamento é obrigatório.', 'error')
    else:
        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO tipos_agendamento (nome) VALUES (?)', (novo_tipo,))
            conn.commit()
            flash('Tipo de agendamento adicionado com sucesso!', 'success')
            app.logger.info(
                f"Tipo '{novo_tipo}' adicionado por {current_user.email}")
        except sqlite3.IntegrityError:
            flash('Este tipo de agendamento já existe!', 'error')
        except sqlite3.Error as e:
            flash('Erro ao adicionar tipo de agendamento.', 'error')
            app.logger.error(f"Erro DB ao adicionar tipo: {e}", exc_info=True)
        finally:
            conn.close()
    return redirect(url_for('configuracoes', tab='tipos'))


@app.route('/remover_tipo/<int:tipo_id>', methods=['POST'])
@admin_required
def remover_tipo(tipo_id):
    conn = get_db_connection()
    try:
        tipo = conn.execute(
            "SELECT nome FROM tipos_agendamento WHERE id = ?", (tipo_id,)).fetchone()
        if not tipo:
            flash("Tipo de agendamento não encontrado.", "error")
        else:
            agendamentos_count = conn.execute(
                "SELECT COUNT(id) as count FROM agendamentos WHERE tipo_id = ?", (tipo_id,)).fetchone()
            if agendamentos_count and agendamentos_count['count'] > 0:
                flash(
                    f"Erro: O tipo '{tipo['nome']}' não pode ser removido pois está associado a agendamentos existentes.", 'error')
            else:
                conn.execute(
                    'DELETE FROM tipos_agendamento WHERE id = ?', (tipo_id,))
                conn.commit()
                flash(
                    f"Tipo '{tipo['nome']}' removido com sucesso!", 'success')
                app.logger.info(
                    f"Tipo ID {tipo_id} removido por {current_user.email}")
    except sqlite3.Error as e:
        flash(f"Erro ao remover tipo: {e}", 'error')
        app.logger.error(f"Erro DB ao remover tipo: {e}", exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='tipos'))

# ROTAS PARA GERENCIAMENTO DE ADMINISTRADORES


@app.route('/promover_admin', methods=['POST'])
@admin_required
def promover_admin():
    user_id_to_promote = request.form.get('user_to_promote_id')
    if not user_id_to_promote:
        flash('Nenhum usuário selecionado para promover.', 'error')
        return redirect(url_for('configuracoes', tab='seguranca'))

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, nome, is_admin FROM usuarios WHERE id = ?", (user_id_to_promote,)).fetchone()
        if not user:
            flash('Usuário não encontrado.', 'error')
        elif user['is_admin']:
            flash(
                f"O usuário '{user['nome'] if user['nome'] else 'ID '+str(user['id'])}' já é um administrador.", 'warning')
        else:
            conn.execute(
                "UPDATE usuarios SET is_admin = 1 WHERE id = ?", (user_id_to_promote,))
            conn.commit()
            flash(
                f"Usuário '{user['nome'] if user['nome'] else 'ID '+str(user['id'])}' promovido a administrador com sucesso!", 'success')
            app.logger.info(
                f"Usuário ID {user_id_to_promote} promovido a admin por {current_user.email}")
    except sqlite3.Error as e:
        flash(f'Erro no banco de dados ao promover usuário: {e}', 'error')
        app.logger.error(f"Erro DB em promover_admin: {e}", exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='seguranca'))


@app.route('/remover_admin/<int:user_id>', methods=['POST'])
@admin_required
def remover_admin(user_id):
    if user_id == current_user.id:
        flash('Você não pode remover seu próprio status de administrador.', 'error')
        return redirect(url_for('configuracoes', tab='seguranca'))

    conn = get_db_connection()
    try:
        target_user = conn.execute(
            "SELECT id, nome, email, is_admin FROM usuarios WHERE id = ?", (user_id,)).fetchone()
        if not target_user:
            flash('Usuário não encontrado.', 'error')
            conn.close()  # Fechar conexão antes do redirect
            return redirect(url_for('configuracoes', tab='seguranca'))

        if target_user['email'] == os.environ.get('SUPER_ADMIN_EMAIL', 'admin@admin.com'):
            flash('O administrador principal não pode ter seu status de admin removido por esta interface.', 'error')
            conn.close()  # Fechar conexão antes do redirect
            return redirect(url_for('configuracoes', tab='seguranca'))

        if not target_user['is_admin']:
            flash(
                f"O usuário '{target_user['nome'] if target_user['nome'] else target_user['email']}' não é um administrador.", 'warning')
        else:
            admin_count_row = conn.execute(
                "SELECT COUNT(id) as count FROM usuarios WHERE is_admin = 1").fetchone()
            if admin_count_row and admin_count_row['count'] <= 1:
                flash(
                    'Não é possível remover o status do último administrador do sistema.', 'error')
            else:
                conn.execute(
                    "UPDATE usuarios SET is_admin = 0 WHERE id = ?", (user_id,))
                conn.commit()
                flash(
                    f"Status de administrador removido do usuário '{target_user['nome'] if target_user['nome'] else target_user['email']}' com sucesso!", 'success')
                app.logger.info(
                    f"Status admin removido do usuário ID {user_id} por {current_user.email}")
    except sqlite3.Error as e:
        flash(
            f'Erro no banco de dados ao remover status de admin: {e}', 'error')
        app.logger.error(f"Erro DB em remover_admin: {e}", exc_info=True)
    finally:
        # Verificar se conn ainda está definida (pode ter sido fechada nos returns antecipados)
        if conn:
            conn.close()
    return redirect(url_for('configuracoes', tab='seguranca'))

# 🧱 Banco de dados


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tipos_agendamento (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1))
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS empreendimentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1))
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS unidades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            empreendimento_id INTEGER NOT NULL,
            ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1)),
            FOREIGN KEY (empreendimento_id) REFERENCES empreendimentos(id) ON DELETE CASCADE,
            UNIQUE(nome, empreendimento_id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0 CHECK(is_admin IN (0, 1)) 
        )
    ''')
    # --- ALTERAÇÃO AQUI: Adicionar 'observacoes' na tabela agendamentos ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agendamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER, 
            tipo_id INTEGER NOT NULL,
            unidade_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            hora TEXT NOT NULL,
            observacoes TEXT, -- NOVA COLUNA: Adicione esta linha
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL,
            FOREIGN KEY (tipo_id) REFERENCES tipos_agendamento(id) ON DELETE RESTRICT,
            FOREIGN KEY (unidade_id) REFERENCES unidades(id) ON DELETE RESTRICT
        )
    ''')
    # Adicionar ALTER TABLE para usuários que já possuem o banco de dados
    # Isso é importante para não perder dados existentes.
    try:
        cursor.execute("ALTER TABLE agendamentos ADD COLUMN observacoes TEXT")
        app.logger.info(
            "Coluna 'observacoes' adicionada à tabela 'agendamentos'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'observacoes' já existe na tabela 'agendamentos'.")
        else:
            app.logger.error(f"Erro ao adicionar coluna 'observacoes': {e}")

    # --- FIM DA ALTERAÇÃO ---
    conn.commit()
    conn.close()
    app.logger.info("Banco de dados inicializado/verificado.")


def criar_usuario_inicial():
    conn = get_db_connection()
    cursor = conn.cursor()
    admin_email = os.environ.get('SUPER_ADMIN_EMAIL', 'admin@admin.com')
    admin_nome = "Administrador Principal"
    admin_user = cursor.execute(
        "SELECT id, is_admin, nome FROM usuarios WHERE email = ?", (admin_email,)).fetchone()

    if not admin_user:
        default_password = os.environ.get('SUPER_ADMIN_PASSWORD', '123456')
        if len(default_password) < 6:
            app.logger.error(
                "Senha padrão do super admin é muito curta. Defina SUPER_ADMIN_PASSWORD com pelo menos 6 caracteres.")
            default_password = "ChangeMeNow123!"

        senha_hash = generate_password_hash(default_password)
        try:
            cursor.execute(
                'INSERT INTO usuarios (nome, email, senha, is_admin) VALUES (?, ?, ?, ?)',
                (admin_nome, admin_email, senha_hash, 1)
            )
            conn.commit()
            app.logger.info(
                f"Usuário administrador inicial '{admin_email}' criado com is_admin=1.")
        except sqlite3.IntegrityError:
            app.logger.warning(
                f"Usuário administrador inicial '{admin_email}' já existe (concorrência).")
    elif not admin_user['is_admin'] or admin_user['nome'] != admin_nome:
        # Construir a query de update dinamicamente
        update_fields = ["is_admin = 1"]
        params = []
        if admin_user['nome'] != admin_nome:
            update_fields.append("nome = ?")
            params.append(admin_nome)

        params.append(admin_email)  # email para a cláusula WHERE

        update_query = f"UPDATE usuarios SET {', '.join(update_fields)} WHERE email = ?"

        cursor.execute(update_query, tuple(params))
        conn.commit()
        app.logger.info(
            f"Usuário '{admin_email}' atualizado para administrador e/ou nome corrigido.")
    else:
        app.logger.info(
            f"Usuário administrador inicial '{admin_email}' já configurado corretamente.")
    conn.close()


# 🚀 Execução
if __name__ == '__main__':
    with app.app_context():
        init_db()
        criar_usuario_inicial()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
