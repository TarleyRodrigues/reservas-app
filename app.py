from dateutil.relativedelta import relativedelta
from datetime import datetime, timedelta, date
import uuid
from werkzeug.utils import secure_filename
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

# 🖼️ Configuração de Uploads de Imagem
UPLOAD_FOLDER = 'static/uploads/perfil'
SYSTEM_IMAGES_FOLDER = 'static/uploads/system'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SYSTEM_IMAGES_FOLDER'] = SYSTEM_IMAGES_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite de 16MB

# Função auxiliar para verificar extensões permitidas


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 🔗 Classe de usuário


class Usuario(UserMixin):
    # CORREÇÃO CRÍTICA AQUI: Adicione 'foto_perfil=None' como um parâmetro de __init__
    def __init__(self, id, nome, email, senha_hash, is_admin=0, tipo_usuario='cliente', telefone=None, foto_perfil=None):
        self.id = id
        self.nome = nome
        self.email = email
        self.senha_hash = senha_hash
        self.is_admin = is_admin
        self.tipo_usuario = tipo_usuario
        self.telefone = telefone
        self.foto_perfil = foto_perfil  # Agora 'foto_perfil' é um parâmetro válido

    @property
    def is_cliente(self):
        return self.tipo_usuario == 'cliente'

    @property
    def is_agente(self):
        return self.tipo_usuario == 'agente'

    @property
    def is_admin_user(self):
        return self.tipo_usuario == 'admin' or self.is_admin == 1


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Funções auxiliares para configurações globais


def get_global_setting(key, default_value=None):
    conn = get_db_connection()
    value = default_value
    try:
        row = conn.execute(
            "SELECT valor FROM configuracoes_globais WHERE chave = ?", (key,)).fetchone()
        if row:
            value = row['valor']
    except sqlite3.Error as e:
        app.logger.error(
            f"Erro DB ao obter configuração global '{key}': {e}", exc_info=True)
    finally:
        if conn:
            conn.close()
    return value


def set_global_setting(key, value):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO configuracoes_globais (chave, valor) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        return True
    except sqlite3.Error as e:
        app.logger.error(
            f"Erro DB ao salvar configuração global '{key}': {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()


def get_regras_reservas():
    conn = get_db_connection()
    regras = conn.execute(
        "SELECT antecedencia_minima_dias, antecedencia_maxima_dias FROM regras_reservas WHERE id = 1").fetchone()
    conn.close()
    if regras:
        return {
            'min_dias': regras['antecedencia_minima_dias'],
            'max_dias': regras['antecedencia_maxima_dias']
        }
    # Retorna valores padrão se a linha não existir (primeira execução ou DB vazio)
    return {'min_dias': 1, 'max_dias': 365}  # Padrões consistentes com init_db


def set_regras_reservas(min_dias, max_dias):
    conn = get_db_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO regras_reservas (id, antecedencia_minima_dias, antecedencia_maxima_dias)
            VALUES (1, ?, ?)""",
            (min_dias, max_dias)
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        app.logger.error(
            f"Erro DB ao salvar regras de reservas: {e}", exc_info=True)
        return False
    finally:
        if conn:
            conn.close()


def buscar_usuario_por_email(email):
    conn = get_db_connection()
    # Garanta que todas as colunas necessárias para o Usuario.__init__ sejam selecionadas
    row = conn.execute(
        "SELECT id, nome, email, senha, is_admin, tipo_usuario, telefone, foto_perfil FROM usuarios WHERE email = ?", (
            email,)
    ).fetchone()
    conn.close()
    if row:
        # CORREÇÃO AQUI: Remova os .get(). Como a coluna foto_perfil agora existe no DB,
        # e as outras já existem, acesso direto por row['chave'] é correto.
        return Usuario(
            id=row["id"],
            nome=row["nome"],
            email=row["email"],
            senha_hash=row["senha"],
            is_admin=row["is_admin"],  # Acesso direto
            tipo_usuario=row["tipo_usuario"],  # Acesso direto
            telefone=row["telefone"],     # Acesso direto
            foto_perfil=row["foto_perfil"]  # Acesso direto
        )
    return None


@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    # Garanta que todas as colunas necessárias para o Usuario.__init__ sejam selecionadas
    row = conn.execute(
        "SELECT id, nome, email, senha, is_admin, tipo_usuario, telefone, foto_perfil FROM usuarios WHERE id = ?", (
            user_id,)
    ).fetchone()
    conn.close()
    if row:
        # CORREÇÃO AQUI: Remova os .get(). Acesso direto por row['chave'] é correto.
        return Usuario(
            id=row["id"],
            nome=row["nome"],
            email=row["email"],
            senha_hash=row["senha"],
            is_admin=row["is_admin"],
            tipo_usuario=row["tipo_usuario"],
            telefone=row["telefone"],
            foto_perfil=row["foto_perfil"]
        )
    return None

# 🏠 Página inicial


@app.route('/')
def index():
    logo_path = get_global_setting('logo_sistema_path', 'images/logo.png')
    return render_template('index.html', logo_path=logo_path)

# 🔐 Login
# --- DECORATORS PARA PERMISSÃO ---


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin_user:
            flash('Acesso restrito a administradores.', 'error')
            app.logger.warning(
                f"Tentativa de acesso não autorizado à rota admin por: {current_user.email} (Tipo: {current_user.tipo_usuario})")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def agente_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_agente or current_user.is_admin_user):
            flash('Acesso restrito a agentes ou administradores.', 'error')
            app.logger.warning(
                f"Tentativa de acesso não autorizado à rota de agente por: {current_user.email} (Tipo: {current_user.tipo_usuario})")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def permissoes_required(roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Por favor, faça login para acessar esta página.', 'info')
                return redirect(url_for('login', next=request.url))

            if current_user.tipo_usuario not in roles and not current_user.is_admin_user:
                flash('Você não tem permissão para acessar esta página.', 'error')
                app.logger.warning(
                    f"Tentativa de acesso não autorizado por: {current_user.email} (Tipo: {current_user.tipo_usuario}) à rota que exige: {roles}")
                return redirect(url_for('index'))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Funções Auxiliares para a Rota /agendar ---


def _get_dados_para_template_agendamento(conn):
    """Busca no banco de dados os dados necessários para renderizar a página de agendamento."""
    tipos = conn.execute(
        'SELECT id, nome, ativo, duracao_minutos FROM tipos_agendamento WHERE ativo = 1 ORDER BY nome'
    ).fetchall()
    empreendimentos = conn.execute(
        'SELECT id, nome, ativo FROM empreendimentos WHERE ativo = 1 ORDER BY nome'
    ).fetchall()
    unidades = conn.execute('''
        SELECT u.id, u.nome, u.empreendimento_id, e.nome as nome_empreendimento
        FROM unidades u
        JOIN empreendimentos e ON u.empreendimento_id = e.id
        WHERE u.ativo = 1 AND e.ativo = 1 ORDER BY e.nome, u.nome
    ''').fetchall()
    return {'tipos': tipos, 'empreendimentos': empreendimentos, 'unidades': unidades}


def _validar_payload_agendamento(form):
    """Valida se os campos obrigatórios do formulário foram preenchidos."""
    errors = []
    campos_obrigatorios = {
        'contato': "O campo 'Contato' é obrigatório.",
        'data': "A data é obrigatória.",
        'hora': "A hora é obrigatória.",
        'tipo_id': "O tipo de agendamento é obrigatório.",
        'empreendimento_id': "O empreendimento é obrigatório.",
        'unidade_id': "A unidade é obrigatória."
    }
    for campo, msg in campos_obrigatorios.items():
        if not form.get(campo):
            errors.append(msg)
    return errors


def _validar_regras_de_negocio(conn, data_hora_agendamento, unidade_id, tipo_id, regras_reservas):
    """Executa todas as validações de regras de negócio para um novo agendamento."""
    errors = []

    # 1. Validação de data no passado
    if data_hora_agendamento < datetime.now():
        errors.append("Não é possível agendar em datas e horários passados.")
        # Se a data já passou, outras validações de tempo são desnecessárias.
        return errors

    # 2. Validação de antecedência (mínima e máxima)
    min_dias = regras_reservas['min_dias']
    max_dias = regras_reservas['max_dias']
    if min_dias > 0:
        min_limite = datetime.now() + timedelta(days=min_dias)
        if data_hora_agendamento < min_limite:
            errors.append(
                f"Agendamentos devem ser feitos com no mínimo {min_dias} dia(s) de antecedência.")
    if max_dias > 0:
        max_limite = date.today() + timedelta(days=max_dias)
        if data_hora_agendamento.date() > max_limite:
            errors.append(
                f"Não é possível agendar com mais de {max_dias} dia(s) de antecedência.")

    # 3. Validação de Entidades (Unidade, Tipo)
    tipo_selecionado = conn.execute(
        'SELECT ativo, duracao_minutos FROM tipos_agendamento WHERE id = ?', (tipo_id,)).fetchone()
    unidade_selecionada = conn.execute(
        'SELECT u.ativo as unidade_ativa, e.ativo as empreendimento_ativo, u.empreendimento_id FROM unidades u JOIN empreendimentos e ON u.empreendimento_id = e.id WHERE u.id = ?', (unidade_id,)).fetchone()

    if not (tipo_selecionado and tipo_selecionado['ativo']):
        errors.append('O tipo de agendamento selecionado não está ativo.')
    if not (unidade_selecionada and unidade_selecionada['unidade_ativa'] and unidade_selecionada['empreendimento_ativo']):
        errors.append(
            'A unidade selecionada ou seu empreendimento não estão ativos.')

    # Se houver erros até aqui, não adianta checar horários e conflitos
    if errors:
        return errors

    # 4. Validação de Horário de Funcionamento
    dia_semana = data_hora_agendamento.weekday()
    empreendimento_id = unidade_selecionada['empreendimento_id']
    horarios_op = conn.execute(
        'SELECT hora_inicio, hora_fim FROM horarios_funcionamento WHERE empreendimento_id = ? AND dia_semana = ?', (empreendimento_id, dia_semana)).fetchall()

    hora_agendamento_obj = data_hora_agendamento.time()
    duracao = tipo_selecionado['duracao_minutos']
    hora_fim_agendamento = (data_hora_agendamento +
                            timedelta(minutes=duracao)).time()

    dentro_horario_funcionamento = False
    for h in horarios_op:
        inicio_op = datetime.strptime(h['hora_inicio'], '%H:%M').time()
        fim_op = datetime.strptime(h['hora_fim'], '%H:%M').time()
        if inicio_op <= hora_agendamento_obj and hora_fim_agendamento <= fim_op:
            dentro_horario_funcionamento = True
            break

    if not dentro_horario_funcionamento:
        errors.append(
            f"O agendamento (duração: {duracao} min) não se encaixa no horário de funcionamento do empreendimento neste dia.")

    # 5. Validação de Conflitos de Horário na Unidade
    agendamentos_existentes = conn.execute('SELECT a.hora, ta.duracao_minutos FROM agendamentos a JOIN tipos_agendamento ta ON a.tipo_id = ta.id WHERE a.unidade_id = ? AND a.data = ?', (
        unidade_id, data_hora_agendamento.strftime('%Y-%m-%d'))).fetchall()

    data_hora_fim_agendamento = data_hora_agendamento + \
        timedelta(minutes=duracao)

    for ag_existente in agendamentos_existentes:
        inicio_existente = datetime.combine(data_hora_agendamento.date(
        ), datetime.strptime(ag_existente['hora'], '%H:%M').time())
        fim_existente = inicio_existente + \
            timedelta(minutes=ag_existente['duracao_minutos'])
        # Checa sobreposição
        if data_hora_agendamento < fim_existente and data_hora_fim_agendamento > inicio_existente:
            errors.append(
                f"Conflito de horário. A unidade já está reservada das {inicio_existente.strftime('%H:%M')} às {fim_existente.strftime('%H:%M')}.")
            break

    return errors

# --- Funções Auxiliares para a API de Slots ---


def _validar_e_parsear_parametros_api(args):
    """Valida e converte os parâmetros da requisição GET para a API de slots."""
    params = {}
    errors = []

    # Valida a presença dos parâmetros
    for p in ['empreendimento_id', 'unidade_id', 'data', 'tipo_id']:
        if not args.get(p):
            errors.append(f"Parâmetro obrigatório ausente: {p}.")
            return None, errors

    # Tenta converter os tipos de dados
    try:
        params['empreendimento_id'] = int(args.get('empreendimento_id'))
        params['unidade_id'] = int(args.get('unidade_id'))
        params['tipo_id'] = int(args.get('tipo_id'))
        params['data_str'] = args.get('data')
        params['data_obj'] = datetime.strptime(
            params['data_str'], '%Y-%m-%d').date()
    except (ValueError, TypeError) as e:
        errors.append(f"Formato de parâmetro inválido: {e}")
        return None, errors

    return params, None


def _get_intervalos_ocupados(conn, data_obj, unidade_id, agentes_ids):
    """Busca e retorna uma lista de tuplas (início, fim) para todos os agendamentos ocupados."""
    intervalos = []
    data_str = data_obj.strftime('%Y-%m-%d')

    # Busca agendamentos da unidade
    agendamentos_unidade = conn.execute('''
        SELECT a.hora, ta.duracao_minutos FROM agendamentos a
        JOIN tipos_agendamento ta ON a.tipo_id = ta.id
        WHERE a.unidade_id = ? AND a.data = ? AND a.status IN ('Pendente', 'Confirmado')
    ''', (unidade_id, data_str)).fetchall()
    for ag in agendamentos_unidade:
        inicio = datetime.combine(
            data_obj, datetime.strptime(ag['hora'], '%H:%M').time())
        fim = inicio + timedelta(minutes=ag['duracao_minutos'])
        intervalos.append((inicio, fim))

    # Busca agendamentos de todos os agentes relevantes de uma só vez
    if agentes_ids:
        placeholders = ','.join('?' for _ in agentes_ids)
        agendamentos_agentes = conn.execute(f'''
            SELECT a.hora, ta.duracao_minutos FROM agendamentos a
            JOIN tipos_agendamento ta ON a.tipo_id = ta.id
            WHERE a.agente_atribuido_id IN ({placeholders}) AND a.data = ? AND a.status = 'Confirmado'
        ''', (*agentes_ids, data_str)).fetchall()
        for ag in agendamentos_agentes:
            inicio = datetime.combine(
                data_obj, datetime.strptime(ag['hora'], '%H:%M').time())
            fim = inicio + timedelta(minutes=ag['duracao_minutos'])
            intervalos.append((inicio, fim))

    return intervalos


def _is_slot_disponivel(slot_inicio, slot_fim, intervalos_ocupados):
    """Verifica se um slot específico conflita com algum intervalo já ocupado."""
    for inicio_ocupado, fim_ocupado in intervalos_ocupados:
        # Verifica sobreposição: (StartA < EndB) and (EndA > StartB)
        if slot_inicio < fim_ocupado and slot_fim > inicio_ocupado:
            return False  # Conflito encontrado
    return True  # Slot está livre


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
            app.logger.info(
                f"Usuário {user.email} logado com sucesso (Tipo: {user.tipo_usuario}).")
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
        telefone = request.form.get('telefone', '').strip()

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
            return render_template('cadastro.html', nome=nome, email=email, telefone=telefone)

        conn = None
        try:
            senha_hash = generate_password_hash(senha)
            conn = get_db_connection()
            # NOVO: Inclui 'foto_perfil' com valor padrão None no INSERT de cadastro
            conn.execute(
                'INSERT INTO usuarios (nome, email, senha, is_admin, tipo_usuario, telefone, foto_perfil) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (nome, email, senha_hash, 0, 'cliente', telefone, None)
            )
            conn.commit()
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            app.logger.info(
                f"Novo usuário cadastrado: {email} como 'cliente'.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Este email já está cadastrado. Por favor, use outro.', 'error')
            app.logger.warning(
                f"Tentativa de cadastro com email duplicado: {email}")
        except sqlite3.Error as e:
            flash(
                'Erro ao cadastrar usuário no banco de dados. Tente novamente.', 'error')
            app.logger.error(f'Erro DB no cadastro: {e}', exc_info=True)
        except Exception as e:
            flash(
                'Ocorreu um erro inesperado durante o cadastro. Por favor, tente mais tarde.', 'error')
            app.logger.error(
                f'Erro inesperado no cadastro: {e}', exc_info=True)
        finally:
            if conn:
                conn.close()

        return render_template('cadastro.html', nome=nome, email=email, telefone=telefone)

    return render_template('cadastro.html', nome='', email='', telefone='')


@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    conn = get_db_connection()
    try:
        if request.method == 'POST':
            novo_nome = request.form.get('nome', '').strip()
            novo_email = request.form.get('email', '').strip()
            novo_telefone = request.form.get('telefone', '').strip()

            senha_atual = request.form.get('senha_atual', '').strip()
            nova_senha = request.form.get('nova_senha', '').strip()
            confirmar_nova_senha = request.form.get(
                'confirmar_nova_senha', '').strip()

            errors = []
            success_messages = []

            # --- Validação e Atualização de Dados Cadastrais (Nome, Email, Telefone) ---
            if not novo_nome:
                errors.append('O nome não pode ser vazio.')
            if not novo_email:
                errors.append('O e-mail não pode ser vazio.')

            if novo_email != current_user.email:
                existing_user = buscar_usuario_por_email(novo_email)
                if existing_user:
                    errors.append(
                        'Este e-mail já está em uso por outro usuário.')

            if not errors and (novo_nome != current_user.nome or
                               novo_email != current_user.email or
                               novo_telefone != current_user.telefone):
                try:
                    conn.execute(
                        'UPDATE usuarios SET nome = ?, email = ?, telefone = ? WHERE id = ?',
                        (novo_nome, novo_email, novo_telefone, current_user.id)
                    )
                    conn.commit()
                    success_messages.append(
                        'Dados cadastrais atualizados com sucesso!')
                    app.logger.info(
                        f"Usuário {current_user.email} (ID: {current_user.id}) atualizou dados cadastrais.")

                    if novo_email != current_user.email:
                        flash(
                            'Seu e-mail foi alterado. Por favor, faça login novamente com o novo e-mail.', 'info')
                        logout_user()
                        return redirect(url_for('login', next=url_for('perfil')))

                except sqlite3.IntegrityError:
                    errors.append(
                        'Erro de integridade ao atualizar dados. O e-mail pode já estar em uso.')
                    app.logger.error(
                        f"IntegrityError ao atualizar perfil de {current_user.email}: {e}", exc_info=True)
                except sqlite3.Error as e:
                    errors.append(
                        f'Erro no banco de dados ao atualizar dados: {str(e)}')
                    app.logger.error(
                        f"Erro DB ao atualizar perfil de {current_user.email}: {e}", exc_info=True)

            # --- Validação e Atualização de Senha ---
            if nova_senha:
                if not senha_atual:
                    errors.append(
                        'Para alterar a senha, você deve informar sua senha atual.')
                elif not check_password_hash(current_user.senha_hash, senha_atual):
                    errors.append('Senha atual incorreta.')
                elif nova_senha != confirmar_nova_senha:
                    errors.append(
                        'A nova senha e a confirmação não coincidem.')
                elif len(nova_senha) < 6:
                    errors.append(
                        'A nova senha deve ter pelo menos 6 caracteres.')

                if not errors:
                    try:
                        nova_senha_hash = generate_password_hash(nova_senha)
                        conn.execute(
                            'UPDATE usuarios SET senha = ? WHERE id = ?',
                            (nova_senha_hash, current_user.id)
                        )
                        conn.commit()
                        success_messages.append(
                            'Senha atualizada com sucesso!')
                        app.logger.info(
                            f"Usuário {current_user.email} (ID: {current_user.id}) alterou a senha.")

                        flash(
                            'Sua senha foi alterada. Por favor, faça login novamente.', 'info')
                        logout_user()
                        return redirect(url_for('login'))

                    except sqlite3.Error as e:
                        errors.append(
                            f'Erro no banco de dados ao atualizar senha: {str(e)}')
                        app.logger.error(
                            f"Erro DB ao atualizar senha de {current_user.email}: {e}", exc_info=True)

            # --- Pós-processamento ---
            if success_messages:
                updated_user = buscar_usuario_por_email(current_user.email)
                if updated_user:
                    login_user(updated_user, remember=True)
                    for msg in success_messages:
                        flash(msg, 'success')

            if errors:
                for msg in errors:
                    flash(msg, 'error')

            return redirect(url_for('perfil'))

        else:  # request.method == 'GET'
            pass

    except Exception as e:
        flash(f'Ocorreu um erro inesperado: {str(e)}', 'error')
        app.logger.error(
            f"Erro inesperado na rota /perfil para {current_user.email}: {e}", exc_info=True)
        return redirect(url_for('index'))
    finally:
        if conn:
            conn.close()

    return render_template('perfil.html')

# --- NOVO: ROTA PARA UPLOAD DE FOTO DE PERFIL ---


@app.route('/upload_foto_perfil', methods=['POST'])
@login_required
def upload_foto_perfil():
    conn = get_db_connection()
    try:
        if 'foto' not in request.files:
            flash('Nenhum arquivo enviado.', 'error')
            return redirect(url_for('perfil'))

        file = request.files['foto']

        if file.filename == '':
            flash('Nenhum arquivo selecionado.', 'error')
            return redirect(url_for('perfil'))

        if file and allowed_file(file.filename):
            filename_base = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + \
                os.path.splitext(filename_base)[1]
            filepath = os.path.join(
                app.config['UPLOAD_FOLDER'], unique_filename)

            file.save(filepath)

            relative_path_for_db = os.path.join(
                'uploads/perfil', unique_filename).replace('\\', '/')

            conn.execute('UPDATE usuarios SET foto_perfil = ? WHERE id = ?',
                         (relative_path_for_db, current_user.id))
            conn.commit()

            updated_user = buscar_usuario_por_email(current_user.email)
            if updated_user:
                login_user(updated_user, remember=True)
                flash('Foto de perfil atualizada com sucesso!', 'success')
                app.logger.info(
                    f"Usuário {current_user.email} (ID: {current_user.id}) fez upload de nova foto de perfil: {unique_filename}")
            else:
                flash(
                    'Erro ao recarregar dados do usuário. Tente fazer login novamente.', 'warning')
                app.logger.warning(
                    f"Erro ao recarregar usuário {current_user.email} após upload de foto.")

        else:
            flash(
                'Tipo de arquivo não permitido. Apenas PNG, JPG, JPEG, GIF são aceitos.', 'error')
            app.logger.warning(
                f"Tentativa de upload de arquivo não permitido por {current_user.email}: {file.filename}")

    except Exception as e:
        flash(f'Erro ao fazer upload da foto: {str(e)}', 'error')
        app.logger.error(
            f"Erro no upload de foto de perfil para {current_user.email}: {e}", exc_info=True)
    finally:
        if conn:
            conn.close()

    return redirect(url_for('perfil'))

# app.py

# ... (seus imports no início, incluindo werkzeug.utils e uuid) ...

# --- ROTA PARA UPLOAD DA LOGO DO SISTEMA ---


@app.route('/upload_logo_sistema', methods=['POST'])
@admin_required  # Garante que apenas administradores podem usar esta rota
def upload_logo_sistema():
    """
    Lida com o upload da logo principal do sistema.
    O arquivo é salvo na pasta 'static/uploads/system' e o caminho é
    armazenado na tabela 'configuracoes_globais' sob a chave 'logo_sistema_path'.
    """

    # Certifique-se de que a pasta de uploads do sistema exista antes de salvar
    os.makedirs(app.config['SYSTEM_IMAGES_FOLDER'], exist_ok=True)

    # 1. Verifica se o campo de arquivo ('logo_file') está no formulário enviado
    if 'logo_file' not in request.files:
        flash('Nenhum campo de arquivo foi encontrado no formulário.', 'error')
        return redirect(url_for('configuracoes', tab='app_config'))

    file = request.files['logo_file']

    # 2. Verifica se o usuário de fato selecionou um arquivo
    if file.filename == '':
        flash('Nenhum arquivo de logo foi selecionado.', 'warning')
        return redirect(url_for('configuracoes', tab='app_config'))

    # 3. Se um arquivo foi selecionado, valida seu tipo e salva
    if file and allowed_file(file.filename):
        # Gera um nome de arquivo único para evitar que navegadores usem cache antigo
        filename_base = secure_filename(file.filename)
        # Ex: "logo_uuid_aleatorio.png"
        unique_filename = f"logo_{uuid.uuid4().hex}{os.path.splitext(filename_base)[1]}"

        filepath = os.path.join(
            app.config['SYSTEM_IMAGES_FOLDER'], unique_filename)

        # Salva o arquivo no sistema de arquivos
        file.save(filepath)

        # Armazena o caminho relativo (a partir da pasta 'static') no banco de dados
        relative_path_for_db = os.path.join(
            'uploads/system', unique_filename).replace('\\', '/')

        # Usa a função auxiliar set_global_setting para atualizar a configuração
        if set_global_setting('logo_sistema_path', relative_path_for_db):
            flash('Logo do sistema atualizada com sucesso!', 'success')
            app.logger.info(
                f"Admin {current_user.email} atualizou a logo do sistema para: {unique_filename}")
        else:
            flash('Erro ao salvar o caminho da nova logo no banco de dados.', 'error')
            # Opcional, mas recomendado: tenta remover o arquivo salvo se o DB falhar
            os.remove(filepath)
            app.logger.error(
                f"Erro DB ao salvar caminho da logo para {current_user.email}.")

    else:
        # Se o arquivo não for de um tipo permitido
        flash('Tipo de arquivo não permitido. Apenas PNG, JPG, JPEG e GIF são aceitos.', 'error')
        app.logger.warning(
            f"Tentativa de upload de logo com arquivo não permitido por {current_user.email}: {file.filename}")

    # Redireciona para a aba de configurações do app
    return redirect(url_for('configuracoes', tab='app_config'))


@app.route('/agendar', methods=['GET', 'POST'])
@login_required
def agendar():
    conn = get_db_connection()
    try:
        regras_reservas = get_regras_reservas()

        # Coleta os dados para popular os selects do formulário (tipos, empreendimentos, etc.)
        contexto_template = _get_dados_para_template_agendamento(conn)
        contexto_template['regras_reservas'] = regras_reservas

        if request.method == 'POST':
            # Cria um dicionário com os dados do formulário para fácil manipulação
            form_data = {k: v.strip() for k, v in request.form.items()}

            # 1. Validação básica de preenchimento do formulário
            errors = _validar_payload_agendamento(form_data)
            if errors:
                for error in errors:
                    flash(error, 'error')
                contexto_template['form_data'] = form_data
                return render_template('agendar.html', **contexto_template)

            try:
                # 2. Conversão e Validação das regras de negócio
                data_agendamento_obj = datetime.strptime(
                    form_data['data'], '%Y-%m-%d').date()
                hora_agendamento_obj = datetime.strptime(
                    form_data['hora'], '%H:%M').time()
                data_hora_agendamento = datetime.combine(
                    data_agendamento_obj, hora_agendamento_obj)

                errors = _validar_regras_de_negocio(conn, data_hora_agendamento, int(
                    form_data['unidade_id']), int(form_data['tipo_id']), regras_reservas)
            except (ValueError, KeyError) as e:
                errors.append(
                    f"Erro no formato dos dados: {e}. Verifique se todos os campos foram selecionados.")

            if errors:
                for error in errors:
                    flash(error, 'error')
                contexto_template['form_data'] = form_data
                return render_template('agendar.html', **contexto_template)

            # 3. Se todas as validações passaram, insere no banco de dados
            try:
                conn.execute(
                    '''INSERT INTO agendamentos (usuario_id, tipo_id, unidade_id, data, hora, observacoes, contato_agendamento, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (current_user.id, int(form_data['tipo_id']), int(form_data['unidade_id']),
                     data_hora_agendamento.strftime('%Y-%m-%d'),
                     data_hora_agendamento.strftime('%H:%M'),
                     form_data.get('observacoes'), form_data.get('contato'), 'Pendente')
                )
                conn.commit()
                flash(
                    'Agendamento realizado com sucesso! Aguardando atribuição de um agente.', 'success')
                app.logger.info(
                    f"Novo agendamento criado por {current_user.email} para {data_hora_agendamento.strftime('%d/%m/%Y %H:%M')}.")
                return redirect(url_for('calendario'))
            except sqlite3.Error as db_error:
                flash(
                    f'Erro ao salvar agendamento no banco de dados: {db_error}', 'error')
                app.logger.error(
                    f'Erro de DB em /agendar (POST): {db_error}', exc_info=True)

        # Para request.method == 'GET'
        contexto_template['form_data'] = {}
        return render_template('agendar.html', **contexto_template)

    except Exception as e:
        flash(f'Ocorreu um erro interno inesperado: {str(e)}', 'error')
        app.logger.error(
            f'Erro inesperado em /agendar: {str(e)}', exc_info=True)
        return redirect(url_for('index'))
    finally:
        if conn:
            conn.close()


@app.route('/api/slots_disponiveis', methods=['GET'])
@login_required
def api_slots_disponiveis():
    # 1. Validar e converter parâmetros da requisição
    params, errors = _validar_e_parsear_parametros_api(request.args)
    if errors:
        return jsonify({"error": " ".join(errors)}), 400

    conn = get_db_connection()
    try:
        # 2. Buscar dados essenciais do DB
        tipo_id = params['tipo_id']
        empreendimento_id = params['empreendimento_id']
        data_obj = params['data_obj']

        tipo = conn.execute(
            'SELECT ativo, duracao_minutos FROM tipos_agendamento WHERE id = ?', (tipo_id,)).fetchone()
        if not tipo or not tipo['ativo']:
            return jsonify({"error": "Tipo de agendamento não encontrado ou inativo."}), 404

        regras = get_regras_reservas()

        # 3. Validar regras de antecedência (verificações que podem encerrar a requisição cedo)
        if regras['max_dias'] > 0 and data_obj > date.today() + timedelta(days=regras['max_dias']):
            msg = f"Não é possível agendar com mais de {regras['max_dias']} dia(s) de antecedência."
            return jsonify({"slots_disponiveis": [], "message": msg}), 200

        dia_semana = data_obj.weekday()
        horarios_op = conn.execute(
            'SELECT hora_inicio, hora_fim FROM horarios_funcionamento WHERE empreendimento_id = ? AND dia_semana = ? ORDER BY hora_inicio', (empreendimento_id, dia_semana)).fetchall()
        if not horarios_op:
            return jsonify({"slots_disponiveis": [], "message": "Empreendimento fechado neste dia."}), 200

        # 4. Preparar dados para verificação de conflitos
        agentes_para_tipo = conn.execute(
            'SELECT id FROM usuarios WHERE tipo_usuario = "agente" AND id IN (SELECT agente_id FROM agente_tipos_servico WHERE tipo_id = ?)', (tipo_id,)).fetchall()
        agentes_ids = [agente['id'] for agente in agentes_para_tipo]

        # Otimização: se não há agentes para o serviço, não há slots.
        if not agentes_ids:
            return jsonify({"slots_disponiveis": [], "message": "Nenhum agente disponível para este tipo de serviço."}), 200

        intervalos_ocupados = _get_intervalos_ocupados(
            conn, data_obj, params['unidade_id'], agentes_ids)

        # 5. Gerar e filtrar os slots
        slots_disponiveis = []
        duracao_agendamento = tipo['duracao_minutos']
        granularidade = 30  # Gerar slots a cada 30 minutos

        # Define o ponto de partida para a geração de slots, respeitando a antecedência mínima
        agora = datetime.now()
        horario_minimo_hoje = agora + timedelta(days=regras['min_dias'])

        for faixa in horarios_op:
            slot_atual = datetime.combine(data_obj, datetime.strptime(
                faixa['hora_inicio'], '%H:%M').time())
            fim_faixa = datetime.combine(
                data_obj, datetime.strptime(faixa['hora_fim'], '%H:%M').time())

            # Ajusta o início do slot se a data for hoje, para não mostrar horários passados
            if slot_atual < horario_minimo_hoje:
                slot_atual = horario_minimo_hoje
                # Arredonda para a próxima granularidade
                if slot_atual.minute % granularidade != 0:
                    slot_atual += timedelta(minutes=(granularidade -
                                            slot_atual.minute % granularidade))

            while slot_atual < fim_faixa:
                slot_fim = slot_atual + timedelta(minutes=duracao_agendamento)

                # O agendamento deve terminar dentro da faixa de horário
                if slot_fim > fim_faixa:
                    break

                if _is_slot_disponivel(slot_atual, slot_fim, intervalos_ocupados):
                    slots_disponiveis.append(slot_atual.strftime('%H:%M'))

                slot_atual += timedelta(minutes=granularidade)

        return jsonify({"slots_disponiveis": list(sorted(set(slots_disponiveis)))}), 200

    except Exception as e:
        app.logger.error(
            f"Erro inesperado em api_slots_disponiveis: {e}", exc_info=True)
        return jsonify({"error": f"Erro interno ao buscar slots: {e}"}), 500
    finally:
        if conn:
            conn.close()


@app.route('/painel_agente')
@agente_required  # Acesso apenas para agentes e administradores
def painel_agente():
    conn = get_db_connection()
    agendamentos_agente = []
    try:
        # Consulta base para todos os agendamentos "ativos"
        query = '''
            SELECT a.id, a.data, a.hora, a.observacoes, a.contato_agendamento, a.status,
                   ta.nome as tipo_nome, un.nome as unidade_nome, e.nome as empreendimento_nome,
                   u_cliente.nome as cliente_nome, u_cliente.email as cliente_email,
                   a.agente_atribuido_id, u_agente.nome as agente_atribuido_nome -- Inclui dados do agente atribuído
            FROM agendamentos a
            JOIN tipos_agendamento ta ON a.tipo_id = ta.id
            JOIN unidades un ON a.unidade_id = un.id
            JOIN empreendimentos e ON un.empreendimento_id = e.id
            JOIN usuarios u_cliente ON a.usuario_id = u_cliente.id
            LEFT JOIN usuarios u_agente ON a.agente_atribuido_id = u_agente.id -- LEFT JOIN para agentes
            WHERE a.status IN ('Pendente', 'Confirmado')
        '''
        params = []

        if current_user.is_agente and not current_user.is_admin_user:  # Agente não-admin
            # Agente vê agendamentos atribuídos a ele OU agendamentos NÃO ATRIBUÍDOS que ele pode atender
            query += """
                AND (
                    a.agente_atribuido_id = ?
                    OR
                    (a.agente_atribuido_id IS NULL AND a.tipo_id IN (
                        SELECT ats.tipo_id FROM agente_tipos_servico ats WHERE ats.agente_id = ?
                    ))
                )
            """
            params.append(current_user.id)
            params.append(current_user.id)  # Segundo ? para a subquery

        # Se for admin_user, não há filtro adicional aqui, ele vê todos os agendamentos pendentes/confirmados

        query += " ORDER BY a.data ASC, a.hora ASC"

        agendamentos_agente = conn.execute(query, params).fetchall()

    except sqlite3.Error as e:
        flash(f'Erro ao carregar agendamentos do agente: {str(e)}', 'error')
        app.logger.error(f'Erro DB em painel_agente: {str(e)}', exc_info=True)
    finally:
        conn.close()

    return render_template('agente_painel.html', agendamentos_agente=agendamentos_agente)

# --- NOVO: ROTA PARA ALTERAR O STATUS DO AGENDAMENTO ---


@app.route('/alterar_status_agendamento', methods=['POST'])
@agente_required  # Acesso apenas para agentes e administradores
def alterar_status_agendamento():
    agendamento_id = request.form.get('agendamento_id')
    novo_status = request.form.get('novo_status')

    if not agendamento_id or not novo_status:
        flash('Dados inválidos para alterar status.', 'error')
        return redirect(url_for('painel_agente'))

    valid_statuses = ['Pendente', 'Confirmado', 'Cancelado', 'Concluído']
    if novo_status not in valid_statuses:
        flash('Status inválido.', 'error')
        return redirect(url_for('painel_agente'))

    conn = get_db_connection()
    try:
        agendamento = conn.execute(
            "SELECT id, agente_atribuido_id, status FROM agendamentos WHERE id = ?", (agendamento_id,)).fetchone()

        if not agendamento:
            flash('Agendamento não encontrado.', 'error')
            return redirect(url_for('painel_agente'))

        # Regra de segurança: Agente só pode alterar agendamentos que lhe foram atribuídos
        # Administrador pode alterar qualquer um
        if not current_user.is_admin_user and agendamento['agente_atribuido_id'] != current_user.id:
            flash(
                'Você não tem permissão para alterar o status deste agendamento.', 'error')
            app.logger.warning(
                f"Tentativa de agente {current_user.email} alterar agendamento {agendamento_id} não atribuído a ele.")
            return redirect(url_for('painel_agente'))

        # Regras de transição de status (opcional, mas recomendado)
        # Ex: Não pode confirmar um agendamento já cancelado/concluído
        if agendamento['status'] == 'Cancelado' and novo_status == 'Confirmado':
            flash(
                'Não é possível confirmar um agendamento que já foi cancelado.', 'warning')
            return redirect(url_for('painel_agente'))
        if agendamento['status'] == 'Concluído' and novo_status in ['Pendente', 'Confirmado', 'Cancelado']:
            flash(
                'Não é possível alterar o status de um agendamento já concluído.', 'warning')
            return redirect(url_for('painel_agente'))

        conn.execute('UPDATE agendamentos SET status = ? WHERE id = ?',
                     (novo_status, agendamento_id))
        conn.commit()
        flash(
            f'Status do agendamento {agendamento_id} alterado para "{novo_status}" com sucesso!', 'success')
        app.logger.info(
            f"Agendamento ID {agendamento_id} status alterado para {novo_status} por {current_user.email}")
    except sqlite3.Error as e:
        flash(f'Erro no banco de dados ao alterar status: {str(e)}', 'error')
        app.logger.error(
            f'Erro DB em alterar_status_agendamento: {str(e)}', exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('painel_agente'))


# --- NOVO: ROTA PARA ATRIBUIR AGENDAMENTO A SI MESMO (AGENTE) ---
@app.route('/atribuir_agendamento_agente', methods=['POST'])
@agente_required  # Acesso apenas para agentes e administradores
def atribuir_agendamento_agente():
    agendamento_id = request.form.get('agendamento_id')

    if not agendamento_id:
        flash('ID do agendamento não fornecido.', 'error')
        return redirect(url_for('painel_agente'))

    conn = get_db_connection()
    try:
        agendamento = conn.execute(
            "SELECT id, agente_atribuido_id, tipo_id, status FROM agendamentos WHERE id = ?", (agendamento_id,)).fetchone()

        if not agendamento:
            flash('Agendamento não encontrado.', 'error')
            return redirect(url_for('painel_agente'))

        # Se já tem um agente atribuído E não é o agente logado, não pode assumir
        if agendamento['agente_atribuido_id'] is not None and agendamento['agente_atribuido_id'] != current_user.id:
            # Apenas admin pode reatribuir de outro agente
            if not current_user.is_admin_user:
                flash('Este agendamento já está atribuído a outro agente.', 'warning')
                return redirect(url_for('painel_agente'))

        # Verifica se o agente logado pode atender a este tipo de serviço (se não for admin)
        if not current_user.is_admin_user:
            agente_pode_atender = conn.execute('''
                SELECT 1 FROM agente_tipos_servico ats
                WHERE ats.agente_id = ? AND ats.tipo_id = ?
            ''', (current_user.id, agendamento['tipo_id'])).fetchone()

            if not agente_pode_atender:
                flash(
                    'Você não está configurado para atender este tipo de serviço.', 'error')
                return redirect(url_for('painel_agente'))

        # Se o agendamento já está confirmado e o agente não é admin, talvez não deva poder assumir
        # Depende da regra de negócio: Se um agendamento já está Confirmado mas sem agente, um agente pode assumir?
        # Por simplicidade, vamos permitir assumir Pendente ou Confirmado.

        # Atualiza o agendamento
        conn.execute('UPDATE agendamentos SET agente_atribuido_id = ?, status = ? WHERE id = ?',
                     # Define status como Confirmado ao assumir
                     (current_user.id, 'Confirmado', agendamento_id))
        conn.commit()

        flash(
            f'Agendamento {agendamento_id} atribuído a você e confirmado com sucesso!', 'success')
        app.logger.info(
            f"Agendamento ID {agendamento_id} atribuído e confirmado por Agente/Admin {current_user.email}")

    except sqlite3.Error as e:
        flash(
            f'Erro no banco de dados ao atribuir agendamento: {str(e)}', 'error')
        app.logger.error(
            f'Erro DB em atribuir_agendamento_agente: {str(e)}', exc_info=True)
    finally:
        conn.close()

    return redirect(url_for('painel_agente'))

# 🛠️ Rota de depuração do usuário


@app.route('/debug-user')
@login_required
def debug_user():
    return jsonify({
        'id': current_user.id,
        'nome': current_user.nome,
        'email': current_user.email,
        'is_authenticated': current_user.is_authenticated,
        'is_admin': current_user.is_admin,
        'tipo_usuario': current_user.tipo_usuario,
        'telefone': current_user.telefone
    })

# --- ROTAS DE ADMINISTRAÇÃO ---


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
    unidade_info_for_redirect = None
    try:
        unidade = conn.execute(
            'SELECT nome, empreendimento_id FROM unidades WHERE id = ?', (unidade_id,)).fetchone()
        if not unidade:
            flash('Unidade não encontrada.', 'error')
        else:
            unidade_info_for_redirect = unidade
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


@app.route('/configuracoes')
@admin_required
def configuracoes():
    conn = get_db_connection()
    tipos_data = []
    empreendimentos_data = []
    admin_users_data = []
    agente_users_data = []
    cliente_users_data = []
    non_admin_users_for_promotion = []

    # CORRIGIDO: Obter regras de reservas usando a nova função e os nomes corretos
    regras_atuais = get_regras_reservas()
    min_antecedencia_dias = regras_atuais['min_dias']
    max_antecedencia_dias = regras_atuais['max_dias']
    current_logo_path = get_global_setting(
        'logo_sistema_path', 'images/logo.png')

    super_admin_email = os.environ.get('SUPER_ADMIN_EMAIL', 'admin@admin.com')

    try:
        tipos_data = conn.execute(
            'SELECT id, nome, ativo, duracao_minutos FROM tipos_agendamento ORDER BY nome').fetchall()
        empreendimentos_data = conn.execute(
            'SELECT * FROM empreendimentos ORDER BY nome').fetchall()

        admin_users_data = conn.execute(
            "SELECT id, nome, email, telefone, tipo_usuario FROM usuarios WHERE tipo_usuario = 'admin' ORDER BY nome").fetchall()
        agente_users_data = conn.execute(
            "SELECT id, nome, email, telefone, tipo_usuario FROM usuarios WHERE tipo_usuario = 'agente' ORDER BY nome").fetchall()
        cliente_users_data = conn.execute(
            "SELECT id, nome, email, telefone, tipo_usuario FROM usuarios WHERE tipo_usuario = 'cliente' ORDER BY nome").fetchall()

        admin_user_ids = {user['id'] for user in admin_users_data}
        all_potential_promotees = agente_users_data + cliente_users_data
        for user in all_potential_promotees:
            if user['id'] not in admin_user_ids:
                non_admin_users_for_promotion.append(user)

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
                           agente_users=agente_users_data,
                           cliente_users=cliente_users_data,
                           super_admin_email=super_admin_email,
                           non_admin_users=non_admin_users_for_promotion,
                           # Passa os valores de DIAS para o template
                           min_antecedencia_dias=min_antecedencia_dias,
                           max_antecedencia_dias=max_antecedencia_dias
                           )


@app.route('/salvar_regras_reservas', methods=['POST'])
@admin_required
def salvar_regras_reservas():
    # Capture os valores do formulário com os nomes de campo do HTML
    min_dias_antecedencia_input = request.form.get(
        'antecedencia_minima_dias', '').strip()
    max_dias_antecedencia_input = request.form.get(
        'antecedencia_maxima_dias', '').strip()

    errors = []

    # --- Lógica para Antecedência Mínima (DIAS) ---
    try:
        # Se a string do input for vazia, use '1' como padrão antes de converter
        min_dias_antecedencia = int(
            min_dias_antecedencia_input) if min_dias_antecedencia_input else 1

        if min_dias_antecedencia < 0:
            errors.append(
                'A antecedência mínima não pode ser um número negativo.')
    except ValueError:
        errors.append(
            'Valor inválido para antecedência mínima. Deve ser um número inteiro.')
    except Exception as e:
        errors.append(
            f'Erro inesperado ao processar antecedência mínima: {str(e)}')
        app.logger.error(
            f"Erro inesperado em /salvar_regras_reservas (min_dias): {e}", exc_info=True)

    # --- Lógica para Antecedência Máxima (DIAS) ---
    try:
        # Se a string do input for vazia, use '365' como padrão antes de converter
        max_dias_antecedencia = int(
            max_dias_antecedencia_input) if max_dias_antecedencia_input else 300

        if max_dias_antecedencia < 0:
            errors.append(
                'A antecedência máxima não pode ser um número negativo.')
    except ValueError:
        errors.append(
            'Valor inválido para antecedência máxima. Deve ser um número inteiro.')
    except Exception as e:
        errors.append(
            f'Erro inesperado ao processar antecedência máxima: {str(e)}')
        app.logger.error(
            f"Erro inesperado em /salvar_regras_reservas (max_dias): {e}", exc_info=True)

    # Se não houver erros de validação, tente salvar no DB
    if not errors:
        if set_regras_reservas(min_dias_antecedencia, max_dias_antecedencia):
            flash('Regras de reservas atualizadas com sucesso!', 'success')
            app.logger.info(
                f"Admin {current_user.email} atualizou regras de reservas para min={min_dias_antecedencia} dias, max={max_dias_antecedencia} dias.")
        else:
            flash('Erro ao salvar as regras de reservas no banco de dados.', 'error')
            app.logger.error(
                f"Falha ao chamar set_regras_reservas para {current_user.email}.")
    else:  # Se há erros, flashea as mensagens de erro
        flash('Ocorreram erros ao atualizar as regras de reservas. Por favor, verifique os campos.', 'error')
        for error_msg in errors:
            flash(error_msg, 'error')

    return redirect(url_for('configuracoes', tab='regras'))


@app.route('/adicionar_agente', methods=['POST'])
@admin_required  # Apenas administradores podem adicionar novos agentes
def adicionar_agente():
    nome = request.form.get('nome', '').strip()
    email = request.form.get('email', '').strip()
    senha = request.form.get('senha', '')
    confirmar_senha = request.form.get('confirmar_senha', '')
    telefone = request.form.get('telefone', '').strip()

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

    # Valida se o email já está cadastrado (independente do tipo de usuário)
    if not errors and buscar_usuario_por_email(email):
        errors.append('Este email já está cadastrado.')

    if errors:
        for error_msg in errors:
            flash(error_msg, 'error')
        # Retorna para a página de configurações, na aba de usuários
        return redirect(url_for('configuracoes', tab='usuarios'))

    conn = None  # Inicializa conn como None para o finally
    try:
        senha_hash = generate_password_hash(senha)
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO usuarios (nome, email, senha, is_admin, tipo_usuario, telefone) VALUES (?, ?, ?, ?, ?, ?)',
            # is_admin=0 e tipo_usuario='agente'
            (nome, email, senha_hash, 0, 'agente', telefone)
        )
        conn.commit()
        flash(f'Agente "{nome}" cadastrado com sucesso!', 'success')
        app.logger.info(
            f"Novo agente cadastrado: {email} por {current_user.email}.")
    except sqlite3.IntegrityError:
        flash('Erro: Este email já está cadastrado. Por favor, use outro.', 'error')
        app.logger.warning(
            f"Tentativa de cadastro de agente com email duplicado: {email}")
    except sqlite3.Error as e:
        flash(
            f'Erro ao cadastrar agente no banco de dados: {str(e)}', 'error')
        app.logger.error(f'Erro DB no cadastro de agente: {e}', exc_info=True)
    except Exception as e:
        flash(
            'Ocorreu um erro inesperado durante o cadastro do agente. Por favor, tente mais tarde.', 'error')
        app.logger.error(
            f'Erro inesperado no cadastro de agente: {e}', exc_info=True)
    finally:
        if conn:
            conn.close()

    # Redireciona de volta para a aba de usuários
    return redirect(url_for('configuracoes', tab='usuarios'))


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

# --- ROTAS PARA VINCULAÇÃO DE SERVIÇOS DO AGENTE ---


@app.route('/api/agente/<int:agente_id>/servicos')
@admin_required
def api_agente_servicos(agente_id):
    conn = get_db_connection()

    agente = conn.execute(
        "SELECT id, tipo_usuario FROM usuarios WHERE id = ?", (agente_id,)).fetchone()
    if not agente or (agente['tipo_usuario'] != 'agente' and agente['tipo_usuario'] != 'admin'):
        conn.close()
        return jsonify({"error": "Agente não encontrado ou sem permissão."}), 404

    servicos_vinculados = conn.execute('''
        SELECT ta.nome FROM agente_tipos_servico ats
        JOIN tipos_agendamento ta ON ats.tipo_id = ta.id
        WHERE ats.agente_id = ? AND ta.ativo = 1
        ORDER BY ta.nome
    ''', (agente_id,)).fetchall()
    conn.close()

    return jsonify({"tipos_vinculados": [s['nome'] for s in servicos_vinculados]})


@app.route('/api/agente/<int:agente_id>/servicos_ids')
@admin_required
def api_agente_servicos_ids(agente_id):
    conn = get_db_connection()

    agente = conn.execute(
        "SELECT id, tipo_usuario FROM usuarios WHERE id = ?", (agente_id,)).fetchone()
    if not agente or (agente['tipo_usuario'] != 'agente' and agente['tipo_usuario'] != 'admin'):
        conn.close()
        return jsonify({"error": "Agente não encontrado ou sem permissão."}), 404

    servicos_vinculados_ids = conn.execute('''
        SELECT ats.tipo_id FROM agente_tipos_servico ats
        JOIN tipos_agendamento ta ON ats.tipo_id = ta.id
        WHERE ats.agente_id = ? AND ta.ativo = 1
    ''', (agente_id,)).fetchall()
    conn.close()

    return jsonify({"vinculados_ids": [s['tipo_id'] for s in servicos_vinculados_ids]})


@app.route('/vincular_servicos_agente', methods=['POST'])
@admin_required
def vincular_servicos_agente():
    agente_id = request.form.get('agente_id')
    tipos_servico_ids = request.form.getlist('tipos_servico[]')

    if not agente_id:
        flash('ID do agente não fornecido.', 'error')
        return redirect(url_for('configuracoes', tab='usuarios'))

    conn = get_db_connection()
    try:
        agente = conn.execute(
            "SELECT id, nome, tipo_usuario FROM usuarios WHERE id = ?", (agente_id,)).fetchone()
        if not agente or (agente['tipo_usuario'] != 'agente' and agente['tipo_usuario'] != 'admin'):
            flash('Agente não encontrado ou sem permissão para vinculação.', 'error')
            return redirect(url_for('configuracoes', tab='usuarios'))

        conn.execute(
            'DELETE FROM agente_tipos_servico WHERE agente_id = ?', (agente_id,))

        for tipo_id_str in tipos_servico_ids:
            try:
                tipo_id = int(tipo_id_str)
                conn.execute(
                    'INSERT INTO agente_tipos_servico (agente_id, tipo_id) VALUES (?, ?)',
                    (agente_id, tipo_id)
                )
            except ValueError:
                app.logger.warning(
                    f"Tipo de serviço ID inválido recebido: {tipo_id_str}")
            except sqlite3.IntegrityError:
                app.logger.warning(
                    f"Tentativa de duplicar vinculação para agente {agente_id} e tipo {tipo_id_str}")

        conn.commit()
        flash(
            f'Tipos de serviço vinculados ao agente "{agente["nome"]}" com sucesso!', 'success')
        app.logger.info(
            f"Serviços vinculados para agente ID {agente_id} por {current_user.email}")

    except sqlite3.Error as e:
        flash(
            f'Erro no banco de dados ao vincular serviços: {str(e)}', 'error')
        app.logger.error(
            f'Erro DB em vincular_servicos_agente: {str(e)}', exc_info=True)
        conn.rollback()
    finally:
        conn.close()

    return redirect(url_for('configuracoes', tab='usuarios'))


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
    duracao_str = request.form.get('duracao')  # NOVO: Capturar a duração

    errors = []
    if not novo_tipo:
        errors.append('Nome do tipo de agendamento é obrigatório.')
    if not duracao_str:
        errors.append('A duração do tipo de agendamento é obrigatória.')
    else:
        try:
            duracao = int(duracao_str)
            if duracao <= 0:
                errors.append('A duração deve ser um número positivo.')
        except ValueError:
            errors.append('Duração inválida. Deve ser um número inteiro.')

    if errors:
        for error_msg in errors:
            flash(error_msg, 'error')
        # Redireciona e mostra os erros
        return redirect(url_for('configuracoes', tab='tipos'))

    conn = get_db_connection()
    try:
        # ATUALIZADO: Incluir duracao_minutos no INSERT
        conn.execute(
            'INSERT INTO tipos_agendamento (nome, duracao_minutos) VALUES (?, ?)', (novo_tipo, duracao))
        conn.commit()
        flash('Tipo de agendamento adicionado com sucesso!', 'success')
        app.logger.info(
            f"Tipo '{novo_tipo}' adicionado com duração {duracao}min por {current_user.email}")
    except sqlite3.IntegrityError:
        flash('Este tipo de agendamento já existe!', 'error')
    except sqlite3.Error as e:
        flash('Erro ao adicionar tipo de agendamento.', 'error')
        app.logger.error(f"Erro DB ao adicionar tipo: {e}", exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='tipos'))

# NOVO: Rota para editar a duração de um tipo de agendamento


@app.route('/editar_duracao_tipo', methods=['POST'])
@admin_required
def editar_duracao_tipo():
    tipo_id = request.form.get('tipo_id')
    duracao_str = request.form.get('duracao')

    if not tipo_id or not duracao_str:
        flash('Dados inválidos para edição da duração do tipo.', 'error')
        return redirect(url_for('configuracoes', tab='tipos'))

    try:
        tipo_id = int(tipo_id)
        duracao = int(duracao_str)
        if duracao <= 0:
            flash('A duração deve ser um número positivo.', 'error')
            return redirect(url_for('configuracoes', tab='tipos'))
    except ValueError:
        flash('Duração inválida. Deve ser um número inteiro.', 'error')
        return redirect(url_for('configuracoes', tab='tipos'))

    conn = get_db_connection()
    try:
        tipo_existente = conn.execute(
            "SELECT nome FROM tipos_agendamento WHERE id = ?", (tipo_id,)).fetchone()
        if not tipo_existente:
            flash('Tipo de agendamento não encontrado.', 'error')
            return redirect(url_for('configuracoes', tab='tipos'))

        conn.execute(
            'UPDATE tipos_agendamento SET duracao_minutos = ? WHERE id = ?', (duracao, tipo_id))
        conn.commit()
        flash(
            f"Duração do tipo '{tipo_existente['nome']}' atualizada para {duracao} minutos!", 'success')
        app.logger.info(
            f"Duração tipo ID {tipo_id} atualizada para {duracao}min por {current_user.email}")
    except sqlite3.Error as e:
        flash(f'Erro no banco de dados ao editar duração: {str(e)}', 'error')
        app.logger.error(f"Erro DB em editar_duracao_tipo: {e}", exc_info=True)
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
            agente_vinculado_count = conn.execute(
                "SELECT COUNT(agente_id) FROM agente_tipos_servico WHERE tipo_id = ?", (tipo_id,)).fetchone()[0]
            if agente_vinculado_count > 0:
                flash(
                    f"Erro: O tipo '{tipo['nome']}' não pode ser removido pois está vinculado a {agente_vinculado_count} agente(s).", 'error')
                return redirect(url_for('configuracoes', tab='tipos'))

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
            "SELECT id, nome, is_admin, tipo_usuario, email FROM usuarios WHERE id = ?", (user_id_to_promote,)).fetchone()
        if not user:
            flash('Usuário não encontrado.', 'error')
        elif user['tipo_usuario'] == 'admin':
            flash(
                f"O usuário '{user['nome'] if user['nome'] else 'ID '+str(user['id'])}' já é um administrador.", 'warning')
        else:
            conn.execute(
                "UPDATE usuarios SET is_admin = 1, tipo_usuario = 'admin' WHERE id = ?", (user_id_to_promote,))
            conn.commit()
            flash(
                f"Usuário '{user['nome'] if user['nome'] else 'ID '+str(user['id'])}' promovido a administrador com sucesso!", 'success')
            app.logger.info(
                f"Usuário ID {user_id_to_promote} promovido a admin por {current_user.email}.")

            # CORREÇÃO: Forçar o recarregamento da sessão se o próprio usuário logado for promovido
            if str(user['id']) == str(current_user.id):
                app.logger.info(
                    f"Forçando recarregamento da sessão para {current_user.email} após promoção a admin.")
                logout_user()  # Limpa a sessão antiga
                updated_user = buscar_usuario_por_email(
                    user['email'])  # Busca do DB com as novas infos
                if updated_user:
                    # Recarrega a nova sessão com dados atualizados
                    login_user(updated_user, remember=True)

    except sqlite3.Error as e:
        flash(f'Erro no banco de dados ao promover usuário: {e}', 'error')
        app.logger.error(f"Erro DB em promover_admin: {e}", exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='seguranca'))


@app.route('/gerenciar_agente', methods=['POST'])
@admin_required
def gerenciar_agente():
    user_id = request.form.get('user_id')
    action = request.form.get('action')

    if not user_id or not action:
        flash('Requisição inválida.', 'error')
        return redirect(url_for('configuracoes', tab='usuarios'))

    conn = get_db_connection()
    try:
        user = conn.execute(
            "SELECT id, nome, email, tipo_usuario, is_admin FROM usuarios WHERE id = ?", (user_id,)).fetchone()

        if not user:
            flash('Usuário não encontrado.', 'error')
            return redirect(url_for('configuracoes', tab='usuarios'))

        if user['tipo_usuario'] == 'admin':
            flash(
                f"O usuário '{user['nome']}' é um administrador e não pode ser gerenciado como agente por aqui.", 'warning')
            return redirect(url_for('configuracoes', tab='usuarios'))

        if action == 'promover':
            if user['tipo_usuario'] == 'agente':
                flash(f"O usuário '{user['nome']}' já é um agente.", 'warning')
            else:
                conn.execute(
                    "UPDATE usuarios SET tipo_usuario = 'agente' WHERE id = ?", (user_id,))
                conn.commit()
                flash(
                    f"Usuário '{user['nome']}' promovido a Agente com sucesso!", 'success')
                app.logger.info(
                    f"Usuário ID {user_id} promovido a agente por {current_user.email}.")

                # CORREÇÃO: Forçar o recarregamento da sessão se o próprio usuário logado for promovido
                if str(user['id']) == str(current_user.id):
                    app.logger.info(
                        f"Forçando recarregamento da sessão para {current_user.email} após promoção a agente.")
                    logout_user()  # Limpa a sessão antiga
                    updated_user = buscar_usuario_por_email(user['email'])
                    if updated_user:
                        # Recarrega a nova sessão com dados atualizados
                        login_user(updated_user, remember=True)

        elif action == 'demover':
            if user['tipo_usuario'] == 'cliente':
                flash(
                    f"O usuário '{user['nome']}' já é um cliente (não é agente).", 'warning')
            else:
                conn.execute(
                    'DELETE FROM agente_tipos_servico WHERE agente_id = ?', (user_id,))
                conn.execute(
                    "UPDATE usuarios SET tipo_usuario = 'cliente' WHERE id = ?", (user_id,))
                conn.commit()
                flash(
                    f"Status de Agente removido do usuário '{user['nome']}' com sucesso! Vinculações de serviço removidas.", 'success')
                app.logger.info(
                    f"Status agente removido do usuário ID {user_id} por {current_user.email}. Vinculações de serviço também removidas.")

                # CORREÇÃO: Forçar o recarregamento da sessão se o próprio usuário logado for demoovido
                if str(user['id']) == str(current_user.id):
                    app.logger.info(
                        f"Forçando recarregamento da sessão para {current_user.email} após despromoção a cliente.")
                    logout_user()  # Limpa a sessão antiga
                    updated_user = buscar_usuario_por_email(user['email'])
                    if updated_user:
                        # Recarrega a nova sessão com dados atualizados
                        login_user(updated_user, remember=True)
        else:
            flash('Ação inválida.', 'error')

    except sqlite3.Error as e:
        flash(f'Erro no banco de dados ao gerenciar agente: {e}', 'error')
        app.logger.error(f"Erro DB em gerenciar_agente: {e}", exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='usuarios'))


@app.route('/remover_admin/<int:user_id>', methods=['POST'])
@admin_required
def remover_admin(user_id):
    if user_id == current_user.id:
        flash('Você não pode remover seu próprio status de administrador.', 'error')
        return redirect(url_for('configuracoes', tab='seguranca'))

    conn = get_db_connection()
    try:
        target_user = conn.execute(
            "SELECT id, nome, email, is_admin, tipo_usuario FROM usuarios WHERE id = ?", (user_id,)).fetchone()
        if not target_user:
            flash('Usuário não encontrado.', 'error')
            return redirect(url_for('configuracoes', tab='seguranca'))

        if target_user['email'] == os.environ.get('SUPER_ADMIN_EMAIL', 'admin@admin.com'):
            flash('O administrador principal não pode ter seu status de admin removido por esta interface.', 'error')
            return redirect(url_for('configuracoes', tab='seguranca'))

        if target_user['tipo_usuario'] != 'admin':
            flash(
                f"O usuário '{target_user['nome'] if target_user['nome'] else target_user['email']}' não é um administrador.", 'warning')
        else:
            admin_count_row = conn.execute(
                "SELECT COUNT(id) as count FROM usuarios WHERE tipo_usuario = 'admin'").fetchone()
            if admin_count_row and admin_count_row['count'] <= 1:
                flash(
                    'Não é possível remover o status do último administrador do sistema.', 'error')
            else:
                conn.execute(
                    "UPDATE usuarios SET is_admin = 0, tipo_usuario = 'cliente' WHERE id = ?", (user_id,))
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
        if conn:
            conn.close()
    return redirect(url_for('configuracoes', tab='seguranca'))

# --- ROTAS PARA HORÁRIOS DE FUNCIONAMENTO ---


@app.route('/adicionar_horario_funcionamento', methods=['POST'])
@admin_required
def adicionar_horario_funcionamento():
    empreendimento_id = request.form.get('empreendimento_id')
    dia_semana = request.form.get('dia_semana')
    hora_inicio = request.form.get('hora_inicio')
    hora_fim = request.form.get('hora_fim')

    if not all([empreendimento_id, dia_semana, hora_inicio, hora_fim]):
        flash('Todos os campos de horário são obrigatórios.', 'error')
        return redirect(url_for('configuracoes', tab='horarios'))

    try:
        datetime.strptime(hora_inicio, '%H:%M')
        datetime.strptime(hora_fim, '%H:%M')
        if hora_inicio >= hora_fim:
            flash('Hora de início deve ser anterior à hora de fim.', 'error')
            return redirect(url_for('configuracoes', tab='horarios'))
    except ValueError:
        flash('Formato de hora inválido. Use HH:MM.', 'error')
        return redirect(url_for('configuracoes', tab='horarios'))

    conn = get_db_connection()
    try:
        emp = conn.execute(
            "SELECT id, nome, ativo FROM empreendimentos WHERE id = ?", (empreendimento_id,)).fetchone()
        if not emp or not emp['ativo']:
            flash('Empreendimento selecionado não encontrado ou inativo.', 'error')
            return redirect(url_for('configuracoes', tab='horarios'))

        conn.execute(
            'INSERT INTO horarios_funcionamento (empreendimento_id, dia_semana, hora_inicio, hora_fim) VALUES (?, ?, ?, ?)',
            (empreendimento_id, dia_semana, hora_inicio, hora_fim)
        )
        conn.commit()
        flash(
            f'Horário de funcionamento adicionado com sucesso para {emp["nome"]}!', 'success')
        app.logger.info(
            f"Horário ({dia_semana}, {hora_inicio}-{hora_fim}) adicionado para emp ID {empreendimento_id} por {current_user.email}")
    except sqlite3.IntegrityError:
        flash('Este horário já está cadastrado para este empreendimento e dia.', 'error')
    except sqlite3.Error as e:
        flash(
            f'Erro no banco de dados ao adicionar horário: {str(e)}', 'error')
        app.logger.error(
            f'Erro DB em adicionar_horario_funcionamento: {str(e)}', exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='horarios'))


@app.route('/api/empreendimento/<int:empreendimento_id>/horarios')
@admin_required
def api_empreendimento_horarios(empreendimento_id):
    conn = get_db_connection()

    emp = conn.execute(
        "SELECT id, nome FROM empreendimentos WHERE id = ?", (empreendimento_id,)).fetchone()
    if not emp:
        conn.close()
        return jsonify({"error": "Empreendimento não encontrado."}), 404

    horarios_db = conn.execute('''
        SELECT hf.id, hf.dia_semana, hf.hora_inicio, hf.hora_fim, e.nome as empreendimento_nome
        FROM horarios_funcionamento hf
        JOIN empreendimentos e ON hf.empreendimento_id = e.id
        WHERE hf.empreendimento_id = ?
        ORDER BY hf.dia_semana, hf.hora_inicio
    ''', (empreendimento_id,)).fetchall()
    conn.close()

    horarios_list = []
    for h in horarios_db:
        horarios_list.append({
            "id": h['id'],
            "empreendimento_nome": h['empreendimento_nome'],
            "dia_semana": h['dia_semana'],
            "hora_inicio": h['hora_inicio'],
            "hora_fim": h['hora_fim']
        })
    return jsonify(horarios_list)


@app.route('/remover_horario_funcionamento/<int:horario_id>', methods=['POST'])
@admin_required
def remover_horario_funcionamento(horario_id):
    conn = get_db_connection()
    try:
        horario = conn.execute(
            "SELECT empreendimento_id FROM horarios_funcionamento WHERE id = ?", (horario_id,)).fetchone()
        if not horario:
            flash("Horário de funcionamento não encontrado.", "error")
            return redirect(url_for('configuracoes', tab='horarios'))

        # TO-DO: Futuramente, verificar se há agendamentos que dependam deste horário antes de remover
        # (ex: se o agendamento já foi criado e está dentro deste slot de horário)

        conn.execute(
            'DELETE FROM horarios_funcionamento WHERE id = ?', (horario_id,))
        conn.commit()
        flash('Horário de funcionamento removido com sucesso!', 'success')
        app.logger.info(
            f"Horário de funcionamento ID {horario_id} removido por {current_user.email}")
    except sqlite3.Error as e:
        flash(f'Erro no banco de dados ao remover horário: {str(e)}', 'error')
        app.logger.error(
            f'Erro DB em remover_horario_funcionamento: {str(e)}', exc_info=True)
    finally:
        conn.close()
    return redirect(url_for('configuracoes', tab='horarios'))


@app.route('/clientes')
@agente_required  # Acesso apenas para agentes e administradores
def gerenciar_clientes():
    """Renderiza a página de gerenciamento de clientes."""
    # A lista inicial de clientes será carregada via AJAX pelo JavaScript
    # ao carregar a página, então não precisamos buscar aqui.
    return render_template('clientes.html')


@app.route('/api/clientes_busca', methods=['GET'])
@agente_required  # Acesso apenas para agentes e administradores
def api_clientes_busca():
    """
    API para buscar clientes por nome, email ou telefone.
    Usada para a funcionalidade de pesquisa em tempo real.
    """
    search_term = request.args.get('q', '').strip()
    conn = get_db_connection()
    clientes = []
    try:
        query_base = """
            SELECT id, nome, email, telefone
            FROM usuarios
            WHERE tipo_usuario = 'cliente'
        """
        params = []

        if search_term:
            # Proteção contra SQL Injection: Usar placeholders para a query
            # e adicionar '%' diretamente no valor do parâmetro.
            search_pattern = f"%{search_term}%"
            query_base += """
                AND (
                    LOWER(nome) LIKE LOWER(?) OR
                    LOWER(email) LIKE LOWER(?) OR
                    LOWER(telefone) LIKE LOWER(?)
                )
            """
            params.extend([search_pattern, search_pattern, search_pattern])

        query_base += " ORDER BY nome ASC"

        clientes_db = conn.execute(query_base, params).fetchall()

        # Converter Rows para dicionários para jsonify
        clientes = [dict(c) for c in clientes_db]

    except sqlite3.Error as e:
        app.logger.error(
            f"Erro DB ao buscar clientes na API: {e}", exc_info=True)
        return jsonify({"error": "Erro ao buscar clientes no banco de dados."}), 500
    finally:
        conn.close()

    return jsonify({"clientes": clientes}), 200

# 📅 Calendário


@app.route('/calendario')
@login_required
def calendario():
    if current_user.is_cliente:
        flash('Você está vendo apenas seus agendamentos. Agentes e Administradores podem ver todos.', 'info')
    return render_template('calendario.html')

# 🗓️ Eventos para o calendário
# app.py

# ... (seus imports e código até a rota /detalhes_agendamento) ...

# --- NOVA ROTA: Detalhes do Agendamento (tela dedicada) ---


@app.route('/agendamento/<int:agendamento_id>')
@login_required
def detalhes_agendamento(agendamento_id):
    conn = get_db_connection()
    agendamento = None
    try:
        # Consulta para buscar todos os detalhes necessários
        query = '''
            SELECT a.id, a.data, a.hora, a.observacoes, a.contato_agendamento, a.status,
                   u_cliente.id as cliente_id, u_cliente.nome as cliente_nome, u_cliente.email as cliente_email, u_cliente.telefone as cliente_telefone,
                   ta.nome as tipo_nome, ta.duracao_minutos,
                   un.nome as unidade_nome,
                   e.nome as empreendimento_nome,
                   u_agente.id as agente_id, u_agente.nome as agente_nome, u_agente.email as agente_email
            FROM agendamentos a
            JOIN usuarios u_cliente ON a.usuario_id = u_cliente.id
            JOIN tipos_agendamento ta ON a.tipo_id = ta.id
            JOIN unidades un ON a.unidade_id = un.id
            JOIN empreendimentos e ON un.empreendimento_id = e.id
            LEFT JOIN usuarios u_agente ON a.agente_atribuido_id = u_agente.id
            WHERE a.id = ?
        '''
        agendamento = conn.execute(query, (agendamento_id,)).fetchone()

        if not agendamento:
            flash('Agendamento não encontrado.', 'error')
            return redirect(url_for('calendario'))

        # Lógica de Permissão para ver o agendamento: Cliente (dono), Agente (atribuído), Admin
        # Esta lógica está correta e será mantida.
        if not current_user.is_admin_user:
            is_owner = current_user.id == agendamento['cliente_id']
            is_assigned_agent = current_user.id == agendamento['agente_id']

            if not (is_owner or is_assigned_agent):
                flash(
                    'Você não tem permissão para ver os detalhes deste agendamento.', 'error')
                app.logger.warning(
                    f"Acesso negado: Usuário {current_user.email} (ID: {current_user.id}) tentou acessar agendamento {agendamento_id} sem permissão.")
                return redirect(url_for('calendario'))

    except sqlite3.Error as e:
        flash(f'Erro ao carregar detalhes do agendamento: {str(e)}', 'error')
        app.logger.error(
            f'Erro DB em detalhes_agendamento: {str(e)}', exc_info=True)
        return redirect(url_for('calendario'))
    finally:
        if conn:
            conn.close()

    # Formata a data para exibição
    data_formatada = datetime.strptime(
        agendamento['data'], '%Y-%m-%d').strftime('%A, %d de %B de %Y')
    dias_semana = {
        'Monday': 'Segunda-feira', 'Tuesday': 'Terça-feira', 'Wednesday': 'Quarta-feira',
        'Thursday': 'Quinta-feira', 'Friday': 'Sexta-feira', 'Saturday': 'Sábado', 'Sunday': 'Domingo'
    }
    meses = {
        'January': 'Janeiro', 'February': 'Fevereiro', 'March': 'Março',
        'April': 'Abril', 'May': 'Maio', 'June': 'Junho', 'July': 'Julho',
        'August': 'Agosto', 'September': 'Setembro', 'October': 'Outubro',
        'November': 'Novembro', 'December': 'Dezembro'
    }

    for en, pt in dias_semana.items():
        data_formatada = data_formatada.replace(en, pt)
    for en, pt in meses.items():
        data_formatada = data_formatada.replace(en, pt)

    return render_template('detalhes_agendamento.html',
                           agendamento=agendamento,
                           data_formatada=data_formatada,
                           is_admin=current_user.is_admin_user,
                           is_agente=current_user.is_agente,
                           is_cliente=current_user.is_cliente  # NOVO: Passa o status de cliente
                           )

# --- NOVO: ROTA PARA CANCELAR AGENDAMENTO PELO CLIENTE ---


@app.route('/cancelar_agendamento', methods=['POST'])
@login_required
def cancelar_agendamento():
    agendamento_id = request.form.get('agendamento_id')

    if not agendamento_id:
        flash('ID do agendamento não fornecido para cancelamento.', 'error')
        return redirect(url_for('calendario'))

    conn = get_db_connection()
    try:
        # Busca o agendamento e o ID do cliente que o criou
        agendamento_db = conn.execute(
            "SELECT id, usuario_id, status FROM agendamentos WHERE id = ?", (agendamento_id,)).fetchone()

        if not agendamento_db:
            flash('Agendamento não encontrado.', 'error')
            return redirect(url_for('calendario'))

        # Regra de segurança: APENAS o proprietário do agendamento ou um ADMIN pode cancelar via esta rota.
        # Agentes só podem cancelar pelo painel deles, onde a lógica de status é diferente.
        if agendamento_db['usuario_id'] != current_user.id and not current_user.is_admin_user:
            flash('Você não tem permissão para cancelar este agendamento.', 'error')
            app.logger.warning(
                f"Tentativa de cancelamento não autorizado: Usuário {current_user.email} (ID: {current_user.id}) tentou cancelar agendamento {agendamento_id} de outro usuário.")
            return redirect(url_for('calendario'))

        # Regra de Negócio: Só pode cancelar se o status for Pendente ou Confirmado
        if agendamento_db['status'] not in ['Pendente', 'Confirmado']:
            flash(
                f"Não é possível cancelar um agendamento com status '{agendamento_db['status']}'.", 'warning')
            return redirect(url_for('detalhes_agendamento', agendamento_id=agendamento_id))

        # Atualiza o status para 'Cancelado'
        conn.execute('UPDATE agendamentos SET status = ? WHERE id = ?',
                     ('Cancelado', agendamento_id))
        conn.commit()

        flash(
            f'Agendamento {agendamento_id} cancelado com sucesso.', 'success')
        app.logger.info(
            f"Agendamento ID {agendamento_id} cancelado por {current_user.email} (Cliente ID: {current_user.id}).")

    except sqlite3.Error as e:
        flash(
            f'Erro no banco de dados ao cancelar agendamento: {str(e)}', 'error')
        app.logger.error(
            f'Erro DB em cancelar_agendamento: {str(e)}', exc_info=True)
    finally:
        if conn:
            conn.close()

    # Redireciona de volta para a página de detalhes, ou para o calendário
    # Redirecionar para ver o status atualizado
    return redirect(url_for('detalhes_agendamento', agendamento_id=agendamento_id))


@app.route('/eventos')
@login_required
def eventos():
    conn = get_db_connection()
    query = '''
        SELECT a.id, u.nome as usuario_nome, u.email as usuario_email, a.data, a.hora, a.observacoes, 
                t.nome AS tipo_nome, un.nome as unidade_nome, e.nome as empreendimento_nome,
                a.status, a.contato_agendamento, 
                a.agente_atribuido_id, u_agente.nome as agente_atribuido_nome -- NOVO: Incluir nome do agente atribuído
        FROM agendamentos a
        JOIN usuarios u ON a.usuario_id = u.id
        JOIN tipos_agendamento t ON a.tipo_id = t.id
        JOIN unidades un ON a.unidade_id = un.id
        JOIN empreendimentos e ON un.empreendimento_id = e.id
        LEFT JOIN usuarios u_agente ON a.agente_atribuido_id = u_agente.id -- NOVO: LEFT JOIN para obter nome do agente
        WHERE t.ativo = 1 AND un.ativo = 1 AND e.ativo = 1
    '''
    params = []

    if current_user.is_cliente:
        query += " AND a.usuario_id = ?"
        params.append(current_user.id)
    # NOVO: Agentes também veem apenas seus agendamentos atribuídos (se não forem admin)
    elif current_user.is_agente and not current_user.is_admin_user:
        query += " AND a.agente_atribuido_id = ?"
        params.append(current_user.id)

    query += " ORDER BY a.data, a.hora"

    eventos_db = conn.execute(query, params).fetchall()
    conn.close()

    eventos_lista = []
    for row in eventos_db:
        try:
            start_datetime_str = f"{row['data']}T{row['hora']}"
            datetime.strptime(start_datetime_str,
                              '%Y-%m-%dT%H:%M')  # Valida formato
            evento = {
                "id": row["id"],
                "title": f"{row['tipo_nome']} - {row['unidade_nome']} ({row['empreendimento_nome']})",
                "start": start_datetime_str,
                "extendedProps": {
                    "usuario_nome": row['usuario_nome'],
                    "usuario_email": row['usuario_email'],
                    "tipo": row['tipo_nome'],
                    "unidade": row['unidade_nome'],
                    "empreendimento": row['empreendimento_nome'],
                    # Padronizar para N/A se vazio
                    "observacoes": row['observacoes'] or "N/A",
                    # Padronizar
                    "contato": row['contato_agendamento'] or "Não informado",
                    "status": row['status'],
                    # NOVO: Nome do agente
                    "agente_atribuido_nome": row['agente_atribuido_nome'] or "Não atribuído",

                    # --- NOVOS CAMPOS PARA O TOOLTIP ---
                    "cliente": row['usuario_nome'],  # Nome do cliente
                    "empreendimento": row['empreendimento_nome'],
                    "unidade": row['unidade_nome'],
                    "contato": row['contato_agendamento'] or "Não informado",
                    "hora_agendamento": row['hora'],  # A hora do agendamento
                }
            }
            eventos_lista.append(evento)
        except ValueError:
            app.logger.error(
                f"Formato de data/hora inválido para agendamento ID {row['id']}: data='{row['data']}', hora='{row['hora']}'")
        except Exception as e:
            app.logger.error(
                f"Erro ao processar evento ID {row['id']}: {e}", exc_info=True)

    return jsonify(eventos_lista)


# 🧱 Banco de dados

# app.py

# ... (seus imports no início do arquivo) ...

# 🛠️ Banco de dados

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    app.logger.info(
        "Iniciando verificação/criação das tabelas do banco de dados...")

    # 1. Tabelas Independentes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0 CHECK(is_admin IN (0, 1)),
            tipo_usuario TEXT DEFAULT 'cliente' NOT NULL,
            telefone TEXT,
            foto_perfil TEXT
        )
    ''')
    app.logger.info("Tabela 'usuarios' verificada/criada.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS empreendimentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1))
        )
    ''')
    app.logger.info("Tabela 'empreendimentos' verificada/creada.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tipos_agendamento (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT UNIQUE NOT NULL,
            ativo INTEGER DEFAULT 1 CHECK(ativo IN (0, 1)),
            duracao_minutos INTEGER DEFAULT 60 NOT NULL
        )
    ''')
    app.logger.info("Tabela 'tipos_agendamento' verificada/criada.")

    # NOVO/CORRIGIDO: Tabela 'regras_reservas' (garante que existe)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configuracoes_globais (
            chave TEXT PRIMARY KEY,
            valor TEXT
        )
    ''')
    app.logger.info("Tabela 'configuracoes_globais' verificada/criada.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS regras_reservas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            antecedencia_minima_dias INTEGER NOT NULL DEFAULT 1,
            antecedencia_maxima_dias INTEGER NOT NULL DEFAULT 365
        )
    ''')
    app.logger.info("Tabela 'regras_reservas' verificada/criada.")

    # Insere uma linha padrão se a tabela estiver vazia
    cursor.execute(
        "INSERT OR IGNORE INTO regras_reservas (id, antecedencia_minima_dias, antecedencia_maxima_dias) VALUES (1, 1, 365)")
    app.logger.info(
        "Linha padrão na tabela 'regras_reservas' verificada/criada.")

    # 2. Tabelas que dependem das tabelas acima
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
    app.logger.info("Tabela 'unidades' verificada/criada.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS horarios_funcionamento (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            empreendimento_id INTEGER NOT NULL,
            dia_semana INTEGER NOT NULL, -- 0=Segunda, 1=Terça, ..., 6=Domingo
            hora_inicio TEXT NOT NULL,  -- Formato "HH:MM"
            hora_fim TEXT NOT NULL,     -- Formato "HH:MM"
            FOREIGN KEY (empreendimento_id) REFERENCES empreendimentos(id) ON DELETE CASCADE,
            UNIQUE (empreendimento_id, dia_semana, hora_inicio, hora_fim)
        )
    ''')
    app.logger.info("Tabela 'horarios_funcionamento' verificada/criada.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agente_tipos_servico (
            agente_id INTEGER NOT NULL,
            tipo_id INTEGER NOT NULL,
            PRIMARY KEY (agente_id, tipo_id),
            FOREIGN KEY (agente_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (tipo_id) REFERENCES tipos_agendamento(id) ON DELETE CASCADE
        )
    ''')
    app.logger.info("Tabela 'agente_tipos_servico' verificada/criada.")

    # 3. Tabela que depende de várias outras
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agendamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER, 
            tipo_id INTEGER NOT NULL,
            unidade_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            hora TEXT NOT NULL,
            observacoes TEXT,
            contato_agendamento TEXT,
            status TEXT DEFAULT 'Pendente' NOT NULL,
            agente_atribuido_id INTEGER,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL,
            FOREIGN KEY (tipo_id) REFERENCES tipos_agendamento(id) ON DELETE RESTRICT,
            FOREIGN KEY (unidade_id) REFERENCES unidades(id) ON DELETE RESTRICT,
            FOREIGN KEY (agente_atribuido_id) REFERENCES usuarios(id) ON DELETE SET NULL
        )
    ''')
    app.logger.info("Tabela 'agendamentos' verificada/criada.")

    # --- Adição de Colunas (ALTER TABLE) e Migração de Dados Existentes (APENAS ALTERS) ---
    # Manter estes ALTERs para compatibilidade com databases antigos,
    # mesmo que a tabela 'usuarios' já inclua as colunas na criação.
    try:
        cursor.execute(
            "ALTER TABLE tipos_agendamento ADD COLUMN duracao_minutos INTEGER DEFAULT 60")
        app.logger.info(
            "Coluna 'duracao_minutos' adicionada à tabela 'tipos_agendamento'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'duracao_minutos' já existe na tabela 'tipos_agendamento'.")
        else:
            app.logger.error(
                f"Erro ao adicionar coluna 'duracao_minutos': {e}")

    try:
        cursor.execute(
            "ALTER TABLE usuarios ADD COLUMN tipo_usuario TEXT DEFAULT 'cliente'")
        app.logger.info(
            "Coluna 'tipo_usuario' adicionada à tabela 'usuarios'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'tipo_usuario' já existe na tabela 'usuarios'.")
        else:
            app.logger.error(f"Erro ao adicionar coluna 'tipo_usuario': {e}")

    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN telefone TEXT")
        app.logger.info("Coluna 'telefone' adicionada à tabela 'usuarios'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'telefone' já existe na tabela 'usuarios'.")
        else:
            app.logger.error(f"Erro ao adicionar coluna 'telefone': {e}")

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

    try:
        cursor.execute(
            "ALTER TABLE agendamentos ADD COLUMN contato_agendamento TEXT")
        app.logger.info(
            "Coluna 'contato_agendamento' adicionada à tabela 'agendamentos'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'contato_agendamento' já existe na tabela 'agendamentos'.")
        else:
            app.logger.error(
                f"Erro ao adicionar coluna 'contato_agendamento': {e}")

    try:
        cursor.execute(
            "ALTER TABLE agendamentos ADD COLUMN status TEXT DEFAULT 'Pendente' NOT NULL")
        app.logger.info("Coluna 'status' adicionada à tabela 'agendamentos'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'status' já existe na tabela 'agendamentos'.")
        else:
            app.logger.error(f"Erro ao adicionar coluna 'status': {e}")

    try:
        cursor.execute(
            "ALTER TABLE agendamentos ADD COLUMN agente_atribuido_id INTEGER")
        app.logger.info(
            "Coluna 'agente_atribuido_id' adicionada à tabela 'agendamentos'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'agente_atribuido_id' já existe na tabela 'agendamentos'.")
        else:
            app.logger.error(
                f"Erro ao adicionar coluna 'agente_atribuido_id': {e}")

    try:
        cursor.execute("ALTER TABLE usuarios ADD COLUMN foto_perfil TEXT")
        app.logger.info("Coluna 'foto_perfil' adicionada à tabela 'usuarios'.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            app.logger.info(
                "Coluna 'foto_perfil' já existe na tabela 'usuarios'.")
        else:
            app.logger.error(f"Erro ao adicionar coluna 'foto_perfil': {e}")

    # Certifique-se de que o diretório de upload exista
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.logger.info(
        f"Diretório de upload '{app.config['UPLOAD_FOLDER']}' verificado/criado.")

    conn.commit()
    conn.close()
    app.logger.info("Banco de dados inicializado/verificado e atualizado.")


def criar_usuario_inicial():
    conn = get_db_connection()
    cursor = conn.cursor()
    admin_email = os.environ.get('SUPER_ADMIN_EMAIL', 'admin@admin.com')
    admin_nome = "Administrador Principal"

    # Definir a senha padrão do super admin e garantir que tenha no mínimo 6 caracteres
    default_password = os.environ.get('SUPER_ADMIN_PASSWORD', '123456')
    if len(default_password) < 6:
        app.logger.error(
            "Senha padrão do super admin é muito curta. Definindo uma mais segura para 'admin@admin.com'."
        )
        default_password = "ChangeMeNow123!"  # Fallback seguro
    senha_hash = generate_password_hash(default_password)

    try:
        # Tentar atualizar o usuário administrador.
        # Se ele existe, garantimos que seu nome, senha, is_admin e tipo_usuario estejam corretos.
        cursor.execute(
            """
            UPDATE usuarios 
            SET nome = ?, senha = ?, is_admin = 1, tipo_usuario = 'admin' 
            WHERE email = ?
            """,
            (admin_nome, senha_hash, admin_email)
        )

        # O cursor.rowcount retorna o número de linhas afetadas pela última operação.
        # Se 0 linhas foram afetadas, significa que o usuário não existe.
        if cursor.rowcount == 0:
            # Se o usuário não existe, então o inserimos.
            cursor.execute(
                'INSERT INTO usuarios (nome, email, senha, is_admin, tipo_usuario, telefone, foto_perfil) VALUES (?, ?, ?, ?, ?, ?, ?)',
                # Telefone e foto_perfil são None para o admin inicial
                (admin_nome, admin_email, senha_hash, 1, 'admin', None, None)
            )
            app.logger.info(
                f"Usuário administrador inicial '{admin_email}' CRIADO com sucesso.")
        else:
            app.logger.info(
                f"Usuário administrador inicial '{admin_email}' ATUALIZADO (estado verificado).")

        conn.commit()
    except sqlite3.Error as e:
        app.logger.error(
            f"Erro ao configurar admin principal: {e}", exc_info=True)
        conn.rollback()  # Garante rollback em caso de erro
    finally:
        conn.close()
    app.logger.info(
        "Configuração do usuário administrador principal finalizada.")


# 🚀 Execução
if __name__ == '__main__':
    with app.app_context():
        init_db()
        criar_usuario_inicial()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
