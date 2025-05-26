# eventos.py
import sqlite3
from flask import Blueprint, jsonify
from flask_login import login_required
from datetime import datetime  # Importar datetime para validação de data/hora

# Define o Blueprint
eventos_bp = Blueprint('eventos', __name__)

# Função auxiliar para obter conexão com o banco de dados
# (Essa função já existe no seu app.py, mas é bom ter uma similar aqui
# ou importar a do app.py se você a expuser para importação)


def get_db_connection_for_events():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Permite acessar colunas por nome
    return conn


@eventos_bp.route('/eventos')
@login_required
def eventos():
    conn = get_db_connection_for_events()  # Usar a função auxiliar

    # Adicionado 'a.observacoes' na consulta SQL
    # E 'u.nome' para ter o nome do usuário, que é mais amigável que o email
    rows = conn.execute('''
    SELECT 
        a.id,
        u.nome AS usuario_nome, -- Pegar o nome do usuário
        u.email AS usuario_email, -- Manter o email também
        t.nome AS tipo_nome,
        un.nome AS unidade_nome,
        e.nome AS empreendimento_nome,
        a.data,
        a.hora,
        a.observacoes -- <--- ADICIONE ESTA LINHA AQUI
    FROM agendamentos a
    JOIN usuarios u ON a.usuario_id = u.id
    JOIN tipos_agendamento t ON a.tipo_id = t.id
    JOIN unidades un ON a.unidade_id = un.id
    JOIN empreendimentos e ON un.empreendimento_id = e.id
    WHERE t.ativo = 1 AND un.ativo = 1 AND e.ativo = 1
    ''').fetchall()

    conn.close()

    eventos_lista = []  # Renomeado para evitar conflito com a variável eventos do loop
    for row in rows:
        try:
            # Combinar data e hora para o formato ISO 8601 exigido pelo FullCalendar
            start_datetime_str = f"{row['data']}T{row['hora']}"

            # Opcional: Validar se a string de data/hora é válida antes de adicionar ao evento
            # Isso é mais uma garantia, já que o strptime no app.py já valida
            datetime.strptime(start_datetime_str, '%Y-%m-%dT%H:%M')

            evento = {
                "id": row["id"],
                # Título mais descritivo para o calendário
                "title": f"{row['tipo_nome']} - {row['unidade_nome']} ({row['empreendimento_nome']})",
                "start": start_datetime_str,
                # Adicionar extendedProps para detalhes adicionais
                "extendedProps": {
                    "usuario_nome": row['usuario_nome'],
                    "usuario_email": row['usuario_email'],
                    "tipo": row['tipo_nome'],
                    "unidade": row['unidade_nome'],
                    "empreendimento": row['empreendimento_nome'],
                    # Garante que seja string vazia se for NULL
                    "observacoes": row['observacoes'] or ""
                }
            }
            eventos_lista.append(evento)
        except ValueError:
            # Logar ou tratar eventos com data/hora inválida, se houver
            print(
                f"AVISO: Agendamento ID {row['id']} possui data/hora inválida: {row['data']} {row['hora']}")
        except Exception as e:
            print(f"Erro ao processar evento ID {row['id']}: {e}")

    return jsonify(eventos_lista)
