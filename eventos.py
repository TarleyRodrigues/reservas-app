import sqlite3
from flask import Blueprint, jsonify
from flask_login import login_required

# Define o Blueprint
eventos_bp = Blueprint('eventos', __name__)


@eventos_bp.route('/eventos')
@login_required
def eventos():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
    SELECT 
        a.id,
        u.email AS cliente_email,
        t.nome AS tipo_nome,
        un.nome AS unidade_nome,
        e.nome AS empreendimento_nome,
        a.data,
        a.hora
    FROM agendamentos a
    JOIN usuarios u ON a.usuario_id = u.id
    JOIN tipos_agendamento t ON a.tipo_id = t.id
    JOIN unidades un ON a.unidade_id = un.id
    JOIN empreendimentos e ON un.empreendimento_id = e.id
''')

    rows = cursor.fetchall()
    conn.close()

    eventos = []
    for row in rows:
        evento = {
            "id": row[0],
            "title": f"{row[1]} ({row[3]})",  # cliente_nome (tipo)
            "start": row[2]
        }
        eventos.append(evento)

    return jsonify(eventos)
