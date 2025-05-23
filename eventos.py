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
            a.cliente_nome,
            a.data_hora,
            t.nome AS tipo_nome,
            u.nome AS unidade_nome,
            e.nome AS empreendimento_nome
        FROM agendamentos a
        JOIN tipos_agendamento t ON a.tipo_id = t.id
        JOIN unidades u ON a.unidade_id = u.id
        JOIN empreendimentos e ON u.empreendimento_id = e.id
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
