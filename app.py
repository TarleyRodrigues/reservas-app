from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)

# ----- Banco de Dados -----


def init_db():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
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


init_db()

# ----- Rotas -----


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/agendar', methods=['POST'])
def agendar():
    nome = request.form.get('nome')
    data = request.form.get('data')
    tipo = request.form.get('tipo')
    unidade = request.form.get('unidade')
    empreendimento = request.form.get('empreendimento')

    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO agendamentos (nome, data, tipo, unidade, empreendimento)
            VALUES (?, ?, ?, ?, ?)
        ''', (nome, data, tipo, unidade, empreendimento))
        conn.commit()

    return redirect(url_for('index'))


@app.route('/calendario')
def calendario():
    return render_template('calendario.html')


@app.route('/eventos')
def eventos():
    with sqlite3.connect('database.db') as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT id, nome, data, tipo, unidade, empreendimento FROM agendamentos')
        rows = cursor.fetchall()

    eventos = []
    for row in rows:
        eventos.append({
            "id": row[0],
            "title": f"{row[2]} - {row[1]} ({row[3]})",
            "start": row[2]
        })
    return jsonify(eventos)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
