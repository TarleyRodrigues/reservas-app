from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3

app = Flask(__name__)

# Cria a tabela caso não exista


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


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/agendar', methods=['POST'])
def agendar():
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
            "title": f"{row[1]} ({row[3]})",
            "start": row[2]
        })
    return jsonify(eventos)


if __name__ == '__main__':
    app.run(debug=True)
