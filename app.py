from flask import Flask, render_template, request, jsonify
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('agendamentos.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agendamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT,
            tipo TEXT,
            unidade TEXT,
            empreendimento TEXT,
            data TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/agendar', methods=['POST'])
def agendar():
    data = request.get_json()
    conn = sqlite3.connect('agendamentos.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO agendamentos (nome, tipo, unidade, empreendimento, data)
        VALUES (?, ?, ?, ?, ?)
    ''', (data['nome'], data['tipo'], data['unidade'], data['empreendimento'], data['data']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})

@app.route('/agendamentos')
def listar_agendamentos():
    conn = sqlite3.connect('agendamentos.db')
    cursor = conn.cursor()
    cursor.execute('SELECT nome, tipo, unidade, empreendimento, data FROM agendamentos')
    rows = cursor.fetchall()
    conn.close()

    eventos = []
    for row in rows:
        eventos.append({
            'title': f"{row[1].capitalize()} - Unidade {row[2]}",
            'start': row[4]
        })
    return jsonify(eventos)

if __name__ == '__main__':
    app.run(debug=True)
