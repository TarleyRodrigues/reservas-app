from flask import Flask, render_template, request, redirect, url_for
from datetime import datetime
import os

app = Flask(__name__)

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

    print(f"[AGENDAMENTO] Nome: {nome} | Data: {data} | Tipo: {tipo} | Unidade: {unidade} | Empreendimento: {empreendimento}")

    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
