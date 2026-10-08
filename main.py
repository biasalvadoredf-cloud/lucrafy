from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb
from flask_bcrypt import Bcrypt

app = Flask(__name__)

bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'chave_secreta_lucrafy'

host = 'localhost'
database = r'C:\Users\Aluno\Downloads\banco_lucrafay\BANCO.FDB'
user = 'sysdba'
password = 'sysdba'

con = fdb.connect(host=host,
                  database=database,
                  user=user,
                  password=password)

# VERIFICAR SENHA FORTE
def senha_forte(senha):

    if len(senha) < 8:
        return False

    if ' ' in senha:
        return False

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_especial = False

    for caractere in senha:

        if caractere >= 'A' and caractere <= 'Z':
            tem_maiuscula = True

        elif caractere >= 'a' and caractere <= 'z':
            tem_minuscula = True

        elif caractere >= '0' and caractere <= '9':
            tem_numero = True

        elif caractere in '!@#$%&*_-':
            tem_especial = True

    if (tem_maiuscula and tem_minuscula and tem_numero and tem_especial):

        return True

    return False

@app.route('/')
def index():
    return render_template('index.html')

# HOME
@app.route('/home')
def home():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    return render_template('home.html', usuario=session['nome'])

# LOGOUT
@app.route('/logout')
def logout():

    session.pop('id_usuario', None)
    flash('Você saiu da sua conta!')
    return redirect(url_for('login'))

# CADASTRO
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():

    if request.method == 'POST':

        nome = request.form['nome']
        email = request.form['email'].strip().lower()
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']
        mao_de_obra = request.form['mao_de_obra']

        # Verifica se os campos foram preenchidos

        if not nome or not email or not senha or not mao_de_obra:
            flash('Preencha todos os campos!')
            return redirect(url_for('cadastro'))

        # Verifica se a senha é forte
        if not senha_forte(senha):
            flash('A senha deve ter pelo menos 8 caracteres, letra maiúscula, minúscula, número, símbolo e não conter espaços.')
            return redirect(url_for('cadastro'))

        if confirmar_senha != senha:
            flash('As senhas precisam ser iguais!')
            return redirect(url_for('cadastro'))


        cursor = con.cursor()

        try:
            # Verifica se o e-mail já existe
            cursor.execute("""
                           SELECT ID_USUARIO
                           FROM USUARIO
                           WHERE LOWER(EMAIL) = ?
                           """, (email,))

            if cursor.fetchone():
                flash('Este e-mail já está cadastrado!')
                return redirect(url_for('cadastro'))

            # Cria o hash da senha
            senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

            # Insere o usuário
            cursor.execute("""
                INSERT INTO USUARIO
                (NOME, EMAIL, SENHA, MAO_DE_OBRA)
                VALUES (?, ?, ?, ?)
            """, (nome, email, senha_hash, mao_de_obra))

            con.commit()

            flash('Cadastro realizado com sucesso!')
            return redirect(url_for('cadastro'))

        except Exception:
            con.rollback()
            flash('Erro ao cadastrar usuário.')
            return redirect(url_for('cadastro'))

        finally:
            cursor.close()

    return render_template('cadastro.html')


# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email'].strip().lower()
        senha = request.form['senha']

        cursor = con.cursor()

        try:

            cursor.execute("""
                SELECT
                    id_usuario,
                    nome,
                    senha,
                    ativo,
                    tentativas_login
                FROM usuario
                WHERE LOWER(email) = ?
            """, (email,))

            usuario = cursor.fetchone()

            if not usuario:
                flash('Email ou senha incorretos!')
                return redirect(url_for('login'))

            if usuario[3] == 0:
                flash('Usuário inativo!')
                return redirect(url_for('login'))

            if usuario[4] >= 3:
                flash('Usuário bloqueado após 3 tentativas!')
                return redirect(url_for('login'))

            if bcrypt.check_password_hash(usuario[2], senha):

                cursor.execute("""
                    UPDATE usuario
                    SET tentativas_login = 0
                    WHERE id_usuario = ?
                """, (usuario[0],))

                con.commit()

                session['id_usuario'] = usuario[0]
                session['nome'] = usuario[1]

                return redirect(url_for('home'))

            else:

                tentativas = usuario[4] + 1

                cursor.execute("""
                    UPDATE usuario
                    SET tentativas_login = ?
                    WHERE id_usuario = ?
                """, (tentativas, usuario[0]))

                con.commit()

                if tentativas >= 3:
                    flash('Usuário bloqueado após 3 tentativas!')
                else:
                    flash('Senha incorreta!')

                return redirect(url_for('login'))

        except Exception as e:

            con.rollback()
            flash(f'Ocorreu um erro -> {e}')
            return redirect(url_for('login'))

        finally:

            cursor.close()

    return render_template('login.html')


# EDITAR USUÁRIO
@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar(id):

    if 'id_usuario' not in session:
        flash('Precisa estar logado')
        return redirect(url_for('login'))

    if id != session['id_usuario']:
        flash('Você não pode editar outro usuário')
        return redirect(url_for('home'))

    cursor = con.cursor()

    try:

        cursor.execute(
            """
            SELECT
                id_usuario,
                nome,
                email,
                mao_de_obra
            FROM usuario
            WHERE id_usuario = ?
            """,
            (id,)
        )

        usuario = cursor.fetchone()

        if not usuario:

            flash("Usuário não encontrado")

            return redirect(url_for('home'))

        if request.method == 'POST':

            nome = request.form['nome']
            email = request.form['email'].strip().lower()
            mao_de_obra = request.form['mao_de_obra']

            cursor.execute(
                """
                SELECT id_usuario
                FROM usuario
                WHERE LOWER(email) = ?
                AND id_usuario <> ?
                """,
                (email, id)
            )

            if cursor.fetchone():

                flash("Este e-mail já está cadastrado")

                return redirect(url_for('editar', id=id))

            cursor.execute(
                """
                UPDATE usuario
                SET
                    nome = ?,
                    email = ?,
                    mao_de_obra = ?

                WHERE id_usuario = ?
                """,
                (
                    nome,
                    email,
                    mao_de_obra,
                    id
                )
            )

            con.commit()

            session['nome'] = nome

            flash("Usuário editado com sucesso")

            return redirect(url_for('editar', id=id))

        return render_template(
            'editar_usuario.html',usuario=usuario)

    except Exception as e:

        flash(f"Ocorreu um erro -> {e}")

        con.rollback()

        return redirect(url_for('home'))

    finally:

        cursor.close()


# ALTERAR SENHA
@app.route('/alterar_senha', methods=['GET', 'POST'])
def alterar_senha():

    if 'id_usuario' not in session:
        flash('Precisa estar logado')
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:

        if request.method == 'POST':

            senha_atual = request.form['senha_atual']
            nova_senha = request.form['nova_senha']
            confirmar_senha = request.form['confirmar_senha']

            cursor.execute("""
                SELECT senha
                FROM usuario
                WHERE id_usuario = ?
            """, (session['id_usuario'],))

            usuario = cursor.fetchone()

            if not usuario:
                flash('Usuário não encontrado')
                return redirect(url_for('login'))

            if not bcrypt.check_password_hash(usuario[0], senha_atual):
                flash('Senha atual incorreta')
                return redirect(url_for('alterar_senha'))

            if nova_senha != confirmar_senha:
                flash('As senhas não coincidem')
                return redirect(url_for('alterar_senha'))

            if not senha_forte(nova_senha):
                flash('A nova senha deve ser forte')
                return redirect(url_for('alterar_senha'))

            # VERIFICAR SENHA ATUAL
            if bcrypt.check_password_hash(usuario[0], nova_senha):
                flash('Utilize uma nova senha')
                return redirect(url_for('alterar_senha'))

            # VERIFICAR AS 3 ÚLTIMAS SENHAS
            cursor.execute("""
                            SELECT FIRST 3 senha
                            FROM historico_senha
                            WHERE id_usuario = ?
                            ORDER BY id_historico DESC
            """, (session['id_usuario'],))

            historico = cursor.fetchall()

            for senha_antiga in historico:

                if bcrypt.check_password_hash(senha_antiga[0], nova_senha):
                    flash('Você não pode reutilizar suas 3 últimas senhas')
                    return redirect(url_for('alterar_senha'))

            # CRIPTOGRAFAR NOVA SENHA
            senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

            # GUARDAR SENHA ANTERIOR
            cursor.execute("""
                INSERT INTO historico_senha
                (id_usuario, senha)
                VALUES (?, ?)
            """, (session['id_usuario'], usuario[0]))

            # ATUALIZAR SENHA
            cursor.execute("""
                UPDATE usuario
                SET senha = ?
                WHERE id_usuario = ?
            """, (senha_hash, session['id_usuario']))

            con.commit()

            flash('Senha alterada com sucesso')
            return redirect(url_for('alterar_senha'))

        return render_template('alterar_senha.html')

    except Exception as e:

        con.rollback()
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('home'))

    finally:

        cursor.close()


if __name__ == '__main__':

    app.run(debug=True)