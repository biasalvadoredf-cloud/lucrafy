from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb
from flask_bcrypt import Bcrypt
from websockets.sync.router import route

# --------------------------------------------------
# 2 - CONFIGURAÇÃO DO FLASK
# --------------------------------------------------

app = Flask(__name__)

bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'chave_secreta_lucrafy'


# --------------------------------------------------
# 3 - CONEXÃO COM O BANCO DE DADOS
# --------------------------------------------------

host = 'localhost'

database = r'C:\Users\Aluno\Downloads\banco_lucrafay\BANCO.FDB'

user = 'sysdba'
password = 'sysdba'

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)


# --------------------------------------------------
# 4 - VERIFICAÇÃO DE SENHA FORTE
# --------------------------------------------------


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


# --------------------------------------------------
# 5 - PÁGINA INICIAL
# --------------------------------------------------

@app.route('/')
def index():

    return render_template('index.html')


# --------------------------------------------------
# 6 - HOME
# --------------------------------------------------

@app.route('/home')
def home():

    if 'id_usuario' not in session:

        return redirect(url_for('login'))

    return render_template(
        'home.html',
        usuario=session['nome']
    )


# --------------------------------------------------
# 7 - LOGOUT
# --------------------------------------------------

@app.route('/logout')
def logout():

    session.pop('id_usuario', None)
    session.pop('nome', None)

    flash('Você saiu da sua conta!', 'info')

    return redirect(url_for('login'))


# --------------------------------------------------
# 8 - CADASTRO DE USUÁRIOS
# --------------------------------------------------


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():

    if request.method == 'POST':

        nome = request.form['nome'].strip()

        email = request.form['email'].strip().lower()
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']
        mao_de_obra = float(request.form['mao_de_obra'])

        # --------------------------------------------------
        # VERIFICAR CAMPOS OBRIGATÓRIOS
        # --------------------------------------------------

        if not nome or not email or not senha or not mao_de_obra:

            flash('Preencha todos os campos!', 'error')

            return redirect(url_for('cadastro'))

        # --------------------------------------------------
        # VERIFICAR SENHA FORTE
        # --------------------------------------------------

        if not senha_forte(senha):

            flash('A senha deve ter pelo menos 8 caracteres, letra maiúscula, minúscula, número, símbolo e não conter espaços.', 'error')

            return redirect(url_for('cadastro'))

        # --------------------------------------------------
        # Verificar se a mão de obra é positiva
        # --------------------------------------------------

        if mao_de_obra < 0:
            flash('O valor da mão de obra não pode ser negativo!', 'error')
            return redirect(url_for('cadastro'))

        # --------------------------------------------------
        # CONFIRMAR SENHA
        # --------------------------------------------------

        if confirmar_senha != senha:

            flash('As senhas precisam ser iguais!', 'error')

            return redirect(url_for('cadastro'))

        cursor = con.cursor()

        try:

            # --------------------------------------------------
            # VERIFICAR E-MAIL DUPLICADO
            # --------------------------------------------------

            cursor.execute("""
                SELECT ID_USUARIO
                FROM USUARIO
                WHERE LOWER(EMAIL) = ?
            """, (email,))

            if cursor.fetchone():

                flash('Este e-mail já está cadastrado!', 'error')

                return redirect(url_for('cadastro'))

            # --------------------------------------------------
            # GERAR HASH DA SENHA
            # --------------------------------------------------

            senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

            # --------------------------------------------------
            # INSERIR USUÁRIO
            # --------------------------------------------------

            cursor.execute("""
                INSERT INTO USUARIO
                (NOME, EMAIL, SENHA, MAO_DE_OBRA)
                VALUES (?, ?, ?, ?)
            """, (nome, email, senha_hash, mao_de_obra))

            con.commit()

            flash('Cadastro realizado com sucesso!', 'success')

            return redirect(url_for('cadastro'))

        except Exception:

            con.rollback()

            flash('Erro ao cadastrar usuário.', 'error')

            return redirect(url_for('cadastro'))

        finally:

            cursor.close()

    return render_template('cadastro.html')


# --------------------------------------------------
# 9 - LOGIN
# --------------------------------------------------


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email'].strip().lower()
        senha = request.form['senha']

        cursor = con.cursor()

        try:

            # --------------------------------------------------
            # CONSULTAR USUÁRIO
            # --------------------------------------------------


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

            # --------------------------------------------------
            # VERIFICAR SE O USUÁRIO EXISTE
            # --------------------------------------------------

            if not usuario:

                flash('Email ou senha incorretos!', 'error')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # VERIFICAR SE ESTÁ ATIVO
            # --------------------------------------------------

            if usuario[3] == 0:

                flash('Usuário inativo!', 'error')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # VERIFICAR BLOQUEIO
            # --------------------------------------------------

            if usuario[4] >= 3:

                flash('Usuário bloqueado após 3 tentativas!', 'error')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # VERIFICAR SENHA
            # --------------------------------------------------

            if bcrypt.check_password_hash(usuario[2], senha):

                # --------------------------------------------------
                # LOGIN CORRETO
                # --------------------------------------------------

                cursor.execute("""
                    UPDATE usuario
                    SET tentativas_login = 0
                    WHERE id_usuario = ?
                """, (usuario[0],))

                con.commit()

                session['id_usuario'] = usuario[0]
                session['nome'] = usuario[1]

                return redirect(url_for('home'))

            # --------------------------------------------------
            # LOGIN INCORRETO
            # --------------------------------------------------

            else:

                tentativas = usuario[4] + 1

                # --------------------------------------------------
                # DESATIVAR APÓS TRÊS TENTATIVAS
                # --------------------------------------------------

                if tentativas >= 3:

                    cursor.execute("""
                        UPDATE usuario
                        SET tentativas_login = ?,
                            ativo = 0
                        WHERE id_usuario = ?
                    """, (tentativas, usuario[0]))

                    con.commit()

                    flash('Usuário bloqueado após 3 tentativas!', 'error')

                # --------------------------------------------------
                # MENOS DE TRÊS TENTATIVAS
                # --------------------------------------------------

                else:

                    cursor.execute("""
                        UPDATE usuario
                        SET tentativas_login = ?
                        WHERE id_usuario = ?
                    """, (tentativas, usuario[0]))

                    con.commit()

                    flash('Senha incorreta!', 'error')

                return redirect(url_for('login'))

        # --------------------------------------------------
        # TRATAMENTO DE ERROS
        # --------------------------------------------------

        except Exception as e:

            con.rollback()

            flash(f'Ocorreu um erro -> {e}', 'error')

            return redirect(url_for('login'))

        finally:

            cursor.close()

    return render_template('login.html')


# --------------------------------------------------
# 10 - EDITAR USUÁRIO
# --------------------------------------------------

@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar(id):

    # --------------------------------------------------
    # VERIFICAR LOGIN
    # --------------------------------------------------

    if 'id_usuario' not in session:

        flash('Precisa estar logado', 'error')

        return redirect(url_for('login'))

    # --------------------------------------------------
    # VERIFICAR PERMISSÃO
    # --------------------------------------------------

    if id != session['id_usuario']:

        flash('Você não pode editar outro usuário', 'error')

        return redirect(url_for('home'))

    cursor = con.cursor()


    try:

        # --------------------------------------------------
        # BUSCAR DADOS DO USUÁRIO
        # --------------------------------------------------

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

        # --------------------------------------------------
        # VERIFICAR SE EXISTE
        # --------------------------------------------------

        if not usuario:

            flash("Usuário não encontrado", 'error')

            return redirect(url_for('home'))

        # --------------------------------------------------
        # RECEBER ALTERAÇÕES
        # --------------------------------------------------

        if request.method == 'POST':

            nome = request.form['nome'].strip()
            email = request.form['email'].strip().lower()
            mao_de_obra = float(request.form['mao_de_obra'])

            # --------------------------------------------------
            # Verificar nome em branco e mào de obra negativa
            # --------------------------------------------------

            if not nome:
                flash('O nome não pode estar vazio!', 'error')
                return redirect(url_for('editar', id=id))

            if not email:
                flash('O e-mail não pode estar vazio!', 'error')
                return redirect(url_for('editar', id=id))

            if mao_de_obra < 0:
                flash('O valor da mão de obra não pode ser negativo!', 'error')
                return redirect(url_for('editar', id=id))

            # --------------------------------------------------
            # VERIFICAR E-MAIL DUPLICADO
            # --------------------------------------------------

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

                flash("Este e-mail já está cadastrado", 'error')

                return redirect(url_for('editar', id=id))

            # --------------------------------------------------
            # ATUALIZAR DADOS
            # --------------------------------------------------

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

            flash("Usuário editado com sucesso", 'success')

            return redirect(url_for('editar', id=id))

        # --------------------------------------------------
        # ABRIR FORMULÁRIO
        # --------------------------------------------------

        return render_template(
            'editar_usuario.html',
            usuario=usuario
        )

    # --------------------------------------------------
    # TRATAMENTO DE ERROS
    # --------------------------------------------------

    except Exception as e:

        flash(f"Ocorreu um erro -> {e}", 'error')

        con.rollback()

        return redirect(url_for('home'))

    finally:

        cursor.close()


# --------------------------------------------------
# 11 - ALTERAR SENHA
# --------------------------------------------------


@app.route('/alterar_senha', methods=['GET', 'POST'])
def alterar_senha():

    # --------------------------------------------------
    # VERIFICAR LOGIN
    # --------------------------------------------------

    if 'id_usuario' not in session:

        flash('Precisa estar logado', 'error')

        return redirect(url_for('login'))

    cursor = con.cursor()

    try:

        # --------------------------------------------------
        # RECEBER DADOS DO FORMULÁRIO
        # --------------------------------------------------

        if request.method == 'POST':

            senha_atual = request.form['senha_atual']
            nova_senha = request.form['nova_senha']
            confirmar_senha = request.form['confirmar_senha']

            # --------------------------------------------------
            # CONSULTAR SENHA ATUAL
            # --------------------------------------------------

            cursor.execute("""
                SELECT senha
                FROM usuario
                WHERE id_usuario = ?
            """, (session['id_usuario'],))

            usuario = cursor.fetchone()

            # --------------------------------------------------
            # VERIFICAR USUÁRIO
            # --------------------------------------------------

            if not usuario:

                flash('Usuário não encontrado', 'error')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # CONFERIR SENHA ATUAL
            # --------------------------------------------------

            if not bcrypt.check_password_hash(usuario[0], senha_atual):

                flash('Senha atual incorreta', 'error')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # CONFIRMAR NOVA SENHA
            # --------------------------------------------------

            if nova_senha != confirmar_senha:

                flash('As senhas não coincidem', 'error')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # VERIFICAR SENHA FORTE
            # --------------------------------------------------

            if not senha_forte(nova_senha):

                flash('A nova senha deve ser forte', 'error')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # IMPEDIR REPETIÇÃO DA SENHA ATUAL
            # --------------------------------------------------

            if bcrypt.check_password_hash(usuario[0], nova_senha):

                flash('Utilize uma nova senha', 'error')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # VERIFICAR HISTÓRICO DE SENHAS
            # --------------------------------------------------

            cursor.execute("""
                SELECT FIRST 3 senha
                FROM historico_senha
                WHERE id_usuario = ?
                ORDER BY id_historico DESC
            """, (session['id_usuario'],))

            historico = cursor.fetchall()

            # --------------------------------------------------
            # COMPARAR SENHAS ANTIGAS
            # --------------------------------------------------

            for senha_antiga in historico:

                if bcrypt.check_password_hash(senha_antiga[0], nova_senha):

                    flash('Você não pode reutilizar suas 3 últimas senhas', 'error')

                    return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # GERAR HASH DA NOVA SENHA
            # --------------------------------------------------

            senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

            # --------------------------------------------------
            # GUARDAR SENHA ANTERIOR
            # --------------------------------------------------

            cursor.execute("""
                INSERT INTO historico_senha
                (id_usuario, senha)
                VALUES (?, ?)
            """, (session['id_usuario'], usuario[0]))

            # --------------------------------------------------
            # ATUALIZAR SENHA
            # --------------------------------------------------

            cursor.execute("""
                UPDATE usuario
                SET senha = ?
                WHERE id_usuario = ?
            """, (senha_hash, session['id_usuario']))

            # --------------------------------------------------
            # CONFIRMAR ALTERAÇÕES
            # --------------------------------------------------

            con.commit()

            flash('Senha alterada com sucesso', 'success')

            return redirect(url_for('alterar_senha'))

        # --------------------------------------------------
        # ABRIR FORMULÁRIO
        # --------------------------------------------------

        return render_template('alterar_senha.html')

    # --------------------------------------------------
    # TRATAMENTO DE ERROS
    # --------------------------------------------------

    except Exception as e:

        con.rollback()

        flash(f'Ocorreu um erro -> {e}', 'error')

        return redirect(url_for('home'))

    finally:

        cursor.close()

# --------------------------------------------------
# 12 - CADASTRO DE INSUMO
# --------------------------------------------------

@app.route('/cadastro_insumo', methods=['GET', 'POST'])
def cadastro_insumo():

    cursor = con.cursor()

    try:
        if request.method == 'POST':

            nome = request.form['nome'].strip()
            custo = float(request.form['custo'])
            unidade_medida = request.form['unidade_medida']
            categoria = request.form['categoria']
            id_usuario = session.get('id_usuario')

            if not nome or not custo or not unidade_medida or not categoria:
                flash('Preencha todos os campos!', 'error')
                return redirect(url_for('cadastro_insumo'))

            if not id_usuario:
                flash('Faça login para cadastrar um insumo!', 'error')
                return redirect(url_for('login'))

            if custo <= 0:
                flash('O custo precisa ser maior que zero!', 'error')
                return redirect(url_for('cadastro_insumo'))

            cursor.execute("""
                SELECT ID_INSUMO
                FROM INSUMO
                WHERE NOME = ? AND ID_USUARIO = ?
            """, (nome, id_usuario))

            if cursor.fetchone():
                flash('Este insumo já está cadastrado!', 'error')
                return redirect(url_for('cadastro_insumo'))

            cursor.execute("""
                INSERT INTO INSUMO
                (NOME, CUSTO, ID_USUARIO, ID_UNIDADE, ID_CATEGORIA)
                VALUES (?, ?, ?, ?, ?)
            """, (nome,custo,id_usuario,unidade_medida,categoria))

            con.commit()

            flash('Insumo cadastrado com sucesso!', 'success')
            return redirect(url_for('cadastro_insumo'))

        # Busca as unidades de medida cadastradas
        cursor.execute("""
            SELECT ID_UNIDADE, NOME, SIGLA
            FROM UNIDADE_MEDIDA
            ORDER BY NOME
        """)

        unidades = cursor.fetchall()

        # Busca as categorias do usuário logado
        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
            ORDER BY NOME""")

        categorias = cursor.fetchall()

        return render_template('insumo.html',unidades=unidades,categorias=categorias)

    except Exception as erro:
        con.rollback()
        flash('Erro ao processar o cadastro do insumo!', 'error')
        return redirect(url_for('cadastro_insumo'))

    finally:
        cursor.close()

@app.route('/visao-geral', methods=['GET'])
def visao_geral():
    return render_template('visao-geral.html')




@app.route('/configuracao', methods=['GET'])
def configuracao():
    return render_template('configuracao.html')






# --------------------------------------------------
#  INICIALIZAÇÃO DO SISTEMA
# --------------------------------------------------

if __name__ == '__main__':

    app.run(debug=True)