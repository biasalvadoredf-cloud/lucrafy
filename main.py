from flask import Flask, render_template, request, flash, redirect, url_for, session, send_file, send_from_directory
import fdb
from flask_bcrypt import Bcrypt
from decimal import Decimal
from fpdf import FPDF
import os

# --------------------------------------------------
# 2 - CONFIGURAÇÃO DO FLASK
# --------------------------------------------------

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'chave_secreta_lucrafy'

# Fotos e PDFs: diretórios conforme os exemplos da aula.
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --------------------------------------------------
# 3 - CONEXÃO COM O BANCO DE DADOS
# --------------------------------------------------

host = 'localhost'
database = (r'C:\Users\Aluno\Downloads\banco_lucrafay\banco_lucrafay\BANCO.FDB')
user = 'sysdba'
password = 'sysdba'

con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password)


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
# 6 - VISÃO GERAL
# --------------------------------------------------

@app.route('/visao_geral')
def visao_geral():

    if 'id_usuario' not in session:

        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        id_usuario = session['id_usuario']

        # Contar os produtos cadastrados
        cursor.execute("""SELECT COUNT(*) FROM PRODUTO WHERE ID_USUARIO = ?""", (id_usuario,))

        total_produtos = cursor.fetchone()[0]

        # Contar os insumos cadastrados
        cursor.execute("""SELECT COUNT(*) FROM INSUMO WHERE ID_USUARIO = ?""", (id_usuario,))

        total_insumos = cursor.fetchone()[0]

        # Custo médio
        cursor.execute("""SELECT AVG(CUSTO) FROM PRODUTO WHERE ID_USUARIO = ?""", (id_usuario,))

        custo_medio = cursor.fetchone()[0]

        if custo_medio is None:
            custo_medio = 0

        # Margem média
        cursor.execute("""SELECT AVG(MARGEM_LUCRO) FROM PRODUTO WHERE ID_USUARIO = ?""", (id_usuario,))

        margem_media = cursor.fetchone()[0]

        if margem_media is None:
            margem_media = 0

        cursor.execute("""SELECT FIRST 3 NOME, CUSTO, PRECO_SUGERIDO FROM PRODUTO WHERE ID_USUARIO = ? 
        ORDER BY margem_lucro DESC
        """, (id_usuario,))

        produtos_destaque = cursor.fetchall()



        return render_template('visao_geral.html', usuario=session['nome'],
                               total_produtos=total_produtos,
                               total_insumos=total_insumos,
                               custo_medio=custo_medio,
                               margem_media=margem_media,
                               produtos_destaque=produtos_destaque)

    finally:
        cursor.close()

    return render_template('visao_geral.html',usuario=session['nome'])


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

                return redirect(url_for('visao_geral'))

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
        return redirect(url_for('visao_geral'))

    cursor = con.cursor()

    try:

        # --------------------------------------------------
        # BUSCAR DADOS DO USUÁRIO
        # --------------------------------------------------

        cursor.execute(
            """SELECT id_usuario,nome,email,mao_de_obra
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

            return redirect(url_for('visao_geral'))

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
                SET nome = ?,
                    email = ?,
                    mao_de_obra = ?
                WHERE id_usuario = ?
                """,
                (nome,email,mao_de_obra,id)
            )

            con.commit()

            session['nome'] = nome
            flash("Usuário editado com sucesso", 'success')
            return redirect(url_for('editar', id=id))

        # --------------------------------------------------
        # ABRIR FORMULÁRIO
        # --------------------------------------------------

        return render_template('editar_usuario.html',usuario=usuario)

    # --------------------------------------------------
    # TRATAMENTO DE ERROS
    # --------------------------------------------------

    except Exception as e:

        flash(f"Ocorreu um erro -> {e}", 'error')

        con.rollback()

        return redirect(url_for('visao_geral'))

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
        return redirect(url_for('visao_geral'))

    finally:

        cursor.close()

# --------------------------------------------------
# INSUMO
# --------------------------------------------------

@app.route('/insumo', methods=['GET', 'POST'])
def insumo():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Buscar unidades de medida
        cursor.execute("""
            SELECT ID_UNIDADE, NOME, SIGLA
            FROM UNIDADE_MEDIDA
            ORDER BY NOME
        """)

        unidades = cursor.fetchall()

        # Buscar categorias do usuário
        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))

        categorias = cursor.fetchall()

        return render_template(
            'insumo.html',
            usuario=session['nome'],
            unidades=unidades,
            categorias=categorias
        )

    finally:
        cursor.close()

# --------------------------------------------------
# CADASTRO DE INSUMO
# --------------------------------------------------

@app.route('/cadastro_insumo', methods=['POST'])
def cadastro_insumo():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        nome = request.form['nome'].strip()
        custo = Decimal(request.form['custo'])
        unidade = request.form['unidade_medida']
        categoria = request.form['categoria']
        estoque = Decimal(request.form['estoque_atual'])

        # Verificar campos obrigatórios
        if not nome or not unidade or not categoria:
            flash('Preencha todos os campos!', 'error')
            return redirect(url_for('insumo'))

        # Verificar custo
        if custo <= 0:
            flash('O custo deve ser maior que zero!', 'error')
            return redirect(url_for('insumo'))

        # Verificar estoque
        if estoque < 0:
            flash('O estoque não pode ser negativo!', 'error')
            return redirect(url_for('insumo'))

        # Verificar nome duplicado
        cursor.execute("""
            SELECT ID_INSUMO
            FROM INSUMO
            WHERE LOWER(NOME) = LOWER(?)
            AND ID_USUARIO = ?
        """, (nome, session['id_usuario']))

        if cursor.fetchone():
            flash('Este insumo já está cadastrado!', 'error')
            return redirect(url_for('insumo'))

        # Cadastrar insumo
        cursor.execute("""
            INSERT INTO INSUMO
            (NOME, CUSTO, ID_USUARIO, ID_UNIDADE,
             ID_CATEGORIA, ESTOQUE_ATUAL, ATIVO)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            nome,
            custo,
            session['id_usuario'],
            unidade,
            categoria,
            estoque,
            1
        ))

        con.commit()

    except Exception as e:
        con.rollback()
        print(f'Erro ao cadastrar insumo: {e}')
        flash('Erro ao cadastrar o insumo!', 'error')
        return redirect(url_for('insumo'))

    finally:
        cursor.close()

    flash('Insumo cadastrado com sucesso!', 'success')
    return redirect(url_for('insumo'))
# --------------------------------------------------
# INSUMOS CADASTRADOS
# --------------------------------------------------


@app.route('/insumos_cadastrados')
def insumos_cadastrados():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Buscar os insumos do usuário
        cursor.execute("""
            SELECT ID_INSUMO, NOME, COALESCE(ATIVO, 1)
            FROM INSUMO
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))

        insumos = cursor.fetchall()

        return render_template(
            'insumo_cadastrado.html',
            insumos=insumos
        )

    finally:
        cursor.close()

# --------------------------------------------------
# EDITAR INSUMO
# --------------------------------------------------

@app.route('/editar_insumo/<int:id>', methods=['GET', 'POST'])
def editar_insumo(id):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Buscar o insumo
        cursor.execute("""
            SELECT ID_INSUMO, NOME, CUSTO, ID_UNIDADE,
                   ID_CATEGORIA, ESTOQUE_ATUAL, COALESCE(ATIVO, 1)
            FROM INSUMO
            WHERE ID_INSUMO = ?
            AND ID_USUARIO = ?
        """, (id, session['id_usuario']))

        insumo = cursor.fetchone()

        if not insumo:
            flash('Insumo não encontrado!', 'error')
            return redirect(url_for('insumos_cadastrados'))

        # Receber os dados da edição
        if request.method == 'POST':

            nome = request.form['nome'].strip()
            custo = Decimal(request.form['custo'])
            estoque = Decimal(request.form['estoque_atual'])
            unidade = request.form['unidade_medida']
            categoria = request.form['categoria']

            # Verificar campos obrigatórios
            if not nome or not unidade or not categoria:
                flash('Preencha todos os campos!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Verificar custo
            if custo <= 0:
                flash('O custo deve ser maior que zero!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Verificar estoque
            if estoque < 0:
                flash('O estoque não pode ser negativo!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Verificar nome duplicado
            cursor.execute("""
                SELECT ID_INSUMO
                FROM INSUMO
                WHERE LOWER(NOME) = LOWER(?)
                AND ID_USUARIO = ?
                AND ID_INSUMO <> ?
            """, (nome, session['id_usuario'], id))

            if cursor.fetchone():
                flash('Este insumo já está cadastrado!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Registrar histórico se o custo mudar
            if insumo[2] != custo:

                cursor.execute("""
                    INSERT INTO HISTORICO_CUSTO
                    (ID_INSUMO, CUSTO_ANTERIOR,
                     CUSTO_NOVO, DATA_ALTERACAO)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (id, insumo[2], custo))

            # Atualizar insumo
            cursor.execute("""
                UPDATE INSUMO
                SET NOME = ?,
                    CUSTO = ?,
                    ID_UNIDADE = ?,
                    ID_CATEGORIA = ?,
                    ESTOQUE_ATUAL = ?
                WHERE ID_INSUMO = ?
                AND ID_USUARIO = ?
            """, (
                nome,
                custo,
                unidade,
                categoria,
                estoque,
                id,
                session['id_usuario']
            ))

            con.commit()

            flash('Insumo atualizado com sucesso!', 'success')
            return redirect(url_for('insumos_cadastrados'))

        # Buscar unidades de medida
        cursor.execute("""
            SELECT ID_UNIDADE, NOME, SIGLA
            FROM UNIDADE_MEDIDA
            ORDER BY NOME
        """)

        unidades = cursor.fetchall()

        # Buscar categorias
        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))

        categorias = cursor.fetchall()

        # Buscar insumos cadastrados
        cursor.execute("""
            SELECT ID_INSUMO, NOME, COALESCE(ATIVO, 1)
            FROM INSUMO
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))

        insumos = cursor.fetchall()

        return render_template(
            'editar_insumo.html',
            insumo=insumo,
            unidades=unidades,
            categorias=categorias,
            insumos=insumos
        )

    except Exception as e:
        con.rollback()
        print('Erro ao editar insumo:', e)
        flash('Erro ao editar insumo.', 'error')
        return redirect(url_for('insumos_cadastrados'))

    finally:
        cursor.close()


#ALTERAR STATUS INSUMO
@app.route('/alterar_status_insumo/<int:id>', methods=['POST'])
def alterar_status_insumo(id):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    ativo = request.form.get('ativo')

    if ativo not in ('0', '1'):
        flash('Status do insumo inválido!', 'error')
        return redirect(url_for('insumos_cadastrados'))

    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT ID_INSUMO
            FROM INSUMO
            WHERE ID_INSUMO = ? AND ID_USUARIO = ?
        """, (id, session['id_usuario']))

        if not cursor.fetchone():
            flash('Insumo não encontrado!', 'error')
            return redirect(url_for('insumos_cadastrados'))

        cursor.execute("""
            UPDATE INSUMO
            SET ATIVO = ?
            WHERE ID_INSUMO = ? AND ID_USUARIO = ?
        """, (int(ativo), id, session['id_usuario']))

        cursor.execute("""
            SELECT DISTINCT C.ID_PRODUTO
            FROM COMPOSICAO_PRODUTO C
            JOIN PRODUTO P ON P.ID_PRODUTO = C.ID_PRODUTO
            WHERE C.ID_INSUMO = ? AND P.ID_USUARIO = ?
        """, (id, session['id_usuario']))

        for vinculo in cursor.fetchall():
            if not atualizar_custo_produto(vinculo[0]):
                raise ValueError('Não foi possível recalcular o produto.')

        con.commit()

        if ativo == '1':
            mensagem = 'Insumo reativado com sucesso!'
        else:
            mensagem = (
                'Insumo inativado com sucesso! '
                'Os produtos vinculados foram recalculados.'
            )

        flash(mensagem, 'success')

    except Exception:
        con.rollback()
        flash(
            'Não foi possível alterar o status do insumo. '
            'Nenhuma alteração foi salva.',
            'error'
        )

    finally:
        cursor.close()

    return redirect(url_for('insumos_cadastrados'))
#===================================================
# EXCLUIR INSUMO
#===================================================

@app.route('/excluir_insumo/<int:id>', methods=['POST'])
def excluir_insumo(id):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Verificar se o insumo pertence ao usuário
        cursor.execute("""
            SELECT ID_INSUMO
            FROM INSUMO
            WHERE ID_INSUMO = ?
            AND ID_USUARIO = ?
        """, (id, session['id_usuario']))

        if not cursor.fetchone():
            flash('Insumo não encontrado!', 'error')
            return redirect(url_for('insumos_cadastrados'))

        # Verificar se o insumo está sendo usado em algum produto
        cursor.execute("""
            SELECT ID_COMPOSICAO
            FROM COMPOSICAO_PRODUTO
            WHERE ID_INSUMO = ?
        """, (id,))

        if cursor.fetchone():
            flash(
                'Este insumo está vinculado a um produto. '
                'Use Inativar para retirá-lo do cálculo sem apagar o vínculo.',
                'error'
            )
            return redirect(url_for('insumos_cadastrados'))

        # Excluir histórico de custos
        cursor.execute("""
            DELETE FROM HISTORICO_CUSTO
            WHERE ID_INSUMO = ?
        """, (id,))

        # Excluir insumo
        cursor.execute("""
            DELETE FROM INSUMO
            WHERE ID_INSUMO = ?
            AND ID_USUARIO = ?
        """, (id, session['id_usuario']))

        con.commit()

        flash('Insumo excluído com sucesso!', 'success')
        return redirect(url_for('insumos_cadastrados'))

    except Exception as e:
        con.rollback()
        flash('Erro ao excluir insumo.', 'error')
        return redirect(url_for('insumos_cadastrados'))

    finally:
        cursor.close()


#===================================================
# ADICIONAR INSUMO AO PRODUTO
#===================================================

@app.route('/adicionar_insumo_produto', methods=['POST'])
def adicionar_insumo_produto():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        id_produto = int(request.form['id_produto'])
        id_insumo = int(request.form['id_insumo'])
        id_unidade = int(request.form['id_unidade'])
        quantidade = Decimal(request.form['quantidade'])

        # Verificar produto
        cursor.execute("""
            SELECT ID_PRODUTO
            FROM PRODUTO
            WHERE ID_PRODUTO = ?
            AND ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        if not cursor.fetchone():
            flash('Produto não encontrado!', 'error')
            return redirect(url_for('produtos_cadastrados'))

        # Verificar insumo e buscar estoque
        cursor.execute("""
            SELECT I.NOME, I.ESTOQUE_ATUAL, U.SIGLA
            FROM INSUMO I
            LEFT JOIN UNIDADE_MEDIDA U
            ON I.ID_UNIDADE = U.ID_UNIDADE
            WHERE I.ID_INSUMO = ?
            AND I.ID_USUARIO = ?
            AND COALESCE(I.ATIVO, 1) = 1
        """, (id_insumo, session['id_usuario']))

        insumo = cursor.fetchone()

        if not insumo:
            flash('Insumo não encontrado ou inativo!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        nome = insumo[0]
        estoque = insumo[1]
        unidade_estoque = insumo[2]

        if estoque is None:
            estoque = 0

        # Buscar unidade escolhida
        cursor.execute("""
            SELECT SIGLA
            FROM UNIDADE_MEDIDA
            WHERE ID_UNIDADE = ?
        """, (id_unidade,))

        unidade = cursor.fetchone()

        if not unidade:
            flash('Unidade não encontrada!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        unidade_escolhida = unidade[0]

        # Verificar quantidade
        if quantidade <= 0:
            flash('A quantidade deve ser maior que zero!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Converter unidades
        quantidade_necessaria = quantidade

        if unidade_escolhida == 'g' and unidade_estoque == 'Kg':
            quantidade_necessaria = quantidade / 1000

        elif unidade_escolhida == 'Kg' and unidade_estoque == 'g':
            quantidade_necessaria = quantidade * 1000

        elif unidade_escolhida == 'mL' and unidade_estoque == 'L':
            quantidade_necessaria = quantidade / 1000

        elif unidade_escolhida == 'L' and unidade_estoque == 'mL':
            quantidade_necessaria = quantidade * 1000

        elif unidade_escolhida != unidade_estoque:
            flash('Unidades incompatíveis!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Verificar estoque
        if quantidade_necessaria > estoque:
            flash(f'Estoque insuficiente de {nome}!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Verificar insumo duplicado
        cursor.execute("""
            SELECT ID_COMPOSICAO
            FROM COMPOSICAO_PRODUTO
            WHERE ID_PRODUTO = ?
            AND ID_INSUMO = ?
        """, (id_produto, id_insumo))

        if cursor.fetchone():
            flash('Esse insumo já está no produto!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # descontar do estoque somente se houver quantidade
        cursor.execute("""
        UPDATE INSUMO
        SET ESTOQUE_ATUAL = ESTOQUE_ATUAL - ?
        WHERE ID_INSUMO = ?
        AND ID_USUARIO = ?
        AND ESTOQUE_ATUAL >= ?""", (quantidade_necessaria, id_insumo, session['id_usuario'], quantidade_necessaria))

        if cursor.rowcount == 0:
            con.rollback()
            flash(f'Estoque insuficiente de {nome}!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Adicionar insumo ao produto
        cursor.execute("""
            INSERT INTO COMPOSICAO_PRODUTO
            (ID_PRODUTO, ID_INSUMO, ID_UNIDADE, QUANTIDADE)
            VALUES (?, ?, ?, ?)
        """, (id_produto, id_insumo, id_unidade, quantidade))


        if not atualizar_custo_produto(id_produto):
            con.rollback()
            flash('Erro ao calcular custo do produto', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        con.commit()

        flash('Insumo adicionado com sucesso!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        print('Erro ao adicionar insumo:', e)
        flash('Erro ao adicionar insumo!', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()

# ===================================================
# EXCLUIR INSUMO DO PRODUTO
# ===================================================
@app.route('/excluir_insumo_produto/<int:id_composicao>', methods=['POST'])
def excluir_insumo_produto(id_composicao):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Buscar insumo e produto
        cursor.execute("""
            SELECT C.ID_PRODUTO, C.ID_INSUMO,
                   C.QUANTIDADE, U1.SIGLA, U2.SIGLA
            FROM COMPOSICAO_PRODUTO C
            LEFT JOIN PRODUTO P
            ON C.ID_PRODUTO = P.ID_PRODUTO
            LEFT JOIN INSUMO I
            ON C.ID_INSUMO = I.ID_INSUMO
            LEFT JOIN UNIDADE_MEDIDA U1
            ON C.ID_UNIDADE = U1.ID_UNIDADE
            LEFT JOIN UNIDADE_MEDIDA U2
            ON I.ID_UNIDADE = U2.ID_UNIDADE
            WHERE C.ID_COMPOSICAO = ?
            AND P.ID_USUARIO = ?
            AND I.ID_USUARIO = ?
        """, (id_composicao,session['id_usuario'],session['id_usuario']))

        resultado = cursor.fetchone()

        if not resultado:
            flash('Insumo não encontrado!', 'error')
            return redirect(url_for('produtos_cadastrados'))

        id_produto = resultado[0]
        id_insumo = resultado[1]
        quantidade = resultado[2]
        unidade_usada = resultado[3]
        unidade_estoque = resultado[4]


        # Converter quantidade para unidade do estoque
        devolver = quantidade

        if unidade_usada == 'g' and unidade_estoque == 'Kg':
            devolver = quantidade / 1000

        elif unidade_usada == 'Kg' and unidade_estoque == 'g':
            devolver = quantidade * 1000

        elif unidade_usada == 'mL' and unidade_estoque == 'L':
            devolver = quantidade / 1000

        elif unidade_usada == 'L' and unidade_estoque == 'mL':
            devolver = quantidade * 1000

        elif unidade_usada != unidade_estoque:
            flash('Unidades incompatíveis!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Devolver ao estoque
        cursor.execute("""
            UPDATE INSUMO
            SET ESTOQUE_ATUAL = COALESCE(ESTOQUE_ATUAL, 0) + ?
            WHERE ID_INSUMO = ?
            AND ID_USUARIO = ?
        """, (devolver, id_insumo, session['id_usuario']))


        # Excluir da receita
        cursor.execute("""
            DELETE FROM COMPOSICAO_PRODUTO
            WHERE ID_COMPOSICAO = ?
        """, (id_composicao,))


        # Atualizar custo e preço sugerido
        if not atualizar_custo_produto(id_produto):
            con.rollback()
            flash('Erro ao calcular custo do produto!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        con.commit()

        flash('Insumo excluído e estoque atualizado!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        flash('Erro ao excluir insumo!', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()

# ===================================================
# EDITAR INSUMO DO PRODUTO
# ===================================================
@app.route('/editar_insumo_produto/<int:id_composicao>', methods=['POST'])
def editar_insumo_produto(id_composicao):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        quantidade = Decimal(request.form['quantidade'])
        id_unidade = int(request.form['id_unidade'])

        # Buscar dados do insumo
        cursor.execute("""
            SELECT C.ID_PRODUTO, C.ID_INSUMO, C.QUANTIDADE,
                   I.NOME, I.ESTOQUE_ATUAL, U.SIGLA, C.ID_UNIDADE
            FROM COMPOSICAO_PRODUTO C
            JOIN PRODUTO P ON C.ID_PRODUTO = P.ID_PRODUTO
            JOIN INSUMO I ON C.ID_INSUMO = I.ID_INSUMO
            JOIN UNIDADE_MEDIDA U ON I.ID_UNIDADE = U.ID_UNIDADE
            WHERE C.ID_COMPOSICAO = ?
            AND P.ID_USUARIO = ?
            AND I.ID_USUARIO = ?
        """, (
            id_composicao,
            session['id_usuario'],
            session['id_usuario']
        ))

        insumo = cursor.fetchone()

        if not insumo:
            flash('Insumo não encontrado!', 'error')
            return redirect(url_for('produtos_cadastrados'))

        id_produto = insumo[0]
        id_insumo = insumo[1]
        quantidade_antiga = insumo[2]
        nome = insumo[3]
        estoque = insumo[4] or Decimal('0')
        unidade_estoque = insumo[5]
        id_unidade_antiga = insumo[6]

        if quantidade <= 0:
            flash('A quantidade deve ser maior que zero!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Buscar unidades
        cursor.execute("""
            SELECT SIGLA
            FROM UNIDADE_MEDIDA
            WHERE ID_UNIDADE = ?
        """, (id_unidade,))

        unidade = cursor.fetchone()

        cursor.execute("""
            SELECT SIGLA
            FROM UNIDADE_MEDIDA
            WHERE ID_UNIDADE = ?
        """, (id_unidade_antiga,))

        unidade_antiga = cursor.fetchone()

        if not unidade or not unidade_antiga:
            flash('Unidade não encontrada!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        unidade_nova = unidade[0]
        unidade_anterior = unidade_antiga[0]

        # Converter quantidade antiga para a unidade do estoque
        quantidade_anterior = quantidade_antiga

        if unidade_anterior == 'g' and unidade_estoque == 'Kg':
            quantidade_anterior = quantidade_antiga / 1000
        elif unidade_anterior == 'Kg' and unidade_estoque == 'g':
            quantidade_anterior = quantidade_antiga * 1000
        elif unidade_anterior == 'mL' and unidade_estoque == 'L':
            quantidade_anterior = quantidade_antiga / 1000
        elif unidade_anterior == 'L' and unidade_estoque == 'mL':
            quantidade_anterior = quantidade_antiga * 1000
        elif unidade_anterior != unidade_estoque:
            flash('Unidades incompatíveis!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Converter nova quantidade para a unidade do estoque
        quantidade_nova = quantidade

        if unidade_nova == 'g' and unidade_estoque == 'Kg':
            quantidade_nova = quantidade / 1000
        elif unidade_nova == 'Kg' and unidade_estoque == 'g':
            quantidade_nova = quantidade * 1000
        elif unidade_nova == 'mL' and unidade_estoque == 'L':
            quantidade_nova = quantidade / 1000
        elif unidade_nova == 'L' and unidade_estoque == 'mL':
            quantidade_nova = quantidade * 1000
        elif unidade_nova != unidade_estoque:
            flash('Unidades incompatíveis!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Calcular diferença entre a quantidade nova e antiga
        diferenca = quantidade_nova - quantidade_anterior

        # Verificar se existe estoque para o aumento
        if diferenca > estoque:
            flash(f'Estoque insuficiente de {nome}!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Atualizar estoque somente pela diferença
        cursor.execute("""
            UPDATE INSUMO
            SET ESTOQUE_ATUAL = ESTOQUE_ATUAL - ?
            WHERE ID_INSUMO = ?
            AND ID_USUARIO = ?
        """, (diferenca, id_insumo, session['id_usuario']))

        # Atualizar quantidade e unidade
        cursor.execute("""
            UPDATE COMPOSICAO_PRODUTO
            SET QUANTIDADE = ?, ID_UNIDADE = ?
            WHERE ID_COMPOSICAO = ?
        """, (quantidade, id_unidade, id_composicao))

        # Atualizar custo e preço
        if not atualizar_custo_produto(id_produto):
            con.rollback()
            flash('Erro ao calcular custo do produto!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        con.commit()

        flash('Insumo atualizado com sucesso!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        print('Erro ao atualizar insumo:', e)
        flash('Erro ao atualizar insumo!', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()


#===================================================
# HISTÓRICO DE CUSTOS
#===================================================
@app.route('/historico_custos')
def historico_custos():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Buscar histórico de custos
        cursor.execute("""
            SELECT I.NOME,
                   H.CUSTO_ANTERIOR,
                   H.CUSTO_NOVO,
                   H.DATA_ALTERACAO
            FROM HISTORICO_CUSTO H
            LEFT JOIN INSUMO I
            ON H.ID_INSUMO = I.ID_INSUMO
            WHERE I.ID_USUARIO = ?
            ORDER BY H.DATA_ALTERACAO DESC
        """, (session['id_usuario'],))

        historico = cursor.fetchall()

        return render_template(
            'historico_custos.html',
            historico=historico,
            usuario=session['nome']
        )

    finally:
        cursor.close()


#===================================================
# FUNÇÃO - PREÇO SUGERIDO
#===================================================

def calcular_preco_sugerido(custo, margem):

    if margem < 0:
        return None

    preco = custo + (custo * margem / 100)

    return round(preco, 2)


#===================================================
# FUNÇÃO - CUSTO DO INSUMO
#===================================================

def calcular_custo_insumo(custo, quantidade, unidade_insumo, unidade_usada):

    if unidade_insumo == unidade_usada:
        return custo * quantidade

    if unidade_insumo == 'Kg' and unidade_usada == 'g':
        quantidade = quantidade / 1000

    elif unidade_insumo == 'g' and unidade_usada == 'Kg':
        quantidade = quantidade * 1000

    elif unidade_insumo == 'L' and unidade_usada == 'mL':
        quantidade = quantidade / 1000

    elif unidade_insumo == 'mL' and unidade_usada == 'L':
        quantidade = quantidade * 1000

    else:
        return None

    return custo * quantidade

#===================================================
# FUNÇÃO - ATUALIZAR CUSTO DO PRODUTO
#===================================================

def atualizar_custo_produto(id_produto):

    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT C.QUANTIDADE, I.CUSTO,
                   U1.SIGLA, U2.SIGLA
            FROM COMPOSICAO_PRODUTO C
            JOIN INSUMO I
            ON C.ID_INSUMO = I.ID_INSUMO
            JOIN UNIDADE_MEDIDA U1
            ON I.ID_UNIDADE = U1.ID_UNIDADE
            JOIN UNIDADE_MEDIDA U2
            ON C.ID_UNIDADE = U2.ID_UNIDADE
            WHERE C.ID_PRODUTO = ?
            AND COALESCE(I.ATIVO, 1) = 1
        """, (id_produto,))
        custo_total = Decimal('0')

        for quantidade, custo, unidade_insumo, unidade_usada in cursor.fetchall():

            valor = calcular_custo_insumo(custo, quantidade, unidade_insumo, unidade_usada)

            if valor is None:
                return False

            custo_total = custo_total + valor

        cursor.execute("""
            SELECT MARGEM_LUCRO
            FROM PRODUTO
            WHERE ID_PRODUTO = ?
        """, (id_produto,))

        margem = cursor.fetchone()[0]

        preco = calcular_preco_sugerido(custo_total, margem)

        if preco is None:
            return False

        cursor.execute("""
            UPDATE PRODUTO
            SET CUSTO = ?, PRECO_SUGERIDO = ?
            WHERE ID_PRODUTO = ?
        """, (round(custo_total, 2), preco, id_produto))

        return True

    finally:
        cursor.close()


#===================================================
# CADASTRAR PRODUTO
#===================================================
@app.route('/produto', methods=['GET', 'POST'])
def produto():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        if request.method == 'POST':

            nome = request.form['nome'].strip()
            descricao = request.form['descricao']
            margem = Decimal(request.form['margem'])
            tempo = int(request.form['tempo'])
            categoria = int(request.form['categoria'])

            if not nome or margem <= 0 or tempo < 0:
                flash('Verifique os dados do produto!', 'error')
                return redirect(url_for('produto'))

            # Verificar categoria
            cursor.execute("""
                SELECT ID_CATEGORIA
                FROM CATEGORIA
                WHERE ID_CATEGORIA = ?
                AND ID_USUARIO = ?
            """, (categoria, session['id_usuario']))

            if not cursor.fetchone():
                flash('Categoria inválida!', 'error')
                return redirect(url_for('produto'))

            cursor.execute("""
                            SELECT ID_PRODUTO
                            FROM produto    
                            WHERE LOWER(NOME) = LOWER(?)
                            AND ID_USUARIO = ?
                        """, (nome, session['id_usuario']))

            if cursor.fetchone():
                flash('Este produto já está cadastrado!', 'error')
                return redirect(url_for('produto'))

            # Cadastrar produto

            cursor.execute("""
                INSERT INTO PRODUTO
                (NOME, DESCRICAO, MARGEM_LUCRO,
                 TEMPO_PRODUCAO, ID_CATEGORIA,
                 ID_USUARIO, CUSTO, PRECO_SUGERIDO, ATIVO)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING ID_PRODUTO
            """, (
                nome, descricao, margem, tempo, categoria,
                session['id_usuario'], 0, 0, 1
            ))

            id_produto = cursor.fetchone()[0]

            arquivo = request.files.get('arquivo')
            if arquivo and arquivo.filename:
                if not arquivo.filename.lower().endswith(('.jpg', '.jpeg')):
                    con.rollback()
                    flash('Envie uma imagem JPG.', 'error')
                    return redirect(url_for('produto'))
                arquivo.save(os.path.join(app.config['UPLOAD_FOLDER'], f'produto{id_produto}.jpg'))

            con.commit()

            flash('Produto cadastrado com sucesso!', 'success')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Buscar insumos
        cursor.execute("""
            SELECT ID_INSUMO, NOME
            FROM INSUMO
            WHERE ID_USUARIO = ?
            AND COALESCE(ATIVO, 1) = 1
            ORDER BY NOME
        """, (session['id_usuario'],))

        insumos = cursor.fetchall()

        # Buscar categorias
        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))

        categorias = cursor.fetchall()

        # Buscar unidades
        cursor.execute("""
            SELECT ID_UNIDADE, NOME, SIGLA
            FROM UNIDADE_MEDIDA
            ORDER BY NOME
        """)

        unidades = cursor.fetchall()

        return render_template(
            'produto.html',
            usuario=session['nome'],
            insumos=insumos,
            categorias=categorias,
            unidades=unidades
        )

    except Exception as e:
        con.rollback()
        print('Erro', e)
        flash('Erro ao cadastrar produto!', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()

# ===================================================
# PRODUTOS CADASTRADOS
# ===================================================

@app.route('/produtos_cadastrados')
def produtos_cadastrados():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT ID_PRODUTO, NOME, CUSTO,
                   PRECO_SUGERIDO, MARGEM_LUCRO
            FROM PRODUTO
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))

        produtos = cursor.fetchall()

        return render_template(
            'produtos_cadastrados.html',
            produtos=produtos,
            usuario=session['nome']
        )

    except Exception as e:
        flash('Erro ao carregar os produtos!', 'error')
        return redirect(url_for('visao_geral'))

    finally:
        cursor.close()

#===================================================
# EDITAR PRODUTO
#===================================================

@app.route('/editar_produto/<int:id_produto>')
def editar_produto(id_produto):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Buscar produto
        cursor.execute("""
            SELECT ID_PRODUTO, NOME, DESCRICAO,
                   MARGEM_LUCRO, TEMPO_PRODUCAO,
                   CUSTO, PRECO_SUGERIDO
            FROM PRODUTO
            WHERE ID_PRODUTO = ?
            AND ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        produto = cursor.fetchone()

        if not produto:
            flash('Produto não encontrado!', 'error')
            return redirect(url_for('produtos_cadastrados'))

        # Buscar insumos disponíveis
        cursor.execute("""
            SELECT ID_INSUMO, NOME
            FROM INSUMO
            WHERE ID_USUARIO = ?
            AND COALESCE(ATIVO, 1) = 1
            ORDER BY NOME
        """, (session['id_usuario'],))

        insumos = cursor.fetchall()

        # Buscar unidades de medida
        cursor.execute("""
            SELECT ID_UNIDADE, NOME, SIGLA
            FROM UNIDADE_MEDIDA
            ORDER BY NOME
        """)

        unidades = cursor.fetchall()

        # Buscar ingredientes do produto
        cursor.execute("""
            SELECT C.ID_COMPOSICAO, I.NOME,
                   C.QUANTIDADE, U.SIGLA, COALESCE(I.ATIVO, 1)
            FROM COMPOSICAO_PRODUTO C
            LEFT JOIN INSUMO I
            ON C.ID_INSUMO = I.ID_INSUMO
            LEFT JOIN UNIDADE_MEDIDA U
            ON C.ID_UNIDADE = U.ID_UNIDADE
            WHERE C.ID_PRODUTO = ?
            ORDER BY I.NOME
        """, (id_produto,))

        composicao = cursor.fetchall()

        return render_template(
            'editar_produto.html',
            usuario=session['nome'],
            produto=produto,
            insumos=insumos,
            unidades=unidades,
            composicao=composicao
        )

    except Exception as e:
        flash('Erro ao carregar o produto!', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()

#===================================================
# SALVAR EDICÃO DE PRODUTOS
#===================================================

@app.route('/salvar_edicao_produto/<int:id_produto>', methods=['POST'])
def salvar_edicao_produto(id_produto):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        nome = request.form['nome'].strip()
        descricao = request.form['descricao']
        tempo = int(request.form['tempo'])
        margem = Decimal(request.form['margem'])

        # Verificar os dados
        if not nome or tempo < 0 or margem <= 0:
            flash('Verifique os dados do produto!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Verificar se o produto pertence ao usuário
        cursor.execute("""
            SELECT ID_PRODUTO
            FROM PRODUTO
            WHERE ID_PRODUTO = ?
            AND ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        if not cursor.fetchone():
            flash('Produto não encontrado!', 'error')
            return redirect(url_for('produtos_cadastrados'))

        # Atualizar produto
        cursor.execute("""
            UPDATE PRODUTO
            SET NOME = ?,
                DESCRICAO = ?,
                TEMPO_PRODUCAO = ?,
                MARGEM_LUCRO = ?
            WHERE ID_PRODUTO = ?
            AND ID_USUARIO = ?
        """, (
            nome, descricao, tempo, margem,
            id_produto, session['id_usuario']
        ))

        # Recalcular os produtos vinculados antes de confirmar a edição.
        cursor.execute("""
            SELECT DISTINCT C.ID_PRODUTO
            FROM COMPOSICAO_PRODUTO C
            JOIN PRODUTO P ON P.ID_PRODUTO = C.ID_PRODUTO
            WHERE C.ID_INSUMO = ? AND P.ID_USUARIO = ?
        """, (id, session['id_usuario']))

        if not atualizar_custo_produto(id_produto):
            raise ValueError('Não foi possível recalcular o produto.')

        con.commit()

        flash('Produto atualizado com sucesso!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        flash('Erro ao atualizar produto!', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()

# ===================================================
# EXCLUIR PRODUTO
# ===================================================

@app.route('/excluir_produto/<int:id_produto>', methods=['POST'])
def excluir_produto(id_produto):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        # Verificar se o produto pertence ao usuário
        cursor.execute("""
            SELECT ID_PRODUTO
            FROM PRODUTO
            WHERE ID_PRODUTO = ?
            AND ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        if not cursor.fetchone():
            flash('Produto não encontrado!', 'error')
            return redirect(url_for('produtos_cadastrados'))

        # Buscar ingredientes do produto
        cursor.execute("""
            SELECT C.ID_INSUMO, C.QUANTIDADE,
                   U1.SIGLA, U2.SIGLA
            FROM COMPOSICAO_PRODUTO C
            LEFT JOIN INSUMO I
            ON C.ID_INSUMO = I.ID_INSUMO
            LEFT JOIN UNIDADE_MEDIDA U1
            ON C.ID_UNIDADE = U1.ID_UNIDADE
            LEFT JOIN UNIDADE_MEDIDA U2
            ON I.ID_UNIDADE = U2.ID_UNIDADE
            WHERE C.ID_PRODUTO = ?
            AND I.ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        ingredientes = cursor.fetchall()

        # Devolver ingredientes ao estoque
        for id_insumo, quantidade, unidade_usada, unidade_estoque in ingredientes:

            devolver = quantidade

            if unidade_usada == 'g' and unidade_estoque == 'Kg':
                devolver = quantidade / 1000

            elif unidade_usada == 'Kg' and unidade_estoque == 'g':
                devolver = quantidade * 1000

            elif unidade_usada == 'mL' and unidade_estoque == 'L':
                devolver = quantidade / 1000

            elif unidade_usada == 'L' and unidade_estoque == 'mL':
                devolver = quantidade * 1000

            elif unidade_usada != unidade_estoque:
                con.rollback()
                flash('Unidades incompatíveis!', 'error')
                return redirect(url_for('produtos_cadastrados'))

            cursor.execute("""
                UPDATE INSUMO
                SET ESTOQUE_ATUAL = COALESCE(ESTOQUE_ATUAL, 0) + ?
                WHERE ID_INSUMO = ?
                AND ID_USUARIO = ?
            """, (devolver, id_insumo, session['id_usuario']))

        # Excluir ingredientes da receita
        cursor.execute("""
            DELETE FROM COMPOSICAO_PRODUTO
            WHERE ID_PRODUTO = ?
        """, (id_produto,))

        # Excluir produto
        cursor.execute("""
            DELETE FROM PRODUTO
            WHERE ID_PRODUTO = ?
            AND ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        con.commit()

        flash('Produto excluído e estoque devolvido!', 'success')
        return redirect(url_for('produtos_cadastrados'))

    except Exception as e:
        con.rollback()
        flash('Erro ao excluir produto!', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()

#===================================================
# UNIDADE DE MEDIDA
#===================================================

@app.route('/unidade_medida', methods=['GET', 'POST'])
def unidade_medida():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        if request.method == 'POST':

            nome = request.form['nome'].strip().lower()
            sigla = request.form['sigla'].strip()

            if not nome or not sigla:
                flash('Preencha todos os campos!', 'error')
                return redirect(url_for('unidade_medida'))

            cursor.execute("""
                            SELECT ID_UNIDADE
                            FROM unidade_medida
                            WHERE LOWER(NOME) = LOWER(?)
                            AND ID_USUARIO = ?
                        """, (nome, session['id_usuario']))

            if cursor.fetchone():
                flash('Unidade já cadastrada!', 'error')
                return redirect(url_for('unidade_medida'))



            cursor.execute("""
                INSERT INTO UNIDADE_MEDIDA (NOME, SIGLA)
                VALUES (?, ?)
            """, (nome, sigla))

            con.commit()

            flash('Unidade cadastrada com sucesso!', 'success')
            return redirect(url_for('insumo'))

        cursor.execute("""
            SELECT ID_UNIDADE, NOME, SIGLA
            FROM UNIDADE_MEDIDA
            ORDER BY NOME
        """)

        unidades = cursor.fetchall()

        return render_template(
            'unidade_medida.html',
            usuario=session['nome'],
            unidades=unidades
        )

    except Exception as e:
        con.rollback()
        flash('Erro ao cadastrar unidade.', 'error')
        return redirect(url_for('insumo'))

    finally:
        cursor.close()

# ===================================================
# CATEGORIA
# ===================================================
@app.route('/categoria', methods=['GET', 'POST'])
def categoria():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        if request.method == 'POST':

            nome = request.form['nome'].strip()

            if not nome:
                flash('Informe o nome da categoria!', 'error')
                return redirect(url_for('categoria'))

            cursor.execute("""
                SELECT ID_CATEGORIA
                FROM CATEGORIA
                WHERE LOWER(NOME) = LOWER(?)
                AND ID_USUARIO = ?
            """, (nome, session['id_usuario']))

            if cursor.fetchone():
                flash('Categoria já cadastrada!', 'error')
                return redirect(url_for('categoria'))

            cursor.execute("""
                INSERT INTO CATEGORIA (NOME, ID_USUARIO)
                VALUES (?, ?)
            """, (nome, session['id_usuario']))

            con.commit()

            flash('Categoria cadastrada com sucesso!', 'success')
            return redirect(url_for('insumo'))

        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))

        categorias = cursor.fetchall()

        return render_template('categoria.html',
            usuario=session['nome'],
            categorias=categorias )

    except Exception as e:
        con.rollback()
        flash('Erro ao cadastrar categoria.', 'error')
        return redirect(url_for('insumo'))

    finally:
        cursor.close()



# ===================================================
# CONFIGURAÇÃO
# ===================================================
@app.route('/configuracao')
def configuracao():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    return render_template(
        'configuracao.html',
        usuario=session['nome']
    )

# --------------------------------------------------
#  INICIALIZAÇÃO DO SISTEMA
# --------------------------------------------------


# --------------------------------------------------
# FOTO DO PRODUTO (modelo do PDF: arquivo pelo ID)
# --------------------------------------------------
@app.route('/foto_produto/<int:id_produto>', methods=['GET', 'POST'])
def foto_produto(id_produto):
    if 'id_usuario' not in session:
        return redirect(url_for('login'))
    cursor = con.cursor()
    try:
        cursor.execute("SELECT ID_PRODUTO FROM PRODUTO WHERE ID_PRODUTO = ? AND ID_USUARIO = ?",
                       (id_produto, session['id_usuario']))
        if not cursor.fetchone():
            return 'Produto não encontrado.', 404
        nome_arquivo = f'produto{id_produto}.jpg'
        if request.method == 'POST':
            arquivo = request.files.get('arquivo')
            if not arquivo or not arquivo.filename:
                flash('Selecione uma imagem JPG.', 'error')
            elif not arquivo.filename.lower().endswith(('.jpg', '.jpeg')):
                flash('Envie uma imagem JPG.', 'error')
            else:
                arquivo.save(os.path.join(app.config['UPLOAD_FOLDER'], nome_arquivo))
                flash('Foto salva com sucesso!', 'success')
            return redirect(url_for('editar_produto', id_produto=id_produto))
        if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], nome_arquivo)):
            return send_from_directory(os.path.join(app.root_path, 'static', 'img'), 'elemento-produtos.svg')
        return send_from_directory(app.config['UPLOAD_FOLDER'], nome_arquivo)
    finally:
        cursor.close()

# --------------------------------------------------
# RELATÓRIOS (FPDF e send_file, conforme o PDF da aula)
# --------------------------------------------------
@app.route('/relatorios')
def relatorios():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))
    cursor = con.cursor()
    try:
        cursor.execute("""SELECT ID_PRODUTO, NOME, CUSTO, PRECO_SUGERIDO, MARGEM_LUCRO
                          FROM PRODUTO WHERE ID_USUARIO = ? ORDER BY MARGEM_LUCRO DESC""",
                       (session['id_usuario'],))
        produtos = cursor.fetchall()
        custo_total = Decimal('0')
        receita = Decimal('0')
        for item in produtos:
            custo_total += item[2] or 0
            receita += item[3] or 0
        return render_template('relatorios.html', produtos=produtos,
                               custo_total=custo_total, receita=receita, lucro=receita-custo_total)
    finally:
        cursor.close()

@app.route('/relatorios/pdf')
def relatorio_pdf():
    if 'id_usuario' not in session:
        return redirect(url_for('login'))
    tipo = request.args.get('tipo', 'margem')
    cursor = con.cursor()
    try:
        if tipo == 'insumos':
            titulo = 'Insumos cadastrados'
            cursor.execute("""SELECT ID_INSUMO, NOME, CUSTO FROM INSUMO
                              WHERE ID_USUARIO = ? AND COALESCE(ATIVO, 1) = 1 ORDER BY NOME""",
                           (session['id_usuario'],))
        elif tipo == 'valor':
            titulo = 'Produtos por valor (maior para menor)'
            cursor.execute("""SELECT ID_PRODUTO, NOME, CUSTO, PRECO_SUGERIDO, MARGEM_LUCRO
                              FROM PRODUTO WHERE ID_USUARIO = ? ORDER BY PRECO_SUGERIDO DESC""",
                           (session['id_usuario'],))
        elif tipo == 'margem':
            titulo = 'Produtos por margem de lucro'
            cursor.execute("""SELECT ID_PRODUTO, NOME, CUSTO, PRECO_SUGERIDO, MARGEM_LUCRO
                              FROM PRODUTO WHERE ID_USUARIO = ? ORDER BY MARGEM_LUCRO DESC""",
                           (session['id_usuario'],))
        else:
            return 'Tipo de relatório inválido.', 400
        itens = cursor.fetchall()
    finally:
        cursor.close()
    if not itens:
        flash('Não há registros para gerar o relatório.', 'error')
        return redirect(url_for('relatorios'))
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font('Arial', style='B', size=16)
    pdf.cell(190, 10, titulo, ln=True, align='C')
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(5)
    for item in itens:
        # Linhas separadas mantêm os nomes de até 100 caracteres dentro da página.
        pdf.set_font('Arial', style='B', size=10)
        pdf.cell(190, 8, f'ID: {item[0]}', ln=True)
        pdf.set_font('Arial', size=9)
        pdf.cell(190, 8, item[1][:50], ln=True)
        if len(item[1]) > 50:
            pdf.cell(190, 8, item[1][50:], ln=True)
        pdf.cell(190, 8, f'Custo: R$ {item[2]:.2f}', ln=True)
        if tipo != 'insumos':
            pdf.cell(190, 8, f'Valor: R$ {item[3]:.2f} - Margem: {item[4]}%', ln=True)
        pdf.ln(5)
    pdf.set_font('Arial', style='B', size=12)
    pdf.cell(190, 10, f'Total de registros: {len(itens)}', ln=True, align='C')
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], f'relatorio_{tipo}_{session["id_usuario"]}.pdf')
    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

if __name__ == '__main__':

    app.run(debug=True)