from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb
from flask_bcrypt import Bcrypt
from decimal import Decimal

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
        cursor.execute("""
            SELECT ID_UNIDADE, NOME, SIGLA
            FROM UNIDADE_MEDIDA
            ORDER BY NOME""")
        unidades = cursor.fetchall()

        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (session['id_usuario'],))
        categorias = cursor.fetchall()

        return render_template('insumo.html',
            usuario=session['nome'],
            unidades=unidades,
            categorias=categorias)

    finally:
        cursor.close()

# --------------------------------------------------
# CADASTRO DE INSUMO
# --------------------------------------------------


@app.route('/cadastro_insumo', methods=['GET', 'POST'])
def cadastro_insumo():

    if 'id_usuario' not in session:
        flash('Faça login para cadastrar um insumo!', 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return redirect(url_for('insumo'))

    cursor = con.cursor()

    try:
        nome = request.form['nome'].strip()
        custo = Decimal(request.form['custo'])
        unidade_medida = request.form['unidade_medida']
        categoria = request.form['categoria']
        id_usuario = session['id_usuario']

        # Receber estoque informado no formulário
        estoque_atual = Decimal(request.form['estoque_atual'])

        if not nome or not unidade_medida or not categoria:
            flash('Preencha todos os campos!', 'error')
            return redirect(url_for('insumo'))

        if not custo.is_finite() or custo <= 0:
            flash('O custo precisa ser maior que zero!', 'error')
            return redirect(url_for('insumo'))

        # Estoque não pode ser negativo
        if not estoque_atual.is_finite() or estoque_atual < 0:
            flash('O estoque não pode ser negativo!', 'error')
            return redirect(url_for('insumo'))

        # Impedir nomes duplicados
        cursor.execute("""
            SELECT ID_INSUMO
            FROM INSUMO
            WHERE LOWER(NOME) = ?
              AND ID_USUARIO = ?
        """, (nome.lower(), id_usuario))

        if cursor.fetchone():
            flash('Este insumo já está cadastrado!', 'error')
            return redirect(url_for('insumo'))

        # Cadastrar insumo com estoque
        cursor.execute("""
            INSERT INTO INSUMO
                (NOME, CUSTO, ID_USUARIO, ID_UNIDADE,
                 ID_CATEGORIA, ESTOQUE_ATUAL)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            nome,
            custo,
            id_usuario,
            unidade_medida,
            categoria,
            estoque_atual
        ))

        con.commit()

        flash('Insumo cadastrado com sucesso!', 'success')
        return redirect(url_for('insumos_cadastrados'))


    except Exception as e:
        con.rollback()
        flash('Não foi possível cadastrar o insumo.', 'error')
        return redirect(url_for('insumo'))

    finally:
        cursor.close()


# --------------------------------------------------
# INSUMOS CADASTRADOS
# --------------------------------------------------

@app.route('/insumos_cadastrados')
def insumos_cadastrados():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    cursor.execute("""
        SELECT ID_INSUMO, NOME
        FROM INSUMO
        WHERE ID_USUARIO = ?
        ORDER BY NOME
    """, (session['id_usuario'],))

    insumos = cursor.fetchall()
    cursor.close()

    return render_template('insumo_cadastrado.html', insumos=insumos)

# --------------------------------------------------
# EDITAR INSUMO
# --------------------------------------------------



@app.route('/editar_insumo/<int:id>', methods=['GET', 'POST'])
def editar_insumo(id):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()

    try:
        # Buscar o insumo, incluindo o estoque atual
        cursor.execute("""
            SELECT ID_INSUMO, NOME, CUSTO, ID_UNIDADE,
                   ID_CATEGORIA, ESTOQUE_ATUAL
            FROM INSUMO
            WHERE ID_INSUMO = ? AND ID_USUARIO = ?
        """, (id, id_usuario))

        insumo = cursor.fetchone()

        if not insumo:
            flash('Insumo não encontrado!', 'error')
            return redirect(url_for('insumos_cadastrados'))

        # Guardar o custo anterior
        custo_anterior = insumo[2]

        if request.method == 'POST':

            nome = request.form['nome'].strip()
            custo = Decimal(request.form['custo'])
            estoque_atual = Decimal(request.form['estoque_atual'])
            unidade_medida = request.form['unidade_medida']
            categoria = request.form['categoria']

            # Verificar campos vazios
            if not nome or not unidade_medida or not categoria:
                flash('Preencha todos os campos!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Validar custo
            if not custo.is_finite() or custo <= 0:
                flash('O custo deve ser maior que zero!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Validar estoque
            if not estoque_atual.is_finite() or estoque_atual < 0:
                flash('O estoque não pode ser negativo!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Verificar nome duplicado
            cursor.execute("""
                SELECT ID_INSUMO
                FROM INSUMO
                WHERE LOWER(NOME) = LOWER(?)
                  AND ID_USUARIO = ?
                  AND ID_INSUMO <> ?
            """, (nome, id_usuario, id))

            if cursor.fetchone():
                flash('Este insumo já está cadastrado!', 'error')
                return redirect(url_for('editar_insumo', id=id))

            # Registrar histórico se o custo mudar
            if round(Decimal(str(custo_anterior)), 2) != round(custo, 2):
                cursor.execute("""
                    INSERT INTO HISTORICO_CUSTO
                    (ID_INSUMO, CUSTO_ANTERIOR, CUSTO_NOVO, DATA_ALTERACAO)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (id, custo_anterior, custo))

            # Atualizar o insumo e seu estoque
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
                unidade_medida,
                categoria,
                estoque_atual,
                id,
                id_usuario
            ))

            con.commit()

            flash('Insumo atualizado com sucesso!', 'success')
            return redirect(url_for('insumos_cadastrados'))

        # Buscar todos os insumos do usuário
        cursor.execute("""
            SELECT ID_INSUMO, NOME
            FROM INSUMO
            WHERE ID_USUARIO = ?
            ORDER BY NOME
        """, (id_usuario,))

        insumos = cursor.fetchall()

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
        """, (id_usuario,))

        categorias = cursor.fetchall()

        return render_template(
            'editar_insumo.html',
            insumo=insumo,
            insumos=insumos,
            unidades=unidades,
            categorias=categorias
        )

    except Exception as e:
        con.rollback()
        print('Erro ao atualizar insumo:', e)

        flash('Não foi possível atualizar o insumo.', 'error')
        return redirect(url_for('insumos_cadastrados'))

    finally:
        cursor.close()



#===================================================
# EXCLUIR INSUMO
#===================================================
@app.route('/excluir_insumo/<int:id>', methods=['POST'])
def excluir_insumo(id):

    if 'id_usuario' not in session:
        flash('Precisa estar logado', 'error')
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

        if cursor.fetchone() is None:
            flash('Insumo não encontrado!', 'error')
            return redirect(url_for('insumos_cadastrados'))

        # Verificar se está vinculado a algum produto
        cursor.execute("""
            SELECT ID_COMPOSICAO
            FROM COMPOSICAO_PRODUTO
            WHERE ID_INSUMO = ?
        """, (id,))

        if cursor.fetchone():
            flash('Não é possível excluir um insumo vinculado a um produto.', 'error')
            return redirect(url_for('insumos_cadastrados'))

        # Apagar o histórico de custos
        cursor.execute("""
            DELETE FROM HISTORICO_CUSTO
            WHERE ID_INSUMO = ?
        """, (id,))

        # Apagar o insumo definitivamente
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

        # Verificar se o produto pertence ao usuário
        cursor.execute("""
            SELECT ID_PRODUTO
            FROM PRODUTO
            WHERE ID_PRODUTO = ? AND ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        if cursor.fetchone() is None:
            flash('Produto não encontrado.', 'error')
            return redirect(url_for('produtos_cadastrados'))

        # Verificar se o insumo pertence ao usuário
        # Buscar também o estoque e a unidade cadastrada
        cursor.execute("""
            SELECT I.ID_INSUMO,
                   I.NOME,
                   I.ESTOQUE_ATUAL,
                   U.SIGLA
            FROM INSUMO I
            LEFT JOIN UNIDADE_MEDIDA U
                ON I.ID_UNIDADE = U.ID_UNIDADE
            WHERE I.ID_INSUMO = ?
              AND I.ID_USUARIO = ?
        """, (id_insumo, session['id_usuario']))

        insumo = cursor.fetchone()

        if insumo is None:
            flash('Insumo não encontrado.', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        nome_insumo = insumo[1]

        estoque = insumo[2]
        if estoque is None:
            estoque = 0

        unidade_estoque = insumo[3]

        # Buscar unidade escolhida no formulário
        cursor.execute("""
            SELECT SIGLA
            FROM UNIDADE_MEDIDA
            WHERE ID_UNIDADE = ?
        """, (id_unidade,))

        unidade = cursor.fetchone()

        if unidade is None:
            flash('Unidade não encontrada.', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        unidade_escolhida = unidade[0]

        # Validar quantidade
        if not quantidade or quantidade <= 0:
            flash('Informe uma quantidade maior que zero.', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Converter a quantidade para a unidade do estoque
        quantidade_necessaria = quantidade

        if unidade_escolhida == 'g' and unidade_estoque == 'Kg':
            quantidade_necessaria = quantidade / Decimal('1000')

        elif unidade_escolhida == 'Kg' and unidade_estoque == 'g':
            quantidade_necessaria = quantidade * Decimal('1000')

        elif unidade_escolhida == 'mL' and unidade_estoque == 'L':
            quantidade_necessaria = quantidade / Decimal('1000')

        elif unidade_escolhida == 'L' and unidade_estoque == 'mL':
            quantidade_necessaria = quantidade * Decimal('1000')

        elif unidade_escolhida != unidade_estoque:
            flash('Unidades incompatíveis com o estoque do insumo.', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Verificar estoque disponível
        if quantidade_necessaria > estoque:
            print("maior que o estoque")
            flash(f'Estoque insuficiente de {nome_insumo}! 'f'Disponível: {estoque} {unidade_estoque}.','error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        # Verificar se o insumo ja foi adicionado

        cursor.execute("""SELECT ID_COMPOSICAO 
                        FROM COMPOSICAO_PRODUTO
                        WHERE ID_PRODUTO = ? AND ID_INSUMO = ?""",(id_produto, id_insumo))

        if cursor.fetchone():
            flash('Esse insumo já está sendo utilizado!', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))






        # Adicionar insumo ao produto
        cursor.execute("""
            INSERT INTO COMPOSICAO_PRODUTO
                (ID_PRODUTO, ID_INSUMO, ID_UNIDADE, QUANTIDADE)
            VALUES (?, ?, ?, ?)
        """, (id_produto, id_insumo, id_unidade, quantidade))

        # Atualizar custo e preço sugerido
        atualizar_custo_produto(id_produto)

        con.commit()

        flash('Insumo adicionado com sucesso!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        flash('Erro ao adicionar insumo.', 'error')
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
        cursor.execute("""
            SELECT C.ID_PRODUTO
            FROM COMPOSICAO_PRODUTO C
            LEFT JOIN PRODUTO P
                ON C.ID_PRODUTO = P.ID_PRODUTO
            WHERE C.ID_COMPOSICAO = ?
              AND P.ID_USUARIO = ?
        """, (id_composicao, session['id_usuario']))

        resultado = cursor.fetchone()

        if resultado is None:
            flash('Insumo não encontrado.', 'error')
            return redirect(url_for('produtos_cadastrados'))

        id_produto = resultado[0]

        cursor.execute("""
            DELETE FROM COMPOSICAO_PRODUTO
            WHERE ID_COMPOSICAO = ?
        """, (id_composicao,))

        atualizar_custo_produto(id_produto)

        con.commit()

        flash('Insumo removido com sucesso!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        flash('Erro ao excluir insumo.', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()


# ==============================================
# EDITAR INSUMO DO PRODUTO
# ==============================================
@app.route('/editar_insumo_produto/<int:id_composicao>', methods=['POST'])
def editar_insumo_produto(id_composicao):

    if 'id_usuario' not in session:
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        quantidade = Decimal(request.form['quantidade'])
        id_unidade = int(request.form['id_unidade'])

        if not quantidade.is_finite() or quantidade <= 0:
            flash('A quantidade deve ser maior que zero.', 'error')
            return redirect(url_for('produtos_cadastrados'))

        cursor.execute("""
        SELECT C.ID_PRODUTO,
        I.NOME,
        I.ESTOQUE_ATUAL,
        U.SIGLA
        FROM COMPOSICAO_PRODUTO C
        LEFT JOIN PRODUTO P
        ON C.ID_PRODUTO = P.ID_PRODUTO
        LEFT JOIN INSUMO I
        ON C.ID_INSUMO = I.ID_INSUMO
        LEFT JOIN UNIDADE_MEDIDA U
        ON I.ID_UNIDADE = U.ID_UNIDADE
        WHERE C.ID_COMPOSICAO = ?
        AND P.ID_USUARIO = ?
        AND I.ID_USUARIO = ?
        """, (
        id_composicao,
        session['id_usuario'],
        session['id_usuario']
        ))

        resultado = cursor.fetchone()

        if resultado is None:
            flash('Insumo não encontrado.', 'error')
            return redirect(url_for('produtos_cadastrados'))

        id_produto = resultado[0]
        nome_insumo = resultado[1]
        estoque = Decimal(str(resultado[2])) if resultado[2] is not None else Decimal('0')
        unidade_estoque = resultado[3]

        cursor.execute("""
        SELECT SIGLA
        FROM UNIDADE_MEDIDA
        WHERE ID_UNIDADE = ?
        """, (id_unidade,))

        unidade = cursor.fetchone()

        if unidade is None:
            flash('Unidade inválida.', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        unidade_escolhida = unidade[0]
        quantidade_necessaria = quantidade

        if unidade_escolhida == 'g' and unidade_estoque == 'Kg':
            quantidade_necessaria = quantidade / Decimal('1000')

        elif unidade_escolhida == 'Kg' and unidade_estoque == 'g':
            quantidade_necessaria = quantidade * Decimal('1000')

        elif unidade_escolhida == 'mL' and unidade_estoque == 'L':
            quantidade_necessaria = quantidade / Decimal('1000')

        elif unidade_escolhida == 'L' and unidade_estoque == 'mL':
            quantidade_necessaria = quantidade * Decimal('1000')

        elif unidade_escolhida != unidade_estoque:
            flash('Unidades incompatíveis com o estoque.', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        if quantidade_necessaria > estoque:
            flash(f'Estoque insuficiente de {nome_insumo}! 'f'Disponível: {estoque} {unidade_estoque}.','error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

        cursor.execute("""
        UPDATE COMPOSICAO_PRODUTO
        SET QUANTIDADE = ?, ID_UNIDADE = ?
        WHERE ID_COMPOSICAO = ?
        """, (quantidade, id_unidade, id_composicao))

        atualizar_custo_produto(id_produto)

        con.commit()

        flash('Insumo atualizado com sucesso!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        flash('Erro ao atualizar insumo.', 'error')
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
        cursor.execute("""
            SELECT
                I.NOME,
                H.CUSTO_ANTERIOR,
                H.CUSTO_NOVO,
                H.DATA_ALTERACAO
            FROM HISTORICO_CUSTO H
            LEFT JOIN INSUMO I ON H.ID_INSUMO = I.ID_INSUMO
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

    custo = Decimal(str(custo))
    margem = Decimal(str(margem))

    if margem < 0 or margem >= 100:
        return None

    preco = (custo / (1 - margem / 100))

    return round(preco, 2)

#===================================================
# FUNÇÃO - CUSTO DO INSUMO
#===================================================

def calcular_custo_insumo(custo, quantidade, unidade_insumo, unidade_usada):

    if unidade_insumo == 'Kg' and unidade_usada == 'g':
        quantidade = quantidade / Decimal('1000')

    elif unidade_insumo == 'L' and unidade_usada == 'mL':
        quantidade = quantidade / Decimal('1000')

    elif unidade_insumo == 'g' and unidade_usada == 'Kg':
        quantidade = quantidade * Decimal('1000')

    elif unidade_insumo == 'mL' and unidade_usada == 'L':
        quantidade = quantidade * Decimal('1000')

    elif unidade_insumo != unidade_usada:
        return None

    return custo * quantidade

#===================================================
# FUNÇÃO - ATUALIZAR CUSTO DO PRODUTO
#===================================================

def atualizar_custo_produto(id_produto):
    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT C.QUANTIDADE, I.CUSTO, U1.SIGLA, U2.SIGLA
            FROM COMPOSICAO_PRODUTO C
            LEFT JOIN INSUMO I ON C.ID_INSUMO = I.ID_INSUMO
            LEFT JOIN UNIDADE_MEDIDA U1 ON I.ID_UNIDADE = U1.ID_UNIDADE
            LEFT JOIN UNIDADE_MEDIDA U2 ON C.ID_UNIDADE = U2.ID_UNIDADE
            WHERE C.ID_PRODUTO = ?
        """, (id_produto,))

        custo_total = Decimal('0')

        for quantidade, custo, unidade_insumo, unidade_usada in cursor.fetchall():
            valor = calcular_custo_insumo(
                Decimal(str(custo)),
                Decimal(str(quantidade)),
                unidade_insumo,
                unidade_usada
            )

            if valor is None:
                raise ValueError('Unidades incompatíveis.')

            custo_total += valor

        cursor.execute("""
            SELECT MARGEM_LUCRO
            FROM PRODUTO
            WHERE ID_PRODUTO = ?
        """, (id_produto,))

        margem = Decimal(str(cursor.fetchone()[0]))
        preco = custo_total / (1 - margem / 100)

        cursor.execute("""
            UPDATE PRODUTO
            SET CUSTO = ?, PRECO_SUGERIDO = ?
            WHERE ID_PRODUTO = ?
        """, (round(custo_total, 2), round(preco, 2), id_produto))

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

            if not nome or margem < 0 or margem >= 100 or tempo < 0:
                flash('Verifique os dados do produto.', 'error')
                return redirect(url_for('produto'))

            cursor.execute("""
                INSERT INTO PRODUTO
                (NOME, DESCRICAO, MARGEM_LUCRO,
                 TEMPO_PRODUCAO, ID_CATEGORIA,
                 ID_USUARIO, CUSTO, PRECO_SUGERIDO, ATIVO)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                nome,
                descricao,
                margem,
                tempo,
                categoria,
                session['id_usuario'],
                Decimal('0.00'),
                Decimal('0.00'),
                1
            ))

            con.commit()

            flash('Produto cadastrado com sucesso!', 'success')
            return redirect(url_for('produtos_cadastrados'))

        cursor.execute("""
            SELECT ID_INSUMO, NOME
            FROM INSUMO
            WHERE ID_USUARIO = ?
        """, (session['id_usuario'],))

        insumos = cursor.fetchall()

        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
        """)

        categorias = cursor.fetchall()

        return render_template(
            'produto.html',
            usuario=session['nome'],
            insumos=insumos,
            categorias=categorias
        )

    except Exception as e:
        con.rollback()
        flash('Erro ao cadastrar produto.', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()


#===================================================
# PRODUTOS CADASTRADOS
#===================================================

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
        # Buscar o produto do usuário
        cursor.execute("""
            SELECT ID_PRODUTO, NOME, DESCRICAO,
                   MARGEM_LUCRO, TEMPO_PRODUCAO,
                   CUSTO, PRECO_SUGERIDO
            FROM PRODUTO
            WHERE ID_PRODUTO = ?
              AND ID_USUARIO = ?
        """, (id_produto, session['id_usuario']))

        produto = cursor.fetchone()

        if produto is None:
            flash('Produto não encontrado.', 'error')
            return redirect(url_for('produtos_cadastrados'))

        # Buscar insumos disponíveis
        cursor.execute("""
            SELECT ID_INSUMO, NOME
            FROM INSUMO
            WHERE ID_USUARIO = ?
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

        # Buscar ingredientes já utilizados
        cursor.execute("""
            SELECT C.ID_COMPOSICAO,
                   I.NOME,
                   C.QUANTIDADE,
                   U.SIGLA
            FROM COMPOSICAO_PRODUTO C
            LEFT JOIN INSUMO I
                ON I.ID_INSUMO = C.ID_INSUMO
            LEFT JOIN UNIDADE_MEDIDA U
                ON U.ID_UNIDADE = C.ID_UNIDADE
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
        print('Erro ao abrir produto:', e)
        flash('Erro ao carregar o produto.', 'error')
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

        if not nome or tempo < 0 or margem < 0 or margem >= 100:
            flash('Verifique os dados do produto.', 'error')
            return redirect(url_for('editar_produto', id_produto=id_produto))

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

        if cursor.rowcount == 0:
            con.rollback()
            flash('Produto não encontrado.', 'error')
            return redirect(url_for('produtos_cadastrados'))

        # Recalcular o preço com a nova margem
        atualizar_custo_produto(id_produto)

        con.commit()

        flash('Produto atualizado com sucesso!', 'success')
        return redirect(url_for('editar_produto', id_produto=id_produto))

    except Exception as e:
        con.rollback()
        flash('Erro ao atualizar produto.', 'error')
        return redirect(url_for('produtos_cadastrados'))

    finally:
        cursor.close()




#===================================================
# CATEGORIA
#===================================================

@app.route('/categoria', methods=['GET', 'POST'])
def categoria():

    # Verifica se o usuário está logado
    if 'id_usuario' not in session:
        flash('Faça login para acessar as categorias!', 'error')
        return redirect(url_for('login'))

    cursor = con.cursor()

    try:
        if request.method == 'POST':

            nome = request.form['nome'].strip()

            if not nome:
                flash('Informe o nome da categoria!', 'error')
                return redirect(url_for('categoria'))

            # Verifica se já existe uma categoria com esse nome
            cursor.execute("""
                SELECT ID_CATEGORIA
                FROM CATEGORIA
                WHERE LOWER(NOME) = LOWER(?)
                  AND ID_USUARIO = ?
            """, (nome, session['id_usuario']))

            if cursor.fetchone():
                flash('Essa categoria já está cadastrada!', 'error')
                return redirect(url_for('categoria'))

            # Salva a categoria no banco
            cursor.execute("""
                INSERT INTO CATEGORIA (NOME, ID_USUARIO)
                VALUES (?, ?)""",
                (nome, session['id_usuario']))

            con.commit()

            flash('Categoria cadastrada com sucesso!', 'success')
            return redirect(url_for('categoria'))

        # Lista as categorias do usuário logado
        cursor.execute("""
            SELECT ID_CATEGORIA, NOME
            FROM CATEGORIA
            WHERE ID_USUARIO = ?
            ORDER BY NOME""",
            (session['id_usuario'],))

        categorias = cursor.fetchall()
        return render_template('categoria.html',usuario=session['nome'], categorias=categorias)


    except Exception as e:

        con.rollback()
        flash(f'Erro ao processar categoria: {e}', 'error')
        return render_template('categoria.html',usuario=session['nome'],categorias=[])

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

            nome = request.form['nome'].strip()
            sigla = request.form['sigla'].strip()

            if not nome or not sigla:
                flash('Preencha o nome e a sigla da unidade!', 'error')
                return redirect(url_for('unidade_medida'))

            cursor.execute("""
                INSERT INTO UNIDADE_MEDIDA (NOME, SIGLA)
                VALUES (?, ?)""",
                (nome, sigla))

            con.commit()

            flash('Unidade cadastrada com sucesso!', 'success')
            return redirect(url_for('unidade_medida'))

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
        flash(f'Erro ao cadastrar unidade: {e}', 'error')
        return redirect(url_for('unidade_medida'))

    finally:
        cursor.close()


# ===================================================
# CONFIGURAÇÃO
# ===================================================
@app.route('/configuracao', methods=['GET'])
def configuracao():

    if 'id_usuario' not in session:
        return redirect(url_for('login'))
    return render_template('configuracao.html',usuario=session['nome'])


# --------------------------------------------------
#  INICIALIZAÇÃO DO SISTEMA
# --------------------------------------------------

if __name__ == '__main__':

    app.run(debug=True)