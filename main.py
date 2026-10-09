# ==========================================================
# 1 - IMPORTAÇÃO DAS BIBLIOTECAS
# ==========================================================

# Flask: cria o sistema web.
# render_template: abre as páginas HTML.
# request: recebe os dados dos formulários.
# flash: exibe mensagens para o usuário.
# redirect: redireciona para outra página.
# url_for: identifica o endereço de uma rota.
# session: armazena os dados do usuário logado.

from flask import Flask, render_template, request, flash, redirect, url_for, session

# Biblioteca utilizada para conectar ao Firebird.
import fdb

# Biblioteca utilizada para gerar e verificar hashes de senhas.
from flask_bcrypt import Bcrypt


# ==========================================================
# 2 - CONFIGURAÇÃO DO FLASK
# ==========================================================

# Cria a aplicação Flask.
app = Flask(__name__)

# Inicializa o Bcrypt.
bcrypt = Bcrypt(app)

# Chave utilizada para proteger a sessão.
# Em produção, deve ser secreta e não ficar fixa no código.
app.config['SECRET_KEY'] = 'chave_secreta_lucrafy'


# ==========================================================
# 3 - CONEXÃO COM O BANCO DE DADOS
# ==========================================================

# Endereço do servidor Firebird.
host = 'localhost'

# Caminho onde está armazenado o banco.
database = r'E:\SENAI 2026\BANCO\BANCO.FDB'

# Credenciais de acesso ao banco.
user = 'sysdba'
password = 'sysdba'

# Realiza a conexão com o Firebird.
con = fdb.connect(
    host=host,
    database=database,
    user=user,
    password=password
)


# ==========================================================
# 4 - VERIFICAÇÃO DE SENHA FORTE
# ==========================================================

# Esta função verifica se a senha atende aos requisitos:
#
# - Mínimo de 8 caracteres.
# - Pelo menos uma letra maiúscula.
# - Pelo menos uma letra minúscula.
# - Pelo menos um número.
# - Pelo menos um símbolo permitido.
# - Não pode conter espaços.
#
# True = senha válida.
# False = senha inválida.

def senha_forte(senha):

    # Verifica se a senha possui pelo menos 8 caracteres.
    if len(senha) < 8:
        return False

    # Impede senhas que contenham espaços.
    if ' ' in senha:
        return False

    # Variáveis utilizadas para identificar
    # os tipos de caracteres encontrados.
    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_especial = False

    # Percorre cada caractere da senha.
    for caractere in senha:

        # Verifica letras maiúsculas de A até Z.
        if caractere >= 'A' and caractere <= 'Z':
            tem_maiuscula = True

        # Verifica letras minúsculas de a até z.
        elif caractere >= 'a' and caractere <= 'z':
            tem_minuscula = True

        # Verifica números de 0 até 9.
        elif caractere >= '0' and caractere <= '9':
            tem_numero = True

        # Verifica os símbolos permitidos.
        elif caractere in '!@#$%&*_-':
            tem_especial = True

    # Todas as condições precisam ser verdadeiras.
    if (tem_maiuscula and tem_minuscula and tem_numero and tem_especial):
        return True

    # Se alguma condição não for atendida,
    # a senha será recusada.
    return False


# ==========================================================
# 5 - PÁGINA INICIAL
# ==========================================================

# Define a rota inicial do sistema.
@app.route('/')
def index():

    # Abre a página index.html.
    return render_template('index.html')


# ==========================================================
# 6 - HOME
# ==========================================================

# Página principal após o login.
@app.route('/home')
def home():

    # Verifica se o usuário está logado.
    if 'id_usuario' not in session:

        # Se não estiver, retorna para o login.
        return redirect(url_for('login'))

    # Abre a Home e envia o nome do usuário.
    return render_template(
        'home.html',
        usuario=session['nome']
    )


# ==========================================================
# 7 - LOGOUT
# ==========================================================

# Função utilizada para sair da conta.
@app.route('/logout')
def logout():

    # Remove os dados de autenticação da sessão.
    session.pop('id_usuario', None)
    session.pop('nome', None)

    # Exibe a mensagem de saída.
    flash('Você saiu da sua conta!')

    # Retorna para a página de login.
    return redirect(url_for('login'))


# ==========================================================
# 8 - CADASTRO DE USUÁRIOS
# ==========================================================

# GET: abre o formulário.
# POST: recebe os dados e realiza o cadastro.
@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():

    # Verifica se o formulário foi enviado.
    if request.method == 'POST':

        # Recebe os dados digitados.
        nome = request.form['nome']

        # strip() remove espaços das extremidades.
        # lower() transforma o e-mail em minúsculas.
        email = request.form['email'].strip().lower()
        senha = request.form['senha']
        confirmar_senha = request.form['confirmar_senha']
        mao_de_obra = request.form['mao_de_obra']

        # --------------------------------------------------
        # VERIFICAR CAMPOS OBRIGATÓRIOS
        # --------------------------------------------------

        # Impede o cadastro se algum campo estiver vazio.
        if not nome or not email or not senha or not mao_de_obra:

            flash('Preencha todos os campos!')

            return redirect(url_for('cadastro'))

        # --------------------------------------------------
        # VERIFICAR SENHA FORTE
        # --------------------------------------------------

        # Chama a função senha_forte.
        if not senha_forte(senha):

            flash('A senha deve ter pelo menos 8 caracteres, letra maiúscula, minúscula, número, símbolo e não conter espaços.')

            return redirect(url_for('cadastro'))

        # --------------------------------------------------
        # CONFIRMAR SENHA
        # --------------------------------------------------

        # Verifica se a senha e a confirmação são iguais.
        if confirmar_senha != senha:

            flash('As senhas precisam ser iguais!')

            return redirect(url_for('cadastro'))

        # Cria o cursor para executar comandos SQL.
        cursor = con.cursor()

        try:

            # --------------------------------------------------
            # VERIFICAR E-MAIL DUPLICADO
            # --------------------------------------------------

            # Consulta se o e-mail já existe no banco.
            cursor.execute("""
                SELECT ID_USUARIO
                FROM USUARIO
                WHERE LOWER(EMAIL) = ?
            """, (email,))

            # fetchone() retorna o primeiro registro.
            # Se encontrar um usuário, impede o cadastro.
            if cursor.fetchone():

                flash('Este e-mail já está cadastrado!')

                return redirect(url_for('cadastro'))

            # --------------------------------------------------
            # GERAR HASH DA SENHA
            # --------------------------------------------------

            # O Bcrypt protege a senha criando um hash.
            # A senha original não é salva no banco.
            senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

            # --------------------------------------------------
            # INSERIR USUÁRIO
            # --------------------------------------------------

            # INSERT INTO adiciona um novo registro.
            # Os ? recebem os valores das variáveis.
            cursor.execute("""
                INSERT INTO USUARIO
                (NOME, EMAIL, SENHA, MAO_DE_OBRA)
                VALUES (?, ?, ?, ?)
            """, (nome, email, senha_hash, mao_de_obra))

            # Confirma o cadastro no banco.
            con.commit()

            # Exibe mensagem de sucesso.
            flash('Cadastro realizado com sucesso!')

            return redirect(url_for('cadastro'))

        # Trata possíveis erros.
        except Exception:

            # Desfaz alterações não confirmadas.
            con.rollback()

            flash('Erro ao cadastrar usuário.')

            return redirect(url_for('cadastro'))

        finally:

            # Fecha o cursor.
            cursor.close()

    # Abre o formulário quando a requisição for GET.
    return render_template('cadastro.html')


# ==========================================================
# 9 - LOGIN
# ==========================================================

# Esta função:
#
# 1. Recebe o e-mail e a senha.
# 2. Procura o usuário no banco.
# 3. Verifica se o usuário está ativo.
# 4. Verifica as tentativas de login.
# 5. Confere a senha utilizando Bcrypt.
# 6. Cria a sessão quando o login é correto.
# 7. Desativa o usuário após três erros.

@app.route('/login', methods=['GET', 'POST'])
def login():

    # Verifica se o formulário foi enviado.
    if request.method == 'POST':

        # Recebe os dados digitados.
        email = request.form['email'].strip().lower()
        senha = request.form['senha']

        # Cria o cursor para acessar o banco.
        cursor = con.cursor()

        try:

            # --------------------------------------------------
            # CONSULTAR USUÁRIO
            # --------------------------------------------------

            # Busca os dados do usuário pelo e-mail.
            #
            # usuario[0] = ID
            # usuario[1] = Nome
            # usuario[2] = Hash da senha
            # usuario[3] = Ativo
            # usuario[4] = Tentativas de login

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

            # Recebe o primeiro usuário encontrado.
            usuario = cursor.fetchone()

            # --------------------------------------------------
            # VERIFICAR SE O USUÁRIO EXISTE
            # --------------------------------------------------

            # Se não encontrar o e-mail, recusa o login.
            if not usuario:

                flash('Email ou senha incorretos!')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # VERIFICAR SE ESTÁ ATIVO
            # --------------------------------------------------

            # ATIVO = 1 significa usuário ativo.
            # ATIVO = 0 significa usuário inativo.
            if usuario[3] == 0:

                flash('Usuário inativo!')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # VERIFICAR BLOQUEIO
            # --------------------------------------------------

            # Se já atingiu três tentativas,
            # o usuário não poderá entrar.
            if usuario[4] >= 3:

                flash('Usuário bloqueado após 3 tentativas!')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # VERIFICAR SENHA
            # --------------------------------------------------

            # Compara a senha digitada com o hash salvo.
            if bcrypt.check_password_hash(usuario[2], senha):

                # --------------------------------------------------
                # LOGIN CORRETO
                # --------------------------------------------------

                # Zera as tentativas de login.
                cursor.execute("""
                    UPDATE usuario
                    SET tentativas_login = 0
                    WHERE id_usuario = ?
                """, (usuario[0],))

                # Confirma a alteração.
                con.commit()

                # Guarda os dados do usuário na sessão.
                session['id_usuario'] = usuario[0]
                session['nome'] = usuario[1]

                # Redireciona para a Home.
                return redirect(url_for('home'))

            # --------------------------------------------------
            # LOGIN INCORRETO
            # --------------------------------------------------

            else:

                # Soma uma tentativa ao contador anterior.
                tentativas = usuario[4] + 1

                # --------------------------------------------------
                # DESATIVAR APÓS TRÊS TENTATIVAS
                # --------------------------------------------------

                # Quando chega a três erros,
                # atualiza ATIVO para 0.
                if tentativas >= 3:

                    cursor.execute("""
                        UPDATE usuario
                        SET tentativas_login = ?,
                            ativo = 0
                        WHERE id_usuario = ?
                    """, (tentativas, usuario[0]))

                    # Salva as alterações no banco.
                    con.commit()

                    flash('Usuário bloqueado após 3 tentativas!')

                # --------------------------------------------------
                # MENOS DE TRÊS TENTATIVAS
                # --------------------------------------------------

                else:

                    # Atualiza somente a quantidade de erros.
                    cursor.execute("""
                        UPDATE usuario
                        SET tentativas_login = ?
                        WHERE id_usuario = ?
                    """, (tentativas, usuario[0]))

                    # Salva o contador.
                    con.commit()

                    flash('Senha incorreta!')

                # Retorna para o login.
                return redirect(url_for('login'))

        # --------------------------------------------------
        # TRATAMENTO DE ERROS
        # --------------------------------------------------

        except Exception as e:

            # Desfaz alterações pendentes.
            con.rollback()

            # Exibe a descrição do erro.
            flash(f'Ocorreu um erro -> {e}')

            return redirect(url_for('login'))

        finally:

            # Fecha o cursor.
            cursor.close()

    # Abre a página de login.
    return render_template('login.html')


# ==========================================================
# 10 - EDITAR USUÁRIO
# ==========================================================

# Permite editar:
# - Nome
# - E-mail
# - Valor da mão de obra
#
# O ID é recebido pela URL.
@app.route('/editar/<int:id>', methods=['GET', 'POST'])
def editar(id):

    # --------------------------------------------------
    # VERIFICAR LOGIN
    # --------------------------------------------------

    # Impede que usuários não logados acessem a edição.
    if 'id_usuario' not in session:

        flash('Precisa estar logado')

        return redirect(url_for('login'))

    # --------------------------------------------------
    # VERIFICAR PERMISSÃO
    # --------------------------------------------------

    # O usuário só pode editar os próprios dados.
    if id != session['id_usuario']:

        flash('Você não pode editar outro usuário')

        return redirect(url_for('home'))

    # Cria o cursor.
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

        # Recebe os dados encontrados.
        usuario = cursor.fetchone()

        # --------------------------------------------------
        # VERIFICAR SE EXISTE
        # --------------------------------------------------

        if not usuario:

            flash("Usuário não encontrado")

            return redirect(url_for('home'))

        # --------------------------------------------------
        # RECEBER ALTERAÇÕES
        # --------------------------------------------------

        if request.method == 'POST':

            # Recebe os novos valores.
            nome = request.form['nome']
            email = request.form['email'].strip().lower()
            mao_de_obra = request.form['mao_de_obra']

            # --------------------------------------------------
            # VERIFICAR E-MAIL DUPLICADO
            # --------------------------------------------------

            # Verifica se o e-mail pertence a outro usuário.
            #
            # <> significa diferente de.
            # O próprio usuário não entra na comparação.
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

            # --------------------------------------------------
            # ATUALIZAR DADOS
            # --------------------------------------------------

            # UPDATE altera os dados do usuário.
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

            # Confirma a atualização.
            con.commit()

            # Atualiza o nome da sessão.
            session['nome'] = nome

            # Exibe mensagem de sucesso.
            flash("Usuário editado com sucesso")

            return redirect(url_for('editar', id=id))

        # --------------------------------------------------
        # ABRIR FORMULÁRIO
        # --------------------------------------------------

        # Envia os dados do usuário para o HTML.
        return render_template(
            'editar_usuario.html',
            usuario=usuario
        )

    # --------------------------------------------------
    # TRATAMENTO DE ERROS
    # --------------------------------------------------

    except Exception as e:

        flash(f"Ocorreu um erro -> {e}")

        con.rollback()

        return redirect(url_for('home'))

    finally:

        # Fecha o cursor.
        cursor.close()


# ==========================================================
# 11 - ALTERAR SENHA
# ==========================================================

# Esta função permite alterar a senha.
#
# O sistema verifica:
# - Se o usuário está logado.
# - Se a senha atual está correta.
# - Se a confirmação corresponde à nova senha.
# - Se a nova senha é forte.
# - Se é diferente da senha atual.
# - Se não foi utilizada nas três últimas alterações.

@app.route('/alterar_senha', methods=['GET', 'POST'])
def alterar_senha():

    # --------------------------------------------------
    # VERIFICAR LOGIN
    # --------------------------------------------------

    if 'id_usuario' not in session:

        flash('Precisa estar logado')

        return redirect(url_for('login'))

    # Cria o cursor.
    cursor = con.cursor()

    try:

        # --------------------------------------------------
        # RECEBER DADOS DO FORMULÁRIO
        # --------------------------------------------------

        if request.method == 'POST':

            # Recebe as senhas digitadas.
            senha_atual = request.form['senha_atual']
            nova_senha = request.form['nova_senha']
            confirmar_senha = request.form['confirmar_senha']

            # --------------------------------------------------
            # CONSULTAR SENHA ATUAL
            # --------------------------------------------------

            # Busca o hash da senha do usuário logado.
            cursor.execute("""
                SELECT senha
                FROM usuario
                WHERE id_usuario = ?
            """, (session['id_usuario'],))

            # Recebe o resultado.
            usuario = cursor.fetchone()

            # --------------------------------------------------
            # VERIFICAR USUÁRIO
            # --------------------------------------------------

            if not usuario:

                flash('Usuário não encontrado')

                return redirect(url_for('login'))

            # --------------------------------------------------
            # CONFERIR SENHA ATUAL
            # --------------------------------------------------

            # Compara a senha digitada com o hash salvo.
            if not bcrypt.check_password_hash(usuario[0], senha_atual):

                flash('Senha atual incorreta')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # CONFIRMAR NOVA SENHA
            # --------------------------------------------------

            if nova_senha != confirmar_senha:

                flash('As senhas não coincidem')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # VERIFICAR SENHA FORTE
            # --------------------------------------------------

            if not senha_forte(nova_senha):

                flash('A nova senha deve ser forte')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # IMPEDIR REPETIÇÃO DA SENHA ATUAL
            # --------------------------------------------------

            # Compara a nova senha com a senha em uso.
            if bcrypt.check_password_hash(usuario[0], nova_senha):

                flash('Utilize uma nova senha')

                return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # VERIFICAR HISTÓRICO DE SENHAS
            # --------------------------------------------------

            # SELECT FIRST 3 busca os três registros
            # mais recentes do histórico.
            #
            # ORDER BY DESC organiza do mais novo
            # para o mais antigo.
            cursor.execute("""
                SELECT FIRST 3 senha
                FROM historico_senha
                WHERE id_usuario = ?
                ORDER BY id_historico DESC
            """, (session['id_usuario'],))

            # Recebe os registros encontrados.
            historico = cursor.fetchall()

            # --------------------------------------------------
            # COMPARAR SENHAS ANTIGAS
            # --------------------------------------------------

            # Percorre cada hash armazenado no histórico.
            for senha_antiga in historico:

                # Verifica se a nova senha corresponde
                # a alguma das três anteriores.
                if bcrypt.check_password_hash(senha_antiga[0], nova_senha):

                    flash('Você não pode reutilizar suas 3 últimas senhas')

                    return redirect(url_for('alterar_senha'))

            # --------------------------------------------------
            # GERAR HASH DA NOVA SENHA
            # --------------------------------------------------

            # Protege a nova senha utilizando Bcrypt.
            senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

            # --------------------------------------------------
            # GUARDAR SENHA ANTERIOR
            # --------------------------------------------------

            # Insere o hash da senha antiga no histórico.
            cursor.execute("""
                INSERT INTO historico_senha
                (id_usuario, senha)
                VALUES (?, ?)
            """, (session['id_usuario'], usuario[0]))

            # --------------------------------------------------
            # ATUALIZAR SENHA
            # --------------------------------------------------

            # Substitui o hash antigo pelo novo.
            cursor.execute("""
                UPDATE usuario
                SET senha = ?
                WHERE id_usuario = ?
            """, (senha_hash, session['id_usuario']))

            # --------------------------------------------------
            # CONFIRMAR ALTERAÇÕES
            # --------------------------------------------------

            # Salva a senha nova e o histórico.
            con.commit()

            flash('Senha alterada com sucesso')

            return redirect(url_for('alterar_senha'))

        # --------------------------------------------------
        # ABRIR FORMULÁRIO
        # --------------------------------------------------

        return render_template('alterar_senha.html')

    # --------------------------------------------------
    # TRATAMENTO DE ERROS
    # --------------------------------------------------

    except Exception as e:

        # Desfaz alterações pendentes.
        con.rollback()

        flash(f'Ocorreu um erro -> {e}')

        return redirect(url_for('home'))

    finally:

        # Fecha o cursor.
        cursor.close()


# ==========================================================
# 12 - INICIALIZAÇÃO DO SISTEMA
# ==========================================================

# Verifica se este arquivo está sendo executado diretamente.
if __name__ == '__main__':

    # Inicia o servidor Flask.
    # debug=True ativa o modo de desenvolvimento.
    # Deve ser desativado em produção.
    app.run(debug=True)
