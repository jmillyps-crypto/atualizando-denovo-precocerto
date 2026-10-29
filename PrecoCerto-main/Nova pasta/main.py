from flask import Flask, render_template, request, flash, redirect, url_for, session
import fdb

import math
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'Aqui_e_a_chave_da_turma_a'

# CONEXÃO COM O BANCO
host = 'localhost'
database = r'C:\Users\Aluno\Downloads\PrecoCerto-main (1)\PrecoCerto-main\Nova pasta\BANCO.FDB'
user = 'SYSDBA'
password = 'sysdba'

con = fdb.connect(host=host, database=database, user=user, password=password)


@app.route('/')  # ROTA INCIAL - LANDING PAGE
def index():
    return render_template('index.html')


# ROTA QUE DIRECIONA PARA A PÁGINA CADASTRO DE USUÁRIO
@app.route('/cadastro_usu')
def cadastro_usu():
    return render_template('cadastro.html')


# VERIFICAR SENHA FORTE
def senha_forte(senha):
    if len(senha) < 8:  # senha menor que 8 digitos
        return False
    if senha.islower():  # letra minuscula
        return False
    if senha.isalpha():  # caracter especial
        return False
    if senha.isdigit():  # digitos
        return False
    else:
        return True


@app.route('/cadastrar', methods=['POST'])  # ROTA QUE REALIZA O CADASTRO
def cadastrar():
    nome = request.form['nome'].strip().lower()
    email = request.form['email']
    senha = request.form['senha']
    mao_obra = request.form['mao-de-obra']

    if not nome:
        flash("O campo nome não pode estar vazio")
        return redirect(url_for('cadastro_usu'))

    if not mao_obra:  # SE A MÃO DE OBRA NÃO TIVER SIDO INFORMADA
        flash("Mão de obra não informada!")
        return redirect(url_for('cadastro_usu'))

    mao_obra = float(mao_obra)  # CONVERSÃO DE STRING PARA NÚMERO

    # SE A SENHA INSERIDA NÃO ATINGIR TODOS OS REQUISITOS PARA SENHA FORTE
    if not senha_forte(senha):
        flash(
            "Senha fraca! Precisa conter 8 ou mais caracteres, pelo menos uma letra maiúscula, um número e um caracter especial")
        return redirect(url_for('cadastro_usu'))

    cursor = con.cursor()  # ABRINDO O CURSOR

    try:  # TRATAMENTO DE ERRO

        # SELECIONA O USUARIO QUE POSSUI ESTE EMAIL DIGITADO
        cursor.execute("""SELECT 1
                          FROM usuario u
                          WHERE email = ?""", (email,))

        # CONFERFE SE JÁ TEM ESTE EMAIL CADASTRADO E PEGA SOMENTE ELE
        confere_email = cursor.fetchone()

        if confere_email:  # SE JA TIVER ESTE EMAIL CADASTRADO
            flash('Erro: Email já cadastrado')
            return redirect(url_for('cadastro_usu'))

        if mao_obra < 0:  # SE A MÃO DE OBRA NÃO TIVER SIDO INFORMADA
            flash("Mão de obra não pode ser negativa!")
            return redirect(url_for('cadastro_usu'))

        # GERA CRIPITOGRAFIA DE SENHA
        senha_hash = bcrypt.generate_password_hash(senha).decode('utf-8')

        # EXECUÇÃO DO INSERT - CADASTRO DO USUÁRIO
        cursor.execute(""" INSERT INTO usuario (nome, email, senha, mao_obra, tentativas)
                           VALUES (?, ?, ?, ?, ?) returning id_usuario""", (nome, email, senha_hash, mao_obra, 0))

        id_usuario = cursor.fetchone()[0]
        # Soma o custo de cada insumo. Divide por 1000 quando a receita
        # usa g/ml e o insumo foi comprado em kg/l.
        cursor.execute("""
                       INSERT INTO senhas_utilizadas (id_usuario, senha)
                       VALUES (?, ?)
                       """, (id_usuario, senha_hash))



        con.commit()  # SALVA AS INFORMAÇÕES
        flash("Usuário cadastrado com sucesso")
        return redirect(url_for('login_usu'))


    except Exception as e:  # SE ACONTECER ALGUM ERRO
        flash(f"Ocorreu um error -> {e}")
        con.rollback()  # CANCELA AS MODIFICAÇÕES QUE CAUSARIAM ERRO
        return redirect(url_for('cadastro_usu'))

    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


# ROTA QUE REALIZA O LOGIN DE USUÁRIO
@app.route('/login_usu', methods=['GET', 'POST'])
def login_usu():
    if request.method == 'GET':  # SE A PÁGINA DE LOGIN FOI ACESSADA
        return render_template('login.html')

    email = request.form['email']
    senha = request.form['senha']

    cursor = con.cursor()  # ABRINDO O CURSOR
    try:
        # SELECIONA OS DADOS QUE PERTENCEM AO EMAIL INSERIDO
        cursor.execute("""SELECT id_usuario, nome, senha, tentativas
                          FROM usuario u
                          WHERE u.email = ? """, (email,))

        # CONFERFE SE JÁ TEM ESTES DADOS DE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()

        if not usuario:  # SE NÃO TIVER ESTE USUÁRIO CADASTRADO
            flash("Usuário não encontrado")
            return redirect(url_for('login_usu'))

        # ARMAZENAMENTO DOS CAMPOS DE LOGIN NA VARIAVEL
        id_usuario, nome, senha_hash, tentativas = usuario

        # SE A QUANTIDADE TENTATIVAS DE LOGIN FOR MAIOR
        if tentativas >= 3:
            flash("Usuário Inativo")
            return redirect(url_for('login_usu'))

        if usuario:  # SE ESTE USUÁRIO ESTIVER CADASTRADO
            if bcrypt.check_password_hash(senha_hash,
                                          senha):  # VERIFICA SE A SENHA INSERIDA É IGUAL A QUE FOI CADASTRADA

                # ATUALIZA O NUMERO DE TENTATIVAS PARA ZERO, APOS ACERTAR A SENHA DE USUÁRIO
                cursor.execute("""UPDATE usuario
                                  set tentativas = 0
                                  where id_usuario = ?""", (id_usuario,))

                con.commit()  # SALVA AS INFORMAÇÕES

                session['id_usuario'] = id_usuario  # GUARDA O ID DOS USUÁRIOS LOGADOS
                session['usuario_nome'] = nome  # GUARDA O NOME DOS USUÁRIOS LOGADOS

                flash('Conta logada')
                return redirect(url_for('home'))

            else:

                # ATUALIZA O NÚMERO DE TENTATIVAS (de um em um) A CADA VEZ QUE ERRAR A SENHA DE CADASTRO
                cursor.execute("""UPDATE usuario
                                  set tentativas = tentativas + 1
                                  where id_usuario = ?""", (id_usuario,))

                con.commit()  # SALVA AS INFORMAÇÕES

                # SE O NÚMERO DE TENTATIVAS FOI MAIOR OU IGUAL A 3
                if tentativas + 1 >= 3:
                    flash('Você passou de 3 tentativas! Sua conta foi bloqueada.')
                else:  # SE AS TENTATIVAS MÁXIMAS AINDA NÃO FOREM ATINGIDAS
                    flash('Email ou senha inválida')
                return redirect(url_for('login_usu'))
        return render_template('login.html')

    except Exception as e:  # SE ACONTECER ALGUM ERRO
        flash(f"Ocorreu um error -> {e}")
        con.rollback()  # CANCELA AS MODIFICAÇÕES QUE CAUSARIAM ERRO
        return redirect(url_for('login_usu'))
    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


@app.route('/perfil')  # ROTA DA PAGINA DE PERFIL DO USUARIO
def perfil():
    if 'id_usuario' not in session:  # SENÃO TIVER O ID DE USUÁRIO NA SESSÃO - NÃO ESTIVER LOGADO
        return redirect(url_for('login_usu'))

    cursor = con.cursor()  # ABRINDO O CURSOR
    try:
        # SELECONA OS DADOS QUE PERTENCE AO USUÁRIO LOGADO
        cursor.execute("""SELECT id_usuario, nome, email, senha, mao_obra
                          FROM usuario u
                          WHERE id_usuario = ? """, (session['id_usuario'],))

        # CONFERFE SE JÁ TEM ESTES DADOS DE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()

        # SE ESTE USUÁRIO NÃO EXISTIR
        if not usuario:
            flash('Usuário não encontrado')
            return redirect(url_for('home'))

        # ARMAZENAMENTO DOS CAMPOS - DADOS NA VARIAVEL
        id_usuario, nome, email, senha, mao_obra = usuario

        return render_template('perfil.html', usuario=usuario,
                               nome=nome,
                               email=email,
                               senha=senha,
                               mao_obra=mao_obra,

                               )

    except Exception as e:  # SE ACONTECER ALGUM ERRO
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('home'))

    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


# ROTA QUE DIRECIONA PARA A PÁGINA EDITAR PERFIL
@app.route('/editar_perfil/<int:id>', methods=['GET', 'POST'])
def editar_perfil(id):
    print('1 entrei ')
    cursor = con.cursor()
    try:
        # SELECIONA OS DADOS QUE PERTENCEM AQUELE ID DE USUÁRIO
        cursor.execute("""SELECT id_usuario, nome, email, senha, mao_obra
                          from usuario
                          WHERE ID_usuario = ?""", (id,))

        # CONFERFE SE JÁ TEM ESTE USUÁRIO CADASTRADO E PEGA SOMENTE ELE
        usuario = cursor.fetchone()
        print('2 ', usuario)

        if not usuario:  # SE ESTE USUÁRIO NÃO EXISTIR
            flash('Usuário não encontrado')
            return redirect(url_for('index'))

        # ARMAZENAMENTO DOS CAMPOS NA VARIAVEL
        id_usuario, nome, email, senha_atual, mao_obra = usuario

        # ENVIO DOS DADOS INSERIDOS
        if request.method == 'POST':
            nome = request.form['nome'].strip().lower()
            email = request.form['email']
            nova_senha = request.form['senha'].strip()
            mao_obra = request.form['mao_obra']
            print('3')

            if not nome:
                flash("O campo nome não pode estar vazio")
                print(4)
                return redirect(url_for('editar_perfil', id=id_usuario))


            print('4,5', id_usuario)
            # SELECIONA AS SENHAS ANTIGAS DO USUÁRIO (da mais recente pra mais antiga)
            cursor.execute("""SELECT first 3 senha
                              FROM senhas_utilizadas
                              WHERE id_usuario = ?
                                order by id_senhas_utilizadas desc
                           """, (id_usuario,))

            # CONFERE E PEGA TODAS AS SENHAS QUE PERTENCEM AO USUÁRIO
            senhas_antigas = cursor.fetchall()
            print(senhas_antigas)
            print('5')
            # VERIFICAÇÃO DAS 3 ÚLTIMAS SENHAS
            #contador = 0  # CONTROLE DE QUANTAS SENHAS FORAM VERIFICADAS

            # SELECIONA O USUARIO QUE POSSUI ESTE NOVO EMAIL DIGITADO
            cursor.execute("""SELECT id_usuario
                              FROM usuario
                              WHERE email = ? """, (email,))

            # CONFERFE SE JÁ TEM ESTE EMAIL CADASTRADO E PEGA SOMENTE ELE
            email_ja_cadastrado = cursor.fetchone()
            print('10')

            if email_ja_cadastrado:  # SE JA TIVER ESTE EMAIL CADASTRADO EM ALGUM USUÁRIO
                if email_ja_cadastrado[0] != id_usuario:  # SE ESSE EMAIL PERTENCE A UM ID DIFERENTE DESTE USUÁRIO
                    flash('Erro: Email já utilizado por outro usuário')
                    print('11')
                    return redirect(url_for('editar_perfil', id=id_usuario))

            # ANALISA UMA SENHA ANTIGA POR VEZ, ENTRE TODAS AS VERIFICADAS
            for senha_antiga in senhas_antigas:
                print('6')

                # if contador == 3:  # SE VERIFICAR 3 SENHAS
                #     break

                    # VERIFICA SE A NOVA SENHA É IGUAL A UMA DAS QUE FORAM CADASTRADAS
                if bcrypt.check_password_hash(senha_antiga[0], nova_senha):
                    flash('Você não pode usar uma das últimas 3 senhas.')
                    print('7')
                    return redirect(url_for('editar_perfil', id=id_usuario))

                # contador += 1  # VERIFICAÇÕES DE SENHA (uma por vez)


            # # VERIFICAÇÃO DA SENHA ATUAL
            # if bcrypt.check_password_hash(senha_atual, nova_senha):  # SE A NOVA SENHA É IGUAL A SENHA ATUAL
            #     flash('Você não pode usar a senha atual.')
            #     print('8')
            #     return redirect(url_for('editar_perfil', id=id_usuario))

            # GUARDA A SENHA ATUAL NA TABELA
            cursor.execute("""
                           INSERT INTO senhas_utilizadas (id_usuario, senha)
                           VALUES (?, ?)""", (id_usuario, senha_atual))
            print('9')


            if nova_senha == "":
                senha_hash = senha_atual
            else:
                if not senha_forte(nova_senha):
                    flash("Senha fraca")
                    return redirect(url_for('perfil'))
                print('12')

                # GERA CRIPITOGRAFIA DA NOVA SENHA
                senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

            # ALTERAÇÃO/ EDIÇÃO DOS DADOS DO USUÁRIO
            cursor.execute(""" UPDATE usuario
                               SET nome     = ?,
                                   email    = ?,
                                   senha    = ?,
                                   mao_obra = ?
                               where id_usuario = ?""", (nome, email, senha_hash, mao_obra, id))

            session['usuario_nome'] = nome
            print('13')

            con.commit()  # SALVA AS INFORMAÇÕES
            flash("Usuário editado com sucesso")
            return redirect(url_for('perfil'))

        # REDIRECIONAMENTO PARA A PÁGINA 'EDITAR PERFIL'
        return render_template('editar_perfil.html', usuario=usuario)



    except Exception as e:  # SE ACONTECER ALGUM ERRO
        con.rollback()  # CANCELA AS INFORMAÇÕES
        flash(f"Ocorreu um error -> {e}")
        return redirect(url_for('perfil'))


    finally:
        cursor.close()  # FECHA A CONVERSA COM O BANCO


@app.route('/home')  # ROTA INCIAL - LANDING PAGE
def home():
    if 'usuario_nome' not in session:  # SE O NOME DO USUÁRIO NÃO ESTIVER NA SESSÃO - NÃO ESTIVER LOGADO
        return redirect(
            url_for('login_usu'))  # VERIFICA SE O USUARIO ESTÁ LOGADO, SE ESTIVER ABRE A HOME COM AS INFORMAÇÕES

    return render_template(
        'home.html',
        id_usuario=session['id_usuario'],
        usuario_nome=session['usuario_nome']
    )


# ROTA QUE PERMITE SAIR DA CONTA
@app.route('/logout')
def logout():
    if 'id_usuario' in session:  # SE O USUÁRIO ESTIVER NA SESSÃO - LOGADO
        session.pop('id_usuario', None)  # REMOVER O USUARIO/ID DA LISTA
        session.pop('usuario_nome', None)
        flash('Logout com sucesso')

    else:
        flash('Nenhuma conta está logada')

    return redirect(url_for('login_usu'))  # REDIRECIONA PARA PAGINA DE LOGIN




@app.route('/adicionar_insumo')
def adicionar_insumo():
    return render_template("adicionar_insumo.html")



@app.route('/cadastrar_insumo', methods=['POST'])
def cadastrar_insumo():


    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    nome = request.form['nome'].strip().lower()
    unidade = int(request.form['unidade'])
    custo_unitario = float(request.form['custo_unitario'])
    estoque = float(request.form['estoque'])

#CADASTRO DE INSUMO

    if not nome:
        flash("O campo nome não pode estar vazio")
        return redirect(url_for('adicionar_insumo'))

    if not estoque:
        flash("Estoque não informado!")
        return redirect(url_for('adicionar_insumo'))

    print('4')

    if custo_unitario <= 0:
        flash("Custo unitário não pode ter um valor negativo!")
        return redirect(url_for('adicionar_insumo'))

    if estoque < 0:
        flash("Estoque não pode ter um valor negativo!")
        return redirect(url_for('adicionar_insumo'))
    print('5')

    cursor = con.cursor()

    try:
        print('6')
        cursor.execute("""SELECT 1
                          FROM insumos
                          WHERE nome = ? AND id_usuario = ?""",
                       (nome, id_usuario))
        print('7')

        insumos = cursor.fetchone()
        print(insumos)

        if insumos:
            flash("Erro: Insumo já cadastrado")
            return redirect(url_for('adicionar_insumo'))
        print('8')

        cursor.execute("""INSERT INTO insumos
                          (nome, unidade, custo_unitario, estoque, id_usuario)
                          VALUES (?, ?, ?, ?, ?)""",
                       (nome, unidade, custo_unitario, estoque, id_usuario))

        con.commit()
        print('9')

        flash("Insumo cadastrado com sucesso")
        return redirect(url_for('pagina_insumos'))

    except Exception as e:
        flash(f"Ocorreu um erro -> {e}")
        con.rollback()
        return redirect(url_for('adicionar_insumo'))

    finally:
        cursor.close()



@app.route('/adicionar_produto')
def adicionar_produto():
    return render_template("adicionar_produto.html")


@app.route('/cadastrar_produto',methods=['POST'])
def cadastrar_produto():


    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    nome = request.form['nome'].strip().lower()
    margem_lucro = request.form['lucro']
    preco = request.form['preco']

    margem_lucro = float(margem_lucro)
    preco = float(preco)

    if margem_lucro < 0:
        flash("Margem de lucro não pode ter um valor negativo!")
        return redirect(url_for('adicionar_produto'))

    if preco <= 0:
        flash("Preço não pode ter um valor negativo!")
        return redirect(url_for('adicionar_produto'))

    if not nome:
        flash("O campo nome não pode estar vazio")
        return redirect(url_for('adicionar_produto'))

    if not margem_lucro:
        flash("Lucro não informado!")
        return redirect(url_for('adicionar_produto'))

    if not preco:
        flash("Preço não informado!")
        return redirect(url_for('adicionar_produto'))

    cursor = con.cursor()

    try:
        cursor.execute("""SELECT 1
                          FROM produtos
                          WHERE nome = ? AND id_usuario = ?""",
                       (nome, id_usuario))

        produtos = cursor.fetchone()

        if produtos:
            flash("Erro: Produto já cadastrado")
            return redirect(url_for('adicionar_produto'))

        cursor.execute("""INSERT INTO produtos
                          (nome, margem_lucro, preco,id_usuario)
                          VALUES (?, ?, ?, ?)
                            RETURNING id_produto""",
                       (nome, margem_lucro, preco,id_usuario))

        id_produto = cursor.fetchone()[0]
        con.commit()

        session['id_produto'] = id_produto


        flash("Produto cadastrado com sucesso")
        return redirect(url_for('adicionar_insumo_produto'))

    except Exception as e:
        flash(f"Ocorreu um erro -> {e}")
        con.rollback()
        return redirect(url_for('adicionar_produto'))

    finally:
        cursor.close()


@app.route('/pagina_insumos')
def pagina_insumos():
    return redirect(url_for("lista_insumos"))

@app.route('/lista_insumos')
def lista_insumos():

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    cursor = con.cursor()

    cursor.execute("""SELECT id_insumos
                    , nome
                    , case unidade
                    WHEN 1 THEN 'Quilograma'
                    WHEN 2 THEN 'Grama'
                    WHEN 3 THEN 'Litros'
                    WHEN 4 THEN 'Mililitro'
                    WHEN 5 THEN 'Unidade'
                    ELSE ''
                    END AS unidade
                    , custo_unitario, estoque
                                          FROM insumos
                                          WHERE id_usuario = ?
                                            ORDER BY id_insumos DESC""", (id_usuario,))



    insumos = cursor.fetchall()

    cursor.close()

    return render_template('lista_insumos.html', insumos=insumos)





@app.route('/editar_insumo/<int:id>', methods=['GET', 'POST'])
def editar_insumo(id):

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT id_insumos, nome, unidade, custo_unitario, estoque
            FROM insumos
            WHERE id_insumos = ? AND id_usuario = ?
        """, (id, id_usuario))

        insumos = cursor.fetchone()

        if not insumos:
            flash("Insumo não encontrado!")
            return redirect(url_for('pagina_insumos'))

        if request.method == 'POST':

            nome = request.form['nome'].strip().lower()
            unidade = int(request.form['unidade'])
            custo_unitario = float(request.form['custo_unitario'])
            estoque = float(request.form['estoque'])

            if not nome:
                flash("O nome não pode estar vazio!")
                return redirect(url_for('editar_insumo', id=id))

            if unidade not in (1, 2, 3, 4, 5):
                flash("Unidade inválida!")
                return redirect(url_for('editar_insumo', id=id))

            if custo_unitario <= 0 or estoque < 0:
                flash("Custo ou estoque inválido!")
                return redirect(url_for('editar_insumo', id=id))

            cursor.execute("""
                SELECT 1 FROM insumos
                WHERE nome = ? AND id_usuario = ? AND id_insumos <> ?
            """, (nome, id_usuario, id))

            if cursor.fetchone():
                flash("Insumo já cadastrado!")
                return redirect(url_for('editar_insumo', id=id))

            # VERIFICA SE O CUSTO MUDOU
            custo_anterior = float(insumos[3])

            if round(custo_anterior, 2) != round(custo_unitario, 2):

                cursor.execute("""
                    INSERT INTO historico_custo_insumos
                    (id_insumos, id_usuario, nome_insumo,
                     custo_anterior, custo_novo)
                    VALUES (?, ?, ?, ?, ?)
                """, (id, id_usuario, nome,
                      custo_anterior, custo_unitario))

            # ATUALIZA O INSUMO
            cursor.execute("""
                UPDATE insumos
                SET nome = ?, unidade = ?, custo_unitario = ?, estoque = ?
                WHERE id_insumos = ? AND id_usuario = ?
            """, (nome, unidade, custo_unitario, estoque, id, id_usuario))

            con.commit()

            flash("Insumo editado com sucesso!")
            return redirect(url_for('pagina_insumos'))

        return render_template('editar_insumo.html', insumo=insumos)

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for('pagina_insumos'))

    finally:
        cursor.close()


@app.route('/historico_insumo/<int:id>')
def historico_insumo(id):

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT nome FROM insumos
            WHERE id_insumos = ? AND id_usuario = ?
        """, (id, session['id_usuario']))

        insumo = cursor.fetchone()

        cursor.execute("""
            SELECT nome_insumo, custo_anterior, custo_novo, data_alteracao
            FROM historico_custo_insumos
            WHERE id_insumos = ? AND id_usuario = ?
            ORDER BY data_alteracao DESC, id_historico DESC
        """, (id, session['id_usuario']))

        historico = cursor.fetchall()

        if not insumo and not historico:
            flash("Histórico não encontrado!")
            return redirect(url_for('pagina_insumos'))

        nome = (insumo or historico[0])[0]

        return render_template(
            'historico_insumo.html',
            nome=nome,
            historico=historico
        )

    except Exception as e:
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for('pagina_insumos'))

    finally:
        cursor.close()


@app.route('/deletar_insumo/<int:id>', methods=['POST'])
def deletar_insumo(id):
    cursor = con.cursor()

    try:
        cursor.execute("""SELECT 1 FROM insumos_utilizado
                          WHERE id_insumos = ?""", (id,))

        insumo_utilizado = cursor.fetchone()

        if insumo_utilizado:
            flash("Erro: Este insumo está vinculado a um produto!")
            return redirect(url_for("pagina_insumos"))

        cursor.execute("""DELETE FROM insumos WHERE id_insumos = ?""", (id,))
        con.commit()

        flash("Insumo deletado com sucesso!")
        return redirect(url_for("pagina_insumos"))

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for("pagina_insumos"))

    finally:
        cursor.close()



@app.route('/pesquisa_insumos', methods=['GET','POST'])
def pesquisa_insumos():

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()
    nome = request.form.get('nome', '').strip().lower()

    try:

        cursor.execute("""
            SELECT id_insumos, nome,
                   CASE unidade
                       WHEN 1 THEN 'Quilograma'
                       WHEN 2 THEN 'Grama'
                       WHEN 3 THEN 'Litros'
                       WHEN 4 THEN 'Mililitro'
                       WHEN 5 THEN 'Unidade'
                       ELSE ''
                   END,
                   custo_unitario, estoque, unidade
            FROM insumos
            WHERE id_usuario = ? AND nome LIKE ?
            ORDER BY id_insumos DESC
        """, (id_usuario, f'%{nome}%'))

        insumos = cursor.fetchall()

        if not insumos:
            flash('Nenhum insumo encontrado.')
        return render_template('pesquisa_insumo.html', insumos=insumos)

    except Exception as e:
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('home'))

    finally:
        cursor.close()


@app.route('/pagina_produtos')
def pagina_produtos():
    return redirect(url_for("lista_produtos"))


@app.route('/lista_produtos')
def lista_produtos():

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    cursor = con.cursor()

    cursor.execute("""
        SELECT id_produto, nome, margem_lucro, custo_total,
               sugestao, preco, lucro_unidade
        FROM produtos
        WHERE id_usuario = ?
        ORDER BY id_produto DESC
    """, (id_usuario,))

    produtos = cursor.fetchall()
    print("PRODUTOS ENVIADOS PARA O HTML:", produtos)

    cursor.close()

    return render_template('lista_produtos.html', produtos=produtos)



@app.route('/editar_produto/<int:id>', methods=['GET','POST'])
def editar_produto(id):
    cursor = con.cursor()
    try:
        cursor.execute("""SELECT  id_produto, nome, margem_lucro,custo_total,sugestao, preco, lucro_unidade
                          FROM produtos
                          WHERE id_produto = ?""",(id,))

        produtos = cursor.fetchone()

        if not produtos:
            flash('Produto não encontrado!')
            return redirect(url_for("pagina_produtos"))

        if request.method == 'POST': #ENVIAR NOVAMENTE
            nome = request.form['nome'].strip().lower()
            margem_lucro = request.form['lucro']
            preco = request.form['preco']

            margem_lucro = float(margem_lucro)
            preco = float(preco)

            if margem_lucro < 0:
                flash("Margem de lucro não pode ter um valor negativo!")
                return redirect(url_for('adicionar_produto'))

            if preco <= 0:
                flash("Preço não pode ter um valor negativo!")
                return redirect(url_for('adicionar_produto'))

            cursor.execute("""SELECT 1
                              FROM produtos
                              WHERE nome = ? AND id_usuario = ? AND id_produto != ?""",
                           (nome, session['id_usuario'], id))

            produto_cadastrado = cursor.fetchone()

            if produto_cadastrado:
                flash("Erro: Produto já cadastrado")
                return redirect(url_for('editar_produto', id=id))


            # Custo total armazenado no banco
            custo_total = float(produtos[3] or 0)
            print('custo: ' ,custo_total)

            # Recalcula a sugestão de preço
            sugestao = round(
                custo_total * (1 + margem_lucro / 100), 2
            )
            print(sugestao)

            # Recalcula o lucro por unidade
            lucro_unidade = round((preco - custo_total) / 100, 2)
            print('lucro por unidade: ',  lucro_unidade)

            # Atualiza todos os valores juntos
            cursor.execute("""
                           UPDATE produtos
                           SET nome = ?,
                               margem_lucro = ?,
                               preco = ?,
                               sugestao = ?,
                               lucro_unidade = ?
                           WHERE id_produto = ? AND id_usuario = ?
                           """,(nome,margem_lucro,preco,sugestao,lucro_unidade,id,session['id_usuario']))

            if lucro_unidade < 0:
                flash("Atenção! Este produto está dando prejuízo!")


            con.commit()
            flash("Produto editado com sucesso")
            return redirect(url_for('pagina_produtos'))

        return render_template('editar_produto.html', produto=produtos)

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for('pagina_produtos'))

    finally:
        cursor.close()




@app.route('/deletar_produto/<int:id>', methods=['POST'])
def deletar_produto(id):
    cursor = con.cursor()

    try:
        cursor.execute("""DELETE FROM insumos_utilizado WHERE id_produto = ?""", (id,))
        cursor.execute("""DELETE FROM produtos WHERE id_produto = ?""", (id,))
        con.commit()

        flash("Produto deletado com sucesso!")
        return redirect(url_for("pagina_produtos"))

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for("pagina_produtos"))

    finally:
        cursor.close()

@app.route('/adicionar_insumo_produto')
def adicionar_insumo_produto(): #PAGINA DO +

    if 'id_usuario' not in session:
        return redirect(url_for('login_usu'))
    if 'id_produto' not in session:
        flash('Produto não encontrado')
        return redirect(url_for('adicionar_produto'))

    id_produto = session['id_produto']
    id_usuario = session['id_usuario']
    cursor = con.cursor()
    try:
        cursor.execute("""
            SELECT nome, margem_lucro, preco, sugestao, lucro_unidade, custo_total
            FROM produtos
            WHERE id_produto = ? AND id_usuario = ?
        """, (id_produto, id_usuario))   #INFORMAÇÕES JÁ DIGITADAS
        produtos = cursor.fetchone()

        if not produtos:
            flash('Produto não encontrado')
            return redirect(url_for('adicionar_produto'))

        return redirect(url_for('adicionando_insumo_produto'))
    except Exception as e:
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('adicionar_produto'))
    finally:
        cursor.close()




@app.route('/adicionando_insumo_produto')
def adicionando_insumo_produto():

    if 'id_usuario' not in session:
        return redirect(url_for('login_usu'))

    if 'id_produto' not in session:
        return redirect(url_for('adicionar_produto'))

    id_usuario = session['id_usuario']
    id_produto = session['id_produto']

    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT mao_obra FROM usuario
            WHERE id_usuario = ?
        """, (id_usuario,))
        usuario = cursor.fetchone()

        cursor.execute("""
            SELECT nome, margem_lucro, preco
            FROM produtos
            WHERE id_produto = ? AND id_usuario = ?
        """, (id_produto, id_usuario))

        produto = cursor.fetchone()

        if not usuario or not produto:
            flash('Usuário ou produto não encontrado!')
            return redirect(url_for('home'))

        cursor.execute("""
            SELECT i.custo_unitario, iu.quantidade,
                   i.unidade, iu.unidade
            FROM insumos_utilizado iu
            INNER JOIN insumos i ON i.id_insumos = iu.id_insumos
            WHERE iu.id_produto = ?
        """, (id_produto,))

        insumos = cursor.fetchall()

        total_insumos = 0

        for insumo in insumos:
            custo = float(insumo[0])
            quantidade = float(insumo[1])
            unidade_insumo = insumo[2]
            unidade_usada = insumo[3]

            if unidade_insumo == 1 and unidade_usada == 2:
                total_insumos += custo * quantidade / 1000

            elif unidade_insumo == 3 and unidade_usada == 4:
                total_insumos += custo * quantidade / 1000

            elif unidade_insumo == unidade_usada:
                total_insumos += custo * quantidade

            else:
                flash('Unidade incompatível com o insumo!')
                return redirect(url_for('adicionar_insumo_produto'))

        mao_obra = float(usuario[0] or 0) #Pega o valor da mão de obra do banco e
                                          # se for None ele usa como 0

        custo_total = round(total_insumos + mao_obra, 2)

        margem = float(produto[1])
        preco = float(produto[2])

        sugestao = round(custo_total + (custo_total * margem / 100), 2)

        lucro_unidade = round((preco - custo_total) / 100, 2)
        #Lucro vai ser negativo se o preço de venda é menor que custo total
        #Lucro vai ser positivo se o preço de venda é maior que custo total

        if lucro_unidade < 0:
            flash('Cuidado! Este produto está dando prejuizo!', 'erro')

        cursor.execute("""
            UPDATE produtos
            SET custo_total = ?,
                sugestao = ?,
                lucro_unidade = ?
            WHERE id_produto = ? AND id_usuario = ?
        """, (custo_total, sugestao, lucro_unidade,
              id_produto, id_usuario))

        con.commit()

        produtos = (produto[0], margem, preco,
                    sugestao, lucro_unidade, custo_total)

        return render_template(
            'adicionar_insumo_produto.html',
            produtos=produtos
        )

    except Exception as e:
        con.rollback()
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('adicionar_insumo_produto'))

    finally:
        cursor.close()





@app.route('/inserir_insumos_produto/<int:id>', methods=['POST'])
def inserir_insumos_produto(id):

    if 'id_usuario' not in session or 'id_produto' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']
    id_produto = session['id_produto']

    cursor = con.cursor()

    try:
        # VERIFICAR SE O INSUMO JÁ FOI INSERIDO
        cursor.execute("""
            SELECT 1
            FROM insumos_utilizado
            WHERE id_produto = ? AND id_insumos = ?
        """, (id_produto, id))

        insumo_utilizado = cursor.fetchone()

        if insumo_utilizado:
            flash("Erro: Insumo já inserido!")
            return redirect(url_for('adicionando_insumo_produto'))

        # BUSCAR ESTOQUE E UNIDADE DO INSUMO
        cursor.execute("""
            SELECT estoque, unidade
            FROM insumos
            WHERE id_insumos = ? AND id_usuario = ?
        """, (id, id_usuario))

        insumo = cursor.fetchone()

        if not insumo:
            flash("Insumo não encontrado!")
            return redirect(url_for('pesquisa_insumos'))

        estoque = float(insumo[0])
        unidade_estoque = int(insumo[1])

        # PEGAR A QUANTIDADE E A UNIDADE ESCOLHIDAS
        quantidade_digitada = float(request.form['quantidade'])
        unidade_receita = int(request.form['unidade_uso'])

        if quantidade_digitada <= 0:
            flash("A quantidade deve ser maior que zero!")
            return redirect(url_for('pesquisa_insumos'))

        # VERIFICAR SE AS UNIDADES SÃO COMPATÍVEIS
        if unidade_estoque in (1, 2) and unidade_receita not in (1, 2):
            flash("Use kg ou g para este insumo!")
            return redirect(url_for('pesquisa_insumos'))

        if unidade_estoque in (3, 4) and unidade_receita not in (3, 4):
            flash("Use litros ou ml para este insumo!")
            return redirect(url_for('pesquisa_insumos'))

        if unidade_estoque == 5 and unidade_receita != 5:
            flash("Use unidade para este insumo!")
            return redirect(url_for('pesquisa_insumos'))

        # CONVERTER KG PARA G E LITROS PARA ML
        if unidade_receita == 1 or unidade_receita == 3:
            quantidade_base = quantidade_digitada * 1000
            unidade_base = unidade_receita + 1
        else:
            quantidade_base = quantidade_digitada
            unidade_base = unidade_receita

        # VERIFICAR SE A QUANTIDADE PODE SER ARMAZENADA COMO INTEIRO
        if not quantidade_base.is_integer():
            flash("A quantidade convertida precisa ser um número inteiro!")
            return redirect(url_for('pesquisa_insumos'))

        quantidade = int(quantidade_base)

        # CONVERTER A QUANTIDADE PARA A UNIDADE DO ESTOQUE
        if unidade_estoque == 1 or unidade_estoque == 3:
            quantidade_estoque = quantidade / 1000
        else:
            quantidade_estoque = quantidade

        # VERIFICAR SE EXISTE ESTOQUE SUFICIENTE
        if quantidade_estoque > estoque:
            flash("Quantidade insuficiente no estoque!")
            return redirect(url_for('pesquisa_insumos'))

        # INSERIR O INSUMO NO PRODUTO
        cursor.execute("""
            INSERT INTO insumos_utilizado
            (quantidade, unidade, id_insumos, id_produto)
            VALUES (?, ?, ?, ?)
        """, (quantidade, unidade_base, id, id_produto))

        # DIMINUIR A QUANTIDADE DO ESTOQUE
        cursor.execute("""
            UPDATE insumos
            SET estoque = estoque - ?
            WHERE id_insumos = ? AND id_usuario = ?
        """, (quantidade_estoque, id, id_usuario))

        # SALVAR AS ALTERAÇÕES NO BANCO
        con.commit()

        flash("Insumo inserido com sucesso!")
        return redirect(url_for('adicionando_insumo_produto'))

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro: {e}")
        return redirect(url_for('pesquisa_insumos'))

    finally:
        cursor.close()



@app.route('/lista_insumos_produto/<int:id_produto>')
def lista_insumos_produto(id_produto):

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']

    cursor = con.cursor()

    try:
        cursor.execute("""SELECT id_produto, nome 
                            FROM produtos
                              WHERE id_produto = ? AND id_usuario = ?""",
                       (id_produto, id_usuario))

        produto = cursor.fetchone()

        if not produto:
            flash('Produto não encontrado')
            return redirect(url_for('home'))


        cursor.execute("""
               SELECT i.nome, iu.quantidade,
                      iu.unidade
               FROM insumos_utilizado iu
               INNER JOIN insumos i ON i.id_insumos = iu.id_insumos
               WHERE iu.id_produto = ? and i.id_usuario = ?
           """, (id_produto,id_usuario))


        cursor.execute("""     SELECT iu.id_insumos
                            , i.nome
                            , case iu.unidade
                            WHEN 1 THEN 'Quilograma'
                            WHEN 2 THEN 'Grama'
                            WHEN 3 THEN 'Litros'
                            WHEN 4 THEN 'Mililitro'
                            WHEN 5 THEN 'Unidade'
                            ELSE ''
                            END AS unidade
                            , i.custo_unitario, i.estoque, iu.quantidade
                             FROM INSUMOS_UTILIZADO iu 
                             LEFT JOIN INSUMOS i  ON i.ID_INSUMOS  = iu.ID_INSUMOS 
                             WHERE i.id_usuario = ? 
                             AND iu.id_produto = ?
                             ORDER BY iu.id_insumos DESC
""", (id_usuario,id_produto))


        insumos = cursor.fetchall()
        return render_template('lista_insumos_produto.html', produto=produto, insumos=insumos)


    except Exception as e:
        con.rollback()
        flash(f'Ocorreu um erro -> {e}')
        return redirect(url_for('adicionar_insumo_produto'))

    finally:
        cursor.close()

@app.route('/editar_insumos_produto/<int:id_produto>/<int:id_insumos>', methods=['GET', 'POST'])
def editar_insumos_produto(id_produto, id_insumos):

    if 'id_usuario' not in session:
        flash("Você precisa estar logado!")
        return redirect(url_for('login_usu'))

    id_usuario = session['id_usuario']
    cursor = con.cursor()

    try:
        cursor.execute("""
            SELECT id_produto, nome
            FROM produtos
            WHERE id_produto = ? AND id_usuario = ?
        """, (id_produto, id_usuario))

        produto = cursor.fetchone()

        if not produto:
            flash("Produto não encontrado!")
            return redirect(url_for('home'))

        cursor.execute("""
            SELECT iu.id_insumos, i.nome, iu.quantidade,
                   iu.unidade, i.unidade, i.estoque
            FROM insumos_utilizado iu
            INNER JOIN insumos i ON i.id_insumos = iu.id_insumos
            WHERE iu.id_produto = ?
            AND iu.id_insumos = ?
            AND i.id_usuario = ?
        """, (id_produto, id_insumos, id_usuario))

        insumo = cursor.fetchone()

        if not insumo:
            flash("Insumo não encontrado!")
            return redirect(url_for(
                'lista_insumos_produto',
                id_produto=id_produto
            ))

        if request.method == 'POST':

            quantidade = float(request.form['quantidade'])
            unidade = int(request.form['unidade'])

            if quantidade <= 0:
                flash("A quantidade deve ser maior que zero!")
                return redirect(url_for(
                    'editar_insumos_produto',
                    id_produto=id_produto,
                    id_insumos=id_insumos
                ))

            # Dados antigos
            quantidade_antiga = float(insumo[2])
            unidade_antiga = int(insumo[3])

            # Unidade e estoque cadastrados no insumo
            unidade_estoque = int(insumo[4])
            estoque_atual = float(insumo[5])

            # Converter a quantidade antiga para g, ml ou unidade
            if unidade_antiga in (1, 3):
                quantidade_antiga_base = quantidade_antiga * 1000
            else:
                quantidade_antiga_base = quantidade_antiga

            # Converter a nova quantidade para g, ml ou unidade
            if unidade in (1, 3):
                quantidade_nova_base = quantidade * 1000
                unidade_base = unidade + 1
            else:
                quantidade_nova_base = quantidade
                unidade_base = unidade

            # Verificar se as unidades são compatíveis
            if unidade_estoque in (1, 2):
                tipo_estoque = 'peso'
            elif unidade_estoque in (3, 4):
                tipo_estoque = 'volume'
            else:
                tipo_estoque = 'unidade'

            if unidade_base in (1, 2):
                tipo_receita = 'peso'
            elif unidade_base in (3, 4):
                tipo_receita = 'volume'
            else:
                tipo_receita = 'unidade'

            if tipo_estoque != tipo_receita:
                flash("A unidade escolhida não é compatível com o insumo!")
                return redirect(url_for(
                    'editar_insumos_produto',
                    id_produto=id_produto,
                    id_insumos=id_insumos
                ))

            # Converter a quantidade antiga para a unidade do estoque
            if unidade_estoque in (1, 3):
                quantidade_antiga_estoque = quantidade_antiga_base / 1000
            else:
                quantidade_antiga_estoque = quantidade_antiga_base

            # Converter a quantidade nova para a unidade do estoque
            if unidade_estoque in (1, 3):
                quantidade_nova_estoque = quantidade_nova_base / 1000
            else:
                quantidade_nova_estoque = quantidade_nova_base

            # Devolver a quantidade antiga e descontar a nova
            estoque_final = (
                estoque_atual
                + quantidade_antiga_estoque
                - quantidade_nova_estoque
            )

            if estoque_final < 0:
                flash("Estoque insuficiente para essa quantidade!")
                return redirect(url_for(
                    'editar_insumos_produto',
                    id_produto=id_produto,
                    id_insumos=id_insumos
                ))

            # Atualizar o estoque
            cursor.execute("""
                UPDATE insumos
                SET estoque = ?
                WHERE id_insumos = ? AND id_usuario = ?
            """, (estoque_final, id_insumos, id_usuario))

            # Atualizar a quantidade utilizada no produto
            cursor.execute("""
                UPDATE insumos_utilizado
                SET quantidade = ?, unidade = ?
                WHERE id_produto = ? AND id_insumos = ?
            """, (
                int(quantidade_nova_base),
                unidade_base,
                id_produto,
                id_insumos
            ))

            con.commit()

            flash("Insumo editado com sucesso!")
            return redirect(url_for(
                'lista_insumos_produto',
                id_produto=id_produto
            ))

        return render_template(
            'editar_insumos_produto.html',
            produto=produto,
            insumo=insumo
        )

    except Exception as e:
        con.rollback()
        flash(f"Ocorreu um erro -> {e}")
        return redirect(url_for(
            'lista_insumos_produto',
            id_produto=id_produto
        ))

    finally:
        cursor.close()

if __name__ == '__main__':
    app.run(debug=True)