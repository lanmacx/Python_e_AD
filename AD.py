import tkinter as tk
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from ldap3 import Server, Connection, ALL, SUBTREE, SIMPLE, AUTO_BIND_TLS_BEFORE_BIND, MODIFY_REPLACE


botao_trocar_senha = None
botao_desbloquear_usuario = None


def verificar_expiracao_senha(nome_usuario):
    try:
        # Configurações do servidor Active Directory
        servidor_ad = os.getenv('SERVIDOR_AD')
        porta_ad = int(os.getenv('PORTA_AD'))
        usuario_ad = os.getenv('USUARIO_AD')
        senha_ad = os.getenv('SENHA_AD')
        dominio_ad = os.getenv('DOMINIO_AD')
        base_dn = os.getenv('BASE_DN')

        # Conectando ao Active Directory
        server = Server(servidor_ad, port=porta_ad, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=AUTO_BIND_TLS_BEFORE_BIND, authentication=SIMPLE)
        conn.search(search_base=base_dn,
                    search_filter=f'(&(objectClass=user)(sAMAccountName={nome_usuario}))',
                    search_scope=SUBTREE,
                    attributes=['cn', 'displayName', 'distinguishedName', 'pwdLastSet', 'lockoutTime'])

        if len(conn.entries) == 0:
            return "Usuário não encontrado no Active Directory.", None, False, False

        result = conn.entries[0]

        pwd_last_set = result['pwdLastSet'].value

        if isinstance(pwd_last_set, datetime):
            pwd_last_set = int(pwd_last_set.timestamp() * 10000000) + 116444736000000000

        last_set_date = datetime.fromtimestamp(pwd_last_set / 10000000 - 11644473600).replace(tzinfo=timezone.utc)

        # Verificando a data de expiração da senha
        expiracao = last_set_date + timedelta(days=90)  # Senha expira em 90 dias
        dias_restantes = (expiracao - datetime.now(timezone.utc)).days

        bloqueado = False
        if 'lockoutTime' in result:
            if (result['lockoutTime'].value is not None and result['lockoutTime'].value >
                    datetime(1601, 1, 1, tzinfo=timezone.utc)):
                bloqueado = True

        if bloqueado:
            status_bloqueado = "Usuário está bloqueado."
        else:
            status_bloqueado = "Usuário não está bloqueado."

        return (f"A senha foi cadastrada em: {last_set_date.strftime('%Y-%m-%d %H:%M:%S')}\nFaltam {dias_restantes} "
                f"dias para a senha expirar.\n{status_bloqueado}", result['distinguishedName'].value, bloqueado, True)
    except Exception as e:
        return f"Erro ao acessar o Active Directory: {str(e)}", None, False, False


def pesquisar_usuario():
    global botao_trocar_senha, botao_desbloquear_usuario

    nome_usuario = entry_usuario.get()
    resultado, dn, bloqueado, encontrado = verificar_expiracao_senha(nome_usuario)
    resposta_label.config(text=resultado)

    # Limpar campo de nova senha e ocultar botão e campo de nova senha
    entry_nova_senha.delete(0, 'end')
    label_nova_senha.grid_forget()
    entry_nova_senha.grid_forget()
    if botao_trocar_senha:
        botao_trocar_senha.grid_forget()

    if encontrado:
        # Adicionando campo e botão para trocar a senha
        botao_trocar_senha = tk.Button(janela, text="Trocar Senha",
                                       command=lambda: mostrar_campos_trocar_senha(dn))
        botao_trocar_senha.grid(row=9, column=1, columnspan=3, padx=10, pady=10)

        # Remover o botão Desbloquear Usuário se ele estiver presente
        if botao_desbloquear_usuario:
            botao_desbloquear_usuario.grid_forget()

        # Adicionando botão para desbloquear usuário, se estiver bloqueado
        if bloqueado:
            botao_desbloquear_usuario = tk.Button(janela, text="Desbloquear Usuário",
                                                  command=lambda: desbloquear_usuario(dn))
            botao_desbloquear_usuario.grid(row=10, column=1, columnspan=3, padx=10, pady=10)


def mostrar_campos_trocar_senha(dn):
    global botao_trocar_senha  # Declarando botao_trocar_senha como variável global

    label_nova_senha.grid(row=7, column=1, padx=10, pady=10)
    entry_nova_senha.grid(row=8, column=1, padx=10, pady=10)

    botao_trocar_senha = tk.Button(janela, text="Trocar Senha",
                                   command=lambda: trocar_senha(dn, entry_nova_senha.get()))
    botao_trocar_senha.grid(row=9, column=1, padx=10, pady=10)


def trocar_senha(dn, nova_senha):
    try:

        # Conectando ao Active Directory
        server = Server(servidor_ad, port=porta_ad, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=AUTO_BIND_TLS_BEFORE_BIND, authentication=SIMPLE)

        # Modificando a senha
        conn.extend.microsoft.modify_password(dn, nova_senha)
        resposta_label.config(text="Senha alterada com sucesso.")
    except Exception as e:
        resposta_label.config(text=f"Erro ao alterar a senha: {str(e)}")


def desbloquear_usuario(dn):
    try:
        # Configurações do servidor Active Directory
        servidor_ad = os.getenv('SERVIDOR_AD')
        porta_ad = int(os.getenv('PORTA_AD'))
        usuario_ad = os.getenv('USUARIO_AD')
        senha_ad = os.getenv('SENHA_AD')
        dominio_ad = os.getenv('DOMINIO_AD')

        # Conectando ao Active Directory
        server = Server(servidor_ad, port=porta_ad, get_info=ALL)
        conn = Connection(server, user=f"{usuario_ad}@{dominio_ad}", password=senha_ad,
                          auto_bind=AUTO_BIND_TLS_BEFORE_BIND, authentication=SIMPLE)

        # Desbloqueando o usuário
        conn.modify(dn, {'lockoutTime': [(MODIFY_REPLACE, [0])]})
        resposta_label.config(text="Usuário desbloqueado com sucesso.")
    except Exception as e:
        resposta_label.config(text=f"Erro ao desbloquear o usuário: {str(e)}")


# Criando a janela
janela = tk.Tk()
janela.title("Pesquisar Usuário no Active Directory")
janela.geometry('500x350')

# Carregando variáveis de ambiente
load_dotenv()

# Criando e posicionando os widgets
texto_orientacao = tk.Label(janela, text='Clique para pesquisar a data de expiração do usuário no AD')
texto_orientacao.grid(column=1, row=0, padx=100, pady=10)

label_usuario = tk.Label(janela, text="Nome de usuário:")
label_usuario.grid(row=1, column=1, padx=10, pady=10)

entry_usuario = tk.Entry(janela)
entry_usuario.grid(row=2, column=1, padx=10, pady=10)

label_nova_senha = tk.Label(janela, text="Nova senha:")
entry_nova_senha = tk.Entry(janela, show="*")
botao = tk.Button(janela, text="Pesquisar", command=pesquisar_usuario)
resposta_label = tk.Label(janela, text="")

botao.grid(row=3, column=1, columnspan=3, padx=10, pady=10)
resposta_label.grid(row=4, column=1, columnspan=3, padx=50, pady=10)

# Rodando a aplicação
janela.mainloop()
