import numpy as np
import streamlit as st
import sqlite3
import pandas as pd
import hashlib
import datetime
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import seaborn as sns
from PIL import Image
import io
import base64
import os # Importar para usar os.urandom para o salt

# --- Configuração Inicial ---
st.set_page_config(
    page_title="LinhaMestre",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Estilos CSS personalizados
def local_css(file_name):
    try:
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except FileNotFoundError:
        st.error(f"Erro: O arquivo '{file_name}' não foi encontrado. Certifique-se de que ele está na mesma pasta do script.")

local_css("styles.css")

# --- Constantes para Níveis de Acesso ---
ACCESS_LEVEL_OPERACIONAL = "Operacional"
ACCESS_LEVEL_SUPERVISOR = "Supervisor"
ACCESS_LEVEL_GERENTE = "Gerente"
ACCESS_LEVEL_CEO = "CEO"
ACCESS_LEVEL_ADMINISTRADOR = "Administrador"

ACCESS_LEVELS_ORDER = {
    ACCESS_LEVEL_OPERACIONAL: 1,
    ACCESS_LEVEL_SUPERVISOR: 2,
    ACCESS_LEVEL_GERENTE: 3,
    ACCESS_LEVEL_CEO: 4,
    ACCESS_LEVEL_ADMINISTRADOR: 5
}

# Constantes para Gráficos de Controle de Qualidade (ISO 8258 / ABNT NBR 5479)
# Estes valores dependem do tamanho da amostra (n).
# Adicione mais conforme necessário para outros tamanhos de amostra.
CONTROL_CHART_CONSTANTS = {
    2: {'A2': 1.880, 'D3': 0, 'D4': 3.267, 'B3': 0, 'B4': 3.267},
    3: {'A2': 1.023, 'D3': 0, 'D4': 2.575, 'B3': 0, 'B4': 2.568},
    4: {'A2': 0.729, 'D3': 0, 'D4': 2.282, 'B3': 0, 'B4': 2.089},
    5: {'A2': 0.577, 'D3': 0, 'D4': 2.114, 'B3': 0, 'B4': 2.089},
    6: {'A2': 0.483, 'D3': 0, 'D4': 2.004, 'B3': 0.030, 'B4': 1.970},
    7: {'A2': 0.419, 'D3': 0.076, 'D4': 1.924, 'B3': 0.118, 'B4': 1.882},
    8: {'A2': 0.373, 'D3': 0.136, 'D4': 1.864, 'B3': 0.185, 'B4': 1.815},
    9: {'A2': 0.337, 'D3': 0.184, 'D4': 1.816, 'B3': 0.239, 'B4': 1.761},
    10: {'A2': 0.308, 'D3': 0.223, 'D4': 1.777, 'B3': 0.284, 'B4': 1.716}
}


# --- Funções de Autenticação e Segurança ---

# Função para criar hash de senhas com salt
def make_hashes(password):
    salt = os.urandom(16) # Gera um salt aleatório de 16 bytes
    hashed_password = hashlib.sha256(salt + password.encode('utf-8')).hexdigest()
    return salt.hex(), hashed_password # Retorna o salt (em hexadecimal) e o hash

# Função para verificar senhas com salt
def check_hashes(password, stored_salt_hex, stored_hashed_text):
    salt = bytes.fromhex(stored_salt_hex) # Converte o salt de volta para bytes
    if hashlib.sha256(salt + password.encode('utf-8')).hexdigest() == stored_hashed_text:
        return True
    return False

# --- Conexão com o Banco de Dados ---
@st.cache_resource
def get_connection():
    conn = sqlite3.connect('linhamestre.db', check_same_thread=False)
    return conn

conn = get_connection()
c = conn.cursor()

# --- Criação e Inicialização de Tabelas ---
def create_tables():
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE,
                 password TEXT,
                 name TEXT,
                 email TEXT,
                 access_level TEXT,
                 salt TEXT, -- Adicione esta linha para armazenar o salt
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 name TEXT,
                 category TEXT,
                 quantity INTEGER,
                 min_quantity INTEGER,
                 unit TEXT,
                 location TEXT,
                 supplier TEXT,
                 cost REAL,
                 price REAL,
                 barcode TEXT,
                 production_date DATE,
                 expiry_date DATE,
                 quality_status TEXT,
                 notes TEXT,
                 created_by INTEGER,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 updated_at TIMESTAMP,
                 FOREIGN KEY(created_by) REFERENCES users(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 sender_id INTEGER,
                 receiver_id INTEGER,
                 subject TEXT,
                 content TEXT,
                 is_read INTEGER DEFAULT 0,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(sender_id) REFERENCES users(id),
                 FOREIGN KEY(receiver_id) REFERENCES users(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT,
                 description TEXT,
                 assigned_to INTEGER,
                 created_by INTEGER,
                 priority TEXT,
                 status TEXT DEFAULT 'Pendente',
                 due_date DATE,
                 completed_at TIMESTAMP,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(assigned_to) REFERENCES users(id),
                 FOREIGN KEY(created_by) REFERENCES users(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS quality_control
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 product_id INTEGER,
                 control_date DATE,
                 sample_size INTEGER,
                 mean_value REAL,
                 range_value REAL,
                 std_dev REAL,
                 created_by INTEGER,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 FOREIGN KEY(product_id) REFERENCES products(id),
                 FOREIGN KEY(created_by) REFERENCES users(id))''')
    
    conn.commit()

create_tables()

# Inicializar dados padrão se não existirem
def init_default_data():
    c.execute("SELECT COUNT(*) FROM users")
    count = c.fetchone()[0]
    
    if count == 0:
        # Inserir usuários padrão
        default_users_data = []
        users_to_add = [
            ("admin", "admin123", "Administrador", "admin@linhamestre.com", ACCESS_LEVEL_ADMINISTRADOR),
            ("ceo", "ceo123", "CEO", "ceo@linhamestre.com", ACCESS_LEVEL_CEO),
            ("gerente", "gerente123", "Gerente Geral", "gerente@linhamestre.com", ACCESS_LEVEL_GERENTE),
            ("supervisor", "super123", "Supervisor", "supervisor@linhamestre.com", ACCESS_LEVEL_SUPERVISOR),
            ("operacional", "oper123", "Operacional", "operacional@linhamestre.com", ACCESS_LEVEL_OPERACIONAL)
        ]
        
        for username, password, name, email, access_level in users_to_add:
            salt, hashed_password = make_hashes(password)
            default_users_data.append((username, hashed_password, name, email, access_level, salt))

        # Ajuste na query para incluir a coluna 'salt'
        c.executemany("INSERT INTO users (username, password, name, email, access_level, salt) VALUES (?, ?, ?, ?, ?, ?)", default_users_data)
        conn.commit()

init_default_data()

# --- Sistema de Autenticação ---
def login():
    st.sidebar.title("Login")
    username = st.sidebar.text_input("Usuário")
    password = st.sidebar.text_input("Senha", type="password")
    
    if st.sidebar.button("Entrar"):
        # Selecione o salt também
        c.execute("SELECT id, username, password, name, email, access_level, salt FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        
        if user and check_hashes(password, user[6], user[2]): # user[6] é a coluna 'salt'
            st.session_state['logged_in'] = True
            st.session_state['user_id'] = user[0]
            st.session_state['username'] = user[1]
            st.session_state['name'] = user[3]
            st.session_state['access_level'] = user[5]
            st.sidebar.success(f"Bem-vindo, {user[3]}!")
            st.experimental_rerun() # Recarrega a página para atualizar o menu
        else:
            st.sidebar.error("Usuário ou senha incorretos")

def logout():
    st.session_state['logged_in'] = False
    st.session_state['user_id'] = None
    st.session_state['username'] = None
    st.session_state['name'] = None
    st.session_state['access_level'] = None
    st.experimental_rerun()

# Verificar permissões
def has_permission(required_level):
    if 'access_level' not in st.session_state:
        return False
    
    user_level = ACCESS_LEVELS_ORDER.get(st.session_state['access_level'], 0)
    required = ACCESS_LEVELS_ORDER.get(required_level, 0)
    
    return user_level >= required

# --- Páginas do Aplicativo ---

# Página principal do dashboard
def dashboard_page():
    st.title(f"📊 Dashboard - LinhaMestre")
    st.write(f"Bem-vindo, {st.session_state['name']} ({st.session_state['access_level']})")

    # Cards de resumo
    col1, col2, col3, col4 = st.columns(4)

    # Total de produtos
    c.execute("SELECT COUNT(*) FROM products")
    total_products = c.fetchone()[0]
    col1.metric("Total de Produtos", total_products)

    # Produtos com estoque crítico
    c.execute("SELECT COUNT(*) FROM products WHERE quantity <= min_quantity")
    critical_products = c.fetchone()[0]
    col2.metric("Estoque Crítico", critical_products, delta=f"-{critical_products} atenção", delta_color="inverse")

    # Produtos próximos da validade (30 dias)
    today = datetime.now().date()
    next_month = today + timedelta(days=30)
    c.execute("SELECT COUNT(*) FROM products WHERE expiry_date BETWEEN ? AND ?", (today.strftime("%Y-%m-%d"), next_month.strftime("%Y-%m-%d")))
    expiring_products = c.fetchone()[0]
    col3.metric("Próximos da Validade", expiring_products, delta=f"-{expiring_products} atenção", delta_color="inverse")

    # Tarefas pendentes
    c.execute("SELECT COUNT(*) FROM tasks WHERE assigned_to = ? AND status = 'Pendente' AND (due_date IS NULL OR due_date >= ?)", (st.session_state['user_id'], today.strftime("%Y-%m-%d")))
    pending_tasks_count = c.fetchone()[0]
    col4.metric("Tarefas Pendentes", pending_tasks_count, delta=f"-{pending_tasks_count} pendentes", delta_color="inverse")

    st.markdown("---")

    # Gráficos e alertas
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Estoque por Categoria")
        c.execute("SELECT category, SUM(quantity) as total FROM products GROUP BY category")
        df_category = pd.DataFrame(c.fetchall(), columns=["Categoria", "Quantidade"])

        if not df_category.empty:
            fig = px.pie(df_category, values='Quantidade', names='Categoria',
                            color_discrete_sequence=px.colors.qualitative.Pastel)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Nenhum dado disponível para exibir o gráfico de categorias.")

    with col2:
        st.subheader("Produtos Próximos da Validade")
        c.execute('''SELECT name, expiry_date, quantity
                        FROM products
                        WHERE expiry_date BETWEEN ? AND ?
                        ORDER BY expiry_date ASC LIMIT 10''', (today.strftime("%Y-%m-%d"), next_month.strftime("%Y-%m-%d")))
        df_expiring = pd.DataFrame(c.fetchall(), columns=["Produto", "Validade", "Quantidade"])

        if not df_expiring.empty:
            df_expiring['Validade'] = pd.to_datetime(df_expiring['Validade']).dt.date
            fig = px.bar(df_expiring, x='Produto', y='Quantidade',
                            color='Validade',
                            color_continuous_scale='YlOrRd',
                            labels={'Quantidade': 'Quantidade em Estoque'},
                            title='Top 10 Produtos Próximos da Validade')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Nenhum produto próximo da validade nos próximos 30 dias.")

    st.markdown("---")

    # Alertas de estoque crítico
    st.subheader("🔔 Alertas de Estoque Crítico")
    c.execute('''SELECT p.name, p.quantity, p.min_quantity, p.unit, p.location
                    FROM products p
                    WHERE p.quantity <= p.min_quantity
                    ORDER BY p.quantity/p.min_quantity ASC LIMIT 5''')
    critical_items = c.fetchall()

    if critical_items:
        for item in critical_items:
            name, quantity, min_quantity, unit, location = item
            percentage = (quantity / min_quantity) * 100
            st.warning(f"**{name}**: {quantity} {unit} (mínimo: {min_quantity}) - {percentage:.0f}% do mínimo - Local: {location}")
    else:
        st.success("Nenhum item em estoque crítico no momento.")

    # Mensagens não lidas
    st.subheader("📩 Mensagens Não Lidas")
    c.execute('''SELECT m.id, u.name, m.subject, m.content, m.is_read, m.created_at
                    FROM messages m
                    JOIN users u ON m.sender_id = u.id
                    WHERE m.receiver_id = ? AND m.is_read = 0
                    ORDER BY m.created_at DESC LIMIT 5''', (st.session_state['user_id'],))
    unread_messages = c.fetchall()

    if unread_messages:
        for msg in unread_messages:
            msg_id, sender, subject, content, is_read, created_at = msg

            container = st.container(border=True)
            container.markdown(f"**{sender}**: **{subject}** (não lida)")

            with container:
                with st.expander("Ver mensagem"):
                    st.write(content)
                    st.caption(f"Enviado em: {created_at}")

                col1, col2 = st.columns(2)
                with col1:
                    if not is_read and st.button("Marcar como lida", key=f"read_{msg_id}"):
                        c.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (msg_id,))
                        conn.commit()
                        st.experimental_rerun()
                with col2:
                    if st.button("Responder", key=f"reply_{msg_id}"):
                        st.session_state['reply_to'] = msg_id
                        st.session_state['reply_sender'] = sender
                        st.session_state['reply_subject'] = f"Re: {subject}"
                        st.experimental_rerun()
    else:
        st.info("Nenhuma mensagem não lida.")

    # Tarefas pendentes
    st.subheader("📝 Tarefas Pendentes")
    c.execute('''SELECT t.id, t.title, t.due_date, u.name
                    FROM tasks t
                    JOIN users u ON t.assigned_to = u.id
                    WHERE t.assigned_to = ? AND t.status = 'Pendente'
                    ORDER BY t.due_date ASC LIMIT 5''', (st.session_state['user_id'],))
    pending_tasks = c.fetchall()

    if pending_tasks:
        for task in pending_tasks:
            task_id, title, due_date_str, assigned_to = task
            
            # Converte due_date_str para objeto date
            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None

            days_left = (due_date - today).days if due_date else None

            if days_left is not None:
                if days_left < 0:
                    status = f"🔴 Atrasada há {-days_left} dias"
                elif days_left == 0:
                    status = "🟡 Vence hoje"
                elif days_left <= 3:
                    status = f"🟠 Vence em {days_left} dias"
                else:
                    status = f"🔵 Vence em {days_left} dias"
            else:
                status = "⚪ Sem data definida"

            with st.expander(f"{title} - {status}"):
                c.execute("SELECT description FROM tasks WHERE id = ?", (task_id,))
                description = c.fetchone()[0]
                st.write(description)
                st.caption(f"Atribuída a: {assigned_to} | Prazo: {due_date.strftime('%d/%m/%Y') if due_date else 'N/A'}")
                if st.button("Marcar como concluída", key=f"complete_{task_id}"):
                    c.execute("UPDATE tasks SET status = 'Concluída', completed_at = CURRENT_TIMESTAMP WHERE id = ?", (task_id,))
                    conn.commit()
                    st.experimental_rerun()
    else:
        st.success("Nenhuma tarefa pendente no momento.")

# Gerenciamento de Produtos
def products_page():
    st.title("📦 Gerenciamento de Produtos")
    
    tab1, tab2, tab3, tab4 = st.tabs(["Lista de Produtos", "Adicionar Produto", "Editar Produto", "Relatórios"])
    
    with tab1:
        st.subheader("Lista de Produtos")
        
        # Filtros
        col1, col2, col3 = st.columns(3)
        
        with col1:
            filter_category = st.selectbox("Filtrar por Categoria", 
                                            ["Todos"] + [row[0] for row in c.execute("SELECT DISTINCT category FROM products").fetchall()])
        
        with col2:
            filter_stock = st.selectbox("Filtrar por Estoque", 
                                            ["Todos", "Normal", "Crítico", "Acima do Mínimo"])
        
        with col3:
            filter_expiry = st.selectbox("Filtrar por Validade", 
                                            ["Todos", "Válidos", "Próximos da Validade", "Vencidos"])
        
        # Consulta SQL base
        query = '''SELECT p.id, p.name, p.category, p.quantity, p.min_quantity, p.unit, 
                            p.expiry_date, p.quality_status, p.location
                    FROM products p'''
        
        conditions = []
        params = []
        
        # Aplicar filtros
        if filter_category != "Todos":
            conditions.append("p.category = ?")
            params.append(filter_category)
        
        if filter_stock == "Crítico":
            conditions.append("p.quantity <= p.min_quantity")
        elif filter_stock == "Acima do Mínimo":
            conditions.append("p.quantity > p.min_quantity")
        
        today = datetime.now().date()
        if filter_expiry == "Válidos":
            conditions.append("(p.expiry_date > ? OR p.expiry_date IS NULL)")
            params.append(today.strftime("%Y-%m-%d")) # Formatado para SQL
        elif filter_expiry == "Próximos da Validade":
            conditions.append("p.expiry_date BETWEEN ? AND ?")
            params.extend([today.strftime("%Y-%m-%d"), (today + timedelta(days=30)).strftime("%Y-%m-%d")]) # Formatado para SQL
        elif filter_expiry == "Vencidos":
            conditions.append("p.expiry_date < ?")
            params.append(today.strftime("%Y-%m-%d")) # Formatado para SQL
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY p.name"
        
        # Executar consulta
        c.execute(query, tuple(params))
        products = c.fetchall()
        
        if products:
            df = pd.DataFrame(products, columns=["ID", "Nome", "Categoria", "Quantidade", "Mínimo", "Unidade", 
                                                 "Validade", "Qualidade", "Localização"])
            
            # Formatar colunas
            df['Validade'] = pd.to_datetime(df['Validade']).dt.date # Converte para tipo data
            df['Status Estoque'] = df.apply(lambda row: "Crítico" if row['Quantidade'] <= row['Mínimo'] else "Normal", axis=1)
            df['Status Validade'] = df.apply(lambda row: 
                "Vencido" if row['Validade'] and row['Validade'] < today else
                "Próximo" if row['Validade'] and row['Validade'] <= today + timedelta(days=30) else
                "Válido" if row['Validade'] else "Sem data", axis=1)
            
            # Exibir tabela
            st.dataframe(df, use_container_width=True, 
                            column_config={
                                "ID": None,
                                "Quantidade": st.column_config.ProgressColumn(
                                    "Quantidade",
                                    help="Quantidade em estoque",
                                    format="%d",
                                    min_value=0,
                                    max_value=df['Quantidade'].max() * 1.2
                                ),
                                "Mínimo": None
                            })
            
            # Opção de exportação
            if st.button("Exportar para Excel"):
                output = io.BytesIO()
                with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                    df.to_excel(writer, index=False, sheet_name='Produtos')
                    writer.close()
                 
                st.download_button(
                    label="Baixar arquivo Excel",
                    data=output.getvalue(),
                    file_name="produtos.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
        else:
            st.warning("Nenhum produto encontrado com os filtros selecionados.")
    
    with tab2:
        if has_permission(ACCESS_LEVEL_SUPERVISOR):
            st.subheader("Adicionar Novo Produto")
            
            with st.form("add_product_form", clear_on_submit=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    name = st.text_input("Nome do Produto*", max_chars=100)
                    category = st.text_input("Categoria*", max_chars=50)
                    quantity = st.number_input("Quantidade em Estoque*", min_value=0, step=1)
                    min_quantity = st.number_input("Quantidade Mínima*", min_value=0, step=1)
                    unit = st.selectbox("Unidade de Medida*", ["Unidade", "Kg", "Litro", "Caixa", "Pacote", "Metro"])
                
                with col2:
                    location = st.text_input("Localização no Armazém", max_chars=50)
                    supplier = st.text_input("Fornecedor", max_chars=100)
                    cost = st.number_input("Custo Unitário (R$)", min_value=0.0, format="%.2f")
                    price = st.number_input("Preço de Venda (R$)", min_value=0.0, format="%.2f")
                    barcode = st.text_input("Código de Barras", max_chars=50)
                
                production_date = st.date_input("Data de Produção")
                expiry_date = st.date_input("Data de Validade")
                quality_status = st.selectbox("Status de Qualidade", ["Aprovado", "Reprovado", "Em Análise"])
                notes = st.text_area("Observações")
                
                submitted = st.form_submit_button("Cadastrar Produto")
                
                if submitted:
                    if not name or not category or not quantity or not min_quantity or not unit:
                        st.error("Por favor, preencha todos os campos obrigatórios (*)")
                    else:
                        try:
                            c.execute('''INSERT INTO products 
                                            (name, category, quantity, min_quantity, unit, location, supplier, 
                                            cost, price, barcode, production_date, expiry_date, quality_status, 
                                            notes, created_by, updated_at)
                                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                                        (name, category, quantity, min_quantity, unit, location, supplier,
                                         cost, price, barcode, 
                                         production_date.strftime("%Y-%m-%d"), # Formata a data para string
                                         expiry_date.strftime("%Y-%m-%d"), # Formata a data para string
                                         quality_status, notes, st.session_state['user_id']))
                            conn.commit()
                            st.success("Produto cadastrado com sucesso!")
                        except Exception as e:
                            st.error(f"Erro ao cadastrar produto: {e}")
        else:
            st.warning("Você não tem permissão para adicionar produtos.")
    
    with tab3:
        if has_permission(ACCESS_LEVEL_SUPERVISOR):
            st.subheader("Editar Produto Existente")
            
            c.execute("SELECT id, name FROM products ORDER BY name")
            products = c.fetchall()
            
            if products:
                product_options = {f"{p[1]} (ID: {p[0]})": p[0] for p in products}
                selected_product_key = st.selectbox("Selecione o produto para editar", options=list(product_options.keys()))
                product_id = product_options[selected_product_key]
                
                c.execute("SELECT * FROM products WHERE id = ?", (product_id,))
                product = c.fetchone()
                
                if product:
                    with st.form("edit_product_form"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            name = st.text_input("Nome do Produto*", value=product[1], max_chars=100)
                            category = st.text_input("Categoria*", value=product[2], max_chars=50)
                            quantity = st.number_input("Quantidade em Estoque*", min_value=0, step=1, value=product[3])
                            min_quantity = st.number_input("Quantidade Mínima*", min_value=0, step=1, value=product[4])
                            unit = st.selectbox("Unidade de Medida*", 
                                                    ["Unidade", "Kg", "Litro", "Caixa", "Pacote", "Metro"],
                                                    index=["Unidade", "Kg", "Litro", "Caixa", "Pacote", "Metro"].index(product[5]))
                        
                        with col2:
                            location = st.text_input("Localização no Armazém", value=product[6] if product[6] else "", max_chars=50)
                            supplier = st.text_input("Fornecedor", value=product[7] if product[7] else "", max_chars=100)
                            cost = st.number_input("Custo Unitário (R$)", min_value=0.0, format="%.2f", value=float(product[8]) if product[8] else 0.0)
                            price = st.number_input("Preço de Venda (R$)", min_value=0.0, format="%.2f", value=float(product[9]) if product[9] else 0.0)
                            barcode = st.text_input("Código de Barras", value=product[10] if product[10] else "", max_chars=50)
                        
                        production_date = st.date_input("Data de Produção", value=datetime.strptime(product[11], "%Y-%m-%d").date() if product[11] else None)
                        expiry_date = st.date_input("Data de Validade", value=datetime.strptime(product[12], "%Y-%m-%d").date() if product[12] else None)
                        quality_status = st.selectbox("Status de Qualidade", 
                                                        ["Aprovado", "Reprovado", "Em Análise"],
                                                        index=["Aprovado", "Reprovado", "Em Análise"].index(product[13]))
                        notes = st.text_area("Observações", value=product[14] if product[14] else "")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            submitted = st.form_submit_button("Atualizar Produto")
                        with col2:
                            if st.form_submit_button("Excluir Produto"):
                                c.execute("DELETE FROM products WHERE id = ?", (product_id,))
                                conn.commit()
                                st.success("Produto excluído com sucesso!")
                                st.experimental_rerun()
                        
                        if submitted:
                            if not name or not category or not quantity or not min_quantity or not unit:
                                st.error("Por favor, preencha todos os campos obrigatórios (*)")
                            else:
                                try:
                                    c.execute('''UPDATE products 
                                                    SET name=?, category=?, quantity=?, min_quantity=?, unit=?, 
                                                        location=?, supplier=?, cost=?, price=?, barcode=?, 
                                                        production_date=?, expiry_date=?, quality_status=?, notes=?, 
                                                        updated_at=CURRENT_TIMESTAMP
                                                    WHERE id=?''',
                                                (name, category, quantity, min_quantity, unit, 
                                                 location, supplier, cost, price, barcode,
                                                 production_date.strftime("%Y-%m-%d") if production_date else None, 
                                                 expiry_date.strftime("%Y-%m-%d") if expiry_date else None, 
                                                 quality_status, notes,
                                                 product_id))
                                    conn.commit()
                                    st.success("Produto atualizado com sucesso!")
                                except Exception as e:
                                    st.error(f"Erro ao atualizar produto: {e}")
                else:
                    st.error("Produto não encontrado.")
            else:
                st.warning("Nenhum produto cadastrado para editar.")
        else:
            st.warning("Você não tem permissão para editar produtos.")
    
    with tab4:
        st.subheader("Relatórios de Produtos")
        
        report_type = st.selectbox("Tipo de Relatório", 
                                    ["Estoque por Categoria", "Produtos Críticos", 
                                     "Validade de Produtos", "Qualidade de Produtos"])
        
        if report_type == "Estoque por Categoria":
            c.execute('''SELECT category, SUM(quantity) as total_quantity, 
                            COUNT(*) as product_count, AVG(price) as avg_price
                            FROM products 
                            GROUP BY category
                            ORDER BY total_quantity DESC''')
            data = c.fetchall()
            
            if data:
                df = pd.DataFrame(data, columns=["Categoria", "Quantidade Total", "Número de Produtos", "Preço Médio"])
                
                fig = px.bar(df, x='Categoria', y='Quantidade Total', 
                                color='Número de Produtos',
                                title='Estoque Total por Categoria',
                                labels={'Quantidade Total': 'Quantidade', 'Número de Produtos': 'Produtos'},
                                hover_data=['Preço Médio'])
                st.plotly_chart(fig, use_container_width=True)
                
                st.dataframe(df, use_container_width=True)
            else:
                st.warning("Nenhum dado disponível para este relatório.")
        
        elif report_type == "Produtos Críticos":
            c.execute('''SELECT name, category, quantity, min_quantity, 
                            (quantity*100.0/min_quantity) as percentage, location
                            FROM products 
                            WHERE quantity <= min_quantity
                            ORDER BY percentage ASC''')
            data = c.fetchall()
            
            if data:
                df = pd.DataFrame(data, columns=["Produto", "Categoria", "Quantidade", "Mínimo", "% do Mínimo", "Localização"])
                df['% do Mínimo'] = df['% do Mínimo'].round(1)
                
                fig = px.bar(df, x='Produto', y='% do Mínimo',
                                color='Categoria',
                                title='Produtos com Estoque Crítico',
                                labels={'% do Mínimo': '% do Estoque Mínimo'},
                                hover_data=['Quantidade', 'Mínimo', 'Localização'])
                fig.update_yaxes(range=[0, 100])
                st.plotly_chart(fig, use_container_width=True)
                
                st.dataframe(df, use_container_width=True)
            else:
                st.success("Nenhum produto em estoque crítico.")
        
        elif report_type == "Validade de Produtos":
            today = datetime.now().date()
            next_month = today + timedelta(days=30)
            
            c.execute('''SELECT 
                            CASE 
                                WHEN expiry_date IS NULL THEN 'Sem Validade'
                                WHEN expiry_date < ? THEN 'Vencidos'
                                WHEN expiry_date <= ? THEN 'Próximos da Validade'
                                ELSE 'Válidos'
                            END as status,
                            COUNT(*) as count,
                            SUM(quantity) as total_quantity
                            FROM products
                            GROUP BY status
                            ORDER BY 
                            CASE status
                                WHEN 'Vencidos' THEN 1
                                WHEN 'Próximos da Validade' THEN 2
                                WHEN 'Válidos' THEN 3
                                ELSE 4
                            END''', (today.strftime("%Y-%m-%d"), next_month.strftime("%Y-%m-%d")))
            data = c.fetchall()
            
            if data:
                df = pd.DataFrame(data, columns=["Status", "Número de Produtos", "Quantidade Total"])
                
                fig = px.pie(df, values='Número de Produtos', names='Status',
                                title='Distribuição por Status de Validade',
                                hover_data=['Quantidade Total'],
                                color_discrete_sequence=px.colors.qualitative.Pastel)
                st.plotly_chart(fig, use_container_width=True)
                
                st.dataframe(df, use_container_width=True)
            else:
                st.warning("Nenhum dado disponível para este relatório.")
        
        elif report_type == "Qualidade de Produtos":
            c.execute('''SELECT quality_status, COUNT(*) as count, SUM(quantity) as total_quantity
                            FROM products
                            GROUP BY quality_status
                            ORDER BY count DESC''')
            data = c.fetchall()
            
            if data:
                df = pd.DataFrame(data, columns=["Status de Qualidade", "Número de Produtos", "Quantidade Total"])
                
                fig = px.bar(df, x='Status de Qualidade', y='Número de Produtos',
                                color='Quantidade Total',
                                title='Distribuição por Status de Qualidade',
                                labels={'Número de Produtos': 'Produtos', 'Quantidade Total': 'Quantidade'})
                st.plotly_chart(fig, use_container_width=True)
                
                # Gráfico de Pareto
                df_pareto = df.sort_values('Número de Produtos', ascending=False)
                df_pareto['Cumulative Percentage'] = (df_pareto['Número de Produtos'].cumsum() / df_pareto['Número de Produtos'].sum()) * 100
                
                fig = go.Figure()
                fig.add_trace(go.Bar(
                    x=df_pareto['Status de Qualidade'],
                    y=df_pareto['Número de Produtos'],
                    name='Número de Produtos',
                    marker_color='rgb(55, 83, 109)'
                ))
                
                fig.add_trace(go.Scatter(
                    x=df_pareto['Status de Qualidade'],
                    y=df_pareto['Cumulative Percentage'],
                    name='Porcentagem Acumulada',
                    yaxis='y2',
                    line=dict(color='rgb(255, 127, 14)', width=2)
                ))
                
                fig.update_layout(
                    title='Análise de Pareto - Status de Qualidade',
                    yaxis=dict(
                        title='Número de Produtos',
                        titlefont=dict(color='rgb(55, 83, 109)'),
                        tickfont=dict(color='rgb(55, 83, 109)')
                    ),
                    yaxis2=dict(
                        title='Porcentagem Acumulada',
                        titlefont=dict(color='rgb(255, 127, 14)'),
                        tickfont=dict(color='rgb(255, 127, 14)'),
                        overlaying='y',
                        side='right',
                        range=[0, 110]
                    ),
                    showlegend=False
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                st.dataframe(df, use_container_width=True)
            else:
                st.warning("Nenhum dado disponível para este relatório.")
        
        # Exportar relatório
        if st.button("Exportar Relatório para CSV"):
            if 'df' in locals() and not df.empty: # Verifica se df existe e não está vazio
                if report_type == "Estoque por Categoria":
                    filename = "estoque_por_categoria.csv"
                elif report_type == "Produtos Críticos":
                    filename = "produtos_criticos.csv"
                elif report_type == "Validade de Produtos":
                    filename = "validade_produtos.csv"
                else: # Qualidade de Produtos
                    filename = "qualidade_produtos.csv"
                
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Baixar CSV",
                    data=csv,
                    file_name=filename,
                    mime="text/csv"
                )
            else:
                st.warning("Não há dados para exportar no relatório selecionado.")


# Sistema de Mensagens
def messages_page():
    st.title("📨 Sistema de Mensagens")
    
    tab1, tab2, tab3 = st.tabs(["Caixa de Entrada", "Enviar Mensagem", "Mensagens Enviadas"])
    
    with tab1:
        st.subheader("Caixa de Entrada")
        
        # Filtros
        col1, col2 = st.columns(2)
        with col1:
            filter_read = st.selectbox("Filtrar por status", ["Todas", "Não lidas", "Lidas"])
        with col2:
            c.execute("SELECT id, name FROM users WHERE id != ?", (st.session_state['user_id'],))
            senders = c.fetchall()
            sender_options = {f"{s[1]} (ID: {s[0]})": s[0] for s in senders}
            filter_sender = st.selectbox("Filtrar por remetente", ["Todos"] + list(sender_options.keys()))
        
        # Consulta SQL
        query = '''SELECT m.id, u.name, m.subject, m.content, m.is_read, m.created_at 
                    FROM messages m 
                    JOIN users u ON m.sender_id = u.id 
                    WHERE m.receiver_id = ?'''
        
        params = [st.session_state['user_id']]
        
        if filter_read == "Não lidas":
            query += " AND m.is_read = 0"
        elif filter_read == "Lidas":
            query += " AND m.is_read = 1"
        
        if filter_sender != "Todos":
            sender_id = sender_options[filter_sender]
            query += " AND m.sender_id = ?"
            params.append(sender_id)
        
        query += " ORDER BY m.created_at DESC"
        
        c.execute(query, tuple(params))
        messages = c.fetchall()
        
        if messages:
            for msg in messages:
                msg_id, sender, subject, content, is_read, created_at = msg
                
                # Estilo diferente para mensagens não lidas
                if not is_read:
                    container = st.container(border=True)
                    container.markdown(f"**{sender}**: **{subject}** (não lida)")
                else:
                    container = st.container(border=True)
                    container.markdown(f"{sender}: {subject}")
                
                with container:
                    with st.expander("Ver mensagem"):
                        st.write(content)
                        st.caption(f"Enviado em: {created_at}")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if not is_read and st.button("Marcar como lida", key=f"read_{msg_id}"):
                            c.execute("UPDATE messages SET is_read = 1 WHERE id = ?", (msg_id,))
                            conn.commit()
                            st.experimental_rerun()
                    with col2:
                        if st.button("Responder", key=f"reply_{msg_id}"):
                            st.session_state['reply_to'] = msg_id
                            st.session_state['reply_sender'] = sender
                            st.session_state['reply_subject'] = f"Re: {subject}"
                            st.experimental_rerun()
        else:
            st.info("Nenhuma mensagem encontrada com os filtros selecionados.")
    
    with tab2:
        st.subheader("Enviar Nova Mensagem")
        
        # Verificar se é uma resposta
        reply_to = st.session_state.get('reply_to', None)
        reply_sender = st.session_state.get('reply_sender', None)
        reply_subject = st.session_state.get('reply_subject', "")
        
        if reply_to:
            st.info(f"Respondendo à mensagem de {reply_sender}")
        
        with st.form("send_message_form", clear_on_submit=True):
            # Selecionar destinatário
            c.execute("SELECT id, name, access_level FROM users WHERE id != ?", (st.session_state['user_id'],))
            recipients = c.fetchall()
            recipient_options = {f"{r[1]} ({r[2]})": r[0] for r in recipients}
            
            # Garante que 'recipient' seja um valor da lista de opções, mesmo se o estado de resposta for definido
            default_recipient_index = 0
            if reply_to and reply_sender:
                for idx, (display_name, r_id) in enumerate(recipient_options.items()):
                    if display_name.startswith(reply_sender): # Busca por parte do nome
                        default_recipient_index = idx
                        break
            
            recipient_selection = st.selectbox("Destinatário*", options=list(recipient_options.keys()), index=default_recipient_index)
            
            subject = st.text_input("Assunto*", value=reply_subject, max_chars=100)
            content = st.text_area("Mensagem*", height=200)
            
            submitted = st.form_submit_button("Enviar Mensagem")
            
            if submitted:
                if not subject or not content:
                    st.error("Por favor, preencha todos os campos obrigatórios (*)")
                else:
                    recipient_id = recipient_options[recipient_selection]
                    c.execute('''INSERT INTO messages 
                                    (sender_id, receiver_id, subject, content, created_at)
                                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''',
                                (st.session_state['user_id'], recipient_id, subject, content))
                    conn.commit()
                    
                    # Limpar estado de resposta se existir
                    if 'reply_to' in st.session_state:
                        del st.session_state['reply_to']
                        del st.session_state['reply_sender']
                        del st.session_state['reply_subject']
                    
                    st.success("Mensagem enviada com sucesso!")
    
    with tab3:
        st.subheader("Mensagens Enviadas")
        
        c.execute('''SELECT m.id, u.name, m.subject, m.content, m.is_read, m.created_at 
                    FROM messages m 
                    JOIN users u ON m.receiver_id = u.id 
                    WHERE m.sender_id = ? 
                    ORDER BY m.created_at DESC''', (st.session_state['user_id'],))
        sent_messages = c.fetchall()
        
        if sent_messages:
            for msg in sent_messages:
                msg_id, recipient, subject, content, is_read, created_at = msg
                
                with st.container(border=True):
                    st.markdown(f"Para: {recipient} - {subject}")
                    with st.expander("Ver mensagem"):
                        st.write(content)
                        st.caption(f"Enviado em: {created_at}")
                        st.caption(f"Status: {'Lida' if is_read else 'Não lida'}")
        else:
            st.info("Você ainda não enviou nenhuma mensagem.")

# Gerenciamento de Tarefas
def tasks_page():
    st.title("✅ Gerenciamento de Tarefas")
    
    tab1, tab2, tab3 = st.tabs(["Minhas Tarefas", "Criar Tarefa", "Todas as Tarefas"])
    
    with tab1:
        st.subheader("Minhas Tarefas")
        
        # Filtros
        col1, col2 = st.columns(2)
        with col1:
            filter_status = st.selectbox("Filtrar por status", ["Todas", "Pendente", "Concluída", "Atrasada"])
        with col2:
            filter_priority = st.selectbox("Filtrar por prioridade", ["Todas", "Alta", "Média", "Baixa"])
        
        # Consulta SQL
        query = '''SELECT t.id, t.title, t.description, t.priority, t.status, t.due_date, 
                            t.completed_at, u.name as created_by
                        FROM tasks t
                        JOIN users u ON t.created_by = u.id
                        WHERE t.assigned_to = ?'''
        
        params = [st.session_state['user_id']]
        
        if filter_status == "Pendente":
            query += " AND t.status = 'Pendente'"
        elif filter_status == "Concluída":
            query += " AND t.status = 'Concluída'"
        elif filter_status == "Atrasada":
            query += " AND t.status = 'Pendente' AND t.due_date < DATE('now')"
        
        if filter_priority != "Todas":
            query += " AND t.priority = ?"
            params.append(filter_priority)
        
        query += " ORDER BY CASE WHEN t.due_date IS NULL THEN 1 ELSE 0 END, t.due_date"
        
        c.execute(query, tuple(params))
        tasks = c.fetchall()
        
        if tasks:
            today = datetime.now().date()
            
            for task in tasks:
                task_id, title, description, priority, status, due_date_str, completed_at_str, created_by = task
                
                # Conversão das datas para objetos datetime.date
                due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None
                # O formato exato de completed_at depende de como o SQLite o armazena.
                # Se for TIMESTAMP DEFAULT CURRENT_TIMESTAMP, pode ser '%Y-%m-%d %H:%M:%S.%f' ou '%Y-%m-%d %H:%M:%S'
                try:
                    completed_at = datetime.strptime(completed_at_str, "%Y-%m-%d %H:%M:%S.%f").date() if completed_at_str else None
                except ValueError: # Tenta o formato sem milissegundos se o primeiro falhar
                    completed_at = datetime.strptime(completed_at_str, "%Y-%m-%d %H:%M:%S").date() if completed_at_str else None


                # Determine color do status
                if status == "Concluída":
                    status_color = "🟢"
                elif due_date and due_date < today and status == "Pendente":
                    status_color = "🔴"
                elif due_date and due_date == today and status == "Pendente":
                    status_color = "🟡"
                else:
                    status_color = "🔵"
                
                # Determine color da prioridade
                if priority == "Alta":
                    priority_color = "🔴"
                elif priority == "Média":
                    priority_color = "🟡"
                else:
                    priority_color = "🟢"
                
                with st.container(border=True):
                    st.markdown(f"**{status_color} {title}** - {priority_color} {priority}")
                    
                    if due_date:
                        days_left = (due_date - today).days
                        if days_left < 0 and status == "Pendente":
                            st.caption(f"⚠️ Atrasada há {-days_left} dias | Prazo: {due_date.strftime('%d/%m/%Y')}")
                        elif days_left == 0 and status == "Pendente":
                            st.caption(f"⚠️ Vence hoje | Prazo: {due_date.strftime('%d/%m/%Y')}")
                        elif status == "Pendente":
                            st.caption(f"Prazo: {due_date.strftime('%d/%m/%Y')} (em {days_left} dias)")
                        else:
                            st.caption(f"Concluída em: {completed_at.strftime('%d/%m/%Y') if completed_at else 'N/A'} | Prazo original: {due_date.strftime('%d/%m/%Y')}")
                    else:
                        st.caption("Sem prazo definido")
                    
                    st.caption(f"Criada por: {created_by}")
                    
                    with st.expander("Ver detalhes"):
                        st.write(description)
                        
                        if status == "Pendente":
                            if st.button("Marcar como Concluída", key=f"complete_{task_id}"):
                                c.execute('''UPDATE tasks 
                                            SET status = 'Concluída', completed_at = CURRENT_TIMESTAMP 
                                            WHERE id = ?''', (task_id,))
                                conn.commit()
                                st.experimental_rerun()
        else:
            st.info("Nenhuma tarefa encontrada com os filtros selecionados.")
    
    with tab2:
        if has_permission(ACCESS_LEVEL_SUPERVISOR):
            st.subheader("Criar Nova Tarefa")
            
            with st.form("create_task_form", clear_on_submit=True):
                title = st.text_input("Título*", max_chars=100)
                description = st.text_area("Descrição*", height=150)
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    priority = st.selectbox("Prioridade*", ["Alta", "Média", "Baixa"])
                with col2:
                    due_date = st.date_input("Prazo")
                with col3:
                    # Selecionar destinatário
                    c.execute("SELECT id, name, access_level FROM users WHERE id != ?", (st.session_state['user_id'],))
                    assignees = c.fetchall()
                    assignee_options = {f"{a[1]} ({a[2]})": a[0] for a in assignees}
                    assignee = st.selectbox("Atribuir a*", options=list(assignee_options.keys()))
                
                submitted = st.form_submit_button("Criar Tarefa")
                
                if submitted:
                    if not title or not description or not priority or not assignee:
                        st.error("Por favor, preencha todos os campos obrigatórios (*)")
                    else:
                        assignee_id = assignee_options[assignee]
                        c.execute('''INSERT INTO tasks 
                                        (title, description, assigned_to, created_by, priority, due_date, status)
                                        VALUES (?, ?, ?, ?, ?, ?, 'Pendente')''',
                                    (title, description, assignee_id, st.session_state['user_id'], priority, due_date.strftime("%Y-%m-%d")))
                        conn.commit()
                        st.success("Tarefa criada com sucesso!")
        else:
            st.warning("Você não tem permissão para criar tarefas.")
    
    with tab3:
        if has_permission(ACCESS_LEVEL_GERENTE):
            st.subheader("Todas as Tarefas")
            
            # Filtros avançados
            col1, col2, col3 = st.columns(3)
            with col1:
                filter_all_status = st.selectbox("Status", ["Todas", "Pendente", "Concluída", "Atrasada"])
            with col2:
                filter_all_priority = st.selectbox("Prioridade", ["Todas", "Alta", "Média", "Baixa"])
            with col3:
                c.execute("SELECT id, name FROM users")
                users = c.fetchall()
                user_options = {f"{u[1]} (ID: {u[0]})": u[0] for u in users}
                filter_user = st.selectbox("Atribuída a", ["Todos"] + list(user_options.keys()))
            
            # Consulta SQL
            query = '''SELECT t.id, t.title, t.description, t.priority, t.status, t.due_date, 
                                t.completed_at, u1.name as assigned_to, u2.name as created_by
                            FROM tasks t
                            JOIN users u1 ON t.assigned_to = u1.id
                            JOIN users u2 ON t.created_by = u2.id'''
            
            conditions = []
            params = []
            
            if filter_all_status == "Pendente":
                conditions.append("t.status = 'Pendente'")
            elif filter_all_status == "Concluída":
                conditions.append("t.status = 'Concluída'")
            elif filter_all_status == "Atrasada":
                conditions.append("t.status = 'Pendente' AND t.due_date < DATE('now')")
            
            if filter_all_priority != "Todas":
                conditions.append("t.priority = ?")
                params.append(filter_all_priority)
            
            if filter_user != "Todos":
                conditions.append("t.assigned_to = ?")
                params.append(user_options[filter_user])
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY CASE WHEN t.due_date IS NULL THEN 1 ELSE 0 END, t.due_date"
            
            c.execute(query, tuple(params))
            all_tasks = c.fetchall()
            
            if all_tasks:
                today = datetime.now().date()
                
                for task in all_tasks:
                    task_id, title, description, priority, status, due_date_str, completed_at_str, assigned_to, created_by = task
                    
                    # Conversão das datas para objetos datetime.date
                    due_date = datetime.strptime(due_date_str, "%Y-%m-%d").date() if due_date_str else None
                    try:
                        completed_at = datetime.strptime(completed_at_str, "%Y-%m-%d %H:%M:%S.%f").date() if completed_at_str else None
                    except ValueError:
                        completed_at = datetime.strptime(completed_at_str, "%Y-%m-%d %H:%M:%S").date() if completed_at_str else None

                    with st.container(border=True):
                        st.markdown(f"**{title}**")
                        st.caption(f"Atribuída a: {assigned_to} | Criada por: {created_by}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"Prioridade: {priority}")
                        with col2:
                            st.write(f"Status: {status}")
                        
                        if due_date:
                            if status == "Pendente":
                                days_left = (due_date - today).days
                                if days_left < 0:
                                    st.warning(f"⚠️ Atrasada há {-days_left} dias | Prazo: {due_date.strftime('%d/%m/%Y')}")
                                elif days_left == 0:
                                    st.warning(f"⚠️ Vence hoje | Prazo: {due_date.strftime('%d/%m/%Y')}")
                                else:
                                    st.info(f"Prazo: {due_date.strftime('%d/%m/%Y')} (em {days_left} dias)")
                            else:
                                st.info(f"Concluída em: {completed_at.strftime('%d/%m/%Y') if completed_at else 'N/A'} | Prazo original: {due_date.strftime('%d/%m/%Y')}")
                        else:
                            st.info("Sem prazo definido")
                        
                        if has_permission(ACCESS_LEVEL_GERENTE) and status == "Pendente":
                            if st.button("Marcar como Concluída", key=f"admin_complete_{task_id}"):
                                c.execute('''UPDATE tasks 
                                            SET status = 'Concluída', completed_at = CURRENT_TIMESTAMP 
                                            WHERE id = ?''', (task_id,))
                                conn.commit()
                                st.experimental_rerun()
            else:
                st.info("Nenhuma tarefa encontrada com os filtros selecionados.")
            
            # Gráfico de Gantt
            st.subheader("Gráfico de Gantt - Tarefas")
            
            # Ajuste na consulta para garantir que as datas sejam strings no formato correto
            c.execute('''SELECT t.title, u.name as assigned_to, 
                                    CASE WHEN t.due_date IS NULL THEN NULL ELSE STRFTIME('%Y-%m-%d', t.due_date) END as due_date_str,
                                    STRFTIME('%Y-%m-%d %H:%M:%S', t.created_at) as created_at_str,
                                    CASE WHEN t.completed_at IS NULL THEN NULL ELSE STRFTIME('%Y-%m-%d %H:%M:%S', t.completed_at) END as completed_at_str,
                                    t.status, t.priority
                                FROM tasks t
                                JOIN users u ON t.assigned_to = u.id
                                WHERE t.due_date IS NOT NULL
                                ORDER BY t.due_date''')
            gantt_data = c.fetchall()
            
            if gantt_data:
                df_gantt = pd.DataFrame(gantt_data, columns=["Tarefa", "Responsável", "Prazo", 
                                                                "Criação", "Conclusão", "Status", "Prioridade"])
                
                # Converter datas para o tipo datetime
                df_gantt['Prazo'] = pd.to_datetime(df_gantt['Prazo'])
                df_gantt['Criação'] = pd.to_datetime(df_gantt['Criação'])
                df_gantt['Conclusão'] = pd.to_datetime(df_gantt['Conclusão'])
                
                # Criar colunas para o gráfico de Gantt
                df_gantt['Start'] = df_gantt.apply(
                    lambda row: row['Criação'] if pd.isna(row['Conclusão']) or row['Status'] == 'Pendente' 
                    else row['Conclusão'] - timedelta(days=1), axis=1) # Pequeno ajuste para tarefas concluídas aparecerem como barra
                
                df_gantt['Finish'] = df_gantt.apply(
                    lambda row: datetime.now() if row['Status'] == 'Pendente' 
                    else row['Conclusão'], axis=1)
                
                df_gantt['Completed'] = df_gantt['Status'] == 'Concluída'
                
                # Criar o gráfico de Gantt
                fig = px.timeline(
                    df_gantt, 
                    x_start="Start", 
                    x_end="Finish", 
                    y="Tarefa",
                    color="Responsável",
                    title="Linha do Tempo das Tarefas",
                    hover_name="Tarefa",
                    hover_data=["Prioridade", "Status", "Prazo"],
                    color_discrete_sequence=px.colors.qualitative.Pastel
                )
                
                fig.update_yaxes(autorange="reversed")
                fig.update_layout(
                    height=600,
                    xaxis_title="",
                    yaxis_title="Tarefas",
                    showlegend=True
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.warning("Nenhuma tarefa com prazos definidos para exibir o gráfico de Gantt.")
        else:
            st.warning("Você não tem permissão para visualizar todas as tarefas.")

# Gráficos de Controle de Qualidade
def quality_control_page():
    if not has_permission(ACCESS_LEVEL_SUPERVISOR):
        st.warning("Você não tem permissão para acessar esta página.")
        return
    
    st.title("📈 Gráficos de Controle de Qualidade")
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["X-Barra & R", "X-Barra & S", "I-MR", "Pareto", "Histograma"])
    
    # Selecionar produto (compartilhado entre as abas para evitar repetição de seleção)
    c.execute("SELECT id, name FROM products ORDER BY name")
    products = c.fetchall()
    product_options = {f"{p[1]} (ID: {p[0]})": p[0] for p in products}

    if not product_options:
        st.info("Nenhum produto cadastrado para análise de controle de qualidade. Cadastre produtos primeiro.")
        return
        
    selected_product_key = st.selectbox("Selecione o produto para análise", options=list(product_options.keys()), key="qc_product_selector")
    product_id = product_options[selected_product_key]

    with tab1:
        st.subheader("Gráficos X-Barra e R")
        
        # Obter dados de controle de qualidade
        c.execute('''SELECT control_date, sample_size, mean_value, range_value 
                        FROM quality_control 
                        WHERE product_id = ? 
                        ORDER BY control_date''', (product_id,))
        qc_data = c.fetchall()
        
        if qc_data:
            df = pd.DataFrame(qc_data, columns=["Data", "Tamanho da Amostra", "Média", "Amplitude"])
            
            # Gráfico X-Barra
            fig_xbar = go.Figure()
            fig_xbar.add_trace(go.Scatter(
                x=df['Data'],
                y=df['Média'],
                mode='lines+markers',
                name='Média',
                line=dict(color='royalblue')
            ))
            
            # Calcular limites de controle para X-Barra
            overall_mean = df['Média'].mean()
            mean_range = df['Amplitude'].mean()
            
            n_xbar = df['Tamanho da Amostra'].iloc[0] # Assume que o tamanho da amostra é constante para estes gráficos
            factors_xbar_r = CONTROL_CHART_CONSTANTS.get(n_xbar)

            if factors_xbar_r and factors_xbar_r['A2'] != 0:
                a2 = factors_xbar_r['A2']
                ucl_xbar = overall_mean + a2 * mean_range
                lcl_xbar = overall_mean - a2 * mean_range
            else:
                st.warning(f"Fator A2 para tamanho de amostra {n_xbar} não encontrado ou inválido. Limites do gráfico X-Barra podem estar incorretos.")
                ucl_xbar = overall_mean # Evita erro, mas não é um cálculo real de limite
                lcl_xbar = overall_mean
            
            fig_xbar.add_trace(go.Scatter(
                x=df['Data'],
                y=[overall_mean] * len(df),
                mode='lines',
                name='Linha Central',
                line=dict(color='green', dash='dash')
            ))
            fig_xbar.add_trace(go.Scatter(
                x=df['Data'],
                y=[ucl_xbar] * len(df),
                mode='lines',
                name='LSC',
                line=dict(color='red', dash='dash')
            ))
            fig_xbar.add_trace(go.Scatter(
                x=df['Data'],
                y=[lcl_xbar] * len(df),
                mode='lines',
                name='LIC',
                line=dict(color='red', dash='dash')
            ))
            fig_xbar.update_layout(
                title='Gráfico X-Barra - Médias',
                xaxis_title='Data',
                yaxis_title='Valor Médio',
                showlegend=True
            )
            
            st.plotly_chart(fig_xbar, use_container_width=True)
            
            # Gráfico R
            fig_r = go.Figure()
            fig_r.add_trace(go.Scatter(
                x=df['Data'],
                y=df['Amplitude'],
                mode='lines+markers',
                name='Amplitude',
                line=dict(color='royalblue')
            ))
            
            # Limites de controle para gráfico R
            if factors_xbar_r and factors_xbar_r['D3'] is not None and factors_xbar_r['D4'] is not None:
                d3 = factors_xbar_r['D3']
                d4 = factors_xbar_r['D4']
                ucl_r = d4 * mean_range
                lcl_r = d3 * mean_range
            else:
                st.warning(f"Fatores D3/D4 para tamanho de amostra {n_xbar} não encontrados ou inválidos para o Gráfico R. Limites podem estar incorretos.")
                ucl_r = mean_range # Fallback para evitar erro
                lcl_r = 0 # Fallback para evitar erro

            fig_r.add_trace(go.Scatter(
                x=df['Data'],
                y=[mean_range] * len(df),
                mode='lines',
                name='Linha Central',
                line=dict(color='green', dash='dash')
            ))
            
            fig_r.add_trace(go.Scatter(
                x=df['Data'],
                y=[ucl_r] * len(df),
                mode='lines',
                name='LSC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_r.add_trace(go.Scatter(
                x=df['Data'],
                y=[lcl_r] * len(df),
                mode='lines',
                name='LIC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_r.update_layout(
                title='Gráfico R - Amplitude',
                xaxis_title='Data',
                yaxis_title='Amplitude',
                showlegend=True
            )
            
            st.plotly_chart(fig_r, use_container_width=True)
            
            # Exibir dados
            st.subheader("Dados de Controle de Qualidade")
            st.dataframe(df, use_container_width=True)
        else:
            st.warning("Nenhum dado de controle de qualidade disponível para este produto.")
            
            # Formulário para adicionar dados
            with st.expander("Adicionar Dados de Controle"):
                with st.form("add_qc_data_form_r"): # Chave única para o formulário
                    control_date = st.date_input("Data de Controle", value=datetime.now().date(), key="qc_date_r")
                    sample_size = st.number_input("Tamanho da Amostra", min_value=2, value=5, key="qc_sample_size_r")
                    mean_value = st.number_input("Média da Amostra", format="%.3f", key="qc_mean_r")
                    range_value = st.number_input("Amplitude da Amostra", min_value=0.0, format="%.3f", key="qc_range_r")
                    std_dev = st.number_input("Desvio Padrão (Opcional, para S-chart)", min_value=0.0, format="%.3f", key="qc_std_dev_r")
                    
                    submitted = st.form_submit_button("Adicionar Dados")
                    
                    if submitted:
                        c.execute('''INSERT INTO quality_control 
                                        (product_id, control_date, sample_size, mean_value, range_value, std_dev, created_by)
                                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                    (product_id, control_date.strftime("%Y-%m-%d"), sample_size, mean_value, range_value, std_dev, st.session_state['user_id']))
                        conn.commit()
                        st.success("Dados de controle de qualidade adicionados com sucesso!")
                        st.experimental_rerun()
    
    with tab2:
        st.subheader("Gráficos X-Barra e S")
        
        # Obter dados de controle de qualidade
        c.execute('''SELECT control_date, sample_size, mean_value, std_dev 
                        FROM quality_control 
                        WHERE product_id = ? 
                        ORDER BY control_date''', (product_id,))
        qc_data_s = c.fetchall()
        
        if qc_data_s:
            df_s = pd.DataFrame(qc_data_s, columns=["Data", "Tamanho da Amostra", "Média", "Desvio Padrão"])
            
            # Gráfico X-Barra (com fatores para S-chart)
            fig_xbar_s = go.Figure()
            fig_xbar_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=df_s['Média'],
                mode='lines+markers',
                name='Média',
                line=dict(color='royalblue')
            ))
            
            # Use o tamanho da amostra do primeiro registro para os fatores S
            n_s = df_s['Tamanho da Amostra'].iloc[0]
            factors_s = CONTROL_CHART_CONSTANTS.get(n_s)
            
            overall_mean_xbar_s = df_s['Média'].mean()
            mean_std_dev = df_s['Desvio Padrão'].mean() # Média dos desvios padrão

            if factors_s and factors_s['A2'] != 0: # A2 também é usado para X-barra no S-chart
                a2_s = factors_s['A2']
                ucl_xbar_s = overall_mean_xbar_s + a2_s * mean_std_dev
                lcl_xbar_s = overall_mean_xbar_s - a2_s * mean_std_dev
            else:
                st.warning(f"Fator A2 para tamanho de amostra {n_s} não encontrado ou inválido para o Gráfico X-Barra (com S-chart). Limites podem estar incorretos.")
                ucl_xbar_s = overall_mean_xbar_s
                lcl_xbar_s = overall_mean_xbar_s


            fig_xbar_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=[overall_mean_xbar_s] * len(df_s),
                mode='lines',
                name='Linha Central',
                line=dict(color='green', dash='dash')
            ))
            fig_xbar_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=[ucl_xbar_s] * len(df_s),
                mode='lines',
                name='LSC',
                line=dict(color='red', dash='dash')
            ))
            fig_xbar_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=[lcl_xbar_s] * len(df_s),
                mode='lines',
                name='LIC',
                line=dict(color='red', dash='dash')
            ))
            fig_xbar_s.update_layout(
                title='Gráfico X-Barra - Médias (com S-chart)',
                xaxis_title='Data',
                yaxis_title='Valor Médio',
                showlegend=True
            )
            st.plotly_chart(fig_xbar_s, use_container_width=True)

            # Gráfico S
            fig_s = go.Figure()
            fig_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=df_s['Desvio Padrão'],
                mode='lines+markers',
                name='Desvio Padrão',
                line=dict(color='royalblue')
            ))
            
            # Limites de controle para gráfico S
            if factors_s and factors_s['B3'] is not None and factors_s['B4'] is not None:
                b3 = factors_s['B3']
                b4 = factors_s['B4']
                ucl_s = b4 * mean_std_dev
                lcl_s = b3 * mean_std_dev
            else:
                st.warning(f"Fatores B3/B4 para tamanho de amostra {n_s} não encontrados ou inválidos para o Gráfico S. Limites podem estar incorretos.")
                ucl_s = mean_std_dev # Fallback
                lcl_s = 0 # Fallback

            fig_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=[mean_std_dev] * len(df_s),
                mode='lines',
                name='Linha Central',
                line=dict(color='green', dash='dash')
            ))
            
            fig_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=[ucl_s] * len(df_s),
                mode='lines',
                name='LSC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_s.add_trace(go.Scatter(
                x=df_s['Data'],
                y=[lcl_s] * len(df_s),
                mode='lines',
                name='LIC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_s.update_layout(
                title='Gráfico S - Desvio Padrão',
                xaxis_title='Data',
                yaxis_title='Desvio Padrão',
                showlegend=True
            )
            
            st.plotly_chart(fig_s, use_container_width=True)
        else:
            st.warning("Nenhum dado de controle de qualidade disponível para este produto. Verifique se o campo 'Desvio Padrão' foi preenchido ao adicionar dados.")

    with tab3:
        st.subheader("Gráficos I-MR (Indivíduos e Amplitude Móvel)")
        
        # Obter dados individuais (simulados para este exemplo)
        # Na prática, você teria medições individuais em vez de médias
        c.execute('''SELECT control_date, mean_value 
                        FROM quality_control 
                        WHERE product_id = ? 
                        ORDER BY control_date''', (product_id,))
        qc_data_imr = c.fetchall()
        
        if qc_data_imr and len(qc_data_imr) >= 2:
            df_imr = pd.DataFrame(qc_data_imr, columns=["Data", "Valor"])
            
            # Calcular amplitude móvel
            df_imr['MR'] = df_imr['Valor'].diff().abs()
            df_imr = df_imr.dropna(subset=['MR']) # Remove a primeira linha que terá NaN para MR
            
            # Gráfico de Indivíduos (I)
            fig_i = go.Figure()
            fig_i.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=df_imr['Valor'],
                mode='lines+markers',
                name='Valor Individual',
                line=dict(color='royalblue')
            ))
            
            # Limites de controle para gráfico I (d2 para n=2 é 1.128, então 2.66 = 3/d2)
            overall_mean_i = df_imr['Valor'].mean()
            mean_mr = df_imr['MR'].mean()
            
            # Fator D4 para MR com n=2 é 3.267, então 2.66 é 3 / (d2_para_MR * sigma_de_MR)
            # Para I-MR, o LSC/LIC para o I-chart é CL +- 3 * (MR_bar / d2)
            # O d2 para tamanho de subgrupo de 2 (para MR) é 1.128.
            # 3 / 1.128 = 2.6595 ~ 2.66
            
            ucl_i = overall_mean_i + 2.66 * mean_mr
            lcl_i = overall_mean_i - 2.66 * mean_mr
            
            fig_i.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=[overall_mean_i] * len(df_imr),
                mode='lines',
                name='Linha Central',
                line=dict(color='green', dash='dash')
            ))
            
            fig_i.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=[ucl_i] * len(df_imr),
                mode='lines',
                name='LSC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_i.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=[lcl_i] * len(df_imr),
                mode='lines',
                name='LIC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_i.update_layout(
                title='Gráfico I - Valores Individuais',
                xaxis_title='Data',
                yaxis_title='Valor Individual',
                showlegend=True
            )
            
            st.plotly_chart(fig_i, use_container_width=True)
            
            # Gráfico MR
            fig_mr = go.Figure()
            fig_mr.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=df_imr['MR'],
                mode='lines+markers',
                name='Amplitude Móvel',
                line=dict(color='royalblue')
            ))
            
            # Limites de controle para gráfico MR (D4 para n=2 é 3.267, D3 para n=2 é 0)
            ucl_mr = 3.267 * mean_mr
            lcl_mr = 0 # D3 para n=2 é 0
            
            fig_mr.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=[mean_mr] * len(df_imr),
                mode='lines',
                name='Linha Central',
                line=dict(color='green', dash='dash')
            ))
            
            fig_mr.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=[ucl_mr] * len(df_imr),
                mode='lines',
                name='LSC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_mr.add_trace(go.Scatter(
                x=df_imr['Data'],
                y=[lcl_mr] * len(df_imr),
                mode='lines',
                name='LIC',
                line=dict(color='red', dash='dash')
            ))
            
            fig_mr.update_layout(
                title='Gráfico MR - Amplitude Móvel',
                xaxis_title='Data',
                yaxis_title='Amplitude Móvel',
                showlegend=True
            )
            
            st.plotly_chart(fig_mr, use_container_width=True)
        else:
            st.warning("Dados insuficientes para gerar gráficos I-MR. São necessárias pelo menos 2 medições com valores para 'Média da Amostra'.")
    
    with tab4:
        st.subheader("Gráfico de Pareto")
        
        # Obter defeitos/problemas (dados simulados para este exemplo)
        # Em uma aplicação real, você teria uma tabela de defeitos/ocorrências
        # Para demonstração, vamos usar os status de qualidade dos produtos
        c.execute('''SELECT quality_status, COUNT(*) as count 
                        FROM products 
                        GROUP BY quality_status 
                        ORDER BY count DESC''')
        defect_data = c.fetchall()

        if defect_data:
            df_pareto = pd.DataFrame(defect_data, columns=["Defeito", "Ocorrências"])
            df_pareto['Cumulative Percentage'] = (df_pareto['Ocorrências'].cumsum() / df_pareto['Ocorrências'].sum()) * 100
            
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=df_pareto['Defeito'],
                y=df_pareto['Ocorrências'],
                name='Ocorrências',
                marker_color='rgb(55, 83, 109)'
            ))
            
            fig.add_trace(go.Scatter(
                x=df_pareto['Defeito'],
                y=df_pareto['Cumulative Percentage'],
                name='Porcentagem Acumulada',
                yaxis='y2',
                line=dict(color='rgb(255, 127, 14)', width=2)
            ))
            
            fig.update_layout(
                title='Análise de Pareto - Defeitos de Qualidade (Baseado no Status dos Produtos)',
                yaxis=dict(
                     title=dict(text='Número de Ocorrências', font=dict(color='rgb(55, 83, 109)')),
                    tickfont=dict(color='rgb(55, 83, 109)')
                ),
                yaxis2=dict(
                    title=dict(text='Porcentagem Acumulada', font=dict(color='rgb(255, 127, 14)')),
                    tickfont=dict(color='rgb(255, 127, 14)'),
                    overlaying='y',
                    side='right',
                    range=[0, 110]
                ),
                showlegend=False
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
            # Exibir tabela de dados
            st.dataframe(df_pareto, use_container_width=True)
        else:
            st.warning("Nenhum dado de status de qualidade de produtos disponível para gerar o Gráfico de Pareto.")
    
    with tab5:
        st.subheader("Histograma de Qualidade")
        
        # Obter dados (simulando medidas individuais a partir das médias registradas)
        c.execute('''SELECT mean_value, sample_size FROM quality_control WHERE product_id = ?''', (product_id,))
        qc_measurements_data = c.fetchall()
        
        if qc_measurements_data:
            all_measurements = []
            
            for mean, sample_size_val in qc_measurements_data:
                if mean is not None and sample_size_val is not None and sample_size_val > 0:
                    # Simula medições individuais em torno da média com um desvio padrão de 5% da média
                    measurements = np.random.normal(mean, mean * 0.05, sample_size_val)
                    all_measurements.extend(measurements)
            
            if all_measurements:
                df_hist = pd.DataFrame(all_measurements, columns=["Medição"])
                
                # Calcular estatísticas
                mean_val = df_hist['Medição'].mean()
                std_val = df_hist['Medição'].std()
                
                # Definir limites de especificação (exemplo: +/- 3 desvios padrão da média global)
                # Você pode substituir por valores de especificação reais do produto (USL, LSL)
                usl = mean_val + 3*std_val 
                lsl = mean_val - 3*std_val 
                
                # Criar histograma
                fig_hist = px.histogram(
                    df_hist, 
                    x='Medição',
                    nbins=20,
                    title='Distribuição das Medições de Qualidade',
                    labels={'Medição': 'Valor da Medição'},
                    color_discrete_sequence=['indianred']
                )
                
                # Adicionar linhas de média e limites
                fig_hist.add_vline(x=mean_val, line_width=3, 
                                    line_dash="dash", line_color="green", 
                                    annotation_text=f"Média: {mean_val:.2f}", annotation_position="top left")
                fig_hist.add_vline(x=usl, line_width=2, line_dash="dash", line_color="red", 
                                    annotation_text=f"LSE: {usl:.2f}", annotation_position="top right")
                fig_hist.add_vline(x=lsl, line_width=2, line_dash="dash", line_color="red", 
                                    annotation_text=f"LIE: {lsl:.2f}", annotation_position="top left")
                
                st.plotly_chart(fig_hist, use_container_width=True)
                
                # Exibir estatísticas
                col1, col2, col3 = st.columns(3)
                col1.metric("Média", f"{mean_val:.2f}")
                col2.metric("Desvio Padrão", f"{std_val:.2f}")
                
                # Cálculo de Cp (Índice de Capacidade do Processo)
                # Somente se USL > LSL e std_val > 0
                if usl > lsl and std_val > 0:
                    cp_value = (usl - lsl) / (6 * std_val)
                    col3.metric("Capabilidade (Cp)", f"{cp_value:.2f}")
                else:
                    col3.metric("Capabilidade (Cp)", "N/A")

            else:
                st.warning("Não há medições válidas para gerar o histograma.")
        else:
            st.warning("Nenhum dado de controle de qualidade disponível para este produto.")


# Gerenciamento de Usuários (apenas para administradores)
def users_page():
    if not has_permission(ACCESS_LEVEL_ADMINISTRADOR):
        st.warning("Você não tem permissão para acessar esta página.")
        return
    
    st.title("👥 Gerenciamento de Usuários")
    
    tab1, tab2, tab3 = st.tabs(["Lista de Usuários", "Adicionar Usuário", "Editar Usuário"])
    
    with tab1:
        st.subheader("Lista de Usuários")
        
        c.execute("SELECT id, username, name, email, access_level, created_at FROM users ORDER BY access_level, name")
        users = c.fetchall()
        
        if users:
            df = pd.DataFrame(users, columns=["ID", "Usuário", "Nome", "Email", "Nível de Acesso", "Criado em"])
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.warning("Nenhum usuário cadastrado.")
    
    with tab2:
        st.subheader("Adicionar Novo Usuário")
        
        with st.form("add_user_form", clear_on_submit=True):
            username = st.text_input("Nome de Usuário*", max_chars=50)
            password = st.text_input("Senha*", type="password", max_chars=100)
            name = st.text_input("Nome Completo*", max_chars=100)
            email = st.text_input("Email", max_chars=100)
            access_level = st.selectbox("Nível de Acesso*", 
                                        [ACCESS_LEVEL_ADMINISTRADOR, ACCESS_LEVEL_CEO, ACCESS_LEVEL_GERENTE, ACCESS_LEVEL_SUPERVISOR, ACCESS_LEVEL_OPERACIONAL])
            
            submitted = st.form_submit_button("Cadastrar Usuário")
            
            if submitted:
                if not username or not password or not name or not access_level:
                    st.error("Por favor, preencha todos os campos obrigatórios (*)")
                else:
                    try:
                        salt_hex, hashed_password = make_hashes(password) # Gera salt e hash
                        c.execute('''INSERT INTO users 
                                        (username, password, name, email, access_level, salt)
                                        VALUES (?, ?, ?, ?, ?, ?)''', # Adiciona o salt aqui
                                    (username, hashed_password, name, email, access_level, salt_hex))
                        conn.commit()
                        st.success("Usuário cadastrado com sucesso!")
                    except sqlite3.IntegrityError:
                        st.error("Nome de usuário já existe. Por favor, escolha outro.")
    
    with tab3:
        st.subheader("Editar Usuário Existente")
        
        c.execute("SELECT id, username FROM users ORDER BY username")
        users = c.fetchall()
        
        if users:
            user_options = {f"{u[1]} (ID: {u[0]})": u[0] for u in users}
            selected_user_key = st.selectbox("Selecione o usuário para editar", options=list(user_options.keys()))
            user_id = user_options[selected_user_key]
            
            # Seleciona o salt também
            c.execute("SELECT id, username, password, name, email, access_level, salt FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            
            if user:
                with st.form("edit_user_form"):
                    st.write(f"Editando usuário: {user[1]}")
                    
                    new_username = st.text_input("Nome de Usuário", value=user[1], max_chars=50)
                    new_password = st.text_input("Nova Senha (deixe em branco para manter a atual)", type="password", max_chars=100)
                    new_name = st.text_input("Nome Completo", value=user[3], max_chars=100)
                    new_email = st.text_input("Email", value=user[4] if user[4] else "", max_chars=100)
                    new_access_level = st.selectbox("Nível de Acesso", 
                                                    [ACCESS_LEVEL_ADMINISTRADOR, ACCESS_LEVEL_CEO, ACCESS_LEVEL_GERENTE, ACCESS_LEVEL_SUPERVISOR, ACCESS_LEVEL_OPERACIONAL],
                                                    index=[ACCESS_LEVEL_ADMINISTRADOR, ACCESS_LEVEL_CEO, ACCESS_LEVEL_GERENTE, ACCESS_LEVEL_SUPERVISOR, ACCESS_LEVEL_OPERACIONAL].index(user[5]))
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        submitted = st.form_submit_button("Atualizar Usuário")
                    with col2:
                        if st.form_submit_button("Excluir Usuário"):
                            # Verifica se o usuário atual não está tentando se excluir
                            if user_id == st.session_state['user_id']:
                                st.error("Você não pode excluir seu próprio usuário enquanto estiver logado.")
                            else:
                                c.execute("DELETE FROM users WHERE id = ?", (user_id,))
                                conn.commit()
                                st.success("Usuário excluído com sucesso!")
                                st.experimental_rerun()
                    
                    if submitted:
                        if not new_username or not new_name or not new_access_level:
                            st.error("Por favor, preencha todos os campos obrigatórios")
                        else:
                            try:
                                if new_password:
                                    salt_hex, hashed_password = make_hashes(new_password) # Gera novo salt e hash
                                    c.execute('''UPDATE users 
                                                    SET username=?, password=?, name=?, email=?, access_level=?, salt=?
                                                    WHERE id=?''', # Atualiza o salt também
                                                (new_username, hashed_password, new_name, new_email, new_access_level, salt_hex, user_id))
                                else:
                                    c.execute('''UPDATE users 
                                                    SET username=?, name=?, email=?, access_level=?
                                                    WHERE id=?''',
                                                (new_username, new_name, new_email, new_access_level, user_id))
                                conn.commit()
                                st.success("Usuário atualizado com sucesso!")
                            except sqlite3.IntegrityError:
                                st.error("Nome de usuário já existe. Por favor, escolha outro.")
            else:
                st.error("Usuário não encontrado.")
        else:
            st.warning("Nenhum usuário cadastrado para editar.")

# Página de Configurações
def settings_page():
    st.title("⚙️ Configurações")
    
    if not has_permission(ACCESS_LEVEL_GERENTE):
        st.warning("Você não tem permissão para acessar esta página.")
        return
    
    tab1, tab2 = st.tabs(["Configurações do Sistema", "Backup e Restauração"])
    
    with tab1:
        st.subheader("Configurações do Sistema")
        
        st.write("Configurações gerais do sistema LinhaMestre")
        
        with st.form("system_settings_form"):
            st.write("**Parâmetros de Estoque**")
            default_min_quantity = st.number_input("Quantidade Mínima Padrão", min_value=1, value=5)
            expiry_warning_days = st.number_input("Dias para Aviso de Validade", min_value=1, value=30)
            
            st.write("**Notificações**")
            enable_email_notifications = st.checkbox("Habilitar Notificações por Email", value=True)
            enable_stock_alerts = st.checkbox("Habilitar Alertas de Estoque Crítico", value=True)
            
            submitted = st.form_submit_button("Salvar Configurações")
            if submitted:
                st.success("Configurações salvas com sucesso!")
    
    with tab2:
        st.subheader("Backup e Restauração")
        
        st.warning("Esta funcionalidade requer implementação adicional para produção.")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Criar Backup**")
            st.write("Gere um arquivo de backup do banco de dados.")
            if st.button("Gerar Backup"):
                # Em produção, você implementaria a lógica real de backup aqui
                st.info("Funcionalidade de backup será implementada na versão de produção.")
        
        with col2:
            st.write("**Restaurar Backup**")
            st.write("Carregue um arquivo de backup para restaurar o sistema.")
            uploaded_file = st.file_uploader("Selecione o arquivo de backup", type=['db', 'sqlite'])
            if uploaded_file is not None and st.button("Restaurar Backup"):
                st.info("Funcionalidade de restauração será implementada na versão de produção.")
        
        st.info("""
            **Nota:** Em um ambiente de produção real, você deve:
            - Implementar backups automáticos periódicos
            - Armazenar backups em local seguro
            - Testar regularmente o processo de restauração
            - Considerar criptografia para dados sensíveis
        """)

# --- Menu Principal ---
def main_menu():
    st.sidebar.title("Menu")
    
    menu_options = {
        "Dashboard": dashboard_page,
        "Produtos": products_page,
        "Mensagens": messages_page,
        "Tarefas": tasks_page,
        "Controle de Qualidade": quality_control_page,
    }
    
    if has_permission(ACCESS_LEVEL_ADMINISTRADOR):
        menu_options["Usuários"] = users_page
    
    if has_permission(ACCESS_LEVEL_GERENTE):
        menu_options["Configurações"] = settings_page
    
    selected_page = st.sidebar.radio("Navegação", list(menu_options.keys()))
    
    # Executar a função da página selecionada
    menu_options[selected_page]()
    
    st.sidebar.markdown("---")
    if st.sidebar.button("Sair"):
        logout()

# --- Fluxo Principal do Aplicativo ---
if 'logged_in' not in st.session_state or not st.session_state['logged_in']:
    login()
else:
    main_menu()

# --- Rodapé ---
st.sidebar.markdown("---")
st.sidebar.markdown("""
    **LinhaMestre** - Sistema de Gerenciamento de Estoque e Produção 
    v1.0.0 
    © 2023 Todos os direitos reservados
""")