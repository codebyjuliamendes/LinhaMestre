import sqlite3
import random
from datetime import datetime, timedelta

def seed_database():
    conn = sqlite3.connect('linhamestre.db')
    c = conn.cursor()

    print("Iniciando semeadura do banco de dados (seeding)...")

    # Garantir criação de tabelas unconditionally
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, name TEXT, email TEXT, access_level TEXT, salt TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, category TEXT, quantity INTEGER, min_quantity INTEGER, unit TEXT, location TEXT, supplier TEXT, cost REAL, price REAL, barcode TEXT, production_date DATE, expiry_date DATE, quality_status TEXT, notes TEXT, created_by INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP, FOREIGN KEY(created_by) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS quality_control (id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER, control_date DATE, sample_size INTEGER, mean_value REAL, range_value REAL, std_dev REAL, created_by INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(product_id) REFERENCES products(id), FOREIGN KEY(created_by) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, subject TEXT, content TEXT, is_read INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(sender_id) REFERENCES users(id), FOREIGN KEY(receiver_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, assigned_to INTEGER, created_by INTEGER, priority TEXT, status TEXT DEFAULT 'Pendente', due_date DATE, completed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(assigned_to) REFERENCES users(id), FOREIGN KEY(created_by) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, details TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))''')

    c.execute("SELECT id FROM users WHERE username = 'admin'")
    admin_row = c.fetchone()
    if not admin_row:
        # Inserir administrador padrão (senha hash/salt mockada)
        c.execute("INSERT OR IGNORE INTO users (id, username, password, name, email, access_level, salt) VALUES (1, 'admin', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'Administrador', 'admin@linhamestre.com', 'Administrador', 'salt_hex_value')")
        admin_id = 1
    else:
        admin_id = admin_row[0]

    c.execute("SELECT id FROM users WHERE username = 'supervisor'")
    super_row = c.fetchone()
    super_id = super_row[0] if super_row else admin_id

    # 2. Inserir Produtos
    products = [
        # name, category, quantity, min_quantity, unit, location, supplier, cost, price, barcode, quality_status
        ("Chapa de Aço Galv 2mm", "Matéria-Prima", 120, 50, "Unidade", "Setor A - P1", "Metalúrgica Gerdau", 45.0, 95.0, "789123456001", "Aprovado"),
        ("Parafuso Sextavado M12", "Fixadores", 5000, 1000, "Unidade", "Setor B - G3", "Parafusos Barão", 0.15, 0.45, "789123456002", "Aprovado"),
        ("Tinta Epóxi Azul 3.6L", "Químicos", 12, 15, "Litro", "Setor C - Inflamáveis", "Sherwin Williams", 120.0, 250.0, "789123456003", "Aprovado"),
        ("Eixo de Transmissão 50mm", "Componentes", 8, 10, "Unidade", "Setor A - P4", "Engrenagens Brasil", 340.0, 680.0, "789123456004", "Em Análise"),
        ("Filtro de Óleo Hidráulico", "Mapeamento", 4, 5, "Unidade", "Setor D - Estante 2", "Tecfil", 85.0, 160.0, "789123456005", "Reprovado"),
        ("Cabo de Cobre Flexível 6mm", "Elétrica", 400, 200, "Metro", "Setor E - Bobinas", "Sil Fios", 4.20, 8.90, "789123456006", "Aprovado"),
    ]

    inserted_product_ids = []
    today = datetime.now().date()

    for name, cat, qty, min_qty, unit, loc, sup, cost, price, bar, status in products:
        c.execute("SELECT id FROM products WHERE name = ?", (name,))
        row = c.fetchone()
        if not row:
            production = today - timedelta(days=random.randint(5, 45))
            expiry = today + timedelta(days=random.randint(90, 365))
            c.execute('''INSERT INTO products (name, category, quantity, min_quantity, unit, location, supplier, cost, price, barcode, production_date, expiry_date, quality_status, notes, created_by)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (name, cat, qty, min_qty, unit, loc, sup, cost, price, bar, production.strftime("%Y-%m-%d"), expiry.strftime("%Y-%m-%d"), status, "Lote inicial semeado", admin_id))
            inserted_product_ids.append(c.lastrowid)
        else:
            inserted_product_ids.append(row[0])

    print(f"{len(inserted_product_ids)} produtos garantidos no banco.")

    # 3. Inserir dados de Controle de Qualidade Históricos (especialmente para a Chapa de Aço e Parafusos)
    # Vamos gerar medições para os últimos 30 dias
    for prod_id in inserted_product_ids[:2]:  # Chapa de Aço (ID 1) e Parafusos (ID 2)
        c.execute("SELECT name FROM products WHERE id = ?", (prod_id,))
        prod_name = c.fetchone()[0]
        
        # Determinar base de valores nominais
        if "Chapa" in prod_name:
            nominal_mean = 2.0  # espessura nominal 2mm
            nominal_std = 0.05
        else:
            nominal_mean = 12.0  # diâmetro nominal 12mm
            nominal_std = 0.12

        # Inserir medições para os últimos 25 dias
        start_date = today - timedelta(days=25)
        for i in range(25):
            control_date = start_date + timedelta(days=i)
            # Simular variação do processo
            # Adicionar uma leve tendência de desvio no final para simular um desvio estatístico real a ser alertado!
            drift = 0.0
            if i > 20:
                drift = nominal_std * 1.5  # Provoca desvio para alertar Western Electric

            sample_values = [random.normalvariate(nominal_mean + drift, nominal_std) for _ in range(5)]
            mean_val = sum(sample_values) / len(sample_values)
            range_val = max(sample_values) - min(sample_values)
            # Desvio padrão amostral
            variance = sum((x - mean_val) ** 2 for x in sample_values) / (len(sample_values) - 1)
            std_dev = variance ** 0.5

            c.execute("SELECT id FROM quality_control WHERE product_id = ? AND control_date = ?", (prod_id, control_date.strftime("%Y-%m-%d")))
            if not c.fetchone():
                c.execute('''INSERT INTO quality_control (product_id, control_date, sample_size, mean_value, range_value, std_dev, created_by)
                             VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (prod_id, control_date.strftime("%Y-%m-%d"), 5, round(mean_val, 4), round(range_val, 4), round(std_dev, 4), super_id))

    print("Dados históricos de Controle de Qualidade semeados com sucesso.")

    # 4. Inserir Mensagens e Tarefas iniciais
    c.execute("SELECT COUNT(*) FROM tasks")
    if c.fetchone()[0] == 0:
        c.execute('''INSERT INTO tasks (title, description, assigned_to, created_by, priority, status, due_date)
                     VALUES ('Auditoria ISO 9001', 'Preparar documentação de controle de qualidade e laudos dos últimos 6 meses para auditoria externa.', ?, ?, 'Alta', 'Pendente', ?)''',
                  (super_id, admin_id, (today + timedelta(days=15)).strftime("%Y-%m-%d")))
        c.execute('''INSERT INTO tasks (title, description, assigned_to, created_by, priority, status, due_date)
                     VALUES ('Verificar Lote Reprovado', 'O Filtro de Óleo Hidráulico foi reprovado com trincas. Entrar em contato com o fornecedor Tecfil.', ?, ?, 'Média', 'Pendente', ?)''',
                  (super_id, admin_id, (today + timedelta(days=2)).strftime("%Y-%m-%d")))

    c.execute("SELECT COUNT(*) FROM messages")
    if c.fetchone()[0] == 0:
        c.execute('''INSERT INTO messages (sender_id, receiver_id, subject, content)
                     VALUES (?, ?, 'Desvio estatístico detectado', 'Olá Supervisor, notamos uma tendência de elevação nos diâmetros dos parafusos nos últimos lotes. Por favor, verifique a calibragem da máquina CNC.')''',
                  (admin_id, super_id))

    # 5. Inserir logs de auditoria iniciais
    c.execute("SELECT COUNT(*) FROM audit_logs")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO audit_logs (user_id, action, details) VALUES (?, 'SYSTEM_INIT', 'Banco de dados inicializado e semeado com dados históricos de demonstração.')", (admin_id,))

    conn.commit()
    conn.close()
    print("Semeadura concluída com sucesso! (Semeadura OK)")

if __name__ == "__main__":
    seed_database()
