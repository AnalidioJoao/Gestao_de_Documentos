from app import create_app, db, User, Direction, Department, DocumentType

# Cria a instância da aplicação
app = create_app()

with app.app_context():
    # Apenas cria as tabelas. 
    # Nao tentamos ler dados ainda, para evitar o erro de coluna inexistente.
    db.create_all()
    print("Tabelas criadas com sucesso (v2)!")

    # --- INSERÇÃO DE DADOS DE TESTE (Em um novo script ou manualmente) ---
    # Este script agora termina aqui, para garantir que as tabelas existam 
    # antes de tentar ler delas.
