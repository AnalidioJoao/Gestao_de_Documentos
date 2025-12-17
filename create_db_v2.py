from app import create_app, db, User

# Criamos a instância da aplicação
app = create_app()

with app.app_context():
    db.create_all()
    print("Tabelas criadas com sucesso (v2)!")
    
    # Cria o admin logo aqui
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password('123456')
        db.session.add(admin)
        db.session.commit()
        print("Admin recriado com sucesso!")

