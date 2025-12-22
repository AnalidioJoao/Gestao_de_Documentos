from app import create_app, db, User, Direction, Department, DocumentType, PERMISSION_READ, PERMISSION_WRITE, PERMISSION_APPROVE, PERMISSION_ADMIN

app = create_app()

with app.app_context():
    # db.create_all() # Apenas se a DB estiver vazia

    if not Direction.query.first():
        dir_geral = Direction(name="Direção Geral")
        dep_ti = Department(name="Tecnologia da Informação", direction=dir_geral)
        doc_type_rel = DocumentType(name="Relatório") # <-- Cria o tipo aqui
        db.session.add(dir_geral)
        db.session.add(dep_ti)
        db.session.add(doc_type_rel)
        db.session.commit()
        print("Direções, Departamentos e Tipos de teste criados.")

    if not User.query.filter_by(username='admin').first():
        dep_ti = Department.query.filter_by(name="Tecnologia da Informação").first()
        admin = User(username='admin', 
                     permissions=PERMISSION_READ|PERMISSION_WRITE|PERMISSION_APPROVE|PERMISSION_ADMIN, 
                     department_id=dep_ti.id if dep_ti else None) 
        admin.set_password('123456')
        db.session.add(admin)
        db.session.commit()
        print("Admin criado com sucesso!")

    print("Dados iniciais verificados.")
