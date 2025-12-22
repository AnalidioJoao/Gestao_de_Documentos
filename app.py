from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
# from flask_migrate import Migrate # Comentado, pois usamos o método manual
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pytesseract
from pdf2image import convert_from_path
import os
import datetime

basedir = os.path.abspath(os.path.dirname(__file__))

# --- Configuração do Tesseract OCR Engine para Servidor/Local ---
TESSERACT_PATH = '/usr/bin/tesseract'
if os.name == 'nt': 
     TESSERACT_PATH = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

db = SQLAlchemy()
# migrate = Migrate() # Comentado
mail = Mail()
login_manager = LoginManager()
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

# Constantes para os níveis de permissão
PERMISSION_READ = 1
PERMISSION_WRITE = 2
PERMISSION_APPROVE = 4
PERMISSION_ADMIN = 8

# --- FUNÇÕES AUXILIARES ---
def allowed_file(filename):
    if '.' not in filename:
        return False
    # Pega a extensão (último elemento [1]) e aplica .lower() a ele
    extension = filename.rsplit('.', 1)[1].lower() 
    return extension in ALLOWED_EXTENSIONS

def extract_text_from_file(filepath, mimetype):
    text = ""
    try:
        if mimetype == 'application/pdf':
            pages = convert_from_path(filepath, 500)
            for page in pages:
                text += pytesseract.image_to_string(page, lang='por')
        elif mimetype.startswith('image/'):
            text += pytesseract.image_to_string(filepath, lang='por')
    except Exception as e:
        print(f"Erro no OCR: {e}")
        text = "OCR Indisponível."
    return text

def send_notification_email(filename, username):
    msg = Message("Novo Documento Carregado: " + filename, recipients=['quiamuxinda@gmail.com'])
    msg.body = f"O usuário {username} acabou de carregar um novo documento: {filename}. Por favor, verifique a dashboard para aprovação."
    try:
        # A app já tem contexto aqui pois a função é chamada dentro de uma rota
        mail.send(msg) 
        print("E-mail de notificação enviado com sucesso!")
    except Exception as e:
        print(f"Falha ao enviar e-mail: {e}")

# --- MODELOS (TABELAS DO BANCO DE DADOS) ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    permissions = db.Column(db.Integer, nullable=False, default=PERMISSION_READ)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    department = db.relationship('Department', backref=db.backref('users', lazy=True))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def can(self, permission):
        return self.permissions & permission == permission
    def is_admin(self):
        return self.can(PERMISSION_ADMIN)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploader = db.relationship('User', backref=db.backref('documents', lazy=True))
    content = db.Column(db.Text, nullable=True)
    version_number = db.Column(db.Integer, nullable=False, default=1)
    parent_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Pendente')
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    document_type_id = db.Column(db.Integer, db.ForeignKey('document_type.id'), nullable=False)


class Direction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    direction_id = db.Column(db.Integer, db.ForeignKey('direction.id'), nullable=False)
    direction = db.relationship('Direction', backref=db.backref('departments', lazy=True))

class DocumentType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

@login_manager.user_loader
def load_user(user_id):
   return db.session.get(User, int(user_id))


def create_app():
    app = Flask(__name__)
    app.secret_key = 'sua_chave_secreta_muito_segura' 
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Ana2025@localhost:5432/gestaodoc'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USE_SSL'] = True
    app.config['MAIL_USERNAME'] = 'quiamuxinda@gmail.com' 
    app.config['MAIL_PASSWORD'] = 'fply jsth nrro vnwh'  
    app.config['MAIL_DEFAULT_SENDER'] = 'asjwebdesigner@gmail.com'

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app) 

    # --- ROTAS ---

    @app.route('/')
    @app.route('/dashboard')
    @login_required
    def dashboard():
        search_query = request.args.get('q', '')
        documents = [] 

        total_docs = Document.query.filter_by(department_id=current_user.department_id, parent_id=None).count() or 0
        total_pendente = Document.query.filter_by(department_id=current_user.department_id, status='Pendente', parent_id=None).count() or 0
        total_aprovado = total_docs - total_pendente

        if search_query:
            query_obj = Document.query.filter_by(parent_id=None, department_id=current_user.department_id)
            query_obj = query_obj.filter(
                (Document.filename.ilike(f'%{search_query}%')) | 
                (Document.content.isnot(None) & Document.content.ilike(f'%{search_query}%'))
            )
            documents = query_obj.all()
            
        return render_template('dashboard.html', 
                               documents=documents, 
                               search_query=search_query,
                               total_docs=total_docs,
                               total_pendente=total_pendente,
                               total_aprovado=total_aprovado)


    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('dashboard'))
            flash('Nome de usuário ou senha inválidos.', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Sessão encerrada.', 'info')
        return redirect(url_for('login'))

    @app.route('/manage_users', methods=['GET', 'POST'])
    @login_required
    def manage_users():
        if not current_user.is_admin():
            flash('Acesso negado! Apenas administradores podem gerir usuários.', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            permission_level = int(request.form.get('permission_level')) 
            
            if User.query.filter_by(username=username).first():
                flash('Nome de usuário já existe.', 'danger')
            else:
                new_user = User(username=username, permissions=permission_level, department_id=current_user.department_id) 
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash(f'Usuário {username} criado com sucesso!', 'success')
            return redirect(url_for('manage_users'))
        users = User.query.all()
        return render_template('manage_users.html', users=users, PERMISSION_READ=PERMISSION_READ, PERMISSION_WRITE=PERMISSION_WRITE)
    
    
    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        if not current_user.is_admin():
            flash('Acesso negado!', 'danger')
            return redirect(url_for('dashboard'))

        user_to_delete = User.query.get_or_404(user_id)
        
        if user_to_delete.username == 'admin' or user_to_delete.id == current_user.id:
            flash('Não é possível eliminar este usuário.', 'danger')
            return redirect(url_for('manage_users'))

        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Usuário {user_to_delete.username} eliminado.', 'success')
        return redirect(url_for('manage_users'))

    @app.route('/upload', methods=['POST'])
    @login_required
    def upload_file():
        file_upload = request.files.get('file')

        if not file_upload:
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(url_for('dashboard'))

        if file_upload.filename == '':
            flash('Nome de arquivo inválido.', 'danger')
            return redirect(url_for('dashboard'))

        if not allowed_file(file_upload.filename):
            flash('Tipo de arquivo não permitido.', 'danger')
            return redirect(url_for('dashboard'))

        filename = secure_filename(file_upload.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_upload.save(filepath)

        existing_doc = Document.query.filter_by(filename=filename, parent_id=None).first()
        parent_id = None
        version = 1
        if existing_doc:
            parent_id = existing_doc.id
            max_version = db.session.query(db.func.max(Document.version_number)).filter_by(parent_id=parent_id).scalar()
            version = (max_version or 0) + 2

        mimetype = file_upload.mimetype
        extracted_content = extract_text_from_file(filepath, mimetype)
        
        # Tipo de documento padrao 1, a ser melhorado na proxima fase
        doc_type = DocumentType.query.first() 
        if not doc_type:
            flash('Erro: Nenhum tipo de documento padrão encontrado. Contacte o administrador.', 'danger')
            return redirect(url_for('dashboard'))
        doc_type_id = doc_type.id

        new_doc = Document(
            filename=filename, 
            storage_path=filepath, 
            uploader_id=current_user.id, 
            content=extracted_content, 
            version_number=version, 
            parent_id=parent_id,
            status='Pendente',
            department_id=current_user.department_id,
            document_type_id=doc_type_id
        )
        db.session.add(new_doc)
        db.session.commit()
        
        send_notification_email(filename, current_user.username)
        flash(f'Arquivo enviado como Versão {version} com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/download/<int:doc_id>')
    @login_required
    def download_file(doc_id):
        doc = Document.query.get_or_404(doc_id)
        # Verifica se o usuario tem permissao (admin ou do mesmo departamento)
        if current_user.is_admin() or current_user.department_id == doc.department_id:
            return send_from_directory(UPLOAD_FOLDER, doc.filename, as_attachment=True)
        else:
            flash('Acesso negado ao documento.', 'danger')
            return redirect(url_for('dashboard'))

    @app.route('/delete/<int:doc_id>', methods=['POST'])
    @login_required
    def delete_file(doc_id):
        if not current_user.is_admin():
            flash('Acesso negado! Apenas administradores podem excluir documentos.', 'danger')
            return redirect(url_for('dashboard'))

        doc = Document.query.get_or_404(doc_id)
        try:
            if os.path.exists(doc.storage_path):
                os.remove(doc.storage_path)
            db.session.delete(doc)
            db.session.commit()
            flash(f'Documento "{doc.filename}" excluído com sucesso.', 'success')
        except Exception as e:
            flash(f'Erro ao excluir arquivo: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

    @app.route('/approve_doc/<int:doc_id>', methods=['POST'])
    @login_required
    def approve_doc(doc_id):
        if not current_user.can(PERMISSION_APPROVE): # Usando a nova permissao granular
            flash('Acesso negado. Você não pode aprovar documentos.', 'danger')
            return redirect(url_for('dashboard'))
            
        doc = Document.query.get_or_404(doc_id)
        # Garante que so aprova documentos do proprio departamento
        if doc.department_id != current_user.department_id:
             flash('Acesso negado. Documento de outro departamento.', 'danger')
             return redirect(url_for('dashboard'))
             
        doc.status = 'Aprovado'
        db.session.commit()
        flash(f'Documento "{doc.filename}" aprovado com sucesso!', 'success')
        return redirect(url_for('dashboard'))

    # --- FIM DAS ROTAS ---
    return app # Retorna a app configurada


# Função auxiliar para o Flask CLI (linha de comando) encontrar a app
def make_app():
    return create_app()


if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        # db.create_all() # Ja criamos manualmente no PostgreSQL
        
        if not Direction.query.first():
            dir_geral = Direction(name="Direção Geral")
            dep_ti = Department(name="Tecnologia da Informação", direction=dir_geral)
            doc_type_rel = DocumentType(name="Relatório")
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

    app.run(debug=True)

