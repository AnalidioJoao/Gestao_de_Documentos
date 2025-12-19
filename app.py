from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pytesseract
from pdf2image import convert_from_path 
from flask_mail import Mail, Message
import os

basedir = os.path.abspath(os.path.dirname(__file__))
pytesseract.pytesseract.tesseract_cmd = r'C:\Users\anali\AppData\Local\Programs\Tesseract-OCR'
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

mail = Mail()

# --- FUNÇÕES AUXILIARES DE EXTRAÇÃO DE TEXTO ---
def extract_text_from_file(filepath, mimetype):
    text = ""
    # Se for um PDF, converte página por página em imagem para o OCR ler
    if mimetype == 'application/pdf':
        try:
            pages = convert_from_path(filepath, 500) # 500 DPI para melhor precisão
            for page in pages:
                text += pytesseract.image_to_string(page, lang='por') # Tenta usar o idioma Português
        except Exception as e:
            print(f"OCR Falhou no PDF: {e}")
            text = "OCR Falhou ou Arquivo Ilegível."
    
    # Se for uma imagem (PNG, JPG, etc.)
    elif mimetype.startswith('image/'):
        try:
            text = pytesseract.image_to_string(filepath, lang='por')
        except Exception as e:
            print(f"OCR Falhou na Imagem: {e}")
            text = "OCR Falhou ou Arquivo Ilegível."

    # Para outros tipos como .txt ou .docx, teríamos que implementar mais lógica
    # Mas para o nosso MVP, focamos em imagens e PDFs digitalizados

    return text

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- MODELOS (Tabelas do Banco de Dados) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user') 
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def is_admin(self):
        return self.role == 'admin'

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploader = db.relationship('User', backref=db.backref('documents', lazy=True))
    # NOVA COLUNA PARA O TEXTO EXTRAÍDO
    content = db.Column(db.Text, nullable=True) 
    # --- NOVA COLUNA PARA O FLUXO DE TRABALHO ---
    status = db.Column(db.String(50), nullable=False, default='Pendente') 
    # --- NOVAS COLUNAS PARA VERSIONAMENTO ---
    version_number = db.Column(db.Integer, nullable=False, default=1)
    # parent_id aponta para o ID do documento "mestre" ou original
    parent_id = db.Column(db.Integer, db.ForeignKey('document.id'), nullable=True) 
    # Relacionamento recursivo para encontrar todas as versões
    versions = db.relationship('Document', backref=db.backref('parent', remote_side=[id]), lazy=True)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    app.secret_key = 'sua_chave_secreta_muito_segura' 
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USE_SSL'] = True
    app.config['MAIL_USERNAME'] = 'quiamuxinda@gmail.com' # Substitua pelo seu email
    app.config['MAIL_PASSWORD'] = 'fply jsth nrro vnwh'  # Substitua pela sua senha de APP (não a senha normal do email)
    app.config['MAIL_DEFAULT_SENDER'] = 'asjwebdesigner@gmail.com'


    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app) # Inicializa o Flask-Mail aqui
    # --- ROTAS ---

    @app.route('/')
    @app.route('/dashboard')
    @login_required
    def dashboard():
        search_query = request.args.get('q', '') # Captura o termo de busca (q)
        # Filtra para mostrar apenas documentos "mestres" (parent_id é Nulo)
        query = Document.query.filter_by(parent_id=None)
        if search_query:
            # Filtra os documentos onde o título OU o conteúdo (OCR) contêm a query
            documents = Document.query.filter(
                (Document.filename.ilike(f'%{search_query}%')) | 
                (Document.content.ilike(f'%{search_query}%'))
            ).all()
        else:
            documents = Document.query.all()
            
        return render_template('dashboard.html', documents=documents, search_query=search_query)


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
        if not current_user.is_admin(): # <--- Usando o novo método is_admin()
            flash('Acesso negado! Apenas administradores podem gerir usuários.', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if User.query.filter_by(username=username).first():
                flash('Nome de usuário já existe.', 'danger')
            else:
                # O novo usuário tem o papel padrão 'user'
                new_user = User(username=username, role='user') 
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash(f'Usuário {username} criado com sucesso!', 'success')
            return redirect(url_for('manage_users'))
        users = User.query.all()
        return render_template('manage_users.html', users=users)

        user = User.query.get_or_404(user_id)
        
        # Opcional: Impedir de apagar o admin principal
        if user.username == 'admin':
            flash('O administrador principal não pode ser excluído.', 'danger')
            return redirect(url_for('manage_users'))

        db.session.delete(user)
        db.session.commit()
        flash(f'Usuário "{user.username}" removido com sucesso.', 'success')
        return redirect(url_for('manage_users'))

    @app.route('/delete_user/<int:user_id>', methods=['POST'])
    @login_required
    def delete_user(user_id):
        # Impede que o admin se apague a si próprio
        if current_user.id == user_id:
            flash('Não pode excluir o usuário atualmente logado.', 'danger')
            return redirect(url_for('manage_users'))

        user = User.query.get_or_404(user_id)
        
        # Proteção extra para o admin principal
        if user.username == 'admin':
            flash('O administrador principal não pode ser removido.', 'danger')
            return redirect(url_for('manage_users'))

        db.session.delete(user)
        db.session.commit()
        flash(f'Usuário {user.username} removido com sucesso.', 'success')
        return redirect(url_for('manage_users'))



    @app.route('/upload', methods=['POST'])
    @login_required
    def upload_file():
        # Captura o arquivo do formulário
        file = request.files.get('file')

        # Se não houver arquivo no formulário, avisa e redireciona
        if not file:
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(url_for('dashboard'))

        # Se o arquivo existe, mas o nome está vazio (erro de upload)
        if file.filename == '':
            flash('Nome de arquivo inválido.', 'danger')
            return redirect(url_for('dashboard'))

        # Se o tipo de arquivo não é permitido
        if not allowed_file(file.filename):
            flash('Tipo de arquivo não permitido.', 'danger')
            return redirect(url_for('dashboard'))

        # Se tudo estiver OK, processa o upload
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Lógica de Extração de Texto e Versionamento (seu código anterior)
            existing_doc = Document.query.filter_by(filename=filename, parent_id=None).first()
            parent_id = None
            version = 1
            if existing_doc:
                parent_id = existing_doc.id
                max_version = db.session.query(db.func.max(Document.version_number)).filter_by(parent_id=parent_id).scalar()
                version = (max_version or 0) + 2

            mimetype = file.mimetype
            extracted_content = extract_text_from_file(filepath, mimetype)
            
            new_doc = Document(filename=filename, storage_path=filepath, uploader_id=current_user.id, content=extracted_content, version_number=version, parent_id=parent_id)
            db.session.add(new_doc)
            db.session.commit()
            # --- CHAMADA DA NOVA FUNÇÃO ---
            send_notification_email(filename, current_user.username)

            flash(f'Arquivo enviado como Versão {version} com sucesso!', 'success')
            return redirect(url_for('dashboard'))

        # Esta linha final serve como uma garantia de retorno, embora a lógica acima já cubra tudo
        return redirect(url_for('dashboard'))

    @app.route('/approve_doc/<int:doc_id>', methods=['POST'])
    @login_required
    def approve_doc(doc_id):
        # Apenas admins podem aprovar
        if not current_user.is_admin():
            flash('Acesso negado. Apenas administradores podem aprovar documentos.', 'danger')
            return redirect(url_for('dashboard'))
            
        doc = Document.query.get_or_404(doc_id)
        doc.status = 'Aprovado'
        db.session.commit()
        flash(f'Documento "{doc.filename}" aprovado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    

    @app.route('/download/<int:doc_id>')
    @login_required
    def download_file(doc_id):
        doc = Document.query.get_or_404(doc_id)
        return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename, as_attachment=True)

    @app.route('/delete/<int:doc_id>', methods=['POST'])
    @login_required
    def delete_file(doc_id):
        
        # --- VERIFICAÇÃO DE SEGURANÇA ---
        if not current_user.is_admin():
            flash('Acesso negado! Apenas administradores podem excluir documentos.', 'danger')
            return redirect(url_for('dashboard'))
        # --------------------------------

        doc = Document.query.get_or_404(doc_id)
        
        # 1. Tentar remover o arquivo físico da pasta uploads
        try:
            if os.path.exists(doc.storage_path):
                os.remove(doc.storage_path)
            
            # 2. Remover o registro do banco de dados
            db.session.delete(doc)
            db.session.commit()
            flash(f'Documento "{doc.filename}" excluído com sucesso.', 'success')
        except Exception as e:
            flash(f'Erro ao excluir arquivo: {str(e)}', 'danger')
            
        return redirect(url_for('dashboard'))

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404



    return app

def send_notification_email(filename, username):
    msg = Message("Novo Documento Carregado: " + filename, recipients=['quiamuxinda@gmail.com']) # Envia para você
    msg.body = f"O usuário {username} acabou de carregar um novo documento: {filename}. Por favor, verifique a dashboard para aprovação."
    try:
        mail.send(msg)
        print("E-mail de notificação enviado com sucesso!")
    except Exception as e:
        print(f"Falha ao enviar e-mail: {e}")


if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            admin.set_password('123456')
            db.session.add(admin)
            db.session.commit()
            print("Admin criado com sucesso!")
    app.run(debug=True)
