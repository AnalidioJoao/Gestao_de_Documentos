from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pytesseract
from pdf2image import convert_from_path 
import os

basedir = os.path.abspath(os.path.dirname(__file__))
pytesseract.pytesseract.tesseract_cmd = r'C:\Users\anali\AppData\Local\Programs\Tesseract-OCR'
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

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
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    app.secret_key = 'sua_chave_secreta_muito_segura' 
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'site.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)

    # --- ROTAS ---

    @app.route('/')
    @app.route('/dashboard')
    @login_required
    def dashboard():
        search_query = request.args.get('q', '') # Captura o termo de busca (q)
        
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
    # ... (verifica se tem o arquivo no request, etc. - código anterior) ...

        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath) 

        # --- NOVA LÓGICA DE EXTRAÇÃO DE TEXTO ---
        # Detecta o tipo de arquivo enviado
        mimetype = file.mimetype 
        extracted_content = extract_text_from_file(filepath, mimetype)
        # ----------------------------------------

        # Salva os metadados E o conteúdo no banco de dados
        new_doc = Document(
            filename=filename, 
            storage_path=filepath, 
            uploader_id=current_user.id,
            content=extracted_content # <--- Salvando o texto extraído
        ) 
        db.session.add(new_doc)
        db.session.commit()

        flash('Arquivo enviado com sucesso e texto extraído!', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/download/<int:doc_id>')
    @login_required
    def download_file(doc_id):
        doc = Document.query.get_or_404(doc_id)
        return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename, as_attachment=True)

    @app.route('/delete/<int:doc_id>', methods=['POST'])
    @login_required
    def delete_file(doc_id):
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
