from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

basedir = os.path.abspath(os.path.dirname(__file__))

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- MODELOS (Tabelas do Banco de Dados) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploader = db.relationship('User', backref=db.backref('documents', lazy=True))

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
        documents = Document.query.all()
        return render_template('dashboard.html', documents=documents)

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
        # SEGURANÇA: Apenas o admin pode aceder a esta página
        if current_user.username != 'admin':
            flash('Acesso negado! Apenas administradores podem gerir usuários.', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            if User.query.filter_by(username=username).first():
                flash('Nome de usuário já existe.', 'danger')
            else:
                new_user = User(username=username)
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
        if 'file' not in request.files:
            flash('Nenhum arquivo selecionado.', 'danger')
            return redirect(url_for('dashboard'))
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            new_doc = Document(filename=filename, storage_path=filepath, uploader_id=current_user.id)
            db.session.add(new_doc)
            db.session.commit()
            flash('Arquivo enviado com sucesso!', 'success')
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
            admin = User(username='admin')
            admin.set_password('123456')
            db.session.add(admin)
            db.session.commit()
            print("Admin criado com sucesso!")
    app.run(debug=True)
