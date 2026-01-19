from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from datetime import datetime
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-tbc-2025-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max


if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'გთხოვთ გაიაროთ ავტორიზაცია'

# ==================== MODELS ====================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    news = db.relationship('News', backref='author', lazy=True, cascade='all, delete-orphan')

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)  # ფოტოს სახელი
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ==================== FORMS ====================
class RegistrationForm(FlaskForm):
    username = StringField('მომხმარებლის სახელი', 
                          validators=[DataRequired(message='სავალდებულო ველი'), 
                                    Length(min=3, max=80, message='მინიმუმ 3 სიმბოლო')])
    password = PasswordField('პაროლი', 
                           validators=[DataRequired(message='სავალდებულო ველი'),
                                     Length(min=6, message='მინიმუმ 6 სიმბოლო')])
    confirm_password = PasswordField('გაიმეორეთ პაროლი',
                                    validators=[DataRequired(message='სავალდებულო ველი'),
                                              EqualTo('password', message='პაროლები არ ემთხვევა')])
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('ეს მომხმარებელი უკვე არსებობს')

class LoginForm(FlaskForm):
    username = StringField('მომხმარებლის სახელი',
                          validators=[DataRequired(message='სავალდებულო ველი')])
    password = PasswordField('პაროლი',
                           validators=[DataRequired(message='სავალდებულო ველი')])

class NewsForm(FlaskForm):
    title = StringField('სათაური',
                       validators=[DataRequired(message='სავალდებულო ველი'),
                                 Length(max=200, message='მაქსიმუმ 200 სიმბოლო')])
    category = SelectField('კატეგორია',
                          choices=[('პოლიტიკა', 'პოლიტიკა'),
                                 ('ეკონომიკა', 'ეკონომიკა'),
                                 ('ტექნოლოგიები', 'ტექნოლოგიები'),
                                 ('სპორტი', 'სპორტი'),
                                 ('კულტურა', 'კულტურა'),
                                 ('სხვა', 'სხვა')],
                          validators=[DataRequired(message='სავალდებულო ველი')])
    content = TextAreaField('შინაარსი',
                          validators=[DataRequired(message='სავალდებულო ველი'),
                                    Length(min=10, message='მინიმუმ 10 სიმბოლო')])
    image = FileField('📸 ფოტო (არასავალდებულო)',
                     validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'მხოლოდ სურათები!')])

# ==================== LOGIN MANAGER ====================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== ROUTES ====================
@app.route('/')
def index():
    category = request.args.get('category', 'all')
    
    if category == 'all':
        news_list = News.query.order_by(News.created_at.desc()).all()
    else:
        news_list = News.query.filter_by(category=category).order_by(News.created_at.desc()).all()
    
    return render_template('index.html', news_list=news_list, current_category=category)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('✅ რეგისტრაცია წარმატებით დასრულდა!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.password == form.password.data:
            login_user(user)
            flash(f'👋 გამარჯობა, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('❌ არასწორი მომხმარებლის სახელი ან პაროლი', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('✅ თქვენ წარმატებით გამოხვედით სისტემიდან', 'info')
    return redirect(url_for('index'))

@app.route('/add-news', methods=['GET', 'POST'])
@login_required
def add_news():
    form = NewsForm()
    
    if form.validate_on_submit():
    
        image_filename = None
        if form.image.data:
            file = form.image.data
            filename = secure_filename(file.filename)
            
            unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            image_filename = unique_filename
        
        news = News(
            title=form.title.data,
            category=form.category.data,
            content=form.content.data,
            image_filename=image_filename,
            author=current_user
        )
        db.session.add(news)
        db.session.commit()
        flash('✅ სიახლე წარმატებით დაემატა!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add_news.html', form=form)

@app.route('/news/<int:id>/delete', methods=['POST'])
@login_required
def delete_news(id):
    news = News.query.get_or_404(id)
    
    if current_user.is_admin or news.user_id == current_user.id:
        # წაშალე ფოტოც თუ არსებობს
        if news.image_filename:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], news.image_filename))
            except:
                pass
        
        db.session.delete(news)
        db.session.commit()
        flash('✅ სიახლე წარმატებით წაიშალა', 'success')
    else:
        flash('❌ თქვენ არ გაქვთ უფლება წაშალოთ ეს სიახლე', 'danger')
    
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('❌ წვდომა აკრძალულია. მხოლოდ ადმინისთვის!', 'danger')
        return redirect(url_for('index'))
    
    users = User.query.all()
    all_news = News.query.order_by(News.created_at.desc()).all()
    
    return render_template('admin.html', users=users, all_news=all_news)

# ==================== INITIALIZATION ====================
def init_db():
    with app.app_context():
        db.create_all()
        
        
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', password='admin123', is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print('✅ ადმინის ანგარიში შეიქმნა: username=admin, password=admin123')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)