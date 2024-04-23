import os
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, Boolean
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)
year = datetime.now().year

class Post(db.Model):
    __tablename__ = "posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String, nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author: Mapped['User'] = relationship("User", back_populates="posts")
    comments: Mapped['Comment'] = relationship("Comment", back_populates="post")

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    about_text: Mapped[str] = mapped_column(Text, nullable=False, default=f"Hello, It is nice to Meet You!")

    posts: Mapped[list["Post"]] = relationship("Post", back_populates="author")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[int] = mapped_column(Text, nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author: Mapped["User"] = relationship("User", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("posts.id"))
    post: Mapped["Post"] = relationship("Post", back_populates="comments")

class Type_User(db.Model):
    __tablename__ = "typeofuser"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, nullable=False, unique=True)
    admin: Mapped[bool] = mapped_column(Boolean, nullable=False)
    premium: Mapped[bool] = mapped_column(Boolean, nullable=False)

with app.app_context():
    db.create_all()

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")

class CreatePostForm(FlaskForm):
    title = StringField("Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Post Text", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class CreateAboutForm(FlaskForm):
    body = CKEditorField("Post Text", validators=[DataRequired()])
    submit = SubmitField("Save")

def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = db.session.execute(db.select(Type_User).where(Type_User.email==current_user.email)).scalar()
        if current_user.get_id() != '1':
            if user and user.admin:
                return function(*args, **kwargs)
            return abort(403)
        else:
            user.admin = True
            return function(*args, **kwargs)
    return wrapper

def premium_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = db.session.execute(db.select(Type_User).where(Type_User.email==current_user.email)).scalar()
        if current_user.get_id() != '1':
            if user and user.premium:
                return function(*args, **kwargs)
            return abort(403)
        else:
            user.admin = True
            return function(*args, **kwargs)
    return wrapper

def logged_on(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            return function(*args, **kwargs)
        else:
            flash('You Need to Login First')
            return redirect(url_for('login'))
    return wrapper

@app.route('/')
def homepage():
    posts = db.session.execute(db.select(Post).order_by(Post.id)).scalars().all()
    return render_template('index.html', posts=list(reversed(posts)), active0="active", count_target=6, year=year, title="Career Post", logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()

        if not user:
            name = form.name.data
            password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)

            new_user = User(
                email=email,
                name=name,
                password=password
            )

            new_type_user = Type_User(
                email=email,
                admin=False,
                premium=False
            )

            db.session.add(new_user)
            db.session.add(new_type_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for('posts'))
        flash("The Email You Entered Already Exists")
        return redirect('login')
    return render_template("form.html", form=form, active3="active", year=year, title="Register", logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()
        if user and check_password_hash(pwhash=user.password, password=form.password.data):
            login_user(user)
            return redirect(url_for('posts'))
        flash("The Email/Password You Entered Is Invalid")
    return render_template("form.html", form=form, active2="active", year=year, title="Log In", logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/posts')
def posts():
    posts = db.session.execute(db.select(Post).order_by(Post.id)).scalars().all()
    return render_template('posts.html', posts=list(reversed(posts)), active1="active", count_target=20, year=year, title="Latest Posts", logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all())

@app.route('/view-post/<id>')
def view_post(id):
    post = db.get_or_404(Post, id)
    if post:
        posts = db.session.execute(db.select(Post).where(Post.author_id==post.author_id)).scalars().all()
        return render_template('viewer.html', edit_url=url_for('edit_post', email=post.author.email, id=id), id=id, posts=list(reversed(posts)), count_target=3, email=post.author.email, title=post.title, subtitle=post.subtitle, name=post.author.name, text=post.text, image=post.img_url, year=year, logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())
    return redirect(url_for('posts'))

@app.route('/create-post', methods=['GET', 'POST'])
@logged_on
def create_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = Post(
            title=form.title.data,
            subtitle=form.subtitle.data,
            text=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("posts"))
    return render_template("form.html", form=form, year=year, title="Log In", logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())

@app.route('/edit-post/<email>/<id>', methods=['GET', 'POST'])
@logged_on
def edit_post(email, id):
    if current_user.email == email:
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()
        posts = db.session.execute(db.select(Post).where(Post.author_id==user.id)).scalars().all()
        post = db.get_or_404(Post, id)
        form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            body=post.text
            )
        if form.validate_on_submit():
            post.title = form.title.data
            post.subtitle = form.subtitle.data
            post.img_url = form.img_url.data
            post.text = form.body.data
            db.session.commit()
            return redirect(url_for('view_post', id=id))
        return render_template('editor.html', form=form, posts=list(reversed(posts)), count_target=3, email=user.email, title=user.name, name=user.name, text=user.about_text, year=year, logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())
    return abort(403)

@app.route('/delete/<email>/<id>')
@logged_on
def delete_post(email, id):
    if current_user.email == email:
        post = db.get_or_404(Post, id)
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('about', email=email))
    return abort(403)

@app.route('/about/<email>')
def about(email):
    user = db.session.execute(db.select(User).where(User.email==email)).scalar()
    if user:
        posts = db.session.execute(db.select(Post).where(Post.author_id==user.id)).scalars().all()
        return render_template('viewer.html', edit_url=url_for('edit_about', email=user.email), posts=list(reversed(posts)), count_target=3, email=user.email, title=user.name, name=user.name, text=user.about_text, year=year, logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())
    return abort(403)

@app.route('/edit-about/<email>', methods=['GET', 'POST'])
@logged_on
def edit_about(email):
    if current_user.email == email:
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()
        posts = db.session.execute(db.select(Post).where(Post.author_id==user.id)).scalars().all()
        form = CreateAboutForm(body=user.about_text)
        if form.validate_on_submit():
            user.about_text = form.body.data
            db.session.commit()
            return redirect(url_for('about', email=email))
        return render_template('editor.html', form=form, posts=list(reversed(posts)), count_target=3, email=user.email, title=user.name, name=user.name, text=user.about_text, year=year, logged_in=current_user.is_authenticated, user=current_user, admins=db.session.execute(db.select(Type_User).where(Type_User.admin==True)).scalars().all(), premiums=db.session.execute(db.select(Type_User).where(Type_User.premium==True)).scalars().all())
    return abort(403)

@app.route('/delete/<email>')
@logged_on
def delete_account(email):
    if current_user.email == email:
        logout_user()
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('register'))
    return abort(403)

@app.route('/make-admin/<email>')
@admin_only
def make_admin(email):
    user = db.session.execute(db.select(Type_User).where(Type_User.email==email)).scalar()
    user.admin == True
    db.session.commit()
    return redirect(url_for('about', email=email))

@app.route('/make-premium/<email>')
@admin_only
def make_premium(email):
    user = db.session.execute(db.select(Type_User).where(Type_User.email==email)).scalar()
    user.premium == True
    db.session.commit()
    return redirect(url_for('about', email=email))

if __name__ == '__main__':
    app.run(debug=True)