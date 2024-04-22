from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from functools import wraps
from admin import Secret, Admin, Premium

app = Flask(__name__)
app.config['SECRET_KEY'] = Secret.FLASK_KEY
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = Secret.DB_URI
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

    posts: Mapped[list["Post"]] = relationship("Post", back_populates="author")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="author")
    about: Mapped[list["About"]] = relationship("About", back_populates="author")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[int] = mapped_column(Text, nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author: Mapped["User"] = relationship("User", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("posts.id"))
    post: Mapped["Post"] = relationship("Post", back_populates="comments")

class About(db.Model):
    __tablename__ = "about_page"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author: Mapped["User"] = relationship("User", back_populates="about")

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

def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        for admin in Admin.ADMINS:
            try:
                if current_user.email == admin:
                    return function(*args, **kwargs)
            except AttributeError:
                break
        return abort(403)
    return wrapper

@app.route('/')
def homepage():
    posts = db.session.execute(db.select(Post).order_by(Post.id)).scalars().all()
    return render_template('index.html', posts=reversed(posts), active0="active", year=year, title="Career Post", logged_in=current_user.is_authenticated, user=current_user, admins=Admin.ADMINS)

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

            db.session.add(new_user)
            db.session.commit()

            login_user(new_user)
            return redirect(url_for('homepage'))
        flash("The Email You Entered Already Exists")
        return redirect('login')
    return render_template("form.html", form=form, active3="active", year=year, title="Register", logged_in=current_user.is_authenticated, user=current_user, admins=Admin.ADMINS)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()
        if user and check_password_hash(pwhash=user.password, password=form.password.data):
            login_user(user)
            return redirect(url_for('homepage'))
        flash("The Email/Password You Entered Is Invalid")
    return render_template("form.html", form=form, active2="active", year=year, title="Log In", logged_in=current_user.is_authenticated, user=current_user, admins=Admin.ADMINS)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('homepage'))

@app.route('/posts')
def posts():
    posts = db.session.execute(db.select(Post).order_by(Post.id)).scalars().all()
    return render_template('posts.html', posts=reversed(posts), active1="active", year=year, title="Latest Posts", logged_in=current_user.is_authenticated, user=current_user, admins=Admin.ADMINS)


@app.route('/create-post', methods=['GET', 'POST'])
@admin_only
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
    return render_template("form.html", form=form, year=year, title="Log In", logged_in=current_user.is_authenticated, user=current_user, admins=Admin.ADMINS)

if __name__ == '__main__':
    app.run(debug=True)