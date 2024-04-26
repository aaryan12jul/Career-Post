# Imports
import os
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, Boolean
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email
from flask_ckeditor import CKEditor, CKEditorField
from flask_gravatar import Gravatar
from werkzeug.security import generate_password_hash, check_password_hash
from smtplib import SMTP
from datetime import datetime, date
from functools import wraps

# Flask App
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_KEY')

# Ckeditor 
ckeditor = CKEditor(app)

# Bootstrap 
bootstrap = Bootstrap5(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

# Gravatar
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

# Current Year
year = datetime.now().year

# Dark Mode
dark_mode = True

# Database Template
class Base(DeclarativeBase):
    pass

# Creating Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DB_URI')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Post Database
class Post(db.Model):
    __tablename__ = "posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String, nullable=True)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author: Mapped['User'] = relationship("User", back_populates="posts")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="post")

# User Database
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    about_text: Mapped[str] = mapped_column(Text, nullable=False, default=f"Hello, It is nice to Meet You!")

    admin: Mapped[bool] = mapped_column(Boolean, nullable=False)
    premium: Mapped[bool] = mapped_column(Boolean, nullable=False)

    posts: Mapped[list["Post"]] = relationship("Post", back_populates="author")
    comments: Mapped[list["Comment"]] = relationship("Comment", back_populates="author")

# Commenting System
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[int] = mapped_column(Text, nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"), unique=False)
    author: Mapped["User"] = relationship("User", back_populates="comments")
    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("posts.id"), unique=False)
    post: Mapped["Post"] = relationship("Post", back_populates="comments")

# Creating Tables in Database
with app.app_context():
    db.create_all()

# Register Form
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    reenter_pass = PasswordField("Re Enter Password", validators=[DataRequired()])
    submit = SubmitField("Sign Up")

# Login Form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")

# Post Creation Form
class CreatePostForm(FlaskForm):
    title = StringField("Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Image URL")
    body = CKEditorField("Post Text", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

# About Page Creation Form
class CreateAboutForm(FlaskForm):
    body = CKEditorField("About Text", validators=[DataRequired()])
    submit = SubmitField("Save")

# Contact Form
class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    phone = StringField("Phone Number", validators=[DataRequired()])
    message = TextAreaField("Message", validators=[DataRequired()])
    submit = SubmitField("Send")

# Comment Form
class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Send Comment")

# Admin Only Decorator
def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.get_id() != '1':
            if current_user.is_authenticated and current_user.admin:
                return function(*args, **kwargs)
            return abort(403)
        else:
            user = db.get_or_404(User, 1)
            user.admin = True
            db.session.commit()
            return function(*args, **kwargs)
    return wrapper

# Premium Only Decorator
def premium_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.get_id() != '1':
            if current_user.is_authenticated and current_user.premium:
                return function(*args, **kwargs)
            return abort(403)
        else:
            user = db.get_or_404(User, 1)
            user.premium = True
            db.session.commit()
            return function(*args, **kwargs)
    return wrapper

# Non Anonymous Users Only Decorator
def logged_on(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            return function(*args, **kwargs)
        else:
            flash('You Need to Login First')
            return redirect(url_for('login'))
    return wrapper

# Homepage
@app.route('/')
def homepage():
    posts = db.session.execute(db.select(Post).order_by(Post.id)).scalars().all()
    return render_template('index.html', posts=list(reversed(posts)), active0="active", dark_mode=dark_mode, count_target=6, year=year, title="Career Post", logged_in=current_user.is_authenticated, user=current_user)

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    premium = request.args.get('premium', False)
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()

        if not user:
            if form.password.data == form.reenter_pass.data:
                name = form.name.data
                password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)

                if premium:
                    new_user = User(
                        email=email,
                        name=name,
                        password=password,
                        admin=False,
                        premium=True
                    )
                else:
                    new_user = User(
                        email=email,
                        name=name,
                        password=password,
                        admin=False,
                        premium=False
                    )

                db.session.add(new_user)
                db.session.commit()

                login_user(new_user)
                return redirect(url_for('posts'))
            flash("The Passwords You Entered Do Not Match")
        else:
            flash("The Email You Entered Already Exists")
            return redirect('login')
    return render_template("form.html", form=form, active3="active", year=year, dark_mode=dark_mode, title="Register", logged_in=current_user.is_authenticated, user=current_user)

# Login Route
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
    return render_template("form.html", form=form, active2="active", year=year, dark_mode=dark_mode, title="Log In", logged_in=current_user.is_authenticated, user=current_user)

# Logout Route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# Latest Post Route
@app.route('/posts')
def posts():
    posts = db.session.execute(db.select(Post).order_by(Post.id)).scalars().all()
    return render_template('posts.html', posts=list(reversed(posts)), active1="active", dark_mode=dark_mode, count_target=20, year=year, title="Latest Posts", logged_in=current_user.is_authenticated, user=current_user)

# View Specified Post
@app.route('/view-post/<id>', methods=['GET', 'POST'])
def view_post(id):
    post = db.get_or_404(Post, id)

    if post:
        posts = db.session.execute(db.select(Post).where(Post.author_id==post.author_id)).scalars().all()
        author = db.get_or_404(User, post.author_id)
        form = CommentForm()
        
        if form.validate_on_submit():
            if current_user.is_authenticated:
                user = db.get_or_404(User, current_user.get_id())

                new_comment = Comment(
                    text=form.comment.data,
                    author=user,
                    post=post,
                )

                db.session.add(new_comment)
                db.session.commit()
            else:
                flash('You Need to Login to Comment on Posts')
                return redirect(url_for('login'))
        return render_template('viewer.html', post=post, form=form, dark_mode=dark_mode, edit_url=url_for('edit_post', email=post.author.email, id=id), id=id, posts=list(reversed(posts)), count_target=3, email=post.author.email, title=post.title, subtitle=post.subtitle, name=post.author.name, text=post.text, image=post.img_url, year=year, logged_in=current_user.is_authenticated, user=current_user, author=author)
    
    return redirect(url_for('posts'))

# Create Post Route
@app.route('/create-post', methods=['GET', 'POST'])
@logged_on
def create_post():
    if not current_user.admin and not current_user.premium:
        posts = db.session.execute(db.select(Post).where(Post.author_id==current_user.id)).scalars().all()
        for post in posts:
            if post.date == date.today().strftime("%B %d, %Y"):
                return redirect(url_for('about', email=current_user.email, message='You Can Not Make Any More Posts Today'))
    
    form = CreatePostForm()
    if form.validate_on_submit():
        post = db.session.execute(db.select(Post).where(Post.title==form.title.data)).scalar()

        if not post:
            new_post = Post(
                title=form.title.data.title(),
                subtitle=form.subtitle.data,
                text=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )

            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("posts"))
        else:
            flash('A Post with that Title Already Exists')
    
    return render_template("form.html", form=form, year=year, dark_mode=dark_mode, title="Create Post", logged_in=current_user.is_authenticated, user=current_user)

# Edit Post
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
        
        return render_template('editor.html', form=form, dark_mode=dark_mode, posts=list(reversed(posts)), count_target=3, email=user.email, title=user.name, name=user.name, text=user.about_text, year=year, logged_in=current_user.is_authenticated, user=current_user)
    return abort(403)

# Deleting Post
@app.route('/delete/<email>/<id>')
@logged_on
def delete_post(email, id):
    if current_user.email == email or current_user.admin:
        post = db.get_or_404(Post, id)
        
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('about', email=email))
    
    return abort(403)

# About Page Route
@app.route('/<email>', methods=['GET', 'POST'])
@app.route('/<email>/<message>')
def about(email, message=''):
    user = db.session.execute(db.select(User).where(User.email==email)).scalar()
    if user:
        email_sent=False
        posts = db.session.execute(db.select(Post).where(Post.author_id==user.id)).scalars().all()
        
        if current_user.is_authenticated:
            form = ContactForm(
                name=current_user.name,
                email=current_user.email
            )

            if form.validate_on_submit():
                name = form.name.data
                from_email = form.email.data
                phone = form.phone.data
                message = form.message.data
                from_user = db.session.execute(db.select(User).where(User.email==from_email)).scalar()
                
                if from_user:
                    EMAIL = os.environ.get('EMAIL')
                    PASSWORD = os.environ.get('PASSWORD')
                    with SMTP('smtp.gmail.com') as connection:
                        connection.starttls()
                        connection.login(user=EMAIL, password=PASSWORD)
                        connection.sendmail(from_addr=EMAIL, to_addrs=email, msg=f"Subject: Someone Using Career Post Has Tried to Contact You\n\nName: {name}\nEmail: {from_email}\nPhone Number: {phone}\nMessage:\n{message}")
                    email_sent=True

                else:
                    flash("The Email You Entered Is Invalid")
        else:
            form = ContactForm()
        return render_template('viewer.html', form=form, dark_mode=dark_mode, message=message, email_sent=email_sent, edit_url=url_for('edit_about', email=user.email), posts=list(reversed(posts)), count_target=3, email=user.email, title=user.name, name=user.name, text=user.about_text, year=year, logged_in=current_user.is_authenticated, user=current_user, author=user)
    return redirect(url_for('homepage'))

# Edit About Page
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
        return render_template('editor.html', form=form, dark_mode=dark_mode, posts=list(reversed(posts)), count_target=3, email=user.email, title=user.name, name=user.name, text=user.about_text, year=year, logged_in=current_user.is_authenticated, user=current_user)
    return abort(403)

# Delete Account Route
@app.route('/delete/<email>')
@logged_on
def delete_account(email):
    if current_user.email == email or current_user.admin:
        user = db.session.execute(db.select(User).where(User.email==email)).scalar()
        posts = db.session.execute(db.select(Post).where(Post.author_id==user.id)).scalars().all()
        comments = db.session.execute(db.select(Comment).where(Comment.author_id==user.id)).scalars().all()
        for post in posts:
            for comment in post.comments:
                db.session.delete(comment)
            db.session.delete(post)

        for comment in comments:
            db.session.delete(comment)

        db.session.delete(user)
        db.session.commit()
        if current_user.email == email:
            logout_user()
            return redirect(url_for('register'))
        else:
            return redirect(url_for('posts'))
    return abort(403)

# Delete Comments Route
@app.route('/delete-comment/<id>')
@logged_on
def delete_comment(id):
    comment = db.get_or_404(Comment, id)
    if current_user.admin or current_user.id == comment.author_id or comment.post.author.email == current_user.email:
        post = db.get_or_404(Post, comment.post_id)
        db.session.delete(comment)
        db.session.commit()
        return redirect(url_for('view_post', id=post.id))
    return abort(403)

# Search Route
@app.route('/search/')
def search():
    query = request.args.get('query').title()
    results = Post.query.filter(Post.title.contains(query)).all()
    return render_template('posts.html', posts=list(results), dark_mode=dark_mode, count_target=20, year=year, title=query, logged_in=current_user.is_authenticated, user=current_user)

# Change Theme
@app.route('/theme/<make>')
def theme(make):
    global dark_mode
    if make == 'True':
        dark_mode = True
    elif make == 'False':
        dark_mode = False
    return redirect(url_for('posts'))

# Making Admin Route
@app.route('/make-admin/<email>')
@admin_only
def make_admin(email):
    user = db.session.execute(db.select(User).where(User.email==email)).scalar()
    user.admin = True
    db.session.commit()
    return redirect(url_for('about', email=email))

# Make Premium Route
@app.route('/make-premium/<email>')
@admin_only
def make_premium(email):
    user = db.session.execute(db.select(User).where(User.email==email)).scalar()
    user.premium = True
    db.session.commit()
    return redirect(url_for('about', email=email))

# Running Code
if __name__ == '__main__':
    app.run(debug=True)