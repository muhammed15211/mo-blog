import sqlalchemy.exc
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
#app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##LOGIN_MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    # USER CAN HAVE MANY POSTS
    posts = relationship("BlogPost", backref="user")

    # USER CAN HAVE MANY COMMENTS
    comments = relationship("Comment", backref="user_comment")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
#    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # BLOGPOST CAN HAVE MANY COMMENTS
    comments = relationship("Comment", backref="post_comments")

    # FOREIGN KEY TO LINK TO USER(refer to primary key of the user)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=True)

    # FOREIGNKEY TO LINK TO USER
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # FOREIGNKEY TO LINK TO BLOGPOSTS
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

## DECORATORS
def admin_only(func):
    wraps(func)
    def wrapper_func(*args, **kwargs):
        if not current_user.is_authenticated:
            return abort(403)
        elif current_user.id != 1:
            return abort(404)
        elif current_user.id == 1:
            return func(*args, **kwargs)

    wrapper_func.__name__ = func.__name__
    return wrapper_func




@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))

    register_form = RegisterForm()
    try:
        if register_form.validate_on_submit():
            email = register_form.email.data
            password = generate_password_hash(password=register_form.password.data, method="pbkdf2:sha256", salt_length=8)
            name = register_form.name.data

            new_user = User(email=email, password=password, name=name)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('get_all_posts'))
    except sqlalchemy.exc.IntegrityError:
        flash("Email already registered! Login instead")
        return redirect(url_for('login'))

    return render_template("register.html", form=register_form)


@app.route('/login', methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))

    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        user = User.query.filter_by(email=email).first()

        if user == None:
            flash("Wrong email address check and try again!")
            return redirect(url_for('login'))

        elif check_password_hash(pwhash=user.password, password=login_form.password.data) == False:
            flash("Wrong password!")
            return redirect(url_for('login'))

        elif check_password_hash(pwhash=user.password, password=login_form.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    authenticated = current_user.is_authenticated

    if not authenticated and comment_form.validate_on_submit():
        flash("You need to login or register to comment!")
        return redirect(url_for('login'))

    elif authenticated and comment_form.validate_on_submit():
        new_comment = Comment(
            text=comment_form.body.data,
            user_id=current_user.id,
            post_id=requested_post.id,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('get_all_posts'))

    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            #author=current_user.name,
            user_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')

@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html')

if __name__ == "__main__":
    app.run(debug=True)
