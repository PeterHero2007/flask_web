from flask import Flask,request,render_template,url_for,redirect,flash
from werkzeug.utils import secure_filename
import os
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager,login_user,login_required,logout_user
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField,PasswordField,BooleanField,SubmitField
from wtforms.validators import DataRequired, Length , Email,Regexp,EqualTo
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = \
    "sqlite:///" + os.path.join(basedir,"data.sqlite")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "1433223"

#app.send_file_max_age_default = timedelta(seconds=1)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
bootstrap = Bootstrap(app)
#models
class User(UserMixin,db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer,primary_key = True)
    email = db.Column(db.String(64),unique=True,index=True)
    username = db.Column(db.String(64),unique=True,index=True)
    password_hash = db.Column(db.String(128))
    @property
    def password(self):
        raise AttributeError("!!")
    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#forms
class LoginForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(),Length(1,64),Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    remember_me = BooleanField("Keep me logged in")
    submit = SubmitField("Log in")

class RegistrationForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(),Length(1,64),Email()])
    username = StringField("Username",validators=[
        DataRequired(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',
            0,"Username must have only letters,number,'.' or '_'.")])
    password =  PasswordField("Password",validators=[DataRequired(),
                                    EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password",validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise AttributeError("!!2")
    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise AttributeError("!!3")

#views
@app.route('/static/<path:filename>')
def get_image(filename):
    # 从指定目录中发送文件
    return send_from_directory('static/', filename)
        
@app.route('/',methods=["get","post"])
def index():
    return render_template("main.html")

@app.route('/login',methods=["get","post"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remember_me.data)
            next = request.args.get("next")
            if next is None or not next.startwith("/"):
                next = url_for("index")
            return redirect(next)
        flash("jntm")
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Out")
    return redirect(url_for("index"))

@app.route('/register',methods=["get","post"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("You can now login.")
        return redirect(url_for("login"))
    return render_template('register.html',form=form)

app.run(debug=True, host='0.0.0.0')
