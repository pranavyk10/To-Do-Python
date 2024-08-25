from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
import werkzeug.security
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import StringField, FlaskForm, SubmitField
from wtforms.validators import InputRequired

# , login_required, current_user, logout_user
app = Flask(__name__)
app.config['SECRET_KEY'] = "qwerty2004"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///D:/Python Projects/Professional Python Projects/TO-DO List/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)




class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000), nullable=False)
    completed = db.Column(db.Boolean, default=False)

# Create a form for adding tasks
class TaskForm(FlaskForm):
    task = StringField('Task', validators=[InputRequired()])
    submit = SubmitField('Add Task')

# Register the Task model for Flask-WTF
bootstrap = Bootstrap(app)
bootstrap.init_app(app)










class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        plain_password = request.form.get("password")
        if plain_password is not None:
            hash_password = werkzeug.security.generate_password_hash(plain_password, method='pbkdf2:sha256',salt_length=8)
            new_user=User(
                email=request.form.get("email"),
                name=request.form.get("name"),
                password=hash_password
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        else:
            flash("PASSWORD REQUIRED !")

    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This email does not exist. Please try again")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Password incorrect. Please try again.")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("home"))
    return render_template("login.html")






if __name__ == "__main__":
    app.run(debug=True)




