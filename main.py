from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, InputRequired
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_bcrypt import Bcrypt
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

db = SQLAlchemy()
app = Flask(__name__)
app.app_context().push()

admin = Admin(app, name='Control Panel')
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///data.db"
app.config['SECRET_KEY'] = "secret"
db.init_app(app)


class University(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    uniName = db.Column(db.String, unique=True, nullable=False)
    officName = db.Column(db.String)
    country = db.Column(db.String)
    province = db.Column(db.String)
    alphaTwoCode = db.Column(db.String)
    domains = db.Column(db.String)
    website = db.Column(db.String)

with app.app_context():
    db.create_all()


login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view='login'


@login_manager.user_loader
def user_load(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    admins = db.relationship('Admin', backref='user')

with app.app_context():
    db.create_all()


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String, unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

with app.app_context():
    db.create_all()


admin.add_view(ModelView(User, db.session))


class RegisterForm(FlaskForm):
    username = StringField(label='Username', validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Enter your username"})
    email = StringField(label='Email', validators=[DataRequired(), Email(), Length(min=4, max=20)],
                        render_kw={"placeholder": "Enter your email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Enter your password"})
    confirm = PasswordField(label='Confirm', validators=[DataRequired(), EqualTo('password')],
                            render_kw={"placeholder": "Enter your password again"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LogForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(min=4, max=20)],
                         render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)],
                             render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('profile.html')


@app.route('/admin_profile')
def admin_profile():
    users = User.query.all()
    return render_template('admin_profile.html', users=users)


@app.errorhandler(KeyError)
def error():
    return render_template('error.html')


@app.route('/result', methods=['GET', 'POST'])
def result():
    print(request)
    print(request.method)
    print(request.form)
    uni = request.form['uni']
    if University.query.filter_by(uniName=uni).first() is None:
        url = f"http://universities.hipolabs.com/search?name={uni}"
        r = requests.get(url)

        if r.status_code == 404:
            return render_template('error.html')

        response = r.json()[0]
        officName = response['name']
        country = response['country']
        province = response['state-province']
        code = response['alpha_two_code']
        domain = response['domains'][0]
        web = response['web_pages'][0]

        uni1 = University(uniName=uni, officName=officName, country=country, province=province,
                          alphaTwoCode=code, domains=domain, website=web)
        db.session.add(uni1)
        db.session.commit()

    q = University.query.filter_by(uniName=uni).first()
    return render_template('result.html', officName=q.officName, country=q.country, province=q.province,
                           code=q.alphaTwoCode, domain=q.domains, web=q.website)


@app.route('/login', methods=['GET', 'POST'])
def login():
    loginForm = LogForm()
    if loginForm.validate_on_submit():
        user = User.query.filter_by(username=loginForm.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, loginForm.password.data):
                login_user(user)
                if user.admins:
                    return redirect(url_for('admin_profile'))
                else:
                    return redirect(url_for('profile'))
            else:
                return "Invalid password. Try again. <a href='/'> Click here to go to back</a> "
    return render_template('login.html', loginForm=loginForm)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
