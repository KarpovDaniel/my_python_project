from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Role, Organization, organization_users

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ваш-секретный-ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://zooob:1q2w3eRT@localhost/flask_auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация SQLAlchemy и Migrate
db.init_app(app)
migrate = Migrate(app, db)

# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_role(role_name):
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')  # Изменено с email на username
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()  # Поиск по username
        if user and user.check_password(password):
            login_user(user)
            flash('Вход выполнен успешно', 'success')
            return redirect(url_for('dashboard'))
        flash('Неверное имя пользователя или пароль', 'error')  # Обновлено сообщение
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято', 'error')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email уже используется', 'error')
            return redirect(url_for('register'))
        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            role = Role.query.filter_by(name='user').first()
            if role:
                new_user.roles.append(role)
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация успешна, пожалуйста, войдите', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при регистрации: {str(e)}', 'error')
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/organizer')
@login_required
@role_required('organizer')
def organizer_panel():
    return render_template('organizer.html')


@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    return render_template('admin.html')


@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not (current_user.has_role('admin') or current_user.has_role('organizer')):
        abort(403)

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role_name = request.form.get('role', 'user')
        organization_id = request.form.get('organization_id')

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято', 'error')
            return redirect(url_for('create_user'))
        if User.query.filter_by(email=email).first():
            flash('Email уже используется', 'error')
            return redirect(url_for('create_user'))

        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password)

            role = Role.query.filter_by(name=role_name).first()
            if not role:
                flash('Выбранная роль не существует', 'error')
                return redirect(url_for('create_user'))
            new_user.roles.append(role)

            if current_user.has_role('admin'):
                if organization_id:
                    org = db.session.get(Organization, organization_id)
                    if org:
                        new_user.organizations.append(org)
            elif current_user.has_role('organizer'):
                # Избегаем проблемы с сессией: загружаем организации организатора через запрос
                organizer_orgs = Organization.query.join(organization_users).filter(
                    organization_users.c.user_id == current_user.id).all()
                if organizer_orgs:
                    new_user.organizations.append(organizer_orgs[0])
                else:
                    flash('Организатор не привязан к организации', 'error')
                    return redirect(url_for('create_user'))

            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь успешно создан', 'success')

            # Перенаправление в зависимости от роли
            if current_user.has_role('admin'):
                return redirect(url_for('user_management'))
            else:  # Для организатора
                return redirect(url_for('organizer_panel'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании пользователя: {str(e)}', 'error')
            return redirect(url_for('create_user'))

    roles = Role.query.all()
    organizations = Organization.query.all() if current_user.has_role('admin') else []
    return render_template('admin/create_user.html', roles=roles, organizations=organizations)


@app.route('/admin/users')
@login_required
@role_required('admin')
def user_management():
    users = User.query.all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=users, roles=roles)


@app.route('/admin/update_roles/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def update_roles(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('Пользователь не найден', 'error')
        return redirect(url_for('user_management'))

    selected_role = request.form.get('role')
    try:
        user.roles = []
        if selected_role:
            role = Role.query.filter_by(name=selected_role).first()
            if role:
                user.roles.append(role)
        db.session.commit()
        flash('Роль пользователя успешно обновлена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при обновлении роли: {str(e)}', 'error')
    return redirect(url_for('user_management'))


@app.route('/admin/organizations')
@login_required
@role_required('admin')
def organization_management():
    organizations = Organization.query.all()
    organizers = User.query.filter(User.roles.any(Role.name == 'organizer')).all()
    return render_template('admin/organizations.html', organizations=organizations, organizers=organizers)


@app.route('/admin/create_organization', methods=['POST'])
@login_required
@role_required('admin')
def create_organization():
    name = request.form.get('name')
    if not name:
        flash('Название организации обязательно', 'error')
        return redirect(url_for('organization_management'))
    if Organization.query.filter_by(name=name).first():
        flash('Организация с таким названием уже существует', 'error')
        return redirect(url_for('organization_management'))
    try:
        org = Organization(name=name)
        db.session.add(org)
        db.session.commit()
        flash('Организация успешно создана', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при создании организации: {str(e)}', 'error')
    return redirect(url_for('organization_management'))


@app.route('/admin/assign_organizer/<int:org_id>', methods=['POST'])
@login_required
@role_required('admin')
def assign_organizer(org_id):
    org = db.session.get(Organization, org_id)
    if not org:
        flash('Организация не найдена', 'error')
        return redirect(url_for('organization_management'))
    organizer_id = request.form.get('organizer_id')
    organizer = db.session.get(User, organizer_id)
    if not organizer:
        flash('Пользователь не найден', 'error')
        return redirect(url_for('organization_management'))
    try:
        if organizer not in org.members:
            org.members.append(organizer)
            db.session.commit()
            flash(f'Организатор {organizer.username} успешно назначен', 'success')
        else:
            flash('Этот пользователь уже назначен организатором', 'error')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при назначении организатора: {str(e)}', 'error')
    return redirect(url_for('organization_management'))


if __name__ == '__main__':
    app.run(debug=True)