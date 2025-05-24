import logging
from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from models import db, User, Organization, CertificateRequest
from koji import KojiCertGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ваш-секретный-ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://daniel:daniel@localhost/flask_auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Инициализация SQLAlchemy и Migrate
db.init_app(app)
migrate = Migrate(app, db)

# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Инициализация KojiCertGenerator
koji_gen = KojiCertGenerator("./kojicert")
# Генерируем CA сертификат, если он ещё не создан
if not (os.path.exists(koji_gen.ca_key_path) and os.path.exists(koji_gen.ca_cert_path)):
    koji_gen.generate_ca_cert()


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
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Вход выполнен успешно', 'success')
            return redirect(url_for('dashboard'))
        flash('Неверное имя пользователя или пароль', 'error')
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
            new_user.role_name = 'user'  # Прямое назначение роли
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
    certificate_requests = CertificateRequest.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', certificate_requests=certificate_requests)


@app.route('/organizer')
@login_required
@role_required('organizer')
def organizer_panel():
    # Проверяем, привязан ли организатор к организации
    if not current_user.organization:
        flash('Вы не привязаны к организации.', 'error')
        return redirect(url_for('organizer_panel'))  # или редирект на другую страницу

    organization = current_user.organization  # Прямой доступ к организации

    # Получаем всех членов организации
    members = organization.members.all()  # Используем lazy='dynamic' из модели

    # Собираем ID членов организации
    member_ids = [member.id for member in members]

    # Получаем запросы на сертификаты от членов организации
    certificate_requests = CertificateRequest.query.filter(
        CertificateRequest.user_id.in_(member_ids)
    ).all()

    return render_template(
        'organizer.html',
        certificate_requests=certificate_requests,
        organization=organization
    )


@app.route('/admin')
@login_required
@role_required('admin')
def admin_panel():
    return render_template('admin.html')


@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not (current_user.has_role('admin') or current_user.has_role('organizer')):
        logger.warning(f"Пользователь {current_user.username} попытался получить доступ к /admin/create_user без прав")
        abort(403)

    organizer_orgs = None
    if current_user.has_role('organizer'):
        organizer_orgs = Organization.query.join(User).filter(User.organization_id == Organization.id).filter(User.id == current_user.id).all()
        if not organizer_orgs:
            flash('Организатор не привязан к организации. Обратитесь к администратору.', 'error')
            return redirect(url_for('organizer'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role_name = request.form.get('role', 'user')
        organization_id = request.form.get('organization_id')

        if not username or not email or not password:
            flash('Все поля (имя пользователя, email, пароль) обязательны.', 'error')
            return redirect(url_for('create_user'))

        if User.query.filter_by(username=username).first():
            flash('Имя пользователя уже занято', 'error')
            return redirect(url_for('create_user'))
        if User.query.filter_by(email=email).first():
            flash('Email уже используется', 'error')
            return redirect(url_for('create_user'))

        try:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            new_user.role_name = role_name

            if current_user.has_role('admin'):
                if organization_id:
                    org = db.session.get(Organization, organization_id)
                    if org:
                        new_user.organization_id = org.id  # Прямое назначение организации
                    else:
                        flash('Выбранная организация не найдена', 'error')
                        return redirect(url_for('create_user'))
            elif current_user.has_role('organizer'):
                new_user.organization_id = organizer_orgs[0].id  # Прямое назначение организации

            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь успешно создан', 'success')
            return redirect(url_for('user_management') if current_user.has_role('admin') else redirect(url_for('organizer')))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Ошибка при создании пользователя: {str(e)}")
            flash(f'Ошибка при создании пользователя: {str(e)}', 'error')
            return redirect(url_for('create_user'))

    roles = ['admin', 'organizer', 'user']
    organizations = Organization.query.all() if current_user.has_role('admin') else []
    return render_template('admin/create_user.html', roles=roles, organizations=organizations)


@app.route('/admin/users')
@login_required
@role_required('admin')
def user_management():
    users = User.query.all()
    roles = ['admin', 'organizer', 'user']
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
        user.role_name = selected_role  # Прямое обновление роли
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
    organizers = User.query.filter(User.role_name == 'organizer').all()
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
        if organizer.organization_id != org.id:
            organizer.organization_id = org.id  # Прямое назначение организации
            db.session.commit()
            flash(f'Организатор {organizer.username} успешно назначен', 'success')
        else:
            flash('Этот пользователь уже назначен организатором', 'error')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при назначении организатора: {str(e)}', 'error')
    return redirect(url_for('organization_management'))


@app.route('/organization_members')
@login_required
@role_required('organizer')
def organization_members():
    if not current_user.organization:
        flash('Вы не привязаны к организации.', 'error')
        return redirect(url_for('organizer'))
    members = current_user.organization.members
    return render_template('organization_members.html', members=members, organization=current_user.organization)


@app.route('/admin/certificate_requests')
@login_required
@role_required('admin')
def certificate_requests():
    requests = CertificateRequest.query.filter_by(status='pending').all()
    return render_template('admin/requests.html', requests=requests)


@app.route('/admin/approve_request/<int:request_id>', methods=['POST'])
@app.route('/organizer/approve_request/<int:request_id>', methods=['POST'])  # Добавлен маршрут для организатора
@login_required
def approve_request(request_id):
    cert_request = CertificateRequest.query.get_or_404(request_id)

    # Проверяем права: админ или организатор из той же организации
    if not (current_user.has_role('admin') or
            (current_user.has_role('organizer') and current_user.organization_id == cert_request.user.organization_id)):
        abort(403)

    if cert_request.status != 'pending':
        flash('Этот запрос уже обработан.', 'error')
        return redirect(url_for('certificate_requests' if current_user.has_role('admin') else 'organizer_panel'))

    try:
        cn = cert_request.user.username
        if cert_request.certificate_type == 'client':
            permissions = koji_gen.get_permissions(cn)
            koji_gen.generate_client_cert(cn, permissions)
        elif cert_request.certificate_type == 'server':
            koji_gen.generate_server_cert(cn)

        cert_request.status = 'approved'
        db.session.commit()
        flash(f'Запрос на {cert_request.certificate_type} сертификат для {cn} одобрен.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Ошибка при одобрении запроса: {str(e)}")
        flash(f'Ошибка при генерации сертификата: {str(e)}', 'error')

    return redirect(url_for('certificate_requests' if current_user.has_role('admin') else 'organizer_panel'))


@app.route('/admin/reject_request/<int:request_id>', methods=['POST'])
@app.route('/organizer/reject_request/<int:request_id>', methods=['POST'])  # Добавлен маршрут для организатора
@login_required
def reject_request(request_id):
    cert_request = CertificateRequest.query.get_or_404(request_id)

    # Проверяем права: админ или организатор из той же организации
    if not (current_user.has_role('admin') or
            (current_user.has_role('organizer') and current_user.organization_id == cert_request.user.organization_id)):
        abort(403)

    if cert_request.status != 'pending':
        flash('Этот запрос уже обработан.', 'error')
        return redirect(url_for('certificate_requests' if current_user.has_role('admin') else 'organizer_panel'))

    try:
        cert_request.status = 'rejected'
        db.session.commit()
        flash(f'Запрос на {cert_request.certificate_type} сертификат отклонён.', 'success')

    except Exception as e:
        db.session.rollback()
        logger.error(f"Ошибка при отклонении запроса: {str(e)}")
        flash(f'Ошибка при отклонении запроса: {str(e)}', 'error')

    return redirect(url_for('certificate_requests' if current_user.has_role('admin') else 'organizer_panel'))


@app.route('/request_certificate', methods=['POST'])
@login_required
def request_certificate():
    if not (current_user.has_role('user') or current_user.has_role('organizer')):
        logger.warning(f"Пользователь {current_user.username} попытался запросить сертификат без прав")
        abort(403)
    certificate_type = request.form.get('certificate_type', 'client')
    permissions = request.form.getlist('permissions')
    cn = current_user.username
    if current_user.has_role('user') and certificate_type != 'client':
        flash('Обычные пользователи могут запрашивать только клиентские сертификаты.', 'error')
        return redirect(url_for('dashboard'))
    elif current_user.has_role('organizer') and certificate_type not in ['client', 'server']:
        flash('Организаторы могут запрашивать только клиентские или серверные сертификаты.', 'error')
        return redirect(url_for('organizer'))
    try:
        existing_request = CertificateRequest.query.filter_by(
            user_id=current_user.id, certificate_type=certificate_type, status='pending'
        ).first()
        if existing_request:
            flash(f'У вас уже есть активный запрос на {certificate_type} сертификат.', 'error')
            return redirect(url_for('dashboard' if current_user.has_role('user') else 'organizer'))
        cert_request = CertificateRequest(
            user_id=current_user.id,
            request_date=datetime.utcnow(),
            status='pending',
            certificate_type=certificate_type
        )
        db.session.add(cert_request)
        db.session.commit()
        if certificate_type == 'client' and permissions:
            koji_gen.assign_permissions(cn, permissions)
        flash(f'Запрос на {certificate_type} сертификат отправлен на рассмотрение.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Ошибка при создании запроса на сертификат: {str(e)}")
        flash(f'Ошибка при отправке запроса: {str(e)}', 'error')
    return redirect(url_for('dashboard' if current_user.has_role('user') else 'organizer'))


if __name__ == '__main__':
    app.run(debug=True)