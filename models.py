from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # Прямое хранение роли и ID организации
    role_name = db.Column(db.String(80), nullable=False)  # Хранение роли как строки
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)

    # Связи с другими таблицами
    organization = db.relationship('Organization', backref=db.backref('members', lazy='dynamic'))
    certificate_requests = db.relationship('CertificateRequest', backref='user', lazy='dynamic')

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def has_role(self, role_name):
        return self.role_name == role_name  # Проверка напрямую по строке


class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)


class CertificateRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, approved, rejected
    certificate_type = db.Column(db.String(20), nullable=False)  # client, server
