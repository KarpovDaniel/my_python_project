from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

organization_users = db.Table('organization_users',
    db.Column('organization_id', db.Integer, db.ForeignKey('organization.id')),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'))
)

class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(200))

    def __repr__(self):
        return f'<Роль {self.name}>'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    organizations = db.relationship('Organization', secondary=organization_users,
                                   backref=db.backref('members', lazy='dynamic'))

    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Пользователь {self.username}>'

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    def __repr__(self):
        return f'<Организация {self.name}>'