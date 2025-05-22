from app import app, db, Role

with app.app_context():
    db.create_all()
    if not Role.query.first():
        roles = [
            Role(name='admin', description='Администратор'),
            Role(name='organizer', description='Организатор событий'),
            Role(name='user', description='Обычный пользователь')
        ]
        db.session.add_all(roles)
        db.session.commit()
        print("База данных инициализирована с ролями по умолчанию")
    else:
        print("База данных уже инициализирована")