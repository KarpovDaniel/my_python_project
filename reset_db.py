import psycopg2
from psycopg2 import Error

# Параметры подключения к PostgreSQL
DB_HOST = "localhost"
DB_USER = "zooob"
DB_PASSWORD = "1q2w3eRT"
DB_NAME = "flask_auth"

def reset_database():
    try:
        # Подключение к базе данных по умолчанию (postgres)
        conn = psycopg2.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database="postgres"  # Используем базу данных postgres для управления
        )
        conn.autocommit = True
        cursor = conn.cursor()

        # Проверка существования базы данных и её удаление
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname='{DB_NAME}'")
        exists = cursor.fetchone()
        if exists:
            cursor.execute(f"DROP DATABASE {DB_NAME}")
            print(f"База данных {DB_NAME} успешно удалена.")

        # Создание новой базы данных
        cursor.execute(f"CREATE DATABASE {DB_NAME}")
        print(f"База данных {DB_NAME} успешно создана.")

        # Закрытие соединения
        cursor.close()
        conn.close()

    except Error as e:
        print(f"Ошибка при работе с PostgreSQL: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    reset_database()
    print("Процесс завершен. Теперь вы можете пересоздать миграции.")