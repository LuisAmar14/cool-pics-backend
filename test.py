from app import app, db, Users
from werkzeug.security import generate_password_hash

with app.app_context():
    try:
        new_user = Users(

            first_name="Test",
            last_name="User",
            username="testuser",
            email="test@example.com",
            password=generate_password_hash("test123")
        )
        db.session.add(new_user)
        db.session.commit()
        print("Usuario de prueba registrado")
    except Exception as e:
        print(f"Error: {str(e)}")
        db.session.rollback()