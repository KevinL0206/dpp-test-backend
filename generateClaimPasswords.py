from app import db, Tags, app  # Import your Flask app
import secrets
import string

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def update_tags_with_random_passwords():
    with app.app_context():  # Add this line to use the application context
        with db.session.begin():
            tags = Tags.query.all()
            for tag in tags:
                tag.claim_password = generate_random_password()
                print(f"Updated tag {tag.id} with password {tag.claim_password}")
            db.session.commit()

if __name__ == "__main__":
    update_tags_with_random_passwords()
