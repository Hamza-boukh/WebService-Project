from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), default='')  # Default value is an empty string
    sector = db.Column(db.String(50), default='')  # Default value is an empty string
    NEgrade = db.Column(db.Float, default=0.0)  # Default value is 0.0
    is_admin = db.Column(db.Boolean, default=False)

    subjects = db.relationship('Subject', backref='user', lazy=True)

    def __repr__(self):
        return f"User(id={self.id}, username={self.username}, email={self.email}, sector={self.sector}, NEgrade={self.NEgrade}, is_admin={self.is_admin})"