from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class State(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    university_number = db.Column(db.Integer, default=0)
    universities = db.relationship('University', backref='state', lazy=True)

    def __repr__(self):
        return f"State(id={self.id}, name={self.name})"