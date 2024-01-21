from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class University(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    location = db.Column(db.String(100))
    status = db.Column(db.String(20))  # 'Private' or 'Public'
    tuition_fee = db.Column(db.Float)
    specialty = db.Column(db.String(100))
    degree = db.Column(db.String(20))  # 'Bachelor', 'Master', 'Doctorate',"license"
    student_capacity = db.Column(db.Integer)
    last_year_score = db.Column(db.Float)
    
    state_id = db.Column(db.Integer, db.ForeignKey('state.id'), nullable=False)

    def __repr__(self):
        return f"University(id={self.id}, name={self.name}, state_id={self.state_id})"