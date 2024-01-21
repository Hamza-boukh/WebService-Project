from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    math = db.Column(db.Float, default=0.0)
    science = db.Column(db.Float, default=0.0)
    physics = db.Column(db.Float, default=0.0)
    french = db.Column(db.Float, default=0.0)
    english = db.Column(db.Float, default=0.0)
    arabic = db.Column(db.Float, default=0.0)
    philosophy = db.Column(db.Float, default=0.0)
    computer_science = db.Column(db.Float, default=0.0)
    hist_geo = db.Column(db.Float, default=0.0)
    economy = db.Column(db.Float, default=0.0)
    gestion = db.Column(db.Float, default=0.0)
    technology = db.Column(db.Float, default=0.0)
    sport = db.Column(db.Float, default=0.0)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def calculate_NEgrade(self, user_sector):
        sector_formulas = {
            'math': ((self.math*4 + self.physics*4 + self.computer_science + self.science + self.french + self.english + self.arabic + self.philosophy + self.sport)/15)*4 + self.math*2 + 1.5*self.physics + 0.5*self.science + self.french + self.english,
            'info': ((self.math*3 + self.physics*2 + self.computer_science*4 + self.french + self.english + self.arabic + self.philosophy + self.sport)/14)*4 +1.5*self.math + self.computer_science*2 + 0.5*self.physics + self.french + self.english ,
            'sc': ((self.math*3 + self.physics*4 + self.science*4 + self.philosophy*2 + self.french + self.english + self.arabic + self.sport + self.computer_science)/18)*4 + self.math*2 + 1.5*self.science + 1.5*self.physics + self.french + self.english ,
            'letter': ((self.french*2 + self.english + self.arabic + self.philosophy*3 +self.sport + self.hist_geo*3 + self.computer_science)/12)*4 +self.french + self.english +1.5*self.english + 1.5*self.philosophy + self.hist_geo,
            'eco': ((self.economy*3 + self.gestion*4 +self.hist_geo*3 + self.math*2 + self.french + self.english + self.arabic + self.philosophy + self.sport + self.computer_science)/18)*4 + 1.5*self.economy + 1.5*self.gestion + 0.5*self.hist_geo + 0.5*self.math + self.french + self.english ,
            'tech': ((self.technology*4 +self.math*3 + self.physics*3 + self.french + self.english + self.arabic + self.philosophy*2 + self.sport + self.computer_science)/17)*4 + self.math + self.physics + self.french + self.english + 1.5*self.technology ,
        }

        return sector_formulas.get(user_sector, 0.0)

    def __repr__(self):
        return f"Subject(id={self.id}, user_id={self.user_id}, math={self.math}, science={self.science}, physics={self.physics}, french={self.french}, english={self.english}, arabic={self.arabic}, philosophy={self.philosophy}, computer_science={self.computer_science}, hist_geo={self.hist_geo}, economy={self.economy}, gestion={self.gestion}, technology={self.technology})"