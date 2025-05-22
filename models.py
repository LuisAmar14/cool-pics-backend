from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    palettes = db.relationship("Palette", backref="user", lazy=True)
    colors = db.relationship("Color", backref="user", lazy=True)

class Palette(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    colors = db.relationship("PaletteColor", backref="palette", lazy=True)

class PaletteColor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    palette_id = db.Column(db.Integer, db.ForeignKey("palette.id"), nullable=False)
    rgb = db.Column(db.String(20), nullable=False)
    hex = db.Column(db.String(7), nullable=False)
    hsl = db.Column(db.String(20), nullable=False)
    position = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(50))

class Color(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    rgb = db.Column(db.String(20), nullable=False)
    hex = db.Column(db.String(7), nullable=False)
    hsl = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)