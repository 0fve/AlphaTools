from sqlalchemy.orm import defaultload
from sqlalchemy.sql.expression import null
from . import db
from flask import Blueprint, render_template, request, redirect, url_for, abort, flash, session
from flask_login import UserMixin
from sqlalchemy.sql import func
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user



class tools(db.Model):
    toolId = db.Column(db.Integer,  primary_key=True)
    toolName = db.Column(db.String(255), unique=True)
    toolDescription = db.Column(db.Text(255))
    toolLink = db.Column(db.String(255))
    Author = db.Column(db.String(255))
    sold = db.Column(db.Integer, nullable=False)
    toolPrice = db.Column(db.Integer, nullable=False)
    toolStatus = db.Column(db.Boolean, default=True)


class SoldTools(db.Model):

    id = db.Column(db.Integer,  primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    toolName = db.Column(db.String(255), unique=False)
    buyingDate = db.Column(db.String(128), default=func.now())
    price = db.Column(db.Integer, nullable=False)

class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(255))
    lastName = db.Column(db.String(255))
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    verified = db.Column(db.Boolean, default=False)
    bought = db.Column(db.Boolean, default=False)
    spentMoney = db.Column(db.Integer, nullable=True)
    admin = db.Column(db.Boolean, default=False)

class MyModelView(ModelView):
    def is_accessible(self):

        if current_user.is_authenticated:
            user = User.query.filter_by(email=current_user.email).first()
            
            if user.admin:
                return current_user.is_authenticated
                
            else:
                return current_user.is_authenticated

        else:
            return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('auth.login'))