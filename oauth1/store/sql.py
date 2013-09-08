from flask.ext.sqlalchemy import SQLAlchemy
from flask import current_app as app
import json
import uuid


class Oauth1StoreSQLAlchemy(object):

    def __init__(self):
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        print db_uri