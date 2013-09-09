from oauth1.store.base import Oauth1StoreBase
from sqlalchemy import create_engine, Column, Integer, String, select
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import time
import string
import random


Base = declarative_base()
Tables = {
    'oauth_apps': 'oauth_apps',
    'oauth_nonces': 'oauth_nonces',
    'oauth_consumer_tokens': 'oauth_consumer_tokens',
    'oauth_user_tokens': 'oauth_user_tokens'
}


class Oauth1StoreSQLAlchemy(Oauth1StoreBase):
    db = None

    def __init__(self, app):
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if not db_uri:
            raise ValueError('SQLALCHEMY_DATABASE_URI is required')

        self.db = create_engine(db_uri, convert_unicode=True)
        self.db.echo = True

        self.get_session()

    def get_session(self):
        self.session = scoped_session(sessionmaker(autocommit=False,
                                                   autoflush=False,
                                                   bind=self.db))

        Base.query = self.session.query_property()
        Base.metadata.create_all(bind=self.db)

    def nonce_is_declared(self, nonce):
        q = NonceModel.query.filter(NonceModel.nonce_key == nonce).first()
        return q is not None

    def create_new_consumer_tokens(self, app_name, app_desc, app_platform, app_url):
        consumer = OauthAppModel(name=app_name, desc=app_desc, platform=app_platform,
                                 url=app_url, created=Oauth1StoreSQLAlchemy.get_unix_time())
        self.session.add(consumer)
        self.session.flush()

        app_id = consumer.app_id

        tokens = self._generate_new_consumer_tokens()

        # Add consumer tokens
        cons_tokens = ConsumerTokensModel(id=app_id, key=tokens['consumer_key'], sec=tokens['consumer_secret'],
                                          created=Oauth1StoreSQLAlchemy.get_unix_time())
        self.session.add(cons_tokens)

        self.session.commit()

        return {
            'app_id': app_id,
            'consumer_key': tokens['consumer_key'],
            'consumer_secret': tokens['consumer_secret']
        }

    def _generate_new_consumer_tokens(self):
        return {
            'consumer_key': Oauth1StoreSQLAlchemy.random_string(size=40),
            'consumer_secret': Oauth1StoreSQLAlchemy.random_string(size=40)
        }

    def is_valid_consumer_key(self, cons_key):
        q = self.session.query(ConsumerTokensModel).filter_by(cons_key=cons_key).first()
        return q is not None and q.cons_key == cons_key

    def get_consumer_secret(self, consumer_key):
        q = self.session.query(ConsumerTokensModel).filter_by(cons_key=consumer_key).first()
        return q.cons_sec if q is not None else None

    @classmethod
    def get_unix_time(cls):
        return int(time.time())

    @classmethod
    def random_string(cls, size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
        return ''.join(random.choice(chars) for x in range(size))


class NonceModel(Base):
    __tablename__ = Tables['oauth_nonces']

    nonce_key = Column(String(50), primary_key=True)
    nonce_app_id = Column(Integer)
    created = Column(Integer)

    def __init__(self, key, app_id, created):
        self.nonce_key, self.nonce_app_id, created = key, int(app_id), int(created)

    def __repr__(self):
        return self.nonce_key


class OauthAppModel(Base):
    __tablename__ = Tables['oauth_apps']

    app_id = Column(Integer, primary_key=True, autoincrement=True)
    app_name = Column(String(50), unique=True)
    app_desc = Column(String(255))
    app_platform = Column(String(50))
    app_url = Column(String(255))
    created = Column(Integer)

    def __init__(self, name, desc, platform, url, created):
        self.app_name = name
        self.app_desc = desc
        self.app_platform = platform
        self.app_url = url
        self.created = created

    def __repr__(self):
        return self.app_name


class ConsumerTokensModel(Base):
    __tablename__ = Tables['oauth_consumer_tokens']

    app_id = Column(Integer, primary_key=True)
    cons_key = Column(String(50), unique=True)
    cons_sec = Column(String(50), unique=True)
    created = Column(Integer)

    def __init__(self, id, key, sec, created):
        self.app_id = id
        self.cons_key = key
        self.cons_sec = sec
        self.created = created

    def __repr__(self):
        return self.app_id


class UserTokensModel(Base):
    __tablename__ = Tables['oauth_user_tokens']

    app_id = Column(Integer)
    user_id = Column(String(20))
    user_key = Column(String(50), primary_key=True)
    user_sec = Column(String(50), unique=True)
    created = Column(Integer)

    def __init__(self, app_id, user_id, key, sec, created):
        self.app_id = app_id
        self.user_id = user_id,
        self.key = key
        self.sec = sec
        self.created = created

    def __repr__(self):
        return self.user_id