from oauth1.store.base import Oauth1StoreBase
from sqlmodels import *
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import time


class Oauth1StoreSQLAlchemy(Oauth1StoreBase):
    db = None

    def __init__(self, app):
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if not db_uri:
            raise ValueError('SQLALCHEMY_DATABASE_URI is required')

        self.db = create_engine(db_uri, convert_unicode=True)

        if app.debug:
            self.db.echo = True

        self.get_session()

    def get_session(self):
        self.session = scoped_session(sessionmaker(autocommit=False,
                                                   autoflush=False,
                                                   bind=self.db))

        Base.query = self.session.query_property()
        Base.metadata.create_all(bind=self.db)

    def register_nonce(self, nonce, app_id):
        n = NonceModel(key=nonce, created=int(time.time()), app_id=app_id)
        self.session.add(n)
        self.session.commit()

    def nonce_is_declared(self, nonce):
        q = self.session.query(NonceModel).filter_by(nonce_key=nonce).first()
        return q is not None

    def get_app_id_from_cons_key(self, cons_key):
        q = self.session.query(ConsumerTokensModel).filter_by(cons_key=cons_key).first()
        return None if q is None else q.app_id

    def create_new_consumer_app(self, app_name, app_desc, app_platform, app_url):
        consumer = OauthAppModel(name=app_name, desc=app_desc, platform=app_platform,
                                 url=app_url, created=Oauth1StoreSQLAlchemy.get_unix_time())
        self.session.add(consumer)
        self.session.commit()

        return {
            'app_id': consumer.app_id
        }

    def create_new_consumer_tokens(self, app_id):
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