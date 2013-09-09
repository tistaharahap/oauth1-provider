from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()
Tables = {
    'oauth_apps': 'oauth_apps',
    'oauth_nonces': 'oauth_nonces',
    'oauth_consumer_tokens': 'oauth_consumer_tokens',
    'oauth_user_tokens': 'oauth_user_tokens'
}


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