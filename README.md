# OAuth 1.0a Provider for Python

I want to build a scalable OAuth 1.0a Provider that is easy to subclass specifically in authenticating users against
various databases.

Initiallly focused in leveraging performance by using Redis as the primary OAuth Provider backend,
user authentications can be handled differently using any other databases. Now SQLAlchemy support is added.

After much thoughts, I am developing more stores other than Redis. To keep things simple, there are 2 types of stores:
- SQL Based (SQLAlchemy)
- NoSQL Based (Currently only Redis)

There is an abstract Base class for stores called <code>Oauth1StoreBase</code>. Extend and implements the required
methods to create your own stores.

Coded against [RFC5849](http://tools.ietf.org/html/rfc5849) so please excuse any mishaps, everyone is welcomed to fork
and send pull requests.

## Compatibility Against [RFC5849](http://tools.ietf.org/html/rfc5849)

With this README, I have no plans in supporting 3 legged authentications. I am only supporting XAuth at the moment.
Fork and contribute to add support to 3 legged authentications.

OAuth 1.0a Authorization components are all expected from Authorization header. Example below.

```
Authorization: OAuth realm="http://localhost:5000/",
        oauth_consumer_key="dpf43f3p2l4k3l03",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131200",
        oauth_nonce="wIjqoS",
        oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"
```

## Usage

The main package depends on these Python modules:
- flask
- redis
- SQLAlchemy

The test.py file depends on these Python modules:
- oauthnesia

### Real Usage and Extending The Provider

#### Using SQLAlchemy as Store
```python
from flask import Flask, jsonify
from oauth1.authorize import Oauth1
from oauth1.errors.oauth import Oauth1Errors
from oauth1.store.sql import Oauth1StoreSQLAlchemy

BASE_URL = "http://localhost:5000/"
app = Flask(__name__)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:@127.0.0.1:3306/oauth"    # Change this to a valid URI
app.auth = None


class SQLProvider(Oauth1):

    def __init__(self):
        store = Oauth1StoreSQLAlchemy(app=app)
        super(SQLProvider, self).__init__(base_url=BASE_URL, store=store)

    def _verify_xauth_credentials(self, username, password):
        return username == 'username' and password == 'password'


@app.before_first_request
def after_run():
    global app
    app.auth = SQLProvider()
    app.auth.create_new_consumer_tokens(app_name='Test App %d' % Oauth1StoreSQLAlchemy.get_unix_time(),
                                        app_desc='Just Testing', app_platform='CLI', app_url=BASE_URL)

@app.teardown_appcontext
def tear_app(exception=None):
    if app.auth is not None:
        app.auth.store.session.remove()


@app.route('/oauth/', methods=['GET', 'POST'])
@app.route('/oauth/<action>/', methods=['POST'])
def oauth(action=None):
    if app.auth is None:
        return Oauth1Errors.server_error(msg='The auth object is not initialized properly')

    if action == 'access_token':
        cons_check = app.auth.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.bad_request(cons_check)

        authorized = app.auth.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        # Check username/password from XAuth
        x_check = app.auth.authorize_xauth()
        if isinstance(x_check, str):
            return Oauth1Errors.bad_request(x_check)

        return jsonify(status='ok')
    else:
        return Oauth1Errors.not_found('There is no valid resource here')


@app.route('/user/<user_uri>/', methods=['GET', 'POST'])
def user(user_uri=None):
    if not user_uri:
        return Oauth1Errors.bad_request('You must supply a User URI')
    else:
        cons_check = app.auth.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.forbidden(cons_check)

        authorized = app.auth.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        return jsonify(uri=user_uri)


@app.errorhandler(404)
def not_found(error):
    return Oauth1Errors.not_found()

if __name__ == "__main__":
    app.run()
```

#### Using Redis as Store

**Currently broken, need to change the whole logic**

```python
from flask import Flask, jsonify
from oauth1.authorize import Oauth1
from oauth1.errors.oauth import Oauth1Errors
from oauth1.store.nosql import Oauth1StoreRedis
from oauth1.store.base import Oauth1StoreBase

BASE_URL = "http://localhost:5000/"
app = Flask(__name__)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:@127.0.0.1:3306/oauth"    # Change this to a valid URI
app.auth = None


app.config['REDIS_HOST'] = '127.0.0.1'
app.config['REDIS_PORT'] = 6379
app.config['REDIS_DB'] = 0
app.config['REDIS_NS'] = 'oauth1-provider-nosql'


class RedisProvider(Oauth1):

    def __init__(self):
        store = Oauth1StoreRedis(host=app.config['REDIS_HOST'], port=app.config['REDIS_PORT'],
                                 db=app.config['REDIS_DB'], namespace=app.config['REDIS_NS'])
        super(RedisProvider, self).__init__(base_url=BASE_URL, store=store)

    def _verify_xauth_credentials(self, username, password):
        return username == 'username' and password == 'password'


@app.before_first_request
def after_run():
    global app
    app.auth = RedisProvider()
    app.auth.create_new_consumer_tokens(app_name='Test App %d' % Oauth1StoreBase.get_unix_time(),
                                        app_desc='Just Testing', app_platform='CLI', app_url=BASE_URL)


@app.route('/oauth/', methods=['GET', 'POST'])
@app.route('/oauth/<action>', methods=['POST'])
def oauth(action=None):
    if app.auth is None:
        return Oauth1Errors.server_error(msg='The auth object is not initialized properly')

    if action == 'access_token':
        cons_check = app.auth.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.bad_request(cons_check)

        authorized = app.auth.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        # Check username/password from XAuth
        x_check = app.auth.authorize_xauth()
        if isinstance(x_check, str):
            return Oauth1Errors.bad_request(x_check)

        return jsonify(status='ok')
    else:
        return Oauth1Errors.not_found('There is no valid resource here')


@app.route('/user/<user_uri>', methods=['GET', 'POST'])
def user(user_uri=None):
    if not user_uri:
        return Oauth1Errors.bad_request('You must supply a User URI')
    else:
        cons_check = app.auth.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.forbidden(cons_check)

        authorized = app.auth.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        return jsonify(uri=user_uri)


@app.errorhandler(404)
def not_found(error):
    return Oauth1Errors.not_found()

if __name__ == "__main__":
    app.run()
```

## Feedbacks

Please give feedbacks on best practices. Pull Requests are very welcomed.

## Contributors

- [Batista Harahap](https://github.com/tistaharahap)
- [Fauzan Erich Emmerling](https://github.com/femmerling)

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/tistaharahap/oauth1-provider/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

