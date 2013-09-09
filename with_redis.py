from flask import Flask, jsonify
from oauth1.authorize import Oauth1
from oauth1.errors.oauth import Oauth1Errors
from oauth1.store.nosql import Oauth1StoreRedis
from oauth1.store.base import Oauth1StoreBase

BASE_URL = "http://localhost:5000/"
app = Flask(__name__)
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
    app.debug = True
    app.run()