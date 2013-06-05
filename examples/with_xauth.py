from flask import Flask, jsonify
from oauth1 import Oauth1, Oauth1Errors

BASE_URL = "http://localhost:5000/"

app = Flask(__name__)

@app.route('/oauth/', methods=['GET', 'POST'])
@app.route('/oauth/<action>', methods=['POST'])
def oauth(action=None):
    if action == 'access_token':
        Oauth1.BASE_URL = BASE_URL

        cons_check = Oauth1.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.forbidden(cons_check)

        authorized = Oauth1.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        # Check username/password from XAuth
        x_check = Oauth1.authorize_xauth()
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
        Oauth1.BASE_URL = BASE_URL

        cons_check = Oauth1.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.forbidden(cons_check)

        authorized = Oauth1.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        return jsonify(uri=user_uri)

@app.errorhandler(404)
def not_found(error):
    return Oauth1Errors.not_found()

if __name__ == "__main__":
    app.debug = True
    app.run()