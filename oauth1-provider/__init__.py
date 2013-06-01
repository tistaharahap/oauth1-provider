from flask import Flask, jsonify
from oauth1 import Oauth1, Oauth1Errors

BASE_URL = "http://localhost:5000/"

app = Flask(__name__)
app.secret_key = 'secret*xxx*secret'

@app.route('/oauth/', methods=['GET', 'POST'])
@app.route('/oauth/<action>', methods=['POST'])
def oauth(action=None):
    if action is None:
        return Oauth1Errors.not_found('There is no valid resource here')
    elif action == 'access_token':
        Oauth1.BASE_URL = BASE_URL

        cons_check = Oauth1.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.forbidden(cons_check)

        # TODO: Verify OAuth signature
        authorized = Oauth1.authorize_request()
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        # Check username/password from XAuth
        x_check = Oauth1.authorize_xauth()
        if isinstance(x_check, str):
            return Oauth1Errors.bad_request(x_check)

        return jsonify(status='ok')

@app.errorhandler(404)
def not_found(error):
    return Oauth1Errors.not_found()

if __name__ == "__main__":
    app.debug = True
    app.run()