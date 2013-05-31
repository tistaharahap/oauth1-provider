from flask import Flask, jsonify
from oauth1 import Oauth1, Oauth1Errors

BASE_URL = "http://localhost:5000/"

app = Flask(__name__)
app.secret_key = 'secret*xxx*secret'


@app.route('/oauth/', methods=['GET', 'POST'])
@app.route('/oauth/<action>/', methods=['POST'])
def oauth(action=None):
    if action is None:
        return jsonify(code=400, message="No Action URI is mentioned."), 400
    elif action == 'access_token':
        Oauth1.BASE_URL = BASE_URL

        cons_check = Oauth1.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.unauthorized(cons_check)



        return jsonify(status='ok')

if __name__ == "__main__":
    app.debug = True
    app.run()