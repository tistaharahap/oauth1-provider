# OAuth 1.0a Provider for Python

I want to build a scalable OAuth 1.0a Provider that is easy to subclass specifically in authenticating users against
various databases. Focuses in leveraging performance by using Redis as the primary OAuth Provider backend, user
authentications can be handled differently using any other databases.

After much thoughts, I am developing more stores other than Redis. To keep things simple, there are 2 types of stores:
- SQL Based (SQLAlchemy)
- NoSQL Based (Currently only Redis)

There is an abstract Base class for stores called <code>Oauth1StoreBase</code>. Extend and implements the required
methods to create your own stores.

Coded against [RFC5849](http://tools.ietf.org/html/rfc5849) so please excuse any mishaps, everyone is welcomed to fork
and send pull requests.

# As of this README, I am restructuring the whole package. Earlier codes will break. Revert to 0.3.0 for safety.

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

```python
from flask import Flask, jsonify
from oauth1.authorize import Oauth1
from oauth1.errors.oauth import Oauth1Errors
from oauth1.store.sql import Oauth1StoreSQLAlchemy

BASE_URL = "http://localhost:5000/"

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///:memory:"    # Change this to a valid URI


class ExampleProvider(Oauth1):

    def __init__(self):
        store = Oauth1StoreSQLAlchemy(app=app)
        super(ExampleProvider, self).__init__(base_url=BASE_URL, store=store)

    def _verify_xauth_credentials(self, username, password):
        return username == 'username' and password == 'password'

oauth = ExampleProvider()

@app.route('/oauth/', methods=['GET', 'POST'])
@app.route('/oauth/<action>', methods=['POST'])
def oauth(action=None):
    if action == 'access_token':
        cons_check = oauth.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.forbidden(cons_check)

        authorized = oauth.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        # Check username/password from XAuth
        x_check = oauth.authorize_xauth()
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
        cons_check = oauth.authorize_consumer()
        if isinstance(cons_check, str):
            return Oauth1Errors.forbidden(cons_check)

        authorized = oauth.authorize_request(uri='oauth/access_token')
        if isinstance(authorized, str):
            return Oauth1Errors.unauthorized(authorized)

        return jsonify(uri=user_uri)

@app.errorhandler(404)
def not_found(error):
    return Oauth1Errors.not_found()

if __name__ == "__main__":
    app.debug = True
    app.run()
```

## Feedbacks

Again I am still new to Python, please give some feedbacks on best practices. Pull Requests are very welcomed.