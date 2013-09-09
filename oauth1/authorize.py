from oauth1.errors.auth import AuthorizeErrors
from oauth1.store.base import Oauth1StoreBase
from flask import request
from hashlib import sha1
import operator
import urllib2
import hmac
import binascii


class Oauth1(object):
    BASE_URL = None
    with_user_tokens = False
    auth_method = None
    store = None

    def __init__(self, base_url, store):
        self.BASE_URL = base_url

        if not isinstance(store, Oauth1StoreBase):
            raise TypeError('The OAuth Store must be a subclass of Oauth1StoreBase')
        self.store = store

    def create_new_consumer_tokens(self, app_name, app_desc, app_platform, app_url):
        return self.store.create_new_consumer_tokens(app_name, app_desc, app_platform, app_url)

    def authorize_request(self, uri):
        auth_headers = request.headers['Authorization'].replace('OAuth ', '').replace(', ', ',').split(',')
        auth_headers = {self.url_decode(couple[0]): self.url_decode(couple[1][1:][:-1])
                        for couple in [field.split('=') for field in auth_headers]}

        # Check Nonce
        if self.is_nonce_used(auth_headers['oauth_nonce']):
            return 'OAuth Nonce has been declared'

        oauth_sig = auth_headers['oauth_signature']
        auth_headers.pop('oauth_signature')

        post = request.form
        get = request.args

        postget = {self.url_encode(k): self.url_encode(v) for (k, v) in post.iteritems()}
        if get:
            postget.update({self.url_encode(k): self.url_encode(v) for (k, v) in get.iteritems()})

        postget.update(auth_headers)
        postget = sorted(postget.iteritems(), key=operator.itemgetter(0))

        method = request.method.upper()
        base_signature = "%s&%s%s&" % (method, self.url_encode(self.BASE_URL), self.url_encode(uri))
        for (k, v) in postget:
            base_signature = "%s%s%s%s%s" % (base_signature, self.url_encode(k), self.url_encode('='),
                                             self.url_encode(v), self.url_encode('&'))
        base_signature = base_signature[:-3]

        signature = self.generate_signature(base_sig=base_signature,
                                            cons_sec=self.store.get_consumer_secret(auth_headers['oauth_consumer_key']))

        if signature != oauth_sig:
            return 'Invalid OAuth signature | %s' % base_signature

        return True

    def is_nonce_used(self, nonce):
        return not self.store.nonce_is_declared(nonce=nonce)

    def generate_signature(self, base_sig, cons_sec, user_sec=None):
        if user_sec:
            key = "%s&%s" % (cons_sec, user_sec)
        else:
            key = "%s&" % cons_sec

        hashed = hmac.new(key, base_sig, sha1)
        arr = binascii.b2a_base64(hashed.digest())
        ret = ""
        for s in arr:
            ret += s
        return ret.replace("\n", "")

    def url_decode(self, str):
        return urllib2.unquote(str)

    def url_encode(self, str):
        return urllib2.quote(str.encode('utf8')).replace('/', '%2F')

    def authorize_xauth(self):
        post = request.form

        if not 'x_auth_username' in post:
            return 'XAuth username is mandatory'

        if not 'x_auth_password' in post:
            return 'XAuth password is mandatory'

        if not 'x_auth_mode' in post:
            return 'Please specify explicitly XAuth method'

        if post['x_auth_mode'] != 'client_auth':
            return 'XAuth mode supported is client_auth only'

        return self._verify_xauth_credentials(username=post['x_auth_username'], password=post['x_auth_password'])

    # Extend this method to provide XAuth
    def _verify_xauth_credentials(self, username, password):
        return True

    def authorize_consumer(self):
        if 'Authorization' in request.headers and request.headers['Authorization'][0:5].lower() == 'oauth':
            self.auth_method = 'header'
            auth = request.headers['Authorization'].replace('OAuth ', '').replace(', ', ',').split(',')
            auth = {couple[0]: couple[1][1:][:-1] for couple in [field.split('=') for field in auth]}
        elif request.form and 'oauth_consumer_key' in request.form:
            auth = request.form
            self.auth_method = 'post'
        else:
            return AuthorizeErrors.missing_auth_data()

        if self.auth_method == 'header':
            if 'realm' in auth and auth['realm'] != self.BASE_URL:
                return AuthorizeErrors.invalid_realm()

            if not 'oauth_signature' in auth:
                return 'OAuth Signature is required'

            if not auth['oauth_signature']:
                return 'OAuth Signature must not be empty'
        elif self.auth_method == 'post':
            if not 'oauth_signature' in request.args:
                return AuthorizeErrors.missing_oauth_signature()

            if not request.args['oauth_signature']:
                return AuthorizeErrors.empty_oauth_signature()

        if not 'oauth_consumer_key' in auth:
            return AuthorizeErrors.missing_consumer_key()

        if not self.store.is_valid_consumer_key(auth['oauth_consumer_key']):
            return AuthorizeErrors.invalid_consumer_key()

        if not ('oauth_signature_method' in auth and auth['oauth_signature_method'] == 'HMAC-SHA1'):
            return AuthorizeErrors.unsupported_sign_method()

        if not 'oauth_timestamp' in auth:
            return AuthorizeErrors.missing_timestamp()

        if not 'oauth_nonce' in auth:
            return AuthorizeErrors.missing_nonce()

        if self.store.nonce_is_declared(auth['oauth_nonce']):
            return AuthorizeErrors.declared_nonce()

        if not 'oauth_version' in auth:
            return AuthorizeErrors.missing_oauth_version()

        if not (auth['oauth_version'] == '1.0'):
            return AuthorizeErrors.invalid_oauth_version()

        if 'oauth_token' in auth and auth['oauth_token']:
            self.with_user_tokens = True

        return True