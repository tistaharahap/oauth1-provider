from flask import request, Response
from hashlib import sha1
import redis, uuid, json, operator, urllib2, hmac, binascii


class Oauth1(object):
    BASE_URL = None
    with_user_tokens = False

    def __init__(self, base_url):
        self.BASE_URL = base_url

    @classmethod
    def authorize_request(cls, uri):
        auth_headers = request.headers['Authorization'].replace('OAuth ', '').replace(', ', ',').split(',')
        auth_headers = {cls.url_decode(couple[0]): cls.url_decode(couple[1][1:][:-1])
                        for couple in [field.split('=') for field in auth_headers]}

        # Check Nonce
        if cls.is_nonce_used(auth_headers['oauth_nonce']):
            return 'OAuth Nonce has been declared'

        oauth_sig = auth_headers['oauth_signature']
        auth_headers.pop('oauth_signature')

        post = request.form
        get = request.args

        postget = {cls.url_encode(k): cls.url_encode(v) for (k, v) in post.iteritems()}
        if get:
            postget.update({cls.url_encode(k): cls.url_encode(v) for (k, v) in get.iteritems()})

        postget.update(auth_headers)
        postget = sorted(postget.iteritems(), key=operator.itemgetter(0))

        method = request.method.upper()
        base_signature = "%s&%s%s&" % (method, cls.url_encode(cls.BASE_URL), cls.url_encode(uri))
        for (k, v) in postget:
            base_signature = "%s%s%s%s%s" % (base_signature, cls.url_encode(k), cls.url_encode('='),
                                             cls.url_encode(v), cls.url_encode('&'))
        base_signature = base_signature[:-3]

        store = Oauth1StoreRedis()
        signature = cls.generate_signature(base_sig=base_signature,
                                           cons_sec=store.get_consumer_secret(auth_headers['oauth_consumer_key']))

        if signature != oauth_sig:
            return 'Invalid OAuth signature'

        return True

    @classmethod
    def is_nonce_used(cls, nonce):
        return not Oauth1StoreRedis().nonce_is_declared(nonce=nonce)

    @classmethod
    def generate_signature(cls, base_sig, cons_sec, user_sec=None):
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

    @classmethod
    def url_decode(cls, str):
        return urllib2.unquote(str)

    @classmethod
    def url_encode(cls, str):
        return urllib2.quote(str.encode('utf8')).replace('/', '%2F')

    @classmethod
    def authorize_xauth(cls):
        post = request.form

        if not 'x_auth_username' in post:
            return 'XAuth username is mandatory'

        if not 'x_auth_password' in post:
            return 'XAuth password is mandatory'

        if not 'x_auth_mode' in post:
            return 'Please specify explicitly XAuth method'

        if post['x_auth_mode'] != 'client_auth':
            return 'XAuth mode supported is client_auth only'

        return cls._verify_xauth_credentials(username=post['x_auth_username'], password=post['x_auth_password'])

    # Extend this method to provide XAuth
    @classmethod
    def _verify_xauth_credentials(cls, username, password):
        return True

    @classmethod
    def authorize_consumer(cls):
        store = Oauth1StoreRedis()

        auth_headers = request.headers['Authorization'].replace('OAuth ', '').replace(', ', ',').split(',')
        auth_headers = {couple[0]: couple[1][1:][:-1] for couple in [field.split('=') for field in auth_headers]}

        if 'realm' in auth_headers and auth_headers['realm'] != cls.BASE_URL:
            return 'The realm must match this server\'s Base URL'

        if not ('oauth_consumer_key' in auth_headers and
                    store.is_valid_consumer_key(auth_headers['oauth_consumer_key'])):
            return 'Missing or Invalid Consumer Key'

        if not ('oauth_signature_method' in auth_headers and auth_headers['oauth_signature_method'] == 'HMAC-SHA1'):
            return 'Supported OAuth Signature Method is only HMAC-SHA1, must be explicitly defined'

        if not 'oauth_signature' in auth_headers:
            return 'OAuth Signature is required'

        if not auth_headers['oauth_signature']:
            return 'OAuth Signature must not be empty'

        if not 'oauth_timestamp' in auth_headers:
            return 'OAuth Timestamp is required'

        if not 'oauth_nonce' in auth_headers:
            return 'OAuth Nonce is required'

        if store.nonce_is_declared(auth_headers['oauth_nonce']):
            return 'OAuth Nonce is already declared'

        if not ('oauth_version' in auth_headers and auth_headers['oauth_version'] == '1.0'):
            return 'Supported OAuth version is 1.0'

        if 'oauth_token' in auth_headers and auth_headers['oauth_token']:
            cls.with_user_tokens = True

        return True

class Oauth1StoreRedis(object):
    redis_host = 'localhost'
    redis_port = 6379
    redis_db = 0
    redis_ns = ""

    conn = None

    def __init__(self, namespace="oauth1-redis"):
        self.conn = redis.StrictRedis(host=self.redis_host, port=self.redis_port, db=self.redis_db)
        if not self.conn:
            raise Exception('Redis is not properly setup. Check redis configs?')

        self.redis_ns = namespace

    def nonce_is_declared(self, nonce):
        hash_name = "%s-nonces" % self.redis_ns
        res = self.conn.hget(hash_name, nonce)
        if res:
            return True
        else:
            self.conn.hset(hash_name, nonce, 1)
            return False

    def create_new_consumer_tokens(self, app_name, app_desc, app_platform, app_url):
        tokens = self._generate_new_consumer_tokens()
        hash_name = "%s-app_info" % self.redis_ns

        app = json.dumps({
            'id': uuid.uuid4().__str__().replace('-', ''),
            'name': app_name,
            'description': app_desc,
            'platform': app_platform,
            'app_url': app_url
        })
        self.conn.hset(hash_name, tokens['consumer_key'], app)

        hash_name = "%s-consumer_tokens" % self.redis_ns
        self.conn.hset(hash_name, tokens['consumer_key'], tokens['consumer_secret'])

    def _generate_new_consumer_tokens(self):
        return {
            'consumer_key': uuid.uuid4().__str__().replace('-', ''),
            'consumer_secret': uuid.uuid4().__str__().replace('-', '')
        }

    def is_valid_consumer_key(self, cons_key):
        hash_name = "%s-consumer_tokens" % self.redis_ns
        cons_sec = self.conn.hget(hash_name, cons_key)

        if isinstance(cons_sec, str):
            return True
        else:
            return False

    def get_consumer_secret(self, consumer_key):
        hash_name = "%s-consumer_tokens" % self.redis_ns
        cons_sec = self.conn.hget(hash_name, consumer_key)

        if isinstance(cons_sec, str):
            return cons_sec
        else:
            return None

class Oauth1Errors(object):
    BASE_URL = None

    def __init__(self):
        self.BASE_URL = Oauth1.BASE_URL

    @classmethod
    def create_response(cls, code, msg):
        data = {
            'code': code,
            'message': msg
        }
        headers = {
            'WWW-Authenticate': 'OAuth realm="%s"' % request.host_url,
            'Server': 'Python OAuth Provider'
        }
        return Response(response=json.dumps(data), mimetype='application/json', headers=headers, status=int(code))

    @classmethod
    def bad_request(cls, msg='Bad Request'):
        return Oauth1Errors.create_response(400, msg)

    @classmethod
    def unauthorized(cls, msg='Unauthorized to access this resource'):
        return Oauth1Errors.create_response(401, msg)

    @classmethod
    def forbidden(cls, msg='Forbidden to consume this resource'):
        return Oauth1Errors.create_response(403, msg)

    @classmethod
    def not_found(cls, msg='Cannot find the resource you are looking for'):
        return Oauth1Errors.create_response(404, msg)