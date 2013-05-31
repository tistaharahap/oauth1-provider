from flask import request, jsonify
import redis, uuid, json


class Oauth1(object):
    BASE_URL = None

    def __init__(self, base_url):
        self.BASE_URL = base_url

    @classmethod
    def authorize_consumer(cls):
        post = request.form
        store = Oauth1StoreRedis()

        if not ('realm' in post and post['realm'] == cls.BASE_URL):
            return 'The realm must match this server\'s Base URL'

        if not ('oauth_consumer_key' in post and store.is_valid_consumer_key(post['oauth_consumer_key'])):
            return 'Missing or Invalid Consumer Key'

        if not ('oauth_signature_method' in post and post['oauth_signature_method'] == 'HMAC-SHA1'):
            return 'Supported OAuth Signature Method is only HMAC-SHA1, must be explicitly defined'

        if not 'oauth_signature' in post:
            return 'OAuth Signature is required'

        if not 'oauth_timestamp' in post:
            return 'OAuth Timestamp is required'

        if not 'oauth_nonce' in post:
            return 'OAuth Nonce is required'

        if store.nonce_is_declared(post['oauth_nonce']):
            return 'OAuth Nonce is already declared'

        if not ('oauth_version' in post and post['oauth_version'] == '1.0'):
            return 'Supported OAuth version is 1.0'

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
            return False

    def create_new_consumer_tokens(self, app_name, app_desc, app_platform, app_url):
        tokens = self._generate_new_consumer_tokens()
        hash_name = "%s-app_info" % self.redis_ns

        app = json.dumps({
            'id': str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                 'hlwBpeX4gIOzl8MCNeF3rFpD1752UfXL6lpy7ZZP5HA3wedBCAvmf559dhaENtO')).replace('-', ''),
            'name': app_name,
            'description': app_desc,
            'platform': app_platform,
            'app_url': app_url
        })
        self.conn.hset(hash_name, tokens['consumer_key'], app)

        hash_name = "%s-consumer_tokens" % self.redis_ns
        self.conn.hset(hash_name, tokens['consumer_key'], tokens['consumer_secret'])

    def _generate_new_consumer_tokens(self):
        seed = 'ny7WpbKCCDBmZW2RnZMWMW4FvD8e6unAepvd9oGkK1cyhGYyye1bBbVZQhjX0or'
        return {
            'consumer_key': str(uuid.uuid5(uuid.NAMESPACE_DNS, seed)).replace('-', ''),
            'consumer_secret': str(uuid.uuid5(uuid.NAMESPACE_DNS, seed)).replace('-', '')
        }

    def is_valid_consumer_key(self, cons_key):
        hash_name = "%s-consumer_tokens" % self.redis_ns
        cons_sec = self.conn.hget(hash_name, cons_key)

        if isinstance(cons_sec, str):
            return True
        else:
            return False

class Oauth1Errors(object):

    @classmethod
    def bad_request(cls, msg='Bad Request'):
        return jsonify(code=400, message=msg), 400

    @classmethod
    def unauthorized(cls, msg='Unauthorized to access this resource'):
        return jsonify(code=401, message=msg), 401

    @classmethod
    def not_found(cls, msg='Cannot find the resource you are looking for'):
        return jsonify(code=404, message=msg), 404