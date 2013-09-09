from oauth1.store.base import Oauth1StoreBase
import redis
import json
import uuid


class Oauth1StoreRedis(Oauth1StoreBase):
    redis_host = None
    redis_port = None
    redis_db = None
    redis_ns = None

    conn = None

    def __init__(self, host='127.0.0.1', port=6379, db=0, namespace="oauth1-redis"):
        self.redis_host = host
        self.redis_port = port
        self.redis_db = db
        self.redis_ns = namespace

        self.conn = redis.StrictRedis(host=self.redis_host, port=self.redis_port, db=self.redis_db)
        if not self.conn:
            raise Exception('Redis is not properly setup. Check redis configs?')

    def nonce_is_declared(self, nonce):
        hash_name = "%s-nonces" % self.redis_ns
        res = self.conn.hget(hash_name, nonce)
        if res:
            return True
        else:
            self.conn.hset(hash_name, nonce, 1)
            return False

    def create_new_consumer_app(self, app_name, app_desc, app_platform, app_url):
        hash_name = "%s-app_info" % self.redis_ns

        app_id = uuid.uuid4().__str__().replace('-', '')
        app = json.dumps({
            'id': app_id,
            'name': app_name,
            'description': app_desc,
            'platform': app_platform,
            'app_url': app_url
        })
        self.conn.hset(hash_name, app_id, app)

        return {
            'app_id': app_id
        }

    def create_new_consumer_tokens(self, app_id):
        tokens = self._generate_new_consumer_tokens()

        hash_name = "%s-consumer_tokens" % self.redis_ns
        self.conn.hset(hash_name, tokens['consumer_key'], tokens['consumer_secret'])

        return {
            'app_id': app_id,
            'consumer_key': tokens['consumer_key'],
            'consumer_secret': tokens['consumer_secret']
        }

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