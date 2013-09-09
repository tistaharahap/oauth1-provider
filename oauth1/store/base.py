import abc
import random
import string
import time


class Oauth1StoreBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def nonce_is_declared(self, nonce):
        raise NotImplementedError("Method nonce_is_declared must be implemented")

    @abc.abstractmethod
    def register_nonce(self, nonce, app_id):
        raise NotImplementedError("Method register_nonce must be implemented")

    @abc.abstractmethod
    def get_app_id_from_cons_key(self, cons_key):
        raise NotImplementedError("Method get_app_id_from_cons_key must be implemented")

    @abc.abstractmethod
    def create_new_consumer_app(self, app_name, app_desc, app_platform, app_url):
        raise NotImplementedError("Method create_new_consumer_app must be implemented")

    @abc.abstractmethod
    def create_new_consumer_tokens(self, app_id):
        raise NotImplementedError("Method create_new_consumer_tokens must be implemented")

    @abc.abstractmethod
    def _generate_new_consumer_tokens(self):
        raise NotImplementedError("Method _generate_new_consumer_tokens must be implemented")

    @abc.abstractmethod
    def is_valid_consumer_key(self, cons_key):
        raise NotImplementedError("Method is_valid_consumer_key must be implemented")

    @abc.abstractmethod
    def get_consumer_secret(self, consumer_key):
        raise NotImplementedError("Method get_consumer_secret must be implemented")

    @classmethod
    def get_unix_time(cls):
        return int(time.time())

    @classmethod
    def random_string(cls, size=6, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase):
        return ''.join(random.choice(chars) for x in range(size))