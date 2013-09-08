import abc


class Oauth1StoreBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def nonce_is_declared(self, nonce):
        raise NotImplementedError("Method nonce_is_declared must be implemented")

    @abc.abstractmethod
    def create_new_consumer_tokens(self, app_name, app_desc, app_platform, app_url):
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