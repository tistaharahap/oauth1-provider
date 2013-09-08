class AuthorizeErrors(object):
    @classmethod
    def invalid_realm(cls):
        return 'The OAuth Realm must match this machine\'s BASE URL'

    @classmethod
    def missing_auth_data(cls):
        return 'No OAuth authorization data is available'

    @classmethod
    def missing_consumer_key(cls):
        return 'OAuth Consumer Key is required'

    @classmethod
    def invalid_consumer_key(cls):
        return 'Invalid or unrecognized Consumer Key'

    @classmethod
    def unsupported_sign_method(cls):
        return 'Supported OAuth Signature Method is only HMAC-SHA1, must be explicitly defined'

    @classmethod
    def missing_oauth_signature(cls):
        return 'OAuth Signature is required'

    @classmethod
    def empty_oauth_signature(cls):
        return 'OAuth Signature must not be empty'

    @classmethod
    def missing_timestamp(cls):
        return 'OAuth Timestamp is required'

    @classmethod
    def missing_nonce(cls):
        return 'OAuth Nonce is required'

    @classmethod
    def declared_nonce(cls):
        return 'OAuth Nonce is already declared'

    @classmethod
    def missing_oauth_version(cls):
        return 'OAuth Version is missing'

    @classmethod
    def invalid_oauth_version(cls):
        return 'Only OAuth 1.0 is supported'