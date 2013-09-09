from oauth1.authorize import Oauth1
from flask import request, Response
import json


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

    @classmethod
    def server_error(cls, msg='Server Error'):
        return Oauth1Errors.create_response(500, msg)