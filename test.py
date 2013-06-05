from oauthnesia import oauthnesia
import httplib, logging

httplib.HTTPConnection.debuglevel = 1

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

o = oauthnesia(base_url='http://localhost:5000/',
               cons_key='6ec8f7f5b54244b3b89f26b92a765368',
               cons_sec='633b64b5ef084528be66e8b459553b5e')
print o.xauth('username', 'password')