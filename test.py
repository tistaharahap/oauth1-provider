from oauthnesia import oauthnesia
import httplib, logging

httplib.HTTPConnection.debuglevel = 1

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

o = oauthnesia(base_url='http://localhost:5000/',
               cons_key='nZ22DRYacPsmZUiiGNrozxQy99SEG7yejs3AVl4u',
               cons_sec='z869iaTCtbRvFIBr2ddahTnfPZJQe4VjkTwamXFx')
print o.xauth('username', 'password')