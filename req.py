from oauthnesia import oauthnesia
import httplib, logging

httplib.HTTPConnection.debuglevel = 1

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

o = oauthnesia(base_url='http://localhost:5000/',
               cons_key='8kO3kOBlpkkthW82RvIqtpsreccWvWJjUHq6mWKm',
               cons_sec='Vps5E1FKrqDfTJ4vucGKeSvm41wjomOmpVZLdBrN')
print o.xauth('username', 'password')