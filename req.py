from oauthnesia import oauthnesia
import httplib, logging

httplib.HTTPConnection.debuglevel = 1

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

o = oauthnesia(base_url='http://localhost:5000/',
               cons_key='OPTddWtrBbSaVoE3105RLjYyfIY3T3WDGRgvgKFs',
               cons_sec='7gS45cQhJEHdfaPxJRqPt4HbFrfn5Gdgu2CK7LDg')
print o.xauth('username', 'password')