import with_sql as sqlprovider
import unittest


class SQLStoreTestCase(unittest.TestCase):

    def setUp(self):
        sqlprovider.app.config['TESTING'] = True
        self.app = sqlprovider.app.test_client()

    def error_mime_json(self):
        return "Return payload data must be a JSON String"

    def error_none(self):
        return "Return must not be None"

    def error_string(self):
        return "Return must be a JSON String"

    def error_200(self):
        return "Not returning HTTP 200"

    def error_404(self):
        return "Not returning HTTP 404"

    def get_unixtime(self):
        import time
        return int(time.time())


class XAuthTestCase(SQLStoreTestCase):

    def test_app_is_not_none(self):
        self.assertIsNotNone(self.app, msg=self.error_none())

    def test_failed_without_oauth(self):
        post = self.app.post('/oauth/access_token', data=dict(
            username='username',
            password='password'
        ), follow_redirects=True)
        self.assertEqual(post.status_code, 400, msg='400 not given for naked auth without consumer token key')


class ProtectedResourceTestCase(SQLStoreTestCase):

    def test_user_profile_without_auth(self):
        get = self.app.get('/user/tista', follow_redirects=True)
        self.assertEqual(get.status_code, 403, msg='403 not given for naked auth without consumer token key')