import threading
import unittest
from http.client import HTTPConnection

from secure_server import HTTPServer, SESSION_STORE, SecureLabHandler, create_session


class SecureAccessControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        SESSION_STORE.clear()
        cls.server = HTTPServer(("127.0.0.1", 0), SecureLabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def request(self, path, session_id=None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port)
        headers = {}
        if session_id:
            headers["Cookie"] = f"session_id={session_id}"
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        connection.close()
        return response.status, body

    def test_user_cannot_escalate_by_changing_role_parameter(self):
        status, body = self.request("/?role=admin")

        self.assertEqual(status, 200)
        self.assertIn("Welcome, User!", body)
        self.assertNotIn("Admin", body)

    def test_server_side_admin_session_is_authorized(self):
        admin_session = create_session("admin")

        status, body = self.request("/?role=user", admin_session)

        self.assertEqual(status, 200)
        self.assertIn("Welcome, Admin!", body)


if __name__ == "__main__":
    unittest.main()
