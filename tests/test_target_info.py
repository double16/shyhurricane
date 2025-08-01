import unittest

from shyhurricane.target_info import parse_target_info


class TestTargetInfo(unittest.TestCase):

    def test_host_port_localhost(self):
        target_info = parse_target_info("localhost:3000")
        self.assertEqual("localhost", target_info.host)
        self.assertEqual(3000, target_info.port)

    def test_host_port_localhost_local(self):
        target_info = parse_target_info("localhost.local:3000")
        self.assertEqual("localhost.local", target_info.host)
        self.assertEqual(3000, target_info.port)

    def test_to_url_from_url(self):
        self.assertEqual("http://localhost:3000", parse_target_info("http://localhost:3000").to_url())

    def test_to_url_from_netloc(self):
        self.assertEqual("https://example.com:443", parse_target_info("example.com:443").to_url())
        self.assertEqual("https://example.com:8443", parse_target_info("example.com:8443").to_url())
        self.assertEqual("http://example.com:80", parse_target_info("example.com:80").to_url())

    def test_to_url_from_host(self):
        self.assertEqual("https://example.com", parse_target_info("example.com").to_url())
        self.assertEqual("http://example.local", parse_target_info("example.local").to_url())
