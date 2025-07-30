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
