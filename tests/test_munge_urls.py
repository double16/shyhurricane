import unittest

from shyhurricane.utils import munge_urls


class TestMungeUrls(unittest.TestCase):

    def test_munge_urls_with_query(self):
        query = "http://example.com/path?query=1"
        expected_prefix = "http://example.com/path?"
        expected_urls = [
            "http://example.com/path?query=1",
            "http://example.com/path",
            "http://example.com/path/"
        ]
        self.assertEqual(munge_urls(query), (expected_prefix, expected_urls))

    def test_munge_urls_without_query(self):
        query = "http://example.com/path"
        expected_prefix = "http://example.com/path/"
        expected_urls = [
            "http://example.com/path",
            "http://example.com/path/"
        ]
        self.assertEqual(munge_urls(query), (expected_prefix, expected_urls))

    def test_munge_urls_with_trailing_slash(self):
        query = "http://example.com/path/"
        expected_prefix = "http://example.com/path/"
        expected_urls = [
            "http://example.com/path/",
            "http://example.com/path",
        ]
        self.assertEqual(munge_urls(query), (expected_prefix, expected_urls))

    def test_munge_urls_with_empty_string(self):
        self.assertEqual(munge_urls(""), ("", []))

    def test_munge_urls_with_only_query(self):
        query = "?query=1"
        expected_prefix = query
        expected_urls = [
            "?query=1",
        ]
        self.assertEqual(munge_urls(query), (expected_prefix, expected_urls))
