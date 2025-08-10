import unittest

from shyhurricane.mcp_server.encoder_decoder_impl import do_encode_decode


class EncoderDecoderImplTest(unittest.TestCase):
    def __init__(self, methodName: str = ...):
        super().__init__(methodName)

    def test_none(self):
        self.assertEqual("", do_encode_decode(None, [""]))

    def test_nop(self):
        self.assertEqual('the quick brown fox', do_encode_decode('the quick brown fox', []))

    def test_base64_encode(self):
        self.assertEqual("dGhlIHF1aWNrIGJyb3duIGZveA==", do_encode_decode('the quick brown fox', ["base64_encode"]))

    def test_base64_decode(self):
        self.assertEqual("the quick brown fox", do_encode_decode('dGhlIHF1aWNrIGJyb3duIGZveA==', ["base64_decode"]))

    def test_to_hex(self):
        self.assertEqual("74686520717569636b2062726f776e20666f78", do_encode_decode("the quick brown fox", ["to_hex"]))

    def test_from_hex(self):
        self.assertEqual("the quick brown fox",
                         do_encode_decode("74686520717569636b2062726f776e20666f78", ["from_hex"]))

    def test_to_charcode(self):
        self.assertEqual("039303b503b903ac002003c303bf03c5", do_encode_decode("Γειά σου", ["to_charcode"]))

    def test_from_charcode(self):
        self.assertEqual("Γειά σου", do_encode_decode("039303b503b903ac002003c303bf03c5", ["from_charcode"]))

    def test_url_encode(self):
        self.assertEqual("the%20quick%20brown%20fox%2C", do_encode_decode("the quick brown fox,", ["url_encode"]))

    def test_url_encode_all(self):
        self.assertEqual("%74%68%65%20%71%75%69%63%6B%20%62%72%6F%77%6E%20%66%6F%78%2C",
                         do_encode_decode("the quick brown fox,", ["url_encode_all"]))

    def test_url_decode(self):
        self.assertEqual("the quick brown fox,",
                         do_encode_decode("%74%68%65%20%71%75%69%63%6B%20%62%72%6F%77%6E%20%66%6F%78%2C",
                                          ["url_decode"]))

    def test_to_htmlentity(self):
        self.assertEqual("&lt;img/&gt;", do_encode_decode("<img/>", ["to_htmlentity"]))

    def test_from_htmlentity(self):
        self.assertEqual("<img/>", do_encode_decode("&lt;img&sol;&gt;", ["from_htmlentity"]))

    def test_escape_unicode_backslash(self):
        self.assertEqual("\\u03C3\\u03BF\\u03C5", do_encode_decode("σου", ["escape_unicode_backslash"]))

    def test_escape_unicode_percent(self):
        self.assertEqual("%u03C3%u03BF%u03C5", do_encode_decode("σου", ["escape_unicode_percent"]))

    def test_escape_unicode_u_plus(self):
        self.assertEqual("U+03C3U+03BFU+03C5", do_encode_decode("σου", ["escape_unicode_u_plus"]))

    def test_unescape_unicode(self):
        self.assertEqual("σου", do_encode_decode(r"\\u03C3%u03BFU+03C5", ["unescape_unicode"]))

    def test_to_uppercase(self):
        self.assertEqual("ABCDEF123", do_encode_decode("abcdef123", ["to_uppercase"]))

    def test_to_lowercase(self):
        self.assertEqual("abcdef123", do_encode_decode("ABCDEF123", ["to_lowercase"]))

    def test_chain(self):
        self.assertEqual("6447686c4948463161574e7249474a796233647549475a7665413d3d",
                         do_encode_decode("the quick brown fox", ["base64_encode", "to_hex"]))
