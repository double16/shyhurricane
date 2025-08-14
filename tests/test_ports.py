import unittest
from bitarray import bitarray

from shyhurricane.ports import parse_ports_spec, ports_to_bitfield, is_subset, bitfield_to_ports, MAX_PORT


class TestPortUtils(unittest.TestCase):

    def test_parse_ports_spec_empty(self):
        result = parse_ports_spec([])
        self.assertTrue(result.all())

    def test_parse_ports_spec_single_port(self):
        result = parse_ports_spec(['80'])
        self.assertTrue(result[80])
        self.assertFalse(result[81])

    def test_parse_ports_spec_multiple_ports(self):
        result = parse_ports_spec(['80, 443'])
        self.assertTrue(result[80])
        self.assertTrue(result[443])
        self.assertFalse(result[81])

    def test_parse_ports_spec_range(self):
        result = parse_ports_spec(['80-82'])
        self.assertTrue(result[80])
        self.assertTrue(result[81])
        self.assertTrue(result[82])
        self.assertFalse(result[83])

    def test_parse_ports_spec_mixed(self):
        result = parse_ports_spec(['80, 443, 8000-8002'])
        self.assertTrue(result[80])
        self.assertTrue(result[443])
        self.assertTrue(result[8000])
        self.assertTrue(result[8001])
        self.assertTrue(result[8002])
        self.assertFalse(result[8003])

    def test_ports_to_bitfield(self):
        result = ports_to_bitfield({80, 443, 8000})
        self.assertTrue(result[80])
        self.assertTrue(result[443])
        self.assertTrue(result[8000])
        self.assertFalse(result[81])

    def test_ports_to_bitfield_out_of_range(self):
        result = ports_to_bitfield({-1, 70000})
        self.assertFalse(result[-1])
        with self.assertRaises(IndexError):
            result[70000]

    def test_bitfield_to_ports(self):
        ba = bitarray(MAX_PORT + 1)
        ba.setall(False)
        ba[80] = True
        ba[443] = True
        ports = bitfield_to_ports(ba)
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertNotIn(81, ports)

    def test_is_subset(self):
        a = bitarray(MAX_PORT + 1)
        a.setall(False)
        a[80] = True
        a[443] = True

        self.assertTrue(is_subset(a, a))

        b = bitarray(MAX_PORT + 1)
        b.setall(False)
        b[80] = True
        b[443] = True
        b[8080] = True

        self.assertTrue(is_subset(b, b))
        self.assertTrue(is_subset(a, b))
        self.assertFalse(is_subset(b, a))

        c = bitarray(MAX_PORT + 1)
        c.setall(False)
        c[80] = True

        self.assertTrue(is_subset(c, c))
        self.assertTrue(is_subset(c, b))
        self.assertFalse(is_subset(b, c))

    def test_is_subset_empty(self):
        a = bitarray(MAX_PORT + 1)
        a.setall(False)

        b = bitarray(MAX_PORT + 1)
        b.setall(False)

        self.assertTrue(is_subset(a, b))
