import unittest

from shyhurricane.utils import coerce_to_list, coerce_to_dict


class CoerceToListTests(unittest.TestCase):
    def test_none_and_falsy_values_return_empty_list(self):
        self.assertEqual([], coerce_to_list(None))
        self.assertEqual([], coerce_to_list(False))
        self.assertEqual([], coerce_to_list(0))
        self.assertEqual([], coerce_to_list(""))

    def test_list_is_returned_as_is(self):
        data = [1, 2, 3]
        self.assertIs(data, coerce_to_list(data))  # same object
        self.assertEqual([1, 2, 3], coerce_to_list(data))

    def test_non_string_iterable_is_converted_to_list(self):
        tup = (1, 2, 3)
        self.assertEqual([1, 2, 3], coerce_to_list(tup))

        gen = (x for x in range(3))
        self.assertEqual([0, 1, 2], coerce_to_list(gen))

    def test_json_list_string_is_parsed(self):
        s = '["a", "b", "c"]'
        # Intended behavior: JSON array string becomes list
        self.assertEqual(["a", "b", "c"], coerce_to_list(s))

    def test_comma_separated_string_is_split(self):
        s = "a,b,c"
        self.assertEqual(["a", "b", "c"], coerce_to_list(s))

    def test_comma_separated_int_is_split(self):
        s = "1,2,3"
        self.assertEqual([1, 2, 3], coerce_to_list(s, int))
        s = "a,b,c"
        self.assertRaises(ValueError, coerce_to_list, s, int)

    def test_non_iterable_non_list_value_is_stringified_and_split(self):
        class Dummy:
            def __str__(self) -> str:
                return "x,y,z"

        obj = Dummy()
        self.assertEqual(["x", "y", "z"], coerce_to_list(obj))

    def test_non_iterable_non_list_value_is_stringified_and_split_as_int(self):
        class Dummy:
            def __str__(self) -> str:
                return "1,2,3"

        obj = Dummy()
        self.assertEqual([1, 2, 3], coerce_to_list(obj, int))


class CoerceToDictTests(unittest.TestCase):
    def test_none_and_falsy_values_return_empty_dict(self):
        self.assertEqual({}, coerce_to_dict(None))
        self.assertEqual({}, coerce_to_dict(False))
        self.assertEqual({}, coerce_to_dict(0))
        self.assertEqual({}, coerce_to_dict(""))

    def test_dict_is_returned_as_is(self):
        data = {"a": 1, "b": 2}
        # identity check
        self.assertIs(data, coerce_to_dict(data))
        # value check
        self.assertEqual({"a": 1, "b": 2}, coerce_to_dict(data))

    def test_json_object_string_is_parsed(self):
        s = '{"a": 1, "b": 2}'
        # Intended behavior: JSON object becomes dict
        self.assertEqual({"a": 1, "b": 2}, coerce_to_dict(s))

    def test_eq_separated_string_is_parsed(self):
        s = "a=b,c=d,e=f"
        self.assertEqual(
            {"a": "b", "c": "d", "e": "f"},
            coerce_to_dict(s),
        )

    def test_colon_separated_string_is_parsed(self):
        s = "a:1,c:2,e:3"
        self.assertEqual(
            {"a": "1", "c": "2", "e": "3"},
            coerce_to_dict(s),
        )
        s = "a=1;c=2;e=3"
        self.assertEqual(
            {"a": "1", "c": "2", "e": "3"},
            coerce_to_dict(s, '=', ';'),
        )
        s = "a= 1; c=2 ;e=3 "
        self.assertEqual(
            {"a": "1", "c": "2", "e": "3"},
            coerce_to_dict(s, '=', ';'),
        )

    def test_iterable_even_length_to_pairs(self):
        items = ["a", "b", "c", "d"]
        self.assertEqual(
            {"a": "b", "c": "d"},
            coerce_to_dict(items),
        )

    def test_iterable_odd_length_last_value_is_none(self):
        items = ["a", "b", "c"]
        self.assertEqual(
            {"a": "b", "c": None},
            coerce_to_dict(items),
        )

    def test_non_iterable_non_dict_value_string_key_empty_value(self):
        value = 42
        self.assertEqual(
            {"42": ""},
            coerce_to_dict(value),
        )

    def test_http_headers(self):
        self.assertEqual(
            {"Host": "example.com:8000"},
            coerce_to_dict("Host: example.com:8000", ':', '\n'),
        )
        self.assertEqual(
            {"Host": "example.com:8000", "User-Agent": "Mozilla/5.0"},
            coerce_to_dict("Host: example.com:8000\nUser-Agent: Mozilla/5.0", ':', '\n'),
        )
