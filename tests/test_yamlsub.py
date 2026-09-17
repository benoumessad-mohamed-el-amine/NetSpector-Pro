"""Unit tests for hand-rolled strict-subset YAML parser."""

import unittest
from netshark.rules.yamlsub import YAMLParseError, parse_yaml_subset


class TestYamlSub(unittest.TestCase):
    def test_parse_scalars(self):
        yaml_str = """
str_val: "hello world"
int_val: 42
float_val: 3.1415
bool_true: true
bool_false: false
"""
        parsed = parse_yaml_subset(yaml_str)
        self.assertEqual(parsed["str_val"], "hello world")
        self.assertEqual(parsed["int_val"], 42)
        self.assertAlmostEqual(parsed["float_val"], 3.1415)
        self.assertTrue(parsed["bool_true"])
        self.assertFalse(parsed["bool_false"])

    def test_nested_dicts_and_lists(self):
        yaml_str = """
beacon:
  enabled: true
  min_samples: 12
  max_cov: 0.20

ports:
  - 22
  - 88
  - 445
"""
        parsed = parse_yaml_subset(yaml_str)
        self.assertTrue(parsed["beacon"]["enabled"])
        self.assertEqual(parsed["beacon"]["min_samples"], 12)
        self.assertEqual(parsed["beacon"]["max_cov"], 0.20)
        self.assertEqual(parsed["ports"], [22, 88, 445])

    def test_syntax_error_line_numbers(self):
        yaml_str = """
valid_key: 123
invalid_line_without_colon
"""
        with self.assertRaises(YAMLParseError) as ctx:
            parse_yaml_subset(yaml_str)
        self.assertIn("line 3", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
