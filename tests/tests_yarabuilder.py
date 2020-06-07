import unittest.mock

from yarabuilder.yarabuilder import YaraBuilder
from yarabuilder.yararule import YaraRule


class TestYaraBuilder(unittest.TestCase):
    @unittest.mock.patch('yarabuilder.yararule.YaraRule')
    def setUp(self, mocked_yara_rule):
        self.yara_builder = YaraBuilder()
        self.yara_builder.yara_rules["test_rule"] = mocked_yara_rule

    def test_no_rule_name_exception_handler(self):
        self.assertRaises(KeyError, self.yara_builder.no_rule_name_exception_handler, "nonexistant_rule")

    def test_create_rule(self):
        self.yara_builder.create_rule("another_rule")
        self.assertIsInstance(self.yara_builder.yara_rules["another_rule"], YaraRule)

    def test_create_two_rules_with_same_name(self):
        self.assertRaises(KeyError, self.yara_builder.create_rule, "test_rule")

    def test_add_tag(self):
        self.yara_builder.add_tag("test_rule", "test_tag")
        self.yara_builder.yara_rules["test_rule"].tags.add_tag.assert_called_once_with("test_tag")

    def test_add_import(self):
        self.yara_builder.add_import("test_rule", "test_import")
        self.yara_builder.yara_rules["test_rule"].imports.add_import.assert_called_once_with("test_import")

    def test_add_meta_custom_type(self):
        self.yara_builder.add_meta("test_rule", "test_meta_name", "test_meta_text", meta_type="custom")
        self.yara_builder.yara_rules["test_rule"].meta.add_meta.assert_called_once_with("test_meta_name", "test_meta_text", meta_type="custom")

    def test_add_meta_text(self):
        self.yara_builder.add_meta("test_rule", "test_meta_name", "test_meta_text")
        self.yara_builder.yara_rules["test_rule"].meta.add_meta.assert_called_once_with("test_meta_name", "test_meta_text", meta_type="text")