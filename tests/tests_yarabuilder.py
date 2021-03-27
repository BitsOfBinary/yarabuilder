import unittest.mock
import logging

from yarabuilder.yarabuilder import YaraBuilder
from yarabuilder.yararule import YaraRule


class TestYaraBuilder(unittest.TestCase):
    @unittest.mock.patch("yarabuilder.yararule.YaraRule")
    def setUp(self, mocked_yara_rule):
        mocked_yara_rule.build_rule = unittest.mock.MagicMock(return_value="")
        mocked_yara_rule.get_yara_rule = unittest.mock.MagicMock(return_value="")
        self.yara_builder = YaraBuilder()
        self.yara_builder.yara_rules["test_rule"] = mocked_yara_rule

    def test_yara_builder_init_custom_logger(self):
        logger = logging.getLogger("test")
        yara_builder = YaraBuilder(logger=logger)
        self.assertEqual(yara_builder.logger, logger)

    def test_no_rule_name_exception_handler(self):
        self.assertRaises(
            KeyError,
            self.yara_builder._no_rule_name_exception_handler,
            "nonexistant_rule",
        )

    def test_create_rule(self):
        self.yara_builder.create_rule("another_rule")
        self.assertIsInstance(self.yara_builder.yara_rules["another_rule"], YaraRule)

    def test_create_two_rules_with_same_name(self):
        self.assertRaises(KeyError, self.yara_builder.create_rule, "test_rule")

    def test_add_tag(self):
        self.yara_builder.add_tag("test_rule", "test_tag")
        self.yara_builder.yara_rules["test_rule"].tags.add_tag.assert_called_once_with(
            "test_tag"
        )

    def test_add_import(self):
        self.yara_builder.add_import("test_rule", "test_import")
        self.yara_builder.yara_rules[
            "test_rule"
        ].imports.add_import.assert_called_once_with("test_import")

    def test_add_meta_custom_type(self):
        self.yara_builder.add_meta(
            "test_rule", "test_meta_name", "test_meta_text", meta_type="custom"
        )
        self.yara_builder.yara_rules["test_rule"].meta.add_meta.assert_called_once_with(
            "test_meta_name", "test_meta_text", meta_type="custom"
        )

    def test_add_meta_text(self):
        self.yara_builder.add_meta("test_rule", "test_meta_name", "test_meta_text")
        self.yara_builder.yara_rules["test_rule"].meta.add_meta.assert_called_once_with(
            "test_meta_name", "test_meta_text", meta_type="text"
        )

    def test_add_meta_int(self):
        self.yara_builder.add_meta("test_rule", "test_meta_name", 0)
        self.yara_builder.yara_rules["test_rule"].meta.add_meta.assert_called_once_with(
            "test_meta_name", 0, meta_type="int"
        )

    def test_add_meta_bool(self):
        self.yara_builder.add_meta("test_rule", "test_meta_name", True)
        self.yara_builder.yara_rules["test_rule"].meta.add_meta.assert_called_once_with(
            "test_meta_name", True, meta_type="bool"
        )

    def test_add_text_string(self):
        self.yara_builder.add_text_string(
            "test_rule", "test_text_string", name="test_string_name"
        )
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_string.assert_called_once_with(
            "test_string_name", "test_text_string", str_type="text"
        )

    def test_add_text_string_anonymous(self):
        self.yara_builder.add_text_string("test_rule", "test_text_string")
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_anonymous_string.assert_called_once_with(
            "test_text_string", str_type="text"
        )

    def test_add_hex_string(self):
        self.yara_builder.add_hex_string(
            "test_rule", "AA BB CC DD", name="test_string_name"
        )
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_string.assert_called_once_with(
            "test_string_name", "AA BB CC DD", str_type="hex"
        )
        
    def test_add_hex_string_with_curly_brackets(self):
        self.yara_builder.add_hex_string(
            "test_rule", "{AA BB CC DD}", name="test_string_name"
        )
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_string.assert_called_once_with(
            "test_string_name", "AA BB CC DD", str_type="hex"
        )

    def test_add_hex_string_anonymous(self):
        self.yara_builder.add_hex_string("test_rule", "AA BB CC DD")
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_anonymous_string.assert_called_once_with(
            "AA BB CC DD", str_type="hex"
        )

    def test_add_regex_string(self):
        self.yara_builder.add_regex_string(
            "test_rule", "test[0-9]{2}", name="test_string_name"
        )
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_string.assert_called_once_with(
            "test_string_name", "test[0-9]{2}", str_type="regex"
        )

    def test_add_regex_string_anonymous(self):
        self.yara_builder.add_regex_string("test_rule", "test[0-9]{2}")
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_anonymous_string.assert_called_once_with(
            "test[0-9]{2}", str_type="regex"
        )
        
    def test_add_regex_string_with_forward_slashes(self):
        self.yara_builder.add_regex_string(
            "test_rule", "/test[0-9]{2}/", name="test_string_name"
        )
        self.yara_builder.yara_rules[
            "test_rule"
        ].strings.add_string.assert_called_once_with(
            "test_string_name", "test[0-9]{2}", str_type="regex"
        )

    def test_modifier_handler(self):
        self.yara_builder.add_text_string(
            "test_rule",
            "test_text_string",
            name="test_string_name",
            modifiers=["ascii", "wide"],
        )
        self.yara_builder.yara_rules["test_rule"].strings.add_modifier.assert_has_calls(
            [
                unittest.mock.call("test_string_name", "ascii"),
                unittest.mock.call("test_string_name", "wide"),
            ]
        )

    def test_add_condition(self):
        self.yara_builder.add_condition("test_rule", "any of them")
        self.yara_builder.yara_rules[
            "test_rule"
        ].condition.add_raw_condition.assert_called_once_with("any of them")

    def test_add_meta_comment(self):
        self.yara_builder.add_meta_comment(
            "test_rule", "test_meta_name", "test_comment"
        )
        self.yara_builder.yara_rules["test_rule"].meta.meta["test_meta_name"][
            0
        ].add_comment.assert_called_once_with("test_comment", position="inline")

    @unittest.mock.patch("yarabuilder.yararule.YaraString")
    def test_add_string_comment(self, mocked_yara_string):
        self.yara_builder.yara_rules["test_rule"].strings.strings[
            "test_string_name"
        ] = mocked_yara_string
        self.yara_builder.add_string_comment(
            "test_rule", "test_string_name", "test_comment"
        )
        self.yara_builder.yara_rules["test_rule"].strings.strings[
            "test_string_name"
        ].add_comment.assert_called_once_with("test_comment", position="inline")

    def test_build_rule(self):
        self.yara_builder.build_rule("test_rule")
        self.yara_builder.yara_rules["test_rule"].build_rule.assert_called_once()

    @unittest.mock.patch("yarabuilder.yararule.YaraRule")
    def test_build_rules(self, mocked_yara_rule):
        mocked_yara_rule.build_rule = unittest.mock.MagicMock(return_value="")
        self.yara_builder.yara_rules["another_rule"] = mocked_yara_rule
        self.yara_builder.build_rules()
        self.yara_builder.yara_rules["test_rule"].build_rule.assert_called_once()
        self.yara_builder.yara_rules["another_rule"].build_rule.assert_called_once()

    @unittest.mock.patch("yarabuilder.yararule.YaraRule")
    def test_get_yara_rules(self, mocked_yara_rule):
        mocked_yara_rule.get_yara_rule = unittest.mock.MagicMock(return_value="")
        self.yara_builder.yara_rules["another_rule"] = mocked_yara_rule
        self.yara_builder.get_yara_rules()
        self.yara_builder.yara_rules["test_rule"].get_yara_rule.assert_called_once()
        self.yara_builder.yara_rules["another_rule"].get_yara_rule.assert_called_once()

    def test_set_yara_rules(self):
        self.yara_builder.set_yara_rules([{"rule_name": "test_rule_name", "condition": "any of them"}])
        self.assertIn("test_rule_name", self.yara_builder.yara_rules)