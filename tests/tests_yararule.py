import logging
import unittest
import collections

from yarabuilder.yararule import (
    YaraRule,
    YaraCondition,
    YaraTags,
    YaraImports,
    YaraString,
    YaraStrings,
    YaraMeta,
    YaraMetaEntry,
    YaraComment,
    YaraCommentEnabledClass,
)


class TestYaraComment(unittest.TestCase):
    def setUp(self):
        self.test_yara_comment = YaraComment()

    def test_yara_comment_init(self):
        self.assertFalse(self.test_yara_comment.above)
        self.assertIsNone(self.test_yara_comment.inline)
        self.assertFalse(self.test_yara_comment.below)

    def test_get_yara_comment(self):
        self.test_yara_comment.above = "above_comment"
        self.test_yara_comment.inline = "inline_comment"
        self.test_yara_comment.below = "below_comment"
        pod_yara_comment = self.test_yara_comment.get_yara_comment()
        self.assertEqual(pod_yara_comment["above"], "above_comment")
        self.assertEqual(pod_yara_comment["inline"], "inline_comment")
        self.assertEqual(pod_yara_comment["below"], "below_comment")

    def test_set_yara_comment(self):
        self.test_yara_comment.set_yara_comment(
            {"above": "test_above", "inline": "test_inline", "below": "test_below"}
        )
        self.assertEqual(self.test_yara_comment.above, "test_above")
        self.assertEqual(self.test_yara_comment.inline, "test_inline")
        self.assertEqual(self.test_yara_comment.below, "test_below")


class TestYaraCommentEnabledClass(unittest.TestCase):
    def setUp(self):
        self.test_yara_comment_enabled_class = YaraCommentEnabledClass()
        self.raw = ""

    def test_yara_comment_enabled_class_init(self):
        self.assertIsInstance(
            self.test_yara_comment_enabled_class.yara_comment, YaraComment
        )

    def test_add_comment(self):
        self.test_yara_comment_enabled_class.add_comment("test1")
        self.assertEqual(
            self.test_yara_comment_enabled_class.yara_comment.inline, "test1"
        )

        self.test_yara_comment_enabled_class.add_comment("test2", position="above")
        self.assertEqual(
            self.test_yara_comment_enabled_class.yara_comment.above, ["test2"]
        )

        self.test_yara_comment_enabled_class.add_comment("test3", position="below")
        self.assertEqual(
            self.test_yara_comment_enabled_class.yara_comment.below, ["test3"]
        )

    def test_add_multiple_comments(self):
        self.test_yara_comment_enabled_class.add_comment("test1", position="above")
        self.test_yara_comment_enabled_class.add_comment("test2", position="above")
        self.assertEqual(
            self.test_yara_comment_enabled_class.yara_comment.above, ["test1", "test2"]
        )

    def test_build_comment_above(self):
        self.test_yara_comment_enabled_class.add_comment("test", position="above")
        self.raw = self.test_yara_comment_enabled_class.build_comments(self.raw)
        self.assertEqual(self.raw, "// test\n        ")

    def test_build_comment_inline(self):
        self.test_yara_comment_enabled_class.add_comment("test", position="inline")
        self.raw = self.test_yara_comment_enabled_class.build_comments(self.raw)
        self.assertEqual(self.raw, " // test")

    def test_build_comment_below(self):
        self.test_yara_comment_enabled_class.add_comment("test", position="below")
        self.raw = self.test_yara_comment_enabled_class.build_comments(self.raw)
        self.assertEqual(self.raw, "\n        // test")

    def test_build_multiple_above_comments(self):
        self.test_yara_comment_enabled_class.add_comment("test1", position="above")
        self.test_yara_comment_enabled_class.add_comment("test2", position="above")
        self.raw = self.test_yara_comment_enabled_class.build_comments(self.raw)
        self.assertEqual(self.raw, "// test1\n        // test2\n        ")

    def test_build_multiple_below_comments(self):
        self.test_yara_comment_enabled_class.add_comment("test1", position="below")
        self.test_yara_comment_enabled_class.add_comment("test2", position="below")
        self.raw = self.test_yara_comment_enabled_class.build_comments(self.raw)
        self.assertEqual(self.raw, "\n        // test1\n        // test2")


class TestYaraRule(unittest.TestCase):
    def setUp(self):
        self.test_rule_name = "test_rule"
        self.test_condition = "filesize > 0"
        self.yara_rule = YaraRule(self.test_rule_name)
        self.raw_rule = ""

    def test_yara_rule_init(self):
        self.assertEqual(self.test_rule_name, self.yara_rule.rule_name)
        self.assertEqual("    ", self.yara_rule.whitespace)

    def test_yara_rule_init_custom_logger(self):
        logger = logging.getLogger("test")
        yara_rule = YaraRule(self.test_rule_name, logger=logger)
        self.assertEqual(yara_rule.logger, logger)

    def test_build_rule_no_condition(self):
        self.assertRaises(KeyError, self.yara_rule.build_rule)

    def test_build_rule_header(self):
        self.yara_rule.condition.add_raw_condition(self.test_condition)
        self.raw_rule = self.yara_rule.build_rule_header(self.raw_rule)
        self.assertEqual(self.raw_rule, "rule %s {\n" % self.test_rule_name)

    def test_build_rule_header_w_tags(self):
        self.yara_rule.condition.add_raw_condition(self.test_condition)
        self.yara_rule.tags.add_tag("test1")
        self.yara_rule.tags.add_tag("test2")
        self.raw_rule = self.yara_rule.build_rule_header(self.raw_rule)
        self.assertEqual(
            self.raw_rule, "rule %s : test1 test2 {\n" % self.test_rule_name
        )

    def test_build_rule_header_w_imports(self):
        self.yara_rule.condition.add_raw_condition(self.test_condition)
        self.yara_rule.imports.add_import("pe")
        self.yara_rule.imports.add_import("math")
        self.raw_rule = self.yara_rule.build_rule_header(self.raw_rule)
        self.assertEqual(
            self.raw_rule,
            'import "pe"\nimport "math"\n\nrule %s {\n' % self.test_rule_name,
        )

    def test_build_rule_strings_section(self):
        self.yara_rule.strings.raw_strings = [
            '$ = "anon_test"',
            '$test_name1 = "test_value1" ascii wide',
            '$test_name2 = "test_value2" nocase',
        ]
        self.raw_rule = self.yara_rule.build_rule_strings_section(self.raw_rule)
        self.assertEqual(
            self.raw_rule,
            '    strings:\n        $ = "anon_test"\n        '
            '$test_name1 = "test_value1" ascii wide\n        $test_name2 = "test_value2" nocase\n\n',
        )

    def test_build_rule_condition_section(self):
        self.yara_rule.condition.raw_condition = "any of them"
        self.raw_rule = self.yara_rule.build_rule_condition_section(self.raw_rule)
        self.assertEqual(self.raw_rule, "    condition:\n        any of them\n}")

    def test_build_rule_meta_section(self):
        self.yara_rule.meta.add_meta("test_name1", "test_value1")
        self.yara_rule.meta.add_meta("test_name2", 10, meta_type="int")
        self.raw_rule = self.yara_rule.build_rule_meta_section(self.raw_rule)
        self.assertEqual(
            self.raw_rule,
            "    meta:\n        "
            'test_name1 = "test_value1"\n        '
            "test_name2 = 10\n\n",
        )

    def test_build_rule(self):
        self.yara_rule.meta.add_meta("description", "Generated by yarabuilder")
        self.yara_rule.strings.add_string("test_name", "test_value")
        self.yara_rule.condition.add_raw_condition("any of them")
        rule = self.yara_rule.build_rule()
        self.assertEqual(
            rule,
            "rule test_rule {\n    meta:\n        "
            'description = "Generated by yarabuilder"\n\n    '
            'strings:\n        $test_name = "test_value"\n\n    '
            "condition:\n        any of them\n}",
        )

    def test_get_yara_rule_no_condition(self):
        self.assertRaises(KeyError, self.yara_rule.get_yara_rule)

    def test_get_yara_rule(self):
        self.yara_rule.meta.add_meta("description", "Generated by yarabuilder")
        self.yara_rule.strings.add_string("test_name", "test_value")
        self.yara_rule.condition.add_raw_condition("any of them")
        self.yara_rule.imports.add_import("pe")
        self.yara_rule.tags.add_tag("test_tag")
        yara_rule = self.yara_rule.get_yara_rule()
        self.assertEqual(yara_rule["rule_name"], "test_rule")
        self.assertEqual(
            yara_rule["meta"]["description"][0]["value"], "Generated by yarabuilder"
        )
        self.assertEqual(yara_rule["strings"]["test_name"]["value"], "test_value")
        self.assertEqual(yara_rule["condition"], "any of them")
        self.assertEqual(yara_rule["imports"][0], "pe")
        self.assertEqual(yara_rule["tags"][0], "test_tag")

    def test_set_yara_rule(self):
        self.yara_rule.set_yara_rule(
            {
                "condition": "any of them",
                "imports": ["pe"],
                "meta": collections.OrderedDict(
                    [
                        (
                            "description",
                            [
                                {
                                    "meta_type": "text",
                                    "name": "description",
                                    "position": 0,
                                    "value": "Generated by yarabuilder",
                                }
                            ],
                        )
                    ]
                ),
                "rule_name": "my_rule",
                "strings": collections.OrderedDict(
                    [
                        (
                            "@anon0",
                            {
                                "is_anonymous": True,
                                "name": "@anon0",
                                "str_type": "text",
                                "value": "Anonymous string",
                            },
                        ),
                        (
                            "str",
                            {
                                "comment": {"inline": "example comment"},
                                "is_anonymous": False,
                                "modifiers": ["ascii", "wide"],
                                "name": "str",
                                "str_type": "text",
                                "value": "Named string",
                            },
                        ),
                        (
                            "@anon1",
                            {
                                "is_anonymous": True,
                                "name": "@anon1",
                                "str_type": "hex",
                                "value": "DE AD BE EF",
                            },
                        ),
                        (
                            "@anon2",
                            {
                                "is_anonymous": True,
                                "name": "@anon2",
                                "str_type": "regex",
                                "value": "regex[0-9]{2}",
                            },
                        ),
                    ]
                ),
                "tags": ["yarabuilder"],
            }
        )
        self.assertEqual(self.yara_rule.rule_name, "my_rule")
        self.assertEqual(self.yara_rule.imports.imports, ["pe"])
        self.assertEqual(self.yara_rule.tags.tags, ["yarabuilder"])
        self.assertEqual(
            self.yara_rule.meta.meta["description"][0].value, "Generated by yarabuilder"
        )
        self.assertEqual(self.yara_rule.strings.strings["str"].value, "Named string")
        self.assertEqual(self.yara_rule.condition.raw_condition, "any of them")


class TestYaraCondition(unittest.TestCase):
    def test_add_raw_condition(self):
        condition = YaraCondition()
        condition.add_raw_condition("filesize > 0")
        self.assertEqual("filesize > 0", condition.raw_condition)

    def test_get_yara_condition(self):
        condition = YaraCondition()
        condition.add_raw_condition("filesize > 0")
        self.assertEqual(condition.get_yara_condition(), "filesize > 0")


class TestYaraTags(unittest.TestCase):
    def setUp(self):
        self.yara_tags = YaraTags()

    def test_yara_tags_constructor(self):
        self.assertEqual(self.yara_tags.tags, [])

    def test_has_tags(self):
        self.assertFalse(self.yara_tags.has_tags())
        self.yara_tags.add_tag("test1")
        self.assertTrue(self.yara_tags.has_tags())

    def test_add_tag(self):
        self.yara_tags.add_tag("test1")
        self.yara_tags.add_tag("test2")
        self.assertEqual(self.yara_tags.tags, ["test1", "test2"])

    def test_build_tags(self):
        self.yara_tags.add_tag("test1")
        self.yara_tags.add_tag("test2")
        self.yara_tags.build_tags()
        self.assertEqual(self.yara_tags.raw_tags, "test1 test2")

    def test_get_yara_tags(self):
        self.yara_tags.add_tag("test1")
        self.yara_tags.add_tag("test2")
        self.assertEqual(self.yara_tags.get_yara_tags(), ["test1", "test2"])

    def test_set_yara_tags(self):
        self.yara_tags.set_yara_tags(["test1", "test2"])
        self.assertEqual(self.yara_tags.tags, ["test1", "test2"])


class TestYaraImports(unittest.TestCase):
    def setUp(self):
        self.yara_imports = YaraImports()

    def test_yara_imports_constructor(self):
        self.assertEqual(self.yara_imports.imports, [])

    def test_has_imports(self):
        self.assertFalse(self.yara_imports.has_imports())
        self.yara_imports.add_import("pe")
        self.assertTrue(self.yara_imports.has_imports())

    def test_add_import(self):
        self.yara_imports.add_import("pe")
        self.yara_imports.add_import("math")
        self.assertEqual(self.yara_imports.imports, ["pe", "math"])

    def test_build_imports(self):
        self.yara_imports.add_import("pe")
        self.yara_imports.add_import("math")
        self.yara_imports.build_imports()
        self.assertEqual(self.yara_imports.raw_imports, 'import "pe"\nimport "math"\n')

    def test_no_duplicate_imports(self):
        self.yara_imports.add_import("pe")
        self.yara_imports.add_import("math")
        self.yara_imports.add_import("pe")
        self.assertEqual(self.yara_imports.imports, ["pe", "math"])

    def test_get_yara_imports(self):
        self.yara_imports.add_import("pe")
        self.yara_imports.add_import("math")
        self.assertEqual(self.yara_imports.get_yara_imports(), ["pe", "math"])

    def test_set_yara_imports(self):
        self.yara_imports.set_yara_imports(["pe", "math"])
        self.assertEqual(self.yara_imports.imports, ["pe", "math"])


class TestYaraString(unittest.TestCase):
    def test_yara_string_constructor(self):
        yara_string = YaraString("test_name", "test_value")
        self.assertEqual(yara_string.name, "test_name")
        self.assertEqual(yara_string.value, "test_value")
        self.assertEqual(yara_string.str_type, "text")
        self.assertFalse(yara_string.is_anonymous)

    def test_build_string_text(self):
        yara_string = YaraString("test_name", "test_value")
        yara_string.build_string()
        self.assertEqual(yara_string.raw_string, '$test_name = "test_value"')

    def test_build_string_hex(self):
        yara_string = YaraString("test_name", "AA BB CC DD", str_type="hex")
        yara_string.build_string()
        self.assertEqual(yara_string.raw_string, "$test_name = {AA BB CC DD}")

    def test_build_string_regex(self):
        yara_string = YaraString("test_name", "test[0-9]{2}", str_type="regex")
        yara_string.build_string()
        self.assertEqual(yara_string.raw_string, "$test_name = /test[0-9]{2}/")
        
    def test_build_string_regex_w_regex_flags(self):
        yara_string = YaraString("test_name", "test[0-9]{2}", str_type="regex", regex_flags="i")
        yara_string.build_string()
        self.assertEqual(yara_string.raw_string, "$test_name = /test[0-9]{2}/i")

    def test_build_string_w_condition(self):
        yara_string = YaraString("test_name", "test_value")
        yara_string.modifiers = ["ascii", "wide"]
        yara_string.build_string()
        self.assertEqual(yara_string.raw_string, '$test_name = "test_value" ascii wide')

    def test_get_yara_string(self):
        yara_string = YaraString("test_name", "test_value")
        yara_string.modifiers = ["ascii", "wide"]
        yara_string.yara_comment = YaraComment()
        yara_string.yara_comment.inline = "test_comment"
        pod_yara_string = yara_string.get_yara_string()
        self.assertEqual(pod_yara_string["name"], "test_name")
        self.assertEqual(pod_yara_string["value"], "test_value")
        self.assertEqual(pod_yara_string["modifiers"], ["ascii", "wide"])
        self.assertEqual(pod_yara_string["comment"]["inline"], "test_comment")
        
    def test_get_yara_string_with_regex_flags(self):
        yara_string = YaraString("test_name", "test_regex", regex_flags="i")
        pod_yara_string = yara_string.get_yara_string()
        self.assertEqual(pod_yara_string["name"], "test_name")
        self.assertEqual(pod_yara_string["value"], "test_regex")
        self.assertEqual(pod_yara_string["regex_flags"], "i")

    def test_set_yara_string(self):
        yara_string = YaraString(None, None)
        yara_string.set_yara_string(
            {
                "comment": {"inline": "example comment"},
                "is_anonymous": False,
                "modifiers": ["ascii", "wide"],
                "name": "str",
                "str_type": "text",
                "value": "Named string",
            }
        )
        self.assertEqual(yara_string.yara_comment.inline, "example comment")
        self.assertEqual(yara_string.is_anonymous, False)
        self.assertEqual(yara_string.modifiers, ["ascii", "wide"])
        self.assertEqual(yara_string.name, "str")
        self.assertEqual(yara_string.str_type, "text")
        self.assertEqual(yara_string.value, "Named string")
        
    def test_set_yara_regex_string_with_flags(self):
        yara_string = YaraString(None, None)
        yara_string.set_yara_string(
            {
                "is_anonymous": False,
                "name": "str",
                "str_type": "regex",
                "value": "test regex",
                "regex_flags": "i"
            }
        )
        self.assertEqual(yara_string.is_anonymous, False)
        self.assertEqual(yara_string.name, "str")
        self.assertEqual(yara_string.str_type, "regex")
        self.assertEqual(yara_string.value, "test regex")
        self.assertEqual(yara_string.regex_flags, "i")

    def test_set_yara_string_invalid_keys(self):
        yara_string = YaraString(None, None)
        self.assertRaises(
            KeyError, yara_string.set_yara_string, {"invalid_key": "test"}
        )


class TestYaraStrings(unittest.TestCase):
    def setUp(self):
        self.yara_strings = YaraStrings()

    def test_add_string(self):
        self.yara_strings.add_string("test_name", "test_value")
        self.assertIn("test_name", self.yara_strings.strings)
        self.assertEqual(self.yara_strings.strings["test_name"].value, "test_value")
        self.assertEqual(self.yara_strings.number_of_strings, 1)

    def test_add_string_invalid_str_type(self):
        self.yara_strings.add_string("test_name", "test_value", str_type="invalid_type")
        self.assertEqual(self.yara_strings.strings["test_name"].str_type, "text")

    def test_add_anonymous_string_invalid_str_type(self):
        name = self.yara_strings.add_anonymous_string(
            "test_value", str_type="invalid_type"
        )
        self.assertEqual(self.yara_strings.strings[name].str_type, "text")

    def test_invalid_str_type_handler_valid_str_type(self):
        str_type = self.yara_strings._invalid_str_type_handler("hex")
        self.assertEqual(str_type, "hex")

    def test_invalid_str_type_handler_invalid_str_type(self):
        str_type = self.yara_strings._invalid_str_type_handler("invalid_type")
        self.assertEqual(str_type, "text")

    def test_no_duplicate_string_names(self):
        self.yara_strings.add_string("test_name", "test_value")
        self.assertRaises(
            ValueError, self.yara_strings.add_string, "test_name", "test_value"
        )

    def test_add_modifier(self):
        self.yara_strings.add_string("test_name", "test_value")
        self.yara_strings.add_modifier("test_name", "ascii")
        self.yara_strings.add_modifier("test_name", "wide")
        self.assertEqual(
            self.yara_strings.strings["test_name"].modifiers, ["ascii", "wide"]
        )

    def test_no_duplicate_modifiers(self):
        self.yara_strings.add_string("test_name", "test_value")
        self.yara_strings.add_modifier("test_name", "ascii")
        self.yara_strings.add_modifier("test_name", "wide")
        self.yara_strings.add_modifier("test_name", "ascii")
        self.assertEqual(
            self.yara_strings.strings["test_name"].modifiers, ["ascii", "wide"]
        )

    def test_add_modifier_when_no_matching_string(self):
        self.assertRaises(
            KeyError, self.yara_strings.add_modifier, "test_name", "test_value"
        )

    def test_add_anonymous_string_returned_name(self):
        name = self.yara_strings.add_anonymous_string("test_value")
        self.assertEqual(name, "@anon0")

    def test_add_anonymous_string(self):
        name = self.yara_strings.add_anonymous_string("test_value")
        self.assertIn(name, self.yara_strings.strings)
        self.assertEqual(self.yara_strings.strings[name].value, "test_value")
        self.assertEqual(self.yara_strings.number_of_strings, 1)
        self.assertEqual(self.yara_strings.number_of_anonymous_strings, 1)

    def test_error_when_adding_modifier_to_hex_string(self):
        self.yara_strings.add_string("test_name", "AA BB CC DD", str_type="hex")
        self.assertRaises(
            TypeError, self.yara_strings.add_modifier, "test_name", "ascii"
        )

    def test_build_text_strings(self):
        self.yara_strings.add_anonymous_string("anon_test")

        self.yara_strings.add_string("test_name1", "test_value1")
        self.yara_strings.add_modifier("test_name1", "ascii")
        self.yara_strings.add_modifier("test_name1", "wide")

        self.yara_strings.add_string("test_name2", "test_value2")
        self.yara_strings.add_modifier("test_name2", "nocase")

        self.yara_strings.build_strings()

        self.assertEqual(
            self.yara_strings.raw_strings,
            [
                '$ = "anon_test"',
                '$test_name1 = "test_value1" ascii wide',
                '$test_name2 = "test_value2" nocase',
            ],
        )

    def test_build_hex_strings(self):
        self.yara_strings.add_anonymous_string("AA BB CC DD", str_type="hex")

        self.yara_strings.add_string("test_name1", "EE FF 00 11", str_type="hex")

        self.yara_strings.build_strings()

        self.assertEqual(
            self.yara_strings.raw_strings,
            ["$ = {AA BB CC DD}", "$test_name1 = {EE FF 00 11}"],
        )

    def test_build_regex_strings(self):
        self.yara_strings.add_anonymous_string("anon_test[0-9]{2}", str_type="regex")

        self.yara_strings.add_string("test_name1", "test_value\\d", str_type="regex")
        self.yara_strings.add_modifier("test_name1", "ascii")
        self.yara_strings.add_modifier("test_name1", "wide")

        self.yara_strings.add_string("test_name2", "test_value\\D", str_type="regex")
        self.yara_strings.add_modifier("test_name2", "nocase")

        self.yara_strings.build_strings()

        self.assertEqual(
            self.yara_strings.raw_strings,
            [
                "$ = /anon_test[0-9]{2}/",
                "$test_name1 = /test_value\\d/ ascii wide",
                "$test_name2 = /test_value\\D/ nocase",
            ],
        )
        
    def test_build_regex_strings_w_regex_flag(self):
        self.yara_strings.add_anonymous_string("anon_test[0-9]{2}", str_type="regex", regex_flags="i")

        self.yara_strings.add_string("test_name1", "test_value\\d", str_type="regex", regex_flags="s")
        self.yara_strings.add_modifier("test_name1", "ascii")
        self.yara_strings.add_modifier("test_name1", "wide")
        
        self.yara_strings.add_string("test_name2", "test_value\\D", str_type="regex", regex_flags="is")
        self.yara_strings.add_modifier("test_name2", "nocase")

        self.yara_strings.build_strings()

        self.assertEqual(
            self.yara_strings.raw_strings,
            [
                "$ = /anon_test[0-9]{2}/i",
                "$test_name1 = /test_value\\d/s ascii wide",
                "$test_name2 = /test_value\\D/is nocase",
            ],
        )

    def test_get_yara_strings(self):
        self.yara_strings.add_string("test_name1", "test_value1")
        self.yara_strings.add_modifier("test_name1", "ascii")
        self.yara_strings.add_modifier("test_name1", "wide")
        self.yara_strings.add_string("test_name2", "test_value2")
        yara_strings = self.yara_strings.get_yara_strings()
        self.assertEqual(yara_strings["test_name1"]["value"], "test_value1")
        self.assertEqual(yara_strings["test_name1"]["modifiers"], ["ascii", "wide"])
        self.assertEqual(yara_strings["test_name2"]["value"], "test_value2")

    def test_set_yara_strings(self):
        self.yara_strings.set_yara_strings(
            collections.OrderedDict(
                [
                    (
                        "@anon0",
                        {
                            "is_anonymous": True,
                            "name": "@anon0",
                            "str_type": "text",
                            "value": "Anonymous string",
                        },
                    ),
                    (
                        "str",
                        {
                            "comment": {"inline": "example comment"},
                            "is_anonymous": False,
                            "modifiers": ["ascii", "wide"],
                            "name": "str",
                            "str_type": "text",
                            "value": "Named string",
                        },
                    ),
                ]
            )
        )
        self.assertEqual(self.yara_strings.strings["@anon0"].value, "Anonymous string")
        self.assertEqual(self.yara_strings.strings["str"].value, "Named string")


class TestYaraMeta(unittest.TestCase):
    def setUp(self):
        self.yara_meta = YaraMeta()

    def test_add_new_meta(self):
        self.yara_meta.add_meta("test_name", "test_value")
        self.assertIn("test_name", self.yara_meta.meta)
        self.assertEqual(self.yara_meta.meta["test_name"][0].value, "test_value")
        self.assertEqual(self.yara_meta.meta["test_name"][0].meta_type, "text")
        self.assertEqual(self.yara_meta.meta["test_name"][0].position, 0)

    def test_add_duplicate_meta_name(self):
        self.yara_meta.add_meta("test_name", "test_value1")
        self.yara_meta.add_meta("test_name", "test_value2")
        self.assertIn("test_name", self.yara_meta.meta)
        self.assertEqual(self.yara_meta.meta["test_name"][0].value, "test_value1")
        self.assertEqual(self.yara_meta.meta["test_name"][0].meta_type, "text")
        self.assertEqual(self.yara_meta.meta["test_name"][0].position, 0)
        self.assertEqual(self.yara_meta.meta["test_name"][1].value, "test_value2")
        self.assertEqual(self.yara_meta.meta["test_name"][1].meta_type, "text")
        self.assertEqual(self.yara_meta.meta["test_name"][1].position, 1)

    def test_add_meta_text(self):
        self.yara_meta.add_meta("test_name", "test_value", meta_type="text")
        self.assertIsInstance(self.yara_meta.meta["test_name"][0].value, str)

    def test_add_meta_int(self):
        self.yara_meta.add_meta("test_name", 10, meta_type="int")
        self.assertIsInstance(self.yara_meta.meta["test_name"][0].value, int)

    def test_add_meta_bool(self):
        self.yara_meta.add_meta("test_name", True, meta_type="bool")
        self.assertIsInstance(self.yara_meta.meta["test_name"][0].value, bool)

    def test_add_invalid_meta_type(self):
        self.yara_meta.add_meta("test_name", "test_value", meta_type="invalid_type")
        self.assertEqual(self.yara_meta.meta["test_name"][0].meta_type, "text")

    def test_build_meta(self):
        self.yara_meta.add_meta("test_name1", "test_value1")
        self.yara_meta.add_meta("test_name2", 10, meta_type="int")
        self.yara_meta.add_meta("test_name3", True, meta_type="bool")
        self.yara_meta.add_meta("test_name4", False, meta_type="bool")
        self.yara_meta.build_meta()
        self.assertEqual(
            self.yara_meta.raw_meta,
            [
                'test_name1 = "test_value1"',
                "test_name2 = 10",
                "test_name3 = true",
                "test_name4 = false",
            ],
        )

    def test_get_yara_meta(self):
        self.yara_meta.add_meta("test_name", "test_value1")
        self.yara_meta.add_meta("test_name", "test_value2")
        pod_yara_meta = self.yara_meta.get_yara_meta()
        self.assertEqual(pod_yara_meta["test_name"][0]["value"], "test_value1")
        self.assertEqual(pod_yara_meta["test_name"][1]["value"], "test_value2")

    def test_set_yara_meta(self):
        self.yara_meta.set_yara_meta(
            collections.OrderedDict(
                [
                    (
                        "test_name",
                        [
                            {
                                "meta_type": "text",
                                "name": "test_name",
                                "position": 0,
                                "value": "test_1",
                            },
                            {
                                "meta_type": "text",
                                "name": "test_name",
                                "position": 1,
                                "value": "test_2",
                            },
                        ],
                    )
                ]
            )
        )
        self.assertEqual(self.yara_meta.meta["test_name"][0].value, "test_1")
        self.assertEqual(self.yara_meta.meta["test_name"][1].value, "test_2")


class TestYaraMetaEntry(unittest.TestCase):
    def test_yara_meta_entry_constructor(self):
        yara_meta_entry = YaraMetaEntry("test_name", "test_value", 0)
        self.assertEqual(yara_meta_entry.name, "test_name")
        self.assertEqual(yara_meta_entry.value, "test_value")
        self.assertEqual(yara_meta_entry.position, 0)

    def test_build_meta_entry_text(self):
        yara_meta_entry = YaraMetaEntry("test_name", "test_value", 0)
        yara_meta_entry.build_meta_entry()
        self.assertEqual(yara_meta_entry.raw_meta_entry, 'test_name = "test_value"')

    def test_build_meta_entry_int(self):
        yara_meta_entry = YaraMetaEntry("test_name", 10, 0, meta_type="int")
        yara_meta_entry.build_meta_entry()
        self.assertEqual(yara_meta_entry.raw_meta_entry, "test_name = 10")

    def test_build_meta_entry_bool(self):
        yara_meta_entry = YaraMetaEntry("test_name", True, 0, meta_type="bool")
        yara_meta_entry.build_meta_entry()
        self.assertEqual(yara_meta_entry.raw_meta_entry, "test_name = true")

        yara_meta_entry = YaraMetaEntry("test_name", False, 0, meta_type="bool")
        yara_meta_entry.build_meta_entry()
        self.assertEqual(yara_meta_entry.raw_meta_entry, "test_name = false")

    def test_get_yara_meta_entry(self):
        yara_meta_entry = YaraMetaEntry("test_name", "test_value", 0)
        yara_meta_entry.yara_comment.inline = "test_inline_comment"
        pod_yara_meta_entry = yara_meta_entry.get_yara_meta_entry()
        self.assertEqual(pod_yara_meta_entry["name"], "test_name")
        self.assertEqual(pod_yara_meta_entry["value"], "test_value")
        self.assertEqual(pod_yara_meta_entry["position"], 0)
        self.assertEqual(pod_yara_meta_entry["meta_type"], "text")
        self.assertEqual(
            pod_yara_meta_entry["comment"]["inline"], "test_inline_comment"
        )

    def test_set_yara_meta_entry(self):
        yara_meta_entry = YaraMetaEntry(None, None, None)
        yara_comment = {"inline": "test_inline_comment"}
        yara_meta_entry.set_yara_meta_entry(
            {
                "name": "test_name",
                "value": "test_value",
                "position": 0,
                "meta_type": "text",
                "comment": yara_comment,
            }
        )
        self.assertEqual(yara_meta_entry.name, "test_name")
        self.assertEqual(yara_meta_entry.value, "test_value")
        self.assertEqual(yara_meta_entry.position, 0)
        self.assertEqual(yara_meta_entry.yara_comment.inline, "test_inline_comment")

    def test_set_yara_meta_entry_invalid_keys(self):
        yara_meta_entry = YaraMetaEntry(None, None, None)
        self.assertRaises(
            KeyError, yara_meta_entry.set_yara_meta_entry, {"invalid_key": "test"}
        )
