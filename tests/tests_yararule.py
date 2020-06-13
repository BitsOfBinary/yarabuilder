import unittest

from yarabuilder.yararule import (
    YaraRule,
    YaraCondition,
    YaraTags,
    YaraImports,
    YaraString,
    YaraStrings,
    YaraMeta,
    YaraMetaEntry,
)


class TestYaraRule(unittest.TestCase):
    def setUp(self):
        self.test_rule_name = "test_rule"
        self.test_condition = "filesize > 0"
        self.yara_rule = YaraRule(self.test_rule_name)
        self.raw_rule = ""

    def test_yara_rule_init(self):
        self.assertEqual(self.test_rule_name, self.yara_rule.rule_name)
        self.assertEqual("    ", self.yara_rule.ws)

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
            '    meta:\n        '
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


class TestYaraCondition(unittest.TestCase):
    def test_add_raw_condition(self):
        condition = YaraCondition()
        condition.add_raw_condition("filesize > 0")
        self.assertEqual("filesize > 0", condition.raw_condition)


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


class TestYaraString(unittest.TestCase):
    def setUp(self):
        self.yara_string = YaraString("test_value")

    def test_yara_string_constructor(self):
        self.assertEqual(self.yara_string.value, "test_value")
        self.assertEqual(self.yara_string.str_type, "text")


class TestYaraStrings(unittest.TestCase):
    def setUp(self):
        self.yara_strings = YaraStrings()

    def test_add_string(self):
        self.yara_strings.add_string("test_name", "test_value")
        self.assertIn("test_name", self.yara_strings.strings)
        self.assertEqual(self.yara_strings.strings["test_name"].value, "test_value")
        self.assertEqual(self.yara_strings.number_of_strings, 1)

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
            ["$ = {AA BB CC DD}", "$test_name1 = {EE FF 00 11}",],
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


class TestYaraMetaEntry(unittest.TestCase):
    def test_yara_meta_entry_constructor(self):
        yara_meta_entry = YaraMetaEntry("test_value", 0)
        self.assertEqual(yara_meta_entry.value, "test_value")
        self.assertEqual(yara_meta_entry.position, 0)
