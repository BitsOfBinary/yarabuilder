import unittest
import collections
import unittest.mock

from yarabuilder import (
    YaraRule,
    YaraCondition,
    YaraTags,
    YaraImports,
    YaraString,
    YaraStrings,
    YaraMeta,
    YaraMetaEntry, YaraBuilder,
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
        self.assertFalse(self.yara_rule.build_rule())

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

    def test_build_strings(self):
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

    def test_build_meta(self):
        self.yara_meta.add_meta("test_name", "test_value1")
        self.yara_meta.add_meta("test_name", "test_value2")
        self.yara_meta.build_meta()
        self.assertEqual(
            self.yara_meta.raw_meta,
            ['test_name = "test_value1"', 'test_name = "test_value2"'],
        )


class TestYaraMetaEntry(unittest.TestCase):
    def test_yara_meta_entry_constructor(self):
        yara_meta_entry = YaraMetaEntry("test_value", 0)
        self.assertEqual(yara_meta_entry.value, "test_value")
        self.assertEqual(yara_meta_entry.position, 0)


class TestYaraBuilder(unittest.TestCase):
    @unittest.mock.patch('yarabuilder.YaraRule')
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