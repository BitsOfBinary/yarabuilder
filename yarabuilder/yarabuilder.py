"""
yarabuilder.py
====================================
The main interface to work with YaraRule objects
"""

import logging
import collections

from yarabuilder.yararule import YaraRule


class YaraBuilder:
    def __init__(self, ws="    "):
        self.ws = ws
        self.yara_rules = collections.OrderedDict()

    def no_rule_name_exception_handler(self, rule_name):
        if rule_name not in self.yara_rules:
            raise KeyError('Rule  "%s" doesn\'t exist', rule_name)

    def create_rule(self, rule_name):
        if rule_name in self.yara_rules:
            raise KeyError('Rule with name "%s" already exists', rule_name)

        self.yara_rules[rule_name] = YaraRule(rule_name)

    def add_tag(self, rule_name, tag):
        self.no_rule_name_exception_handler(rule_name)
        self.yara_rules[rule_name].tags.add_tag(tag)

    def add_import(self, rule_name, import_str):
        self.no_rule_name_exception_handler(rule_name)
        self.yara_rules[rule_name].imports.add_import(import_str)

    def add_meta(self, rule_name, name, value, meta_type=None):
        self.no_rule_name_exception_handler(rule_name)

        if meta_type:
            self.yara_rules[rule_name].meta.add_meta(name, value, meta_type=meta_type)

        elif value is True or value is False:
            self.yara_rules[rule_name].meta.add_meta(name, value, meta_type="bool")

        elif isinstance(value, int):
            self.yara_rules[rule_name].meta.add_meta(name, value, meta_type="int")

        elif isinstance(value, str):
            self.yara_rules[rule_name].meta.add_meta(name, value, meta_type="text")

    def add_text_string(self, rule_name, value, name=None):
        self.no_rule_name_exception_handler(rule_name)

        if name:
            self.yara_rules[rule_name].strings.add_string(name, value, str_type="text")

        else:
            self.yara_rules[rule_name].strings.add_anonymous_string(
                value, str_type="text"
            )

    def add_hex_string(self, rule_name, value, name=None):
        self.no_rule_name_exception_handler(rule_name)

        if name:
            self.yara_rules[rule_name].strings.add_string(name, value, str_type="hex")

        else:
            self.yara_rules[rule_name].strings.add_anonymous_string(
                value, str_type="hex"
            )

    def add_regex_string(self, rule_name, value, name=None):
        self.no_rule_name_exception_handler(rule_name)

        if name:
            self.yara_rules[rule_name].strings.add_string(name, value, str_type="regex")

        else:
            self.yara_rules[rule_name].strings.add_anonymous_string(
                value, str_type="regex"
            )

    def add_condition(self, rule_name, condition):
        self.no_rule_name_exception_handler(rule_name)

        self.yara_rules[rule_name].condition.add_raw_condition(condition)

    def build_rule(self, rule_name):
        self.no_rule_name_exception_handler(rule_name)

        return self.yara_rules[rule_name].build_rule()

    def build_rules(self):
        built_rules = []

        for rule in self.yara_rules.values():
            built_rules.append(rule.build_rule())

        return "\n\n".join(built_rules)


def main():  # pragma: no cover
    logging.basicConfig(level=logging.DEBUG)

    yara_builder = YaraBuilder()

    yara_builder.create_rule("test_rule1")
    yara_builder.add_meta("test_rule1", "test_name", "test_value")
    yara_builder.add_condition("test_rule1", "filesize > 0")

    yara_builder.create_rule("test_rule2")
    yara_builder.add_text_string("test_rule2", "hello")
    yara_builder.add_text_string("test_rule2", "world")
    yara_builder.add_condition("test_rule2", "any of them")

    print(yara_builder.build_rules())


if __name__ == "__main__":  # pragma: no cover
    main()
