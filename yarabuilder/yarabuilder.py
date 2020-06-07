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

        elif isinstance(value, str):
            self.yara_rules[rule_name].meta.add_meta(name, value, meta_type="text")

    def add_string(self, rule_name, string):
        pass

    def add_condition(self, rule_name, condition):
        pass

    def build_rule(self, rule_name):
        pass

    def build_rules(self):
        pass


def main():  # pragma: no cover
    logging.basicConfig(level=logging.DEBUG)


if __name__ == "__main__":  # pragma: no cover
    main()
