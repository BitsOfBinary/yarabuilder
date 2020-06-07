import logging
import collections


class YaraMetaEntry:
    def __init__(self, value, position, meta_type="text"):
        self.value = value
        self.position = position
        self.meta_type = meta_type


class YaraMeta:
    def __init__(self):
        self.meta = collections.OrderedDict()
        self.raw_meta = []
        self.number_of_meta_entries = 0

    def add_meta(self, name, value, meta_type="text"):
        if name not in self.meta:
            self.meta[name] = []

        self.meta[name].append(
            YaraMetaEntry(value, self.number_of_meta_entries, meta_type)
        )

        self.number_of_meta_entries += 1

    def build_meta(self):
        self.raw_meta = [None] * self.number_of_meta_entries

        for meta_name, meta_entries in self.meta.items():
            for meta_entry in meta_entries:
                self.raw_meta[meta_entry.position] = '%s = "%s"' % (
                    meta_name,
                    meta_entry.value,
                )


class YaraString:
    def __init__(self, value, str_type="text", is_anonymous=False):
        self.value = value
        self.str_type = str_type
        self.modifiers = []
        self.is_anonymous = is_anonymous


class YaraStrings:
    def __init__(self):
        self.raw_strings = []
        self.strings = collections.OrderedDict()
        self.number_of_strings = 0
        self.number_of_anonymous_strings = 0

    def add_string(self, name, value, str_type="text"):

        if name in self.strings:
            raise ValueError('String with name "%s" already exists', name)

        self.strings[name] = YaraString(value, str_type)
        self.number_of_strings += 1

    def add_anonymous_string(self, value, str_type="text"):
        name = "@anon%d" % self.number_of_anonymous_strings
        self.strings[name] = YaraString(value, str_type, is_anonymous=True)
        self.number_of_strings += 1
        self.number_of_anonymous_strings += 1

        return name

    def add_modifier(self, name, modifier):
        if name not in self.strings:
            raise KeyError("String with name %s doesn't exist", name)

        if self.strings[name].str_type == "hex":
            raise TypeError(
                'String with name %s is of type "hex", and cannot have modifiers added',
                name,
            )

        if modifier not in self.strings[name].modifiers:
            self.strings[name].modifiers.append(modifier)

    def build_strings(self):
        for name, yara_string in self.strings.items():
            raw_string = "$"

            if not yara_string.is_anonymous:
                raw_string += name

            raw_string += " = "

            if yara_string.str_type == "text":
                raw_string += '"%s"' % yara_string.value

            elif yara_string.str_type == "hex":
                raw_string += "{%s}" % yara_string.value

            elif yara_string.str_type == "regex":
                raw_string += "/%s/" % yara_string.value

            if yara_string.modifiers:
                for modifier in yara_string.modifiers:
                    raw_string += " %s" % modifier

            self.raw_strings.append(raw_string)


class YaraCondition:
    def __init__(self):
        self.raw_condition = None

    def add_raw_condition(self, raw_condition):
        self.raw_condition = raw_condition


class YaraImports:
    def __init__(self):
        self.raw_imports = ""
        self.imports = []

    def has_imports(self):
        if self.imports:
            return True
        else:
            return False

    def add_import(self, import_str):
        if import_str not in self.imports:
            self.imports.append(import_str)

    def build_imports(self):
        for import_str in self.imports:
            self.raw_imports += 'import "%s"\n' % import_str


class YaraTags:
    def __init__(self):
        self.tags = []
        self.raw_tags = ""

    def has_tags(self):
        if self.tags:
            return True
        else:
            return False

    def add_tag(self, tag):
        self.tags.append(tag)

    def build_tags(self):
        self.raw_tags = " ".join(self.tags)


class YaraRule:
    def __init__(self, rule_name, ws="    "):
        self.rule_name = rule_name
        self.ws = ws

        self.raw_rule = ""
        self.meta = YaraMeta()
        self.strings = YaraStrings()
        self.condition = YaraCondition()
        self.imports = YaraImports()
        self.tags = YaraTags()

    def build_rule_header(self, rule):
        if self.imports.has_imports():
            self.imports.build_imports()
            rule += "%s\n" % self.imports.raw_imports

        if self.tags.has_tags():
            self.tags.build_tags()
            rule += "rule %s : %s {\n" % (self.rule_name, self.tags.raw_tags)
        else:
            rule += "rule %s {\n" % self.rule_name

        return rule

    def build_rule_condition_section(self, rule):
        rule += "%scondition:\n" % self.ws
        rule += "%s%s%s\n" % (self.ws, self.ws, self.condition.raw_condition)
        rule += "}"

        return rule

    def build_rule_strings_section(self, rule):
        self.strings.build_strings()

        rule += "%sstrings:\n" % self.ws

        for raw_string in self.strings.raw_strings:
            rule += "%s%s%s\n" % (self.ws, self.ws, raw_string)

        rule += "\n"

        return rule

    def build_rule_meta_section(self, rule):
        self.meta.build_meta()

        rule += "%smeta:\n" % self.ws

        for raw_meta_entry in self.meta.raw_meta:
            rule += "%s%s%s\n" % (self.ws, self.ws, raw_meta_entry)

        rule += "\n"

        return rule

    def build_rule(self):

        if not self.condition.raw_condition:
            logging.error("%s has no raw_condition, cannot build rule", self.rule_name)
            return False

        else:
            self.raw_rule = self.build_rule_header(self.raw_rule)

            if self.meta.number_of_meta_entries > 0:
                self.raw_rule = self.build_rule_meta_section(self.raw_rule)

            if self.strings.number_of_strings > 0:
                self.raw_rule = self.build_rule_strings_section(self.raw_rule)

            self.raw_rule = self.build_rule_condition_section(self.raw_rule)

            return self.raw_rule


def main():  # pragma: no cover
    logging.basicConfig(level=logging.DEBUG)

    rule = YaraRule("command_line_rule")
    rule.condition.add_raw_condition("filesize > 0")
    rule.tags.add_tag("test1")
    rule.tags.add_tag("test2")
    rule.imports.add_import("pe")
    rule.imports.add_import("math")
    rule.meta.add_meta("test_meta", "test1")
    rule.meta.add_meta("test_meta", "test2")
    rule.strings.add_string("test_string_text", "string_text_val")
    rule.strings.add_modifier("test_string_text", "ascii")
    rule.strings.add_string("test_string_hex", "AA BB CC DD", str_type="hex")
    rule.strings.add_string("test_string_regex", "[0-9]{10}", str_type="regex")
    print(rule.build_rule())


if __name__ == "__main__":  # pragma: no cover
    main()
