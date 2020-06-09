"""
Python representation of a YARA rule
"""

import collections


class YaraMetaEntry:
    """
    Class to represent an entry in the meta section
    """

    def __init__(self, value, position, meta_type="text"):
        """
        Constructor for YaraMetaEntry
        :param value: the meta entry
        :param position: the position in the meta section
        :param meta_type: the type of the meta entry
        """
        self.value = value
        self.position = position
        self.meta_type = meta_type


class YaraMeta:
    """
    Class to represent the YARA meta section
    """

    def __init__(self):
        """
        Constructor for YaraMeta
        """
        self.meta = collections.OrderedDict()
        self.raw_meta = []
        self.number_of_meta_entries = 0

    def add_meta(self, name, value, meta_type="text"):
        """
        Add a YaraMetaEntry to YaraMeta
        :param name: the name of the meta entry
        :param value: the meta entry
        :param meta_type: the type of the meta entry (defaults to "text")
        """
        if name not in self.meta:
            self.meta[name] = []

        self.meta[name].append(
            YaraMetaEntry(value, self.number_of_meta_entries, meta_type)
        )

        self.number_of_meta_entries += 1

    def build_meta(self):
        """
        Build the meta section in the correct order
        """
        self.raw_meta = [None] * self.number_of_meta_entries

        for meta_name, meta_entries in self.meta.items():
            for meta_entry in meta_entries:
                if meta_entry.meta_type == "text":
                    self.raw_meta[meta_entry.position] = '%s = "%s"' % (
                        meta_name,
                        meta_entry.value,
                    )

                elif meta_entry.meta_type == "int":
                    self.raw_meta[meta_entry.position] = "%s = %d" % (
                        meta_name,
                        meta_entry.value,
                    )

                if meta_entry.meta_type == "bool":
                    if meta_entry.value:
                        self.raw_meta[meta_entry.position] = "%s = true" % meta_name

                    else:
                        self.raw_meta[meta_entry.position] = "%s = false" % meta_name


class YaraString:
    """
    Class to represent a string object
    """

    def __init__(self, value, str_type="text", is_anonymous=False):
        """
        Constructor for YaraString
        :param value: the value of the string
        :param str_type: the type of the string ("text", "hex", or "regex")
        :param is_anonymous: bool set to False by default
        """
        self.value = value
        self.str_type = str_type
        self.modifiers = []
        self.is_anonymous = is_anonymous


class YaraStrings:
    """
    Class to represent the YARA strings section
    """

    def __init__(self):
        """
        Constructor for YaraStrings
        """
        self.raw_strings = []
        self.strings = collections.OrderedDict()
        self.number_of_strings = 0
        self.number_of_anonymous_strings = 0

    def add_string(self, name, value, str_type="text"):
        """
        Add a named string to the YaraStrings object
        :param name: name of the string
        :param value: the string
        :param str_type: the type of the string ("text", "hex", "regex")
        """
        if name in self.strings:
            raise ValueError('String with name "%s" already exists', name)

        self.strings[name] = YaraString(value, str_type)
        self.number_of_strings += 1

    def add_anonymous_string(self, value, str_type="text"):
        """
        Add an anonymous string to the YaraStrings object
        :param value: the string
        :param str_type: the type of the string ("text", "hex", "regex")
        :return: the generated name of the string for later handling
        """
        name = "@anon%d" % self.number_of_anonymous_strings
        self.strings[name] = YaraString(value, str_type, is_anonymous=True)
        self.number_of_strings += 1
        self.number_of_anonymous_strings += 1

        return name

    def add_modifier(self, name, modifier):
        """
        Add a modifier to a string
        :param name: the name of the string to add the modifier to
        :param modifier: the modifier to add
        """
        if name not in self.strings:
            raise KeyError("String with name %s doesn't exist", name)

        if self.strings[name].str_type == "hex":
            raise TypeError(
                'String with name {0} is of type "hex", and cannot have modifiers added'.format(
                    name
                )
            )

        if modifier not in self.strings[name].modifiers:
            self.strings[name].modifiers.append(modifier)

    def build_strings(self):
        """
        Build each string object
        """
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
    """
    Class to represent the YARA condition section
    """

    def __init__(self):
        """
        Constructor for YaraCondition
        """
        self.raw_condition = None

    def add_raw_condition(self, raw_condition):
        """
        Add a raw condition
        :param raw_condition: the string representing the condition
        """
        self.raw_condition = raw_condition


class YaraImports:
    """
    Class to represent the YARA imports section
    """

    def __init__(self):
        """
        Constructor for YaraImports
        """
        self.raw_imports = ""
        self.imports = []

    def has_imports(self):
        """
        Utility method to determine if there are any imports
        :return: True if there are imports, False otherwise
        """
        if self.imports:
            return True

        return False

    def add_import(self, import_str):
        """
        Add an import to the YaraImports object
        :param import_str: the import string to add
        """
        if import_str not in self.imports:
            self.imports.append(import_str)

    def build_imports(self):
        """
        Build the imports section into one string
        """
        for import_str in self.imports:
            self.raw_imports += 'import "%s"\n' % import_str


class YaraTags:
    """
    Class to represent the YARA tags section
    """

    def __init__(self):
        """
        Constructor for YaraTags
        """
        self.tags = []
        self.raw_tags = ""

    def has_tags(self):
        """
        Utility method to determine if there are any tags
        :return: True if there are tags, False otherwise
        """
        if self.tags:
            return True

        return False

    def add_tag(self, tag):
        """
        Add a tag to the YaraTags object
        :param tag: the string representing the tag
        """
        self.tags.append(tag)

    def build_tags(self):
        """
        Build the tags into one string
        """
        self.raw_tags = " ".join(self.tags)


class YaraRule:
    """
    Class to represent a YARA rule
    """

    def __init__(self, rule_name, ws="    "):
        """
        Constructor for YaraRule
        :param rule_name: the name of the rule to create (every rule has to have a name)
        :param ws: whitespace to use when building the rule (defaults to 4 spaces)
        """
        self.rule_name = rule_name
        self.ws = ws

        self.raw_rule = ""
        self.meta = YaraMeta()
        self.strings = YaraStrings()
        self.condition = YaraCondition()
        self.imports = YaraImports()
        self.tags = YaraTags()

    def build_rule_header(self, rule):
        """
        Method to build the rule header, including the imports, tags and rule_name
        :param rule: string of the rule built so far
        :return: string of the built rule with added rule header
        """
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
        """
        Method to build the rule condition section
        :param rule: string of the rule built so far
        :return: string of the built rule with added rule condition
        """
        rule += "%scondition:\n" % self.ws
        rule += "%s%s%s\n" % (self.ws, self.ws, self.condition.raw_condition)
        rule += "}"

        return rule

    def build_rule_strings_section(self, rule):
        """
        Method to build the rule strings section
        :param rule: string of the rule built so far
        :return: string of the built rule with added rule strings
        """
        self.strings.build_strings()

        rule += "%sstrings:\n" % self.ws

        for raw_string in self.strings.raw_strings:
            rule += "%s%s%s\n" % (self.ws, self.ws, raw_string)

        rule += "\n"

        return rule

    def build_rule_meta_section(self, rule):
        """
        Method to build the rule meta section
        :param rule: string of the rule built so far
        :return: string of the built rule with added rule meta
        """
        self.meta.build_meta()

        rule += "%smeta:\n" % self.ws

        for raw_meta_entry in self.meta.raw_meta:
            rule += "%s%s%s\n" % (self.ws, self.ws, raw_meta_entry)

        rule += "\n"

        return rule

    def build_rule(self):
        """
        Method to build the whole YARA rule
        :return: the string of the built rule
        """
        if not self.condition.raw_condition:
            raise KeyError(
                '"{0}" has no raw_condition, cannot build rule'.format(self.rule_name)
            )

        self.raw_rule = self.build_rule_header(self.raw_rule)

        if self.meta.number_of_meta_entries > 0:
            self.raw_rule = self.build_rule_meta_section(self.raw_rule)

        if self.strings.number_of_strings > 0:
            self.raw_rule = self.build_rule_strings_section(self.raw_rule)

        self.raw_rule = self.build_rule_condition_section(self.raw_rule)

        return self.raw_rule


def main():  # pragma: no cover
    """
    Method to test if running the module from the command line
    """
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
