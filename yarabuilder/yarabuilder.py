"""
The main interface to work with YaraRule objects
"""

import logging
import collections

from yarabuilder.yararule import YaraRule


class YaraBuilder:
    """
    Main class to interface with the YaraRule object

    Attributes:
        yara_rules (OrderedDict()): collection of YaraRule objects being built
        logger: the logger for this class

    Todo:
        * Add in optional validation for the string modifiers
        * Add in optional validation for the imports
    """

    def __init__(self, whitespace="    ", logger=None):
        """
        Initialise YaraBuilder

        Args:
            whitespace (str): whitespace to use when building the rules (defaults to 4 spaces)
            logger (optional): logger to use in the class
        """
        self.whitespace = whitespace
        self.yara_rules = collections.OrderedDict()
        self.logger = logger or logging.getLogger(__name__)

    def _no_rule_name_exception_handler(self, rule_name):
        """
        Handler for if a rule_name is not present in the YaraBuilder object

        Args:
            rule_name (str): the rule_name to check if present in the YaraBuilder
        """
        if rule_name not in self.yara_rules:
            raise KeyError('Rule "{0}" doesn\'t exist'.format(rule_name))

    def create_rule(self, rule_name):
        """
        Create a new YaraRule object in the YaraBuilder

        Args:
            rule_name (str): the name of the rule to create
        """
        if rule_name in self.yara_rules:
            raise KeyError('Rule with name "{0}" already exists'.format(rule_name))

        self.logger.debug("Creating %s...", rule_name)
        self.yara_rules[rule_name] = YaraRule(rule_name, whitespace=self.whitespace)

    def add_tag(self, rule_name, tag):
        """
        Add a tag to a specified rule (i.e. appears after the rule_name when built)

        Args:
            rule_name (str): the rule_name to add the tag to
            tag (str): the tag to be added
        """
        self._no_rule_name_exception_handler(rule_name)
        self.yara_rules[rule_name].tags.add_tag(tag)

    def add_import(self, rule_name, import_str):
        """
        Add an import to a specified rule (i.e. appears before the rule_name when built)

        Args:
            rule_name (str): the rule_name to add the import to
            import_str (str): the import to be added
        """
        self._no_rule_name_exception_handler(rule_name)
        self.yara_rules[rule_name].imports.add_import(import_str)

    def add_meta(self, rule_name, name, value, meta_type=None):
        """
        Add a meta key/value pair to the specified rule_name

        Args:
            rule_name (str): the rule_name to add the meta to
            name (str): the name of the meta key
            value (str/int/bool): the value to go in the metadata
            meta_type (str, optional): the type of the meta data,
                       which will be determined by the function if nothing supplied
        """
        self._no_rule_name_exception_handler(rule_name)

        if not meta_type:
            if value is True or value is False:
                meta_type = "bool"

            elif isinstance(value, int):
                meta_type = "int"

            else:
                meta_type = "text"

        self.logger.debug("Using meta_type %s", meta_type)
        self.yara_rules[rule_name].meta.add_meta(name, value, meta_type=meta_type)

    def add_text_string(self, rule_name, value, name=None, modifiers=None):
        """
        Wrapper method to add a text string (e.g. $ = "test") to the specified rule_name

        Args:
            rule_name (str): the rule_name to add the string to
            value (str): the text string
            name (str, optional): the optional name of the string
                (if not provided will add as anonymous string)
            modifiers (:obj:`list` of :obj:`str`, optional): any modifiers to add to the string
        """
        self._add_string(rule_name, value, "text", name=name, modifiers=modifiers)

    def add_hex_string(self, rule_name, value, name=None, modifiers=None):
        """
        Wrapper method to add a hex string (e.g. $ = {DE AD BE EF}) to the specified rule_name

        Args:
            rule_name (str): the rule_name to add the string to
            value (str): the hex string
            name (str, optional): the name of the string
                (if not provided will add as anonymous string)
            modifiers (:obj:`list` of :obj:`str`, optional): any modifiers to add to the string
        """
        self._add_string(rule_name, value, "hex", name=name, modifiers=modifiers)

    def add_regex_string(self, rule_name, value, name=None, modifiers=None):
        """
        Wrapper method to add a regex string (e.g. $ = /test[0-9]{2}/) to the specified rule_name

        Args:
            rule_name (str): the rule_name to add the string to
            value (str): the regex string
            name (str, optional): the name of the string
                (if not provided will add as anonymous string)
            modifiers (:obj:`list` of :obj:`str`, optional): any modifiers to add to the string
        """
        self._add_string(rule_name, value, "regex", name=name, modifiers=modifiers)

    def _add_string(self, rule_name, value, str_type, name=None, modifiers=None):
        """
        Generic method to add a string based on the wrapper method call

        Args:
            rule_name (str): the rule_name to add the string to
            value (str): the string
            str_type (str): the type of the string
            name (str, optional): the name of the string
                (if not provided will add as anonymous string):
            modifiers (:obj:`list` of :obj:`str`, optional): any modifiers to add to the string
        """

        if modifiers is None:
            modifiers = []
        self._no_rule_name_exception_handler(rule_name)

        if name:
            self.yara_rules[rule_name].strings.add_string(name, value, str_type=str_type)

        else:
            self.yara_rules[rule_name].strings.add_anonymous_string(
                value, str_type=str_type
            )

        self._modifier_handler(rule_name, name, modifiers)

    def _modifier_handler(self, rule_name, str_name, modifiers=None):
        """
        Handler for to add several modifiers to a string

        Args:
            rule_name (str): the rule_name to add the modifiers to
            str_name (str): the name of the string to add the modifiers to
            modifiers (:obj:`list` of :obj:`str`, optional): a list of modifiers
        """
        if modifiers:
            for modifier in modifiers:
                self.yara_rules[rule_name].strings.add_modifier(str_name, modifier)

    def add_condition(self, rule_name, condition):
        """
        Add a raw condition to the specified rule_name

        Args:
            rule_name (str): the rule_name to add the condition to
            condition (str): the condition as a string
        """
        self._no_rule_name_exception_handler(rule_name)

        self.yara_rules[rule_name].condition.add_raw_condition(condition)

    def add_meta_comment(
        self, rule_name, meta_name, comment, position="inline", meta_entry=0
    ):
        """
        Add a comment to a meta entry

        Args:
            rule_name (str): the name of the rule to add the comment to
            meta_name (str): the name of the meta entry to add the comment to
            comment (str): the comment
            position (str): the position of the comment (above, inline, below)
            meta_entry (int): the meta entry, given there could be multiple meta fields
                (defaults to the first entry)
        """
        self._no_rule_name_exception_handler(rule_name)

        self.yara_rules[rule_name].meta.meta[meta_name][meta_entry].add_comment(
            comment, position=position
        )

    def add_string_comment(self, rule_name, str_name, comment, position="inline"):
        """
        Add a comment to a string

        Args:
            rule_name (str): the name of the rule to add the comment to
            str_name (str): the name of the string to add the comment to
            comment (str): the comment
            position (str): the position of the comment (above, inline, below)
        """
        self._no_rule_name_exception_handler(rule_name)

        self.yara_rules[rule_name].strings.strings[str_name].add_comment(
            comment, position=position
        )

    def build_rule(self, rule_name):
        """
        Build an individual rule in the YaraBuilder object

        Args:
            rule_name (str): the rule_name to build

        Returns:
            str: a text string of the built rule
        """
        self._no_rule_name_exception_handler(rule_name)

        return self.yara_rules[rule_name].build_rule()

    def build_rules(self):
        """
        Build all rules in the YaraBuilder object

        Returns:
            str: a text string of all built rules
        """
        built_rules = []

        for rule in self.yara_rules.values():
            self.logger.debug("Building %s...", rule.rule_name)
            built_rules.append(rule.build_rule())

        return "\n\n".join(built_rules)

    def get_yara_rules(self):
        """
        Get POD versions of all YaraRules

        Returns:
            list: the constructed YaraRules
        """

        yara_rules = []

        for rule in self.yara_rules.values():
            self.logger.debug("Getting %s...", rule.rule_name)
            yara_rules.append(rule.get_yara_rule())

        return yara_rules

    def set_yara_rules(self, yara_rules):
        """
        Set up a YaraBuilder object from a list of YaraRules

        Args:
            yara_rules (list): a list of the YaraRules
        """

        for yara_rule in yara_rules:
            self.logger.debug("Setting %s...", yara_rule["rule_name"])
            self.yara_rules[yara_rule["rule_name"]] = YaraRule(None)
            self.yara_rules[yara_rule["rule_name"]].set_yara_rule(yara_rule)


def main():  # pragma: no cover
    """
    Method to test if running the module from the command line
    """

    yara_builder = YaraBuilder()

    yara_builder.create_rule("test_rule1")
    yara_builder.add_meta("test_rule1", "test_name", "test_value")
    yara_builder.add_meta_comment("test_rule1", "test_name", "test_comment")
    yara_builder.add_condition("test_rule1", "filesize > 0")

    yara_builder.create_rule("test_rule2")
    yara_builder.add_text_string("test_rule2", "hello")
    yara_builder.add_text_string("test_rule2", "world")
    yara_builder.add_text_string("test_rule2", "test_str_val", "test_str_name")
    yara_builder.add_string_comment("test_rule2", "test_str_name", "test_comment")

    yara_builder.add_condition("test_rule2", "any of them")

    print(yara_builder.build_rules())


if __name__ == "__main__":  # pragma: no cover
    main()
