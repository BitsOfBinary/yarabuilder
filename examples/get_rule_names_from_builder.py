import yarabuilder

yara_builder = yarabuilder.YaraBuilder()

yara_builder.create_rule("my_rule")
yara_builder.add_import("my_rule", "pe")
yara_builder.add_condition("my_rule", "pe.number_of_sections == 1")

yara_builder.create_rule("another_rule")
yara_builder.add_import("another_rule", "math")
yara_builder.add_condition("another_rule", "math.entropy(0, filesize) >= 7")

yara_builder.create_rule("one_more_rule")
yara_builder.add_condition("one_more_rule", "uint16(0) == 0x5A4D")

print(yara_builder.get_yara_rule_names())