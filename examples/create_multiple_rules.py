import yarabuilder
import pprint

yara_builder = yarabuilder.YaraBuilder()

yara_builder.create_rule("my_rule")
yara_builder.add_import("my_rule", "pe")
yara_builder.add_condition("my_rule", "pe.number_of_sections == 1")

yara_builder.create_rule("another_rule")
yara_builder.add_import("another_rule", "math")
yara_builder.add_condition("another_rule", "math.entropy(0, filesize) >= 7")

rules = yara_builder.build_rules(imports_at_top=False)
print(rules)

print("")

rules = yara_builder.build_rules(imports_at_top=True)
print(rules)