import io
import pytest
import yara_x


def test_syntax_error():
  compiler = yara_x.Compiler()
  with pytest.raises(yara_x.CompileError):
    compiler.add_source('bad rule')


def test_bad_variable_type():
  compiler = yara_x.Compiler()
  with pytest.raises(TypeError):
    compiler.define_global()


def test_relaxed_re_syntax():
  compiler = yara_x.Compiler(relaxed_re_syntax=True)
  compiler.add_source(r'rule test {strings: $a = /\Release/ condition: $a}')
  rules = compiler.build()
  matching_rules = rules.scan(b'Release').matching_rules
  assert len(matching_rules) == 1


def test_error_on_slow_pattern():
  compiler = yara_x.Compiler(error_on_slow_pattern=True)
  with pytest.raises(yara_x.CompileError):
    compiler.add_source(r'rule test {strings: $a = /a.*/ condition: $a}')


def test_invalid_rule_name_regexp():
  compiler = yara_x.Compiler()
  with pytest.raises(ValueError):
    compiler.rule_name_regexp("(AXS|ERS")


def test_int_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_int', 1)
  compiler.add_source('rule test {condition: some_int == 1}')
  rules = compiler.build()

  scanner = yara_x.Scanner(rules)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1

  scanner.set_global('some_int', 2)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 0

  scanner.set_global('some_int', 1)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1


def test_float_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_float', 1.0)
  compiler.add_source('rule test {condition: some_float == 1.0}')
  rules = compiler.build()

  scanner = yara_x.Scanner(rules)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1

  scanner.set_global('some_float', 2.0)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 0

  scanner.set_global('some_float', 1.0)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1


def test_str_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_str', 'foo')
  compiler.add_source('rule test {condition: some_str == "foo"}')
  rules = compiler.build()

  scanner = yara_x.Scanner(rules)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1

  scanner.set_global('some_str', 'bar')
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 0

  scanner.set_global('some_str', 'foo')
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1

def test_dict_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_dict', {"foo": "bar"})
  compiler.add_source('rule test {condition: some_dict.foo == "bar"}')
  rules = compiler.build()

  scanner = yara_x.Scanner(rules)
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1

  scanner.set_global('some_dict', {"foo": "foo"})
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 0

  scanner.set_global('some_dict', {"foo": "bar"})
  matching_rules = scanner.scan(b'').matching_rules
  assert len(matching_rules) == 1

def test_namespaces():
  compiler = yara_x.Compiler()
  compiler.new_namespace('foo')
  compiler.add_source('rule foo {strings: $foo = "foo" condition: $foo}')
  compiler.new_namespace('bar')
  compiler.add_source('rule bar {strings: $bar = "bar" condition: $bar}')
  rules = compiler.build()
  matching_rules = rules.scan(b'foobar').matching_rules

  assert len(matching_rules) == 2

  assert matching_rules[0].identifier == 'foo'
  assert matching_rules[0].namespace == 'foo'
  assert len(matching_rules[0].patterns) == 1
  assert matching_rules[0].patterns[0].identifier == '$foo'
  assert len(matching_rules[0].patterns[0].matches) == 1
  assert matching_rules[0].patterns[0].matches[0].offset == 0
  assert matching_rules[0].patterns[0].matches[0].length == 3
  assert matching_rules[0].patterns[0].matches[0].xor_key is None

  assert matching_rules[1].identifier == 'bar'
  assert matching_rules[1].namespace == 'bar'
  assert len(matching_rules[1].patterns) == 1
  assert matching_rules[1].patterns[0].identifier == '$bar'
  assert len(matching_rules[1].patterns[0].matches) == 1
  assert matching_rules[1].patterns[0].matches[0].offset == 3
  assert matching_rules[1].patterns[0].matches[0].length == 3
  assert matching_rules[1].patterns[0].matches[0].xor_key is None


def test_metadata():
  rules = yara_x.compile('''
	rule test {
		meta:
			foo = 1
			bar = 2.0
			baz = true
			qux = "qux"
			quux = "qu\x00x"
		condition:
		  true
	}
	''')

  matching_rules = rules.scan(b'').matching_rules

  assert matching_rules[0].metadata == (
      ("foo", 1),
      ("bar", 2.0),
      ("baz", True),
      ("qux", "qux"),
      ("quux", "qu\x00x")
  )


def test_tags():
  rules = yara_x.compile('''
	rule test : tag1 tag2 {
		condition:
		  true
	}
	''')

  matching_rules = rules.scan(b'').matching_rules

  assert matching_rules[0].tags == ("tag1", "tag2")


def test_compile_and_scan():
  rules = yara_x.compile('rule foo {strings: $a = "foo" condition: $a}')
  matching_rules = rules.scan(b'foobar').matching_rules
  assert len(matching_rules) == 1
  assert matching_rules[0].identifier == 'foo'
  assert matching_rules[0].namespace == 'default'
  assert len(matching_rules[0].patterns) == 1
  assert matching_rules[0].patterns[0].identifier == '$a'


def test_compiler_and_scanner():
  rules = yara_x.compile('rule foo {strings: $a = "foo" condition: $a}')
  matching_rules = rules.scan(b'foobar').matching_rules
  assert len(matching_rules) == 1
  assert matching_rules[0].identifier == 'foo'
  assert matching_rules[0].namespace == 'default'
  assert len(matching_rules[0].patterns) == 1
  assert matching_rules[0].patterns[0].identifier == '$a'


def test_xor_key():
  rules = yara_x.compile('rule foo {strings: $a = "foo" xor condition: $a}')
  matching_rules = rules.scan(b'\xCC\xC5\xC5').matching_rules
  assert len(matching_rules) == 1
  assert matching_rules[0].identifier == 'foo'
  assert matching_rules[0].namespace == 'default'
  assert len(matching_rules[0].patterns) == 1
  assert matching_rules[0].patterns[0].identifier == '$a'
  assert len(matching_rules[0].patterns[0].matches) == 1
  assert matching_rules[0].patterns[0].matches[0].xor_key == 0xAA


def test_scanner_timeout():
  compiler = yara_x.Compiler()
  compiler.add_source(
      'rule foo {condition: for all i in (0..100000000000) : ( true )}')
  scanner = yara_x.Scanner(compiler.build())
  scanner.set_timeout(1)
  with pytest.raises(yara_x.TimeoutError):
    scanner.scan(b'foobar')

def test_scanner_max_matches_per_pattern():
  compiler = yara_x.Compiler()
  compiler.add_source('rule test {strings: $a = "." condition: #a > 1}')

  scanner = yara_x.Scanner(compiler.build())
  scanner.max_matches_per_pattern(1)
  matching_rules = scanner.scan(b'..').matching_rules
  assert len(matching_rules) == 0

  scanner.max_matches_per_pattern(2)
  matching_rules = scanner.scan(b'..').matching_rules
  assert len(matching_rules) == 1


def test_scan_options():
  if 'test_proto2' not in yara_x.module_names():
    return

  rules = yara_x.compile('import "test_proto2" rule foo {condition: false}')
  options = yara_x.ScanOptions()
  options.set_module_metadata('test_proto2', b'foo bar baz')
  module_outputs = rules.scan_with_options(b'', options).module_outputs
  assert module_outputs['test_proto2']['metadata'] == b'foo bar baz'


def test_module_outputs():
  if 'test_proto2' not in yara_x.module_names():
    return

  import datetime
  rules = yara_x.compile('import "test_proto2" rule foo {condition: false}')
  module_outputs = rules.scan(b'').module_outputs
  assert module_outputs['test_proto2']['int32_one'] == 1
  assert module_outputs['test_proto2']['bytes_foo'] == b'foo'
  assert module_outputs['test_proto2']['bytes_raw'] == b'\xfcH\x83\xe4\xf0\xeb3]\x8bE\x00H'
  assert module_outputs['test_proto2']['timestamp'] == datetime.datetime(2025, 5, 30, 7, 50, 40, tzinfo=datetime.timezone.utc)

def test_ignored_modules():
  compiler = yara_x.Compiler()
  compiler.ignore_module("unsupported_module")
  compiler.add_source(
      'import "unsupported_module" rule foo {condition: true}')
  rules = compiler.build()
  assert len(rules.scan(b'').matching_rules) == 1


def test_serialization():
  rules = yara_x.compile('rule foo {condition: true}')
  f = io.BytesIO()
  rules.serialize_into(f)
  f.seek(0)
  rules = yara_x.Rules.deserialize_from(f)
  assert len(rules.scan(b'').matching_rules) == 1


def tests_compiler_errors():
  compiler = yara_x.Compiler()

  with pytest.raises(yara_x.CompileError):
    compiler.add_source('rule foo { condition: bar }')

  errors = compiler.errors()

  assert len(errors) == 1
  assert errors[0]['type'] == "UnknownIdentifier"
  assert errors[0]['code'] == "E009"
  assert errors[0]['title'] == "unknown identifier `bar`"


def tests_compiler_warnings():
  compiler = yara_x.Compiler()

  compiler.add_source(
      'rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }')

  warnings = compiler.warnings()

  assert len(warnings) == 2

  assert warnings[0]['type'] == "ConsecutiveJumps"
  assert warnings[0]['code'] == "consecutive_jumps"
  assert warnings[0]['title'] == "consecutive jumps in hex pattern `$a`"

  assert warnings[1]['type'] == "SlowPattern"
  assert warnings[1]['code'] == "slow_pattern"
  assert warnings[1]['title'] == "slow pattern"


def test_console_log():
  if 'console' not in yara_x.module_names():
      return

  ok = False

  def callback(msg):
    nonlocal ok
    if msg == 'foo':
      ok = True

  compiler = yara_x.Compiler()
  compiler.add_source(
      'import "console" rule foo {condition: console.log("foo")}')
  scanner = yara_x.Scanner(compiler.build())
  scanner.console_log(callback)
  scanner.scan(b'')
  assert ok


def test_format():
  import io
  expected_output = (
      '''rule test {
  strings:
    $a = "foo"

  condition:
    $a at 0
}
''')
  inp = io.StringIO(
      'rule test { strings: $a = "foo" condition: $a at 0 }')
  output = io.StringIO()
  fmt = yara_x.Formatter()
  fmt.format(inp, output)
  result = output.getvalue()
  assert result == expected_output


def test_module():
  with pytest.raises(ValueError):
    yara_x.Module('AXS')

  if 'pe' not in yara_x.module_names():
    return

  # We aren't interested in testing the actual parsing functionality of the
  # module as that is covered in module tests. Instead we just want to make sure
  # we get a dict object back, and we can do that by passing non-PE data.
  result = yara_x.Module('PE').invoke(b'ERS')
  assert isinstance(result, dict)


def test_compiler_disables_includes():
  compiler = yara_x.Compiler()
  compiler.enable_includes(False)

  with pytest.raises(yara_x.CompileError,
                     match="include statements not allowed"):
    compiler.add_source(f'include "foo.yar"\nrule main {{ condition: true }}')


def test_rules_iterator():
  rules = yara_x.compile('''
rule foo {
  condition:
    true
}
rule bar {
  condition:
    true
}
''')

  rules_list = list(rules)
  assert len(rules_list) == 2
  assert rules_list[0].identifier == 'foo'
  assert rules_list[1].identifier == 'bar'


def test_rules_imports():
  rules = yara_x.compile('''
import "pe"
import "elf"
rule test {
  condition:
    true
}
''')
  assert rules.imports() == ["pe", "elf"]
