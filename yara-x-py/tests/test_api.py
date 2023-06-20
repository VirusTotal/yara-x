import pytest
import yara_x

def test_syntax_error():
  compiler = yara_x.Compiler()
  with pytest.raises(SyntaxError):
    compiler.add_source('bad rule')

def test_bad_variable_type():
  compiler = yara_x.Compiler()
  with pytest.raises(TypeError):
    compiler.define_global()

def test_int_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_int', 1);
  compiler.add_source('rule test {condition: some_int == 1}')
  rules = compiler.build()

  scanner = yara_x.Scanner(rules)
  matches = scanner.scan(b'')
  assert len(matches) == 1

  scanner.set_global('some_int', 2)
  matches = scanner.scan(b'')
  assert len(matches) == 0

  scanner.set_global('some_int', 1)
  matches = scanner.scan(b'')
  assert len(matches) == 1

def test_float_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_float', 1.0);
  compiler.add_source('rule test {condition: some_float == 1.0}')
  rules = compiler.build()

  scanner = yara_x.Scanner(rules)
  matches = scanner.scan(b'')
  assert len(matches) == 1

  scanner.set_global('some_float', 2.0)
  matches = scanner.scan(b'')
  assert len(matches) == 0

  scanner.set_global('some_float', 1.0)
  matches = scanner.scan(b'')
  assert len(matches) == 1

def test_str_globals():
  compiler = yara_x.Compiler()
  compiler.define_global('some_str', 'foo');
  compiler.add_source('rule test {condition: some_str == "foo"}')
  rules = compiler.build()

  scanner = yara_x.Scanner(rules)
  matches = scanner.scan(b'')
  assert len(matches) == 1

  scanner.set_global('some_str', 'bar')
  matches = scanner.scan(b'')
  assert len(matches) == 0

  scanner.set_global('some_str', 'foo')
  matches = scanner.scan(b'')
  assert len(matches) == 1


def test_namespaces():
  compiler = yara_x.Compiler()
  compiler.new_namespace('foo')
  compiler.add_source('rule foo {strings: $a = "foo" condition: $a}')
  compiler.new_namespace('bar')
  compiler.add_source('rule bar {strings: $a = "bar" condition: $a}')
  scanner = yara_x.Scanner(compiler.build())
  matches = scanner.scan(b"foobar")
  assert len(matches) == 2


def test_compile_and_scan():
  rules = yara_x.compile('rule foo {strings: $a = "foo" condition: $a}')
  matches = rules.scan(b"foobar")
  assert len(matches) == 1

def test_compiler_and_scanner():
  compiler = yara_x.Compiler()
  compiler.add_source('rule foo {strings: $a = "foo" condition: $a}')
  scanner = yara_x.Scanner(compiler.build())
  matches = scanner.scan(b"foobar")
  assert len(matches) == 1