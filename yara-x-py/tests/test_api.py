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