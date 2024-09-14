package yara_x

import "fmt"

func Example_basic() {
	// Compile some YARA rules.
	rules, _ := Compile(`
rule foo {
  strings:
    $foo = "foo"
  condition:
    $foo
}

rule bar {
  strings:
    $bar = "bar"
  condition:
    $bar
}`)

	// Use the compiled rules for scanning some data.
	scanResults, _ := rules.Scan([]byte("foobar"))

	// Iterate over the matching rules.
	for _, r := range scanResults.MatchingRules() {
		fmt.Printf("rule %s matched\n", r.Identifier())
	}

	// Output:
	// rule foo matched
	// rule bar matched
}

func Example_compilerAndScanner() {
	// Create a new compiler.
	compiler, _ := NewCompiler()

	// Add some rules to the compiler.
	err := compiler.AddSource(`rule foo {
		strings:
		  $foo = "foo"
		condition:
          $foo
	}

    rule bar {
		strings:
		$bar = "bar"
		condition:
		$bar
	}`)

	if err != nil {
		panic(err)
	}

	// Get the compiled rules.
	rules := compiler.Build()

	// Pass the compiled rules to a scanner.
	scanner := NewScanner(rules)

	// Use the scanner for scanning some data.
	scanResults, _ := scanner.Scan([]byte("foobar"))

	// Iterate over the matching rules.
	for _, r := range scanResults.MatchingRules() {
		fmt.Printf("rule %s matched\n", r.Identifier())
	}

	// Output:
	// rule foo matched
	// rule bar matched
}
