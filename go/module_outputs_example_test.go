package yara_x

import (
	"encoding/json"
	"fmt"
)

func Example_moduleOutputs() {
	rules, err := Compile(`import "pe" rule t { condition: true }`)
	if err != nil {
		panic(err)
	}
	scanner := NewScanner(rules)
	defer scanner.Destroy()
	scanner.CollectModuleOutputs(true)
	results, err := scanner.Scan(nil)
	if err != nil {
		panic(err)
	}
	var output struct {
		IsPE bool `json:"is_pe"`
	}
	if err := json.Unmarshal(results.ModuleOutputs()["pe"], &output); err != nil {
		panic(err)
	}
	fmt.Println("is_pe:", output.IsPE)
	// Output: is_pe: false
}
