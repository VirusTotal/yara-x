module benchcmp

go 1.26

require (
	github.com/VirusTotal/yara-x/go v0.0.0
	yaraxwasm v0.0.0
)

require (
	github.com/josharian/intern v1.0.0 // indirect
	github.com/klauspost/compress v1.18.1 // indirect
	github.com/mailru/easyjson v0.9.1 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)

replace github.com/VirusTotal/yara-x/go => ../go

replace yaraxwasm => ../go-wasm
