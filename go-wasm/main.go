package yara_x

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"

	easyjson "github.com/mailru/easyjson"
)

// Compile receives YARA source code and returns compiled [Rules] that can be
// used for scanning data.
func Compile(src string, opts ...CompileOption) (*Rules, error) {
	c, err := NewCompiler(opts...)
	if err != nil {
		return nil, err
	}

	if err := c.AddSource(src); err != nil {
		return nil, err
	}

	return c.Build(), nil
}

// ReadFrom reads compiled rules from a reader.
//
// The counterpart is [Rules.WriteTo].
func ReadFrom(r io.Reader) (*Rules, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	client, err := newGuestClient()
	if err != nil {
		return nil, err
	}
	defer client.close()

	ptr, length, err := client.allocAndWrite(data, 1)
	if err != nil {
		return nil, err
	}
	defer client.free(ptr, length, 1)

	handle, err := client.callHandle(
		"go_yrx_rules_deserialize",
		uint64(ptr),
		uint64(length),
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = client.call("go_yrx_rules_destroy", uint64(handle))
	}()

	rules, err := newPortableRules(client, handle, data)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(rules, (*Rules).Destroy)
	return rules, nil
}

// Rules represents a set of compiled YARA rules.
type Rules struct {
	serialized []byte
	count      int
	imports    []string
	rules      []*Rule
}

// Scan scans data with the compiled rules.
func (r *Rules) Scan(data []byte) (*ScanResults, error) {
	scanner := NewScanner(r)
	defer scanner.Destroy()
	return scanner.Scan(data)
}

// ScanReader scans data streamed from an [io.Reader].
func (r *Rules) ScanReader(reader io.Reader) (*ScanResults, error) {
	scanner := NewScanner(r)
	defer scanner.Destroy()
	return scanner.ScanReader(reader)
}

// ScanReaderAt scans data exposed through an [io.ReaderAt].
//
// When the configured guest-memory allocator supports it, this may scan the
// data through a direct guest-memory mapping. Otherwise, the data is copied
// into guest memory before scanning.
func (r *Rules) ScanReaderAt(reader io.ReaderAt, size int64) (*ScanResults, error) {
	scanner := NewScanner(r)
	defer scanner.Destroy()
	return scanner.ScanReaderAt(reader, size)
}

func (r *Rules) serializeBytes() ([]byte, error) {
	if r == nil || r.serialized == nil {
		return nil, errors.New("rules object is destroyed")
	}
	return r.serialized, nil
}

// WriteTo writes the compiled rules into a writer.
//
// The counterpart is [ReadFrom].
func (r *Rules) WriteTo(w io.Writer) (int64, error) {
	data, err := r.serializeBytes()
	if err != nil {
		return 0, err
	}

	bytesWritten := int64(0)
	for len(data) > 0 {
		n, err := w.Write(data)
		bytesWritten += int64(n)
		data = data[n:]
		if err != nil {
			return bytesWritten, err
		}
		if n == 0 {
			return bytesWritten, io.ErrShortWrite
		}
	}

	return bytesWritten, nil
}

// Destroy destroys the compiled YARA rules represented by [Rules].
//
// Calling this method directly is not necessary, it will be invoked by the
// garbage collector when the rules are not used anymore.
func (r *Rules) Destroy() {
	if r == nil {
		return
	}
	r.serialized = nil
	r.count = 0
	r.imports = nil
	r.rules = nil
	runtime.SetFinalizer(r, nil)
}

// Slice returns a slice with all the individual rules contained in this
// set of compiled rules.
func (r *Rules) Slice() []*Rule {
	if r == nil || r.rules == nil {
		return []*Rule{}
	}
	return cloneRules(r.rules)
}

// Count returns the total number of rules.
//
// This is a more efficient alternative to len(rules.Slice()).
func (r *Rules) Count() int {
	if r == nil {
		return 0
	}
	return r.count
}

// Imports returns the names of the imported modules.
func (r *Rules) Imports() []string {
	if r == nil || len(r.imports) == 0 {
		return []string{}
	}
	return append([]string(nil), r.imports...)
}

// Rule represents a YARA rule.
type Rule struct {
	namespace  string
	identifier string
	tags       []string
	patterns   []Pattern
	metadata   []Metadata
}

// Pattern represents a pattern in a Rule.
type Pattern struct {
	identifier string
	matches    []Match
}

// Metadata represents a metadata in a Rule.
type Metadata struct {
	identifier string
	value      interface{}
}

// Match contains information about the offset where a match occurred and
// the length of the match.
type Match struct {
	offset uint64
	length uint64
}

// Identifier returns the rule's identifier.
func (r *Rule) Identifier() string {
	return r.identifier
}

// Namespace returns the rule's namespace.
func (r *Rule) Namespace() string {
	return r.namespace
}

// Tags returns the rule's tags.
func (r *Rule) Tags() []string {
	if r == nil || len(r.tags) == 0 {
		return []string{}
	}
	return append([]string(nil), r.tags...)
}

// Identifier returns the metadata identifier.
func (m *Metadata) Identifier() string {
	return m.identifier
}

// Value returns the metadata value.
func (m *Metadata) Value() interface{} {
	return m.value
}

// Metadata returns the rule's metadata.
func (r *Rule) Metadata() []Metadata {
	if r == nil || r.metadata == nil {
		return []Metadata{}
	}

	metadata := make([]Metadata, 0, len(r.metadata))
	for _, item := range r.metadata {
		metadata = append(metadata, Metadata{
			identifier: item.identifier,
			value:      cloneMetadataValue(item.value),
		})
	}
	return metadata
}

// Patterns returns the patterns defined by this rule.
func (r *Rule) Patterns() []Pattern {
	if r == nil || len(r.patterns) == 0 {
		return []Pattern{}
	}
	return append([]Pattern(nil), r.patterns...)
}

// Identifier returns the pattern's identifier (i.e: $a, $foo).
func (p *Pattern) Identifier() string {
	return p.identifier
}

// Matches returns the matches found for this pattern.
func (p *Pattern) Matches() []Match {
	if p == nil || len(p.matches) == 0 {
		return []Match{}
	}
	return append([]Match(nil), p.matches...)
}

// Offset returns the offset within the scanned data where a match occurred.
func (m *Match) Offset() uint64 {
	return m.offset
}

// Length returns the length of a match in bytes.
func (m *Match) Length() uint64 {
	return m.length
}

type ruleJSON struct {
	Namespace  string         `json:"n"`
	Identifier string         `json:"i"`
	Tags       []string       `json:"t"`
	Patterns   []patternJSON  `json:"p"`
	Metadata   []metadataJSON `json:"m"`
}

type patternJSON struct {
	Identifier string      `json:"i"`
	Matches    []matchJSON `json:"m"`
}

type matchJSON struct {
	Offset uint64 `json:"o"`
	Length uint64 `json:"l"`
}

type metadataJSON struct {
	Identifier string            `json:"i"`
	Value      metadataValueJSON `json:"v"`
}

type metadataValueJSON struct {
	Kind  string              `json:"k"`
	Value easyjson.RawMessage `json:"v"`
}

func decodeRuleJSON(raw ruleJSON) (*Rule, error) {
	patterns := make([]Pattern, 0, len(raw.Patterns))
	for _, p := range raw.Patterns {
		matches := make([]Match, 0, len(p.Matches))
		for _, m := range p.Matches {
			matches = append(matches, Match{offset: m.Offset, length: m.Length})
		}
		patterns = append(patterns, Pattern{identifier: p.Identifier, matches: matches})
	}

	metadata := make([]Metadata, 0, len(raw.Metadata))
	for _, m := range raw.Metadata {
		decoded, err := decodeMetadataValue(m.Value)
		if err != nil {
			return nil, fmt.Errorf("decode metadata %q: %w", m.Identifier, err)
		}
		metadata = append(metadata, Metadata{identifier: m.Identifier, value: decoded})
	}

	return &Rule{
		namespace:  raw.Namespace,
		identifier: raw.Identifier,
		tags:       raw.Tags,
		patterns:   patterns,
		metadata:   metadata,
	}, nil
}

func decodeMetadataValue(raw metadataValueJSON) (interface{}, error) {
	switch raw.Kind {
	case "i":
		value, err := strconv.ParseInt(wireJSONBytesToString(raw.Value), 10, 64)
		if err != nil {
			return nil, err
		}
		return value, nil
	case "f":
		value, err := strconv.ParseFloat(wireJSONBytesToString(raw.Value), 64)
		if err != nil {
			return nil, err
		}
		return value, nil
	case "b":
		if len(raw.Value) == 0 {
			return nil, errors.New("invalid bool metadata encoding")
		}
		switch raw.Value[0] {
		case 't':
			return true, nil
		case 'f':
			return false, nil
		default:
			return nil, fmt.Errorf("invalid bool metadata encoding %q", raw.Value)
		}
	case "s":
		value, err := strconv.Unquote(wireJSONBytesToString(raw.Value))
		if err != nil {
			return nil, err
		}
		return value, nil
	case "x":
		if len(raw.Value) < 2 || raw.Value[0] != '"' || raw.Value[len(raw.Value)-1] != '"' {
			return nil, fmt.Errorf("invalid bytes metadata encoding %q", raw.Value)
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(raw.Value)-2))
		n, err := base64.StdEncoding.Decode(decoded, raw.Value[1:len(raw.Value)-1])
		if err != nil {
			return nil, err
		}
		return decoded[:n], nil
	default:
		return nil, fmt.Errorf("unknown metadata kind %q", raw.Kind)
	}
}

func newPortableRules(
	client *guestClient,
	handle uint32,
	serialized []byte,
) (*Rules, error) {
	count, err := client.callInt32("go_yrx_rules_count", uint64(handle))
	if err != nil {
		return nil, err
	}

	importsPayload, err := readRulesBuffer(client, "go_yrx_rules_imports_json", handle)
	if err != nil {
		return nil, err
	}

	var imports []string
	if err := json.Unmarshal(importsPayload, &imports); err != nil {
		return nil, err
	}

	rulesPayload, err := readRulesBuffer(client, "go_yrx_rules_slice_json", handle)
	if err != nil {
		return nil, err
	}

	decodedRules, err := decodeRulesJSON(rulesPayload)
	if err != nil {
		return nil, err
	}

	if count < 0 {
		count = 0
	}

	return &Rules{
		serialized: serialized,
		count:      int(count),
		imports:    imports,
		rules:      decodedRules,
	}, nil
}

func readRulesBuffer(
	client *guestClient,
	export string,
	handle uint32,
) ([]byte, error) {
	bufHandle, err := client.callHandle(export, uint64(handle))
	if err != nil {
		return nil, err
	}
	return client.readAndFreeBuffer(bufHandle)
}

func decodeRulesJSON(payload []byte) ([]*Rule, error) {
	var encoded ruleJSONList
	if err := unmarshalWireJSON(payload, &encoded); err != nil {
		return nil, err
	}

	rules := make([]*Rule, 0, len(encoded))
	for _, raw := range encoded {
		rule, err := decodeRuleJSON(raw)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func cloneRules(src []*Rule) []*Rule {
	out := make([]*Rule, 0, len(src))
	for _, rule := range src {
		if rule == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, cloneRule(rule))
	}
	return out
}

func cloneRule(rule *Rule) *Rule {
	if rule == nil {
		return nil
	}

	return &Rule{
		namespace:  rule.namespace,
		identifier: rule.identifier,
		tags:       rule.tags,
		patterns:   rule.patterns,
		metadata:   rule.metadata,
	}
}

func cloneMetadataValue(value interface{}) interface{} {
	switch v := value.(type) {
	case []byte:
		return append([]byte(nil), v...)
	default:
		return v
	}
}
