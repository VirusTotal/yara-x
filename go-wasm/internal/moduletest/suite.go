package moduletest

import (
	"archive/zip"
	"encoding/hex"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go-wasm"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// ScanConfig carries per-scan configuration used by specific module tests.
type ScanConfig struct {
	ModuleOutput  proto.Message
	ConsoleOutput io.Writer
}

// Harness describes one way of driving the shared module functionality suite.
type Harness struct {
	Name string
	Scan func(
		t *testing.T,
		rules *yara_x.Rules,
		data []byte,
		cfg ScanConfig,
	) (*yara_x.ScanResults, error)
}

type flushingStringWriter struct {
	builder strings.Builder
	flushes int
}

func (w *flushingStringWriter) Write(p []byte) (int, error) {
	return w.builder.Write(p)
}

func (w *flushingStringWriter) Flush() error {
	w.flushes++
	return nil
}

func (w *flushingStringWriter) String() string {
	return w.builder.String()
}

// Run executes the shared module fixture suite with the provided scan harness.
func Run(t *testing.T, harness Harness) {
	t.Helper()
	require.NotNil(t, harness.Scan)

	t.Run("hash", func(t *testing.T) {
		requireRuleMatches(t, harness, `
			import "hash"
			rule test {
				condition:
					hash.md5(0, filesize) == "6df23dc03f9b54cc38a0fc1483df6e21" and
					hash.md5(3, 3) == "37b51d194a7513e45b56f6524f2d51f2" and
					hash.md5(0, filesize) == hash.md5("foobarbaz") and
					hash.md5(3, 3) == hash.md5("bar") and
					hash.sha1(0, filesize) == "5f5513f8822fdbe5145af33b64d8d970dcf95c6e" and
					hash.sha1(3, 3) == "62cdb7020ff920e5aa642c3d4066950dd1f01f4d" and
					hash.sha1(0, filesize) == hash.sha1("foobarbaz") and
					hash.sha1(3, 3) == hash.sha1("bar") and
					hash.sha256(0, filesize) == "97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d" and
					hash.sha256(3, 3) == "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9" and
					hash.sha256(0, filesize) == hash.sha256("foobarbaz") and
					hash.sha256(3, 3) == hash.sha256("bar") and
					hash.crc32(0, filesize) == 0x1a7827aa and
					hash.crc32(3, 3) == 0x76ff8caa and
					hash.crc32(0, filesize) == hash.crc32("foobarbaz") and
					hash.crc32(3, 3) == hash.crc32("bar")
			}
		`, []byte("foobarbaz"))

		requireRuleMatches(t, harness, `
			import "hash"
			rule test {
				condition:
					hash.checksum32("TEST STRING") == 0x337
			}
		`, []byte("foobarbaz"))

		requireRuleMatches(t, harness, `
			import "hash"
			rule test {
				condition:
					hash.checksum32(0, filesize) == 0x337
			}
		`, []byte("TEST STRING"))
	})

	t.Run("crx", func(t *testing.T) {
		crx := mustReadZippedIHEXFixture(t, "crx", "3d1c2b1777fb5d5f4e4707ab3a1b64131c26f8dc1c30048dce7a1944b4098f3e.in.zip")

		requireRuleMatches(t, harness, `
			import "crx"
			rule test {
				condition:
					crx.permhash() == "0bd16e5d8c30b71e844aa6f30b381adf20dc14cc555f5594fc3ac49985c9a52e"
			}
		`, crx)
	})

	t.Run("console", func(t *testing.T) {
		expected := []string{
			"foo",
			"bar: 1",
			"baz: 3.14",
			"10",
			"6.28",
			"true",
			"bool: true",
			"0xa",
			"qux: 0xff",
			"hello world!",
		}
		source := `
			import "console"
			rule test {
				condition:
					console.log("foo") and
					console.log("bar: ", 1) and
					console.log("baz: ", 3.14) and
					console.log(10) and
					console.log(6.28) and
					console.log(true) and
					console.log("bool: ", true) and
					console.hex(10) and
					console.hex("qux: ", 255) and
					console.log("hello ", "world!")
			}
		`

		rules, err := yara_x.Compile(source)
		require.NoError(t, err)
		defer rules.Destroy()

		writer := &flushingStringWriter{}
		results, err := harness.Scan(t, rules, nil, ScanConfig{
			ConsoleOutput: writer,
		})
		require.NoError(t, err)
		require.Len(t, results.MatchingRules(), 1)
		require.Equal(t, strings.Join(expected, "\n")+"\n", writer.String())
		require.Equal(t, len(expected), writer.flushes)
	})

	t.Run("dex", func(t *testing.T) {
		dex := mustReadZippedIHEXFixture(t, "dex", "c14c75d58399825287e0ee0fcfede6ec06f93489fb52f70bca2736fae5fceab2.in.zip")

		requireRuleMatches(t, harness, `
			import "dex"
			rule test {
				condition:
					dex.checksum() == 0x200c7aa1 and
					dex.header.checksum == dex.checksum() and
					dex.signature() == "e9bd6aa16e8eea1a71e7fd2eb3236749a10a64ef" and
					dex.header.signature == dex.signature()
			}
		`, dex)

		requireRuleMatches(t, harness, `
			import "dex"
			rule test {
				condition:
					dex.contains_string("loadLibrary") and
					dex.contains_method("getPackageName") and
					dex.contains_class("Lwmczycqxv/egztwrhea;")
			}
		`, dex)
	})

	t.Run("elf", func(t *testing.T) {
		elf := mustReadZippedIHEXFixture(t, "elf", "8bfe885838b4d1fba194b761ca900a0425aa892e4b358bf5a9bf4304e571df1b.in.zip")

		requireRuleMatches(t, harness, `
			import "elf"
			rule test {
				condition:
					elf.import_md5() == "141ad500037085bdbe4665241c44f936" and
					elf.telfhash() == "T174B012188204F00184540770331E0B111373086019509C464D0ACE88181266C09774FA"
			}
		`, elf)
	})

	t.Run("dotnet", func(t *testing.T) {
		types2 := mustReadZippedIHEXFixture(t, "dotnet", "types2.dll.in.zip")
		empty := mustReadZippedIHEXFixture(t, "dotnet", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.in.zip")

		requireRuleMatches(t, harness, `
			import "dotnet"
			rule test {
				condition:
					dotnet.is_dotnet and
					dotnet.module_name == "types2.dll" and
					dotnet.version == "v4.0.30319" and
					dotnet.streams.len() == 5 and
					dotnet.guids.len() == 1 and
					dotnet.resources.len() == 0 and
					dotnet.classes.len() == 2 and
					dotnet.classes[0].name == "Cmk" and
					dotnet.classes[1].name == "VolatileMethods" and
					dotnet.classes[1].methods.len() == 3 and
					dotnet.classes[1].methods[0].name == "withCmod" and
					dotnet.classes[1].methods[1].parameters[0].type == "int[3]" and
					dotnet.classes[1].methods[2].parameters.len() == 4
			}
		`, types2)

		requireRuleMatches(t, harness, `
			import "dotnet"
			rule test {
				condition:
					not dotnet.is_dotnet
			}
		`, empty)
	})

	t.Run("macho", func(t *testing.T) {
		tinyUniversal := mustReadZippedIHEXFixture(t, "macho", "tiny_universal.in.zip")

		requireRuleMatches(t, harness, `
			import "macho"
			rule test {
				condition:
					macho.MH_MAGIC == 0xfeedface and
					macho.MH_NO_REEXPORTED_DYLIBS == 0x00100000 and
					macho.MH_CIGAM == 0xcefaedfe and
					macho.CPU_TYPE_MIPS == 0x00000008
			}
		`, nil)

		requireRuleMatches(t, harness, `
			import "macho"
			rule test {
				condition:
					macho.file_index_for_arch(0x00000007) == 0 and
					macho.file_index_for_arch(0x01000007) == 1 and
					macho.entry_point_for_arch(0x00000007) == 0x00001EE0 and
					macho.entry_point_for_arch(0x01000007) == 0x00004EE0 and
					macho.has_dylib("/usr/lib/libSystem.B.dylib") and
					macho.has_export("_factorial")
			}
		`, tinyUniversal)

		requireRuleDoesNotMatch(t, harness, `
			import "macho"
			rule test {
				condition:
					macho.MH_MAGIC == 0xfeeeeeee or
					macho.CPU_TYPE_MIPS == 0x00000000 or
					macho.has_dylib("totally not present dylib")
			}
		`, tinyUniversal)

		requireRuleMatches(t, harness, `
			import "macho"
			rule test {
				condition:
					not defined macho.file_index_for_arch(0x01000008) and
					not defined macho.entry_point_for_arch(0x00000007, 0x00000003)
			}
		`, nil)
	})

	t.Run("lnk", func(t *testing.T) {
		standard := mustReadZippedIHEXFixture(t, "lnk", "lnk-standard.in.zip")
		network := mustReadZippedIHEXFixture(t, "lnk", "lnk-network.in.zip")
		empty := mustReadZippedIHEXFixture(t, "lnk", "lnk-empty.in.zip")

		requireRuleMatches(t, harness, `
			import "lnk"
			rule test {
				condition:
					lnk.is_lnk and
					lnk.file_attributes == lnk.FILE_ATTRIBUTE_ARCHIVE and
					lnk.show_command == 1 and
					lnk.drive_type == 3 and
					lnk.drive_serial_number == 813337217 and
					lnk.local_base_path == "C:\\test\\a.txt" and
					lnk.relative_path == ".\\a.txt" and
					lnk.working_dir == "C:\\test" and
					lnk.overlay_size == 0 and
					lnk.tracker_data.machine_id == "chris-xps"
			}
		`, standard)

		requireRuleMatches(t, harness, `
			import "lnk"
			rule test {
				condition:
					lnk.is_lnk and
					lnk.common_path_suffix == "calc.exe" and
					lnk.relative_path == ".\\calc.exe" and
					lnk.working_dir == "Z:\\" and
					lnk.tracker_data.machine_id == "localhost"
			}
		`, network)

		requireRuleMatches(t, harness, `
			import "lnk"
			rule test {
				condition:
					not lnk.is_lnk
			}
		`, empty)
	})

	t.Run("math", func(t *testing.T) {
		t.Run("basic", func(t *testing.T) {
			requireRuleMatches(t, harness, `
				import "math"
				rule test {
					condition:
						math.min(1, 2) == 1 and
						math.min(-1, 0) == -1 and
						math.max(1, 2) == 2 and
						math.max(-1, 0) == 0 and
						math.abs(-1) == 1 and
						math.abs(1) == 1 and
						math.in_range(1, 1, 2) and
						math.in_range(2, 1, 2) and
						not math.in_range(3, 1, 2) and
						math.in_range(0.5, 0.0, 0.6)
				}
			`, nil)
		})

		t.Run("statistics", func(t *testing.T) {
			requireRuleMatches(t, harness, `
				import "math"
				rule test {
					condition:
						math.entropy("AAAAA") == 0.0 and
						math.entropy("AABB") == 1.0 and
						math.entropy("") == 0.0 and
						math.deviation("AAAAA", 0.0) == 65.0 and
						math.deviation("ABAB", 65.0) == 0.5 and
						math.mean("ABCABC") == 66.0 and
						math.mean(0, 3) == 66.0 and
						math.serial_correlation("BCA") == -0.5 and
						math.serial_correlation(1, 3) == -0.5
				}
			`, []byte("ABCABC"))
		})

		t.Run("entropy-range", func(t *testing.T) {
			requireRuleMatches(t, harness, `
				import "math"
				rule test {
					condition:
						math.entropy(2, 3) == 0.0 and
						math.entropy(2, 100) == 1.0
				}
			`, []byte("CCAAACCC"))
		})

		t.Run("deviation-range", func(t *testing.T) {
			requireRuleMatches(t, harness, `
				import "math"
				rule test {
					condition:
						math.deviation(2, 4, 65.0) == 0.5
				}
			`, []byte("ABABABAB"))
		})

		t.Run("count-and-percentage", func(t *testing.T) {
			requireRuleMatches(t, harness, `
				import "math"
				rule test {
					condition:
						math.count(0x41, 0, 3) == 2 and
						math.count(0x41, 4, 10) == 1 and
						math.count(0x41, 0, 100) == 4 and
						math.percentage(0x41, 0, 3) >= 0.66 and
						math.percentage(0x41, 4, 10) == 0.5 and
						math.mode() == 0x41
				}
			`, []byte("AABAAB"))
		})

		t.Run("mode-range", func(t *testing.T) {
			requireRuleMatches(t, harness, `
				import "math"
				rule test {
					condition:
						math.mode(2, 3) == 0x41
				}
			`, []byte("CCABACC"))
		})

		t.Run("conversions", func(t *testing.T) {
			requireRuleMatches(t, harness, `
				import "math"
				rule test {
					condition:
						math.monte_carlo_pi(3, 15) < 0.3 and
						math.monte_carlo_pi("ABCDEF123456987") < 0.3 and
						math.to_string(1234) == "1234" and
						math.to_string(-1) == "-1" and
						math.to_string(32, 16) == "20" and
						math.to_string(32, 8) == "40" and
						math.to_string(32, 10) == "32" and
						not defined math.to_string(32, 7)
				}
			`, []byte("123ABCDEF123456987DE"))
		})
	})

	t.Run("pe", func(t *testing.T) {
		richPE := mustReadZippedIHEXFixture(t, "pe", "079a472d22290a94ebb212aa8015cdc8dd28a968c6b4d3b88acdd58ce2d3b885.in.zip")
		importsPE := mustReadZippedIHEXFixture(t, "pe", "2775d97f8bdb3311ace960a42eee35dbec84b9d71a6abbacb26c14e83f5897e4.in.zip")
		importRvaPE := mustReadZippedIHEXFixture(t, "pe", "0ba6042247d90a187919dd88dc2d55cd882c80e5afc511c4f7b2e0e193968f7f.in.zip")

		requireRuleMatches(t, harness, `
			import "pe"
			rule test {
				condition:
					pe.rich_signature.toolid(157) == 1 and
					pe.rich_signature.toolid(157, 40219) == 1 and
					pe.rich_signature.toolid(1, 0) > 40 and
					pe.rich_signature.toolid(1, 0) < 45 and
					pe.rich_signature.version(30319) == 3 and
					pe.rich_signature.version(40219) == 22 and
					pe.rich_signature.version(40219, 170) == 11 and
					pe.delayed_import_rva("QDB.dll", 95) == 16416
			}
		`, richPE)

		requireRuleMatches(t, harness, `
			import "pe"
			rule test {
				condition:
					pe.imports("KERNEL32.dll") == 17 and
					pe.imports("kernel32.dll") == 17 and
					pe.imports("KERNEL32.dll", "InterlockedExchange") and
					pe.imports(pe.IMPORT_DELAYED, "USER32.dll", "CreateMenu") and
					pe.imports(pe.IMPORT_ANY, "USER32.dll", "CreateMenu") and
					not pe.imports(pe.IMPORT_STANDARD, "USER32.dll", "CreateMenu") and
					pe.imports(pe.IMPORT_DELAYED, "COMCTL32.dll", 17)
			}
		`, importsPE)

		requireRuleMatches(t, harness, `
			import "pe"
			rule test {
				condition:
					pe.imports("kernel32.dll") == 6 and
					pe.imports("ws2_32.dll", 20) and
					pe.imports(pe.IMPORT_ANY, "ws2_32.dll") == 1 and
					pe.import_rva("ws2_32.dll", 20) == 38116 and
					pe.import_rva("kernel32.dll", "VirtualProtect") == 38072
			}
		`, importRvaPE)
	})

	t.Run("string", func(t *testing.T) {
		requireRuleMatches(t, harness, `
			import "string"
			rule test {
				condition:
					string.length("AXsx00ERS") == 9 and
					not (string.length("AXsx00ERS") > 9) and
					not (string.length("AXsx00ERS") < 9) and
					string.to_int("1234") == 1234 and
					string.to_int("-10") == -10 and
					string.to_int("A", 16) == 10 and
					string.to_int("011", 8) == 9 and
					string.to_int("-011", 8) == -9
			}
		`, nil)
	})

	t.Run("test-proto2", func(t *testing.T) {
		requireRuleMatches(t, harness, `
			import "test_proto2"
			rule test {
				condition:
					test_proto2.add(1, 2) == 3 and
					test_proto2.add(1.0, 2.0) == 3.0 and
					test_proto2.nested.nested_func() and
					test_proto2.uppercase("foo") == "FOO" and
					test_proto2.uppercase(test_proto2.string_foo) == "FOO" and
					test_proto2.int64_zero == 0 and
					test_proto2.int64_one == 1 and
					test_proto2.double_one + test_proto2.float_one == 2.0 and
					test_proto2.string_foo contains "oo" and
					test_proto2.string_bar iequals "BAR" and
					test_proto2.bytes_foo == test_proto2.string_foo and
					test_proto2.head(3) == "\x01\x02\x03"
			}
		`, []byte{0x01, 0x02, 0x03, 0x04})

		requireRuleMatches(t, harness, `
			import "test_proto2"
			rule test {
				condition:
					test_proto2.array_int64[0] == 1 and
					test_proto2.array_int64[1] == 10 and
					test_proto2.array_float[2] == 100.0 and
					not test_proto2.array_bool[0] and
					test_proto2.array_bool[1] and
					test_proto2.array_string[2] == "baz" and
					test_proto2.array_struct[0].nested_array_int64[1] == 10 and
					test_proto2.map_string_int64["one"] == 1 and
					test_proto2.map_string_bool["foo"] and
					test_proto2.map_string_struct["foo"].nested_int64_one == 1 and
					test_proto2.map_int64_string[100] == "one thousand" and
					test_proto2.map_int64_bool[100] and
					test_proto2.map_int64_struct[100].nested_int64_one == 1 and
					for any i in test_proto2.array_int64 : (i == 10) and
					for all s in test_proto2.array_string : (s == "foo" or s == "bar" or s == "baz")
			}
		`, []byte("ignored"))

		requireRuleMatches(t, harness, `
			import "test_proto2"
			rule test {
				condition:
					test_proto2.bool_yara and
					test_proto2.get_foo() == "foo" and
					test_proto2.to_int("123") == 123 and
					not test_proto2.nested.nested_method() and
					test_proto2.nested.nested_method_with_arg("foo") and
					not test_proto2.array_struct[0].nested_method() and
					test_proto2.array_struct[1].nested_method() and
					test_proto2.NestedProto2.NestedEnumeration.ITEM_1 == 1 and
					not (test_proto2.int64_undef == 0 and true) and
					(test_proto2.int64_undef == 0 or true)
			}
		`, []byte("ignored"))
	})

	t.Run("time", func(t *testing.T) {
		requireRuleMatches(t, harness, `
			import "time"
			rule test {
				condition:
					time.now() >= 0
			}
		`, nil)
	})

	t.Run("vt", func(t *testing.T) {
		vtOpts := []yara_x.CompileOption{
			yara_x.WithFeature("ip_address"),
			yara_x.WithFeature("file"),
		}

		requireRuleMatchesWithModuleOutput(t, harness, `
			import "vt"
			rule test {
				condition:
					vt.net.ip.raw == "192.168.1.100" and
					vt.metadata.itw.ip.raw == "142.250.184.164" and
					vt.net.ip.in_range("192.168.1.100/32") and
					vt.net.ip.in_range("192.168.1.1/17") and
					vt.net.ip.in_range("192.168.1.0/24") and
					not vt.net.ip.in_range("192.168.1.0/32") and
					not vt.net.ip.in_range("192.168.1.0/31") and
					vt.metadata.itw.ip.in_range("142.250.184.164/20") and
					vt.metadata.itw.ip.in_range("142.250.176.0/20")
			}
		`, nil, mustVtLiveHuntDataWithIPs(t, "192.168.1.100", "142.250.184.164"), vtOpts...)

		requireRuleMatchesWithModuleOutput(t, harness, `
			import "vt"
			rule test {
				condition:
					vt.net.ip.raw == "2001:0DB8:7654:0010:FEDC:0000:0000:3210" and
					vt.metadata.itw.ip.raw == "2001:db8::1" and
					vt.net.ip.in_range("2001:db8::1/32") and
					not vt.net.ip.in_range("2001:db8::1/34") and
					vt.metadata.itw.ip.in_range("2001:db8::1/64")
			}
		`, nil, mustVtLiveHuntDataWithIPs(t, "2001:0DB8:7654:0010:FEDC:0000:0000:3210", "2001:db8::1"), vtOpts...)

		requireRuleMatches(t, harness, `
			import "vt"
			rule test {
				condition:
					vt.Domain.Permutation.ALL == vt.Domain.Permutation.TYPO
						| vt.Domain.Permutation.HYPHENATION
						| vt.Domain.Permutation.HOMOGLYPH
						| vt.Domain.Permutation.SUBDOMAIN
						| vt.Domain.Permutation.BITSQUATTING
			}
		`, nil, vtOpts...)

		requireRuleMatchesWithModuleOutput(t, harness, `
			import "vt"
			rule test {
				condition:
					vt.net.domain.permutation_of("bankofamerica.com")
			}
		`, nil, mustVtLiveHuntDataWithDomain(t, "bancofamerica.com"), vtOpts...)

		requireRuleDoesNotMatchWithModuleOutput(t, harness, `
			import "vt"
			rule test {
				condition:
					vt.net.domain.permutation_of("www.google.com")
			}
		`, nil, mustVtLiveHuntDataWithDomain(t, "www.goggle.es"), vtOpts...)
	})
}

func requireRuleMatches(
	t *testing.T,
	h Harness,
	source string,
	data []byte,
	opts ...yara_x.CompileOption,
) {
	t.Helper()

	results := compileAndScan(t, h, source, data, ScanConfig{}, opts...)
	require.Len(t, results.MatchingRules(), 1)
}

func requireRuleDoesNotMatch(
	t *testing.T,
	h Harness,
	source string,
	data []byte,
	opts ...yara_x.CompileOption,
) {
	t.Helper()

	results := compileAndScan(t, h, source, data, ScanConfig{}, opts...)
	require.Empty(t, results.MatchingRules())
}

func requireRuleMatchesWithModuleOutput(
	t *testing.T,
	h Harness,
	source string,
	data []byte,
	output proto.Message,
	opts ...yara_x.CompileOption,
) {
	t.Helper()

	results := compileAndScan(t, h, source, data, ScanConfig{
		ModuleOutput: output,
	}, opts...)
	require.Len(t, results.MatchingRules(), 1)
}

func requireRuleDoesNotMatchWithModuleOutput(
	t *testing.T,
	h Harness,
	source string,
	data []byte,
	output proto.Message,
	opts ...yara_x.CompileOption,
) {
	t.Helper()

	results := compileAndScan(t, h, source, data, ScanConfig{
		ModuleOutput: output,
	}, opts...)
	require.Empty(t, results.MatchingRules())
}

func compileAndScan(
	t *testing.T,
	h Harness,
	source string,
	data []byte,
	cfg ScanConfig,
	opts ...yara_x.CompileOption,
) *yara_x.ScanResults {
	t.Helper()

	rules, err := yara_x.Compile(source, opts...)
	require.NoError(t, err)
	defer rules.Destroy()

	results, err := h.Scan(t, rules, data, cfg)
	require.NoError(t, err)
	return results
}

func mustReadZippedIHEXFixture(t *testing.T, module, filename string) []byte {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	require.True(t, ok)

	archivePath := filepath.Join(
		filepath.Dir(currentFile),
		"..",
		"..",
		"..",
		"lib",
		"src",
		"modules",
		module,
		"tests",
		"testdata",
		filename,
	)
	reader, err := zip.OpenReader(archivePath)
	require.NoError(t, err)
	defer reader.Close()

	innerName := strings.TrimSuffix(filepath.Base(archivePath), ".zip")
	for _, file := range reader.File {
		if file.Name != innerName {
			continue
		}

		rc, err := file.Open()
		require.NoError(t, err)

		content, err := io.ReadAll(rc)
		_ = rc.Close()
		require.NoError(t, err)

		return mustDecodeIHEX(t, string(content))
	}

	t.Fatalf("fixture archive %q does not contain %q", archivePath, innerName)
	return nil
}

func mustDecodeIHEX(t *testing.T, ihex string) []byte {
	t.Helper()

	lines := strings.Split(strings.ReplaceAll(ihex, "\r\n", "\n"), "\n")
	data := make([]byte, 0, len(lines)*16)

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}

		require.Truef(t, strings.HasPrefix(line, ":"), "invalid ihex line %q", line)
		require.GreaterOrEqualf(t, len(line), 11, "short ihex line %q", line)

		byteCount := mustParseHexByte(t, line[1:3])
		recordType := mustParseHexByte(t, line[7:9])
		payloadEnd := 9 + int(byteCount)*2
		require.GreaterOrEqualf(t, len(line), payloadEnd, "truncated ihex line %q", line)

		if recordType != 0x00 {
			continue
		}

		payload, err := hex.DecodeString(line[9:payloadEnd])
		require.NoError(t, err)
		data = append(data, payload...)
	}

	return data
}

func mustParseHexByte(t *testing.T, s string) uint8 {
	t.Helper()

	value, err := strconv.ParseUint(s, 16, 8)
	require.NoError(t, err)
	return uint8(value)
}

type vtMessageDescriptors struct {
	liveHuntData protoreflect.MessageDescriptor
	fileMetadata protoreflect.MessageDescriptor
	enrichedNet  protoreflect.MessageDescriptor
	enrichedIP   protoreflect.MessageDescriptor
	enrichedDom  protoreflect.MessageDescriptor
}

var (
	vtDescriptorOnce sync.Once
	vtDescriptorSet  vtMessageDescriptors
	vtDescriptorErr  error
)

func mustVtLiveHuntDataWithIPs(t *testing.T, netIP, metadataIP string) proto.Message {
	t.Helper()

	descs := mustVTMessageDescriptors(t)
	message := dynamicpb.NewMessage(descs.liveHuntData)

	net := message.Mutable(descs.liveHuntData.Fields().ByName("net")).Message()
	netIPMessage := net.Mutable(descs.enrichedNet.Fields().ByName("ip")).Message()
	netIPMessage.Set(descs.enrichedIP.Fields().ByName("raw"), protoreflect.ValueOfString(netIP))

	meta := message.Mutable(descs.liveHuntData.Fields().ByName("meta")).Message()
	itw := meta.Mutable(descs.fileMetadata.Fields().ByName("itw")).Message()
	metadataIPMessage := itw.Mutable(descs.enrichedNet.Fields().ByName("ip")).Message()
	metadataIPMessage.Set(descs.enrichedIP.Fields().ByName("raw"), protoreflect.ValueOfString(metadataIP))

	return message
}

func mustVtLiveHuntDataWithDomain(t *testing.T, domain string) proto.Message {
	t.Helper()

	descs := mustVTMessageDescriptors(t)
	message := dynamicpb.NewMessage(descs.liveHuntData)

	net := message.Mutable(descs.liveHuntData.Fields().ByName("net")).Message()
	domainMessage := net.Mutable(descs.enrichedNet.Fields().ByName("domain")).Message()
	domainMessage.Set(descs.enrichedDom.Fields().ByName("raw"), protoreflect.ValueOfString(domain))

	return message
}

func mustVTMessageDescriptors(t *testing.T) vtMessageDescriptors {
	t.Helper()

	vtDescriptorOnce.Do(func() {
		files := new(protoregistry.Files)

		vtnetFile, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
			Syntax:  proto.String("proto3"),
			Name:    proto.String("vt/vtnet.proto"),
			Package: proto.String("vt.net"),
			MessageType: []*descriptorpb.DescriptorProto{
				{
					Name: proto.String("EnrichedIP"),
					Field: []*descriptorpb.FieldDescriptorProto{
						{
							Name:   proto.String("raw"),
							Number: proto.Int32(18),
							Label:  fieldLabel(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
							Type:   fieldType(descriptorpb.FieldDescriptorProto_TYPE_STRING),
						},
					},
				},
				{
					Name: proto.String("EnrichedDomain"),
					Field: []*descriptorpb.FieldDescriptorProto{
						{
							Name:   proto.String("raw"),
							Number: proto.Int32(18),
							Label:  fieldLabel(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
							Type:   fieldType(descriptorpb.FieldDescriptorProto_TYPE_STRING),
						},
					},
				},
				{
					Name: proto.String("EnrichedNetloc"),
					Field: []*descriptorpb.FieldDescriptorProto{
						{
							Name:     proto.String("ip"),
							Number:   proto.Int32(2),
							Label:    fieldLabel(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
							Type:     fieldType(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE),
							TypeName: proto.String(".vt.net.EnrichedIP"),
						},
						{
							Name:     proto.String("domain"),
							Number:   proto.Int32(3),
							Label:    fieldLabel(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
							Type:     fieldType(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE),
							TypeName: proto.String(".vt.net.EnrichedDomain"),
						},
					},
				},
			},
		}, files)
		if err != nil {
			vtDescriptorErr = err
			return
		}
		if err := files.RegisterFile(vtnetFile); err != nil {
			vtDescriptorErr = err
			return
		}

		titanFile, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
			Syntax:     proto.String("proto3"),
			Name:       proto.String("vt/titan.proto"),
			Package:    proto.String("vt.titan"),
			Dependency: []string{"vt/vtnet.proto"},
			MessageType: []*descriptorpb.DescriptorProto{
				{
					Name: proto.String("FileMetadata"),
					Field: []*descriptorpb.FieldDescriptorProto{
						{
							Name:     proto.String("itw"),
							Number:   proto.Int32(32),
							Label:    fieldLabel(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
							Type:     fieldType(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE),
							TypeName: proto.String(".vt.net.EnrichedNetloc"),
						},
					},
				},
				{
					Name: proto.String("LiveHuntData"),
					Field: []*descriptorpb.FieldDescriptorProto{
						{
							Name:     proto.String("meta"),
							Number:   proto.Int32(1),
							Label:    fieldLabel(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
							Type:     fieldType(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE),
							TypeName: proto.String(".vt.titan.FileMetadata"),
						},
						{
							Name:     proto.String("net"),
							Number:   proto.Int32(3),
							Label:    fieldLabel(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
							Type:     fieldType(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE),
							TypeName: proto.String(".vt.net.EnrichedNetloc"),
						},
					},
				},
			},
		}, files)
		if err != nil {
			vtDescriptorErr = err
			return
		}

		vtDescriptorSet = vtMessageDescriptors{
			liveHuntData: titanFile.Messages().ByName("LiveHuntData"),
			fileMetadata: titanFile.Messages().ByName("FileMetadata"),
			enrichedNet:  vtnetFile.Messages().ByName("EnrichedNetloc"),
			enrichedIP:   vtnetFile.Messages().ByName("EnrichedIP"),
			enrichedDom:  vtnetFile.Messages().ByName("EnrichedDomain"),
		}
	})

	require.NoError(t, vtDescriptorErr)
	return vtDescriptorSet
}

func fieldLabel(label descriptorpb.FieldDescriptorProto_Label) *descriptorpb.FieldDescriptorProto_Label {
	return &label
}

func fieldType(typ descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto_Type {
	return &typ
}
