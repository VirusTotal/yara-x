// File generated automatically by build.rs. Do not edit.
{
#[cfg(feature = "console-module")]
add_module!(modules, "console", console, "console.Console", Some("console"), Some(console::__main__ as MainFn));
#[cfg(feature = "cuckoo-module")]
add_module!(modules, "cuckoo", cuckoo, "cuckoo.Cuckoo", Some("cuckoo"), Some(cuckoo::__main__ as MainFn));
#[cfg(feature = "dotnet-module")]
add_module!(modules, "dotnet", dotnet, "dotnet.Dotnet", Some("dotnet"), Some(dotnet::__main__ as MainFn));
#[cfg(feature = "elf-module")]
add_module!(modules, "elf", elf, "elf.ELF", Some("elf"), Some(elf::__main__ as MainFn));
#[cfg(feature = "hash-module")]
add_module!(modules, "hash", hash, "hash.Hash", Some("hash"), Some(hash::__main__ as MainFn));
#[cfg(feature = "lnk-module")]
add_module!(modules, "lnk", lnk, "lnk.Lnk", Some("lnk"), Some(lnk::__main__ as MainFn));
#[cfg(feature = "macho-module")]
add_module!(modules, "macho", macho, "macho.Macho", Some("macho"), Some(macho::__main__ as MainFn));
#[cfg(feature = "magic-module")]
add_module!(modules, "magic", magic, "magic.Magic", Some("magic"), Some(magic::__main__ as MainFn));
#[cfg(feature = "math-module")]
add_module!(modules, "math", math, "math.Math", Some("math"), Some(math::__main__ as MainFn));
#[cfg(feature = "pe-module")]
add_module!(modules, "pe", pe, "pe.PE", Some("pe"), Some(pe::__main__ as MainFn));
#[cfg(feature = "string-module")]
add_module!(modules, "string", string, "string.String", Some("string"), Some(string::__main__ as MainFn));
#[cfg(feature = "test_proto2-module")]
add_module!(modules, "test_proto2", test_proto2, "test_proto2.TestProto2", Some("test_proto2"), Some(test_proto2::__main__ as MainFn));
#[cfg(feature = "test_proto3-module")]
add_module!(modules, "test_proto3", test_proto3, "test_proto3.TestProto3", Some("test_proto3"), Some(test_proto3::__main__ as MainFn));
#[cfg(feature = "text-module")]
add_module!(modules, "text", text, "text.Text", Some("text"), Some(text::__main__ as MainFn));
#[cfg(feature = "time-module")]
add_module!(modules, "time", time, "time.Time", Some("time"), Some(time::__main__ as MainFn));
}