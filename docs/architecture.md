# YARA-X Architecture

## Overview
YARA-X is a pattern-matching engine designed to scan files and data streams for specific content defined by rules. To handle large files and tens of thousands of rules efficiently, YARA-X separates its work into two distinct phases: **Compilation** and **Scanning**. This separation allows heavy processing and optimization to occur once during compilation, producing efficient artifacts that can be executed quickly against many files.

---

## 1. The Compilation Pipeline
The compiler translates YARA rules from text into executable WebAssembly (WASM) bytecode and search structures.

### 1.1 Tokenization
- Path: `parser/src/tokenizer/mod.rs`
The first step is breaking the raw source text into tokens (keywords, identifiers, strings, operators). This is done using a finite state recognizer generated at compile time, ensuring fast processing without heap allocations.

### 1.2 Concrete Syntax Tree (CST)
- Path: `parser/src/cst/mod.rs`, `parser/src/parser/mod.rs`
The parser organizes tokens into a tree reflecting the exact grammar of the rules. This tree is "lossless," meaning it retains all whitespace and comments. This full fidelity is used by external tools like code formatters and language servers to understand the code exactly as written.

### 1.3 Abstract Syntax Tree (AST)
- Path: `parser/src/ast/mod.rs`
The compiler then derives an Abstract Syntax Tree (AST) by removing formatting details and focusing on the semantic meaning. Here, the compiler performs type checking, ensures variables are defined, and validates module imports.

### 1.4 Intermediate Representation (IR)
- Path: `lib/src/compiler/ir/ast2ir.rs`
The AST is lowered into an Intermediate Representation (IR), which is an internal language optimized for code generation. At this stage, optimizations like short-circuit evaluation are applied (e.g., ordering checks so that failing a cheap check avoids running an expensive one).

### 1.5 WebAssembly (WASM) Emission
- Path: `lib/src/compiler/emit.rs`
The final step of compilation translates the IR into WebAssembly bytecode. Each rule's condition becomes a Wasm function. WebAssembly provides a secure, sandboxed environment and near-native execution speed when run by a JIT compiler like Wasmtime.

---

## 2. Multi-Pattern Search Engine
Checking thousands of patterns individually against large files is slow. YARA-X uses a two-tier approach to search for all patterns simultaneously.

### 2.1 Atom Extraction
- Path: `lib/src/compiler/atoms/mod.rs`
Instead of searching for full regular expressions or long strings immediately, the compiler extracts "atoms"—short, fixed-length substrings (typically up to 4 bytes) that *must* be present for the pattern to match. If the extracted atom is not found in the file, the full pattern cannot match and is skipped. This drastically reduces the amount of data that needs to be processed by complex matching engines.

### 2.2 Pattern Splitting (Chaining)
- Path: `lib/src/compiler/ir/hex2hir.rs`
Patterns containing variable-length jumps (like `{ 01 02 [10-20] 03 04 }`) are difficult to handle efficiently in a single search structure. YARA-X splits these patterns into sub-patterns at the jump points. The search engine looks for the components independently and then verifies that they occur at the correct relative distance.

### 2.3 Aho-Corasick Automaton
- Path: `lib/src/compiler/rules.rs`
All atoms extracted from all rules are loaded into a single Aho-Corasick automaton. This data structure allows scanning the input data once to find all occurrences of all atoms simultaneously, making the initial search time independent of the number of rules.

---

## 3. Verification Virtual Machines
When the Aho-Corasick engine finds an atom, it triggers a verification step to see if the full pattern matches. YARA-X uses specialized virtual machines for this.

### 3.1 PikeVM
- Path: `lib/src/re/thompson/pikevm.rs`
For complex regular expressions, YARA-X uses PikeVM, which implements a Thompson NFA (Non-deterministic Finite Automaton) simulation. Unlike traditional regex engines that backtrack when a path fails (potentially causing exponential execution time called ReDoS), PikeVM explores all possible matching paths concurrently. This guarantees that execution time grows linearly with the file size.

### 3.2 FastVM
- Path: `lib/src/re/fast/fastvm.rs`
For simpler patterns that do not require tracking multiple simultaneous execution paths, YARA-X uses FastVM. This is a simpler, faster bytecode interpreter that handles basic matching without the overhead of state queue maintenance required by PikeVM.

---

## 4. Runtime Execution
- Path: `lib/src/scanner/context.rs`

During a scan, execution state is held in a `ScanContext`.
1. The **Aho-Corasick** engine scans the file and finds candidate atoms.
2. The **Virtual Machines** (PikeVM/FastVM) are triggered to verify full pattern matches and record them in the context.
3. The **WebAssembly** runtime executes the compiled bytecode, using the recorded match results and data from modules (like PE or ELF parsers) to evaluate the final rule conditions.
