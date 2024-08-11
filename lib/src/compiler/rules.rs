use std::fmt;
use std::io::{BufWriter, Read, Write};
#[cfg(feature = "logging")]
use std::time::Instant;

use aho_corasick::AhoCorasick;
use bincode::Options;
#[cfg(feature = "logging")]
use log::*;
use regex_automata::meta::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::compiler::atoms::Atom;
use crate::compiler::report::SourceRef;
use crate::compiler::warnings::Warning;
use crate::compiler::{
    IdentId, Imports, LiteralId, NamespaceId, PatternId, RegexpId, RuleId,
    SubPattern, SubPatternId,
};
use crate::re::{BckCodeLoc, FwdCodeLoc, RegexpAtom};
use crate::string_pool::{BStringPool, StringPool};
use crate::{re, types, SerializationError};

/// A set of YARA rules in compiled form.
///
/// This is the result from [`crate::Compiler::build`].
#[derive(Serialize, Deserialize)]
pub struct Rules {
    /// Pool with identifiers used in the rules. Each identifier has its
    /// own [`IdentId`], which can be used for retrieving the identifier
    /// from the pool as a `&str`.
    pub(in crate::compiler) ident_pool: StringPool<IdentId>,

    /// Pool with the regular expressions used in the rules conditions. Each
    /// regular expression has its own [`RegexpId`]. Regular expressions
    /// include the starting and ending slashes (`/`), and the modifiers
    /// `i` and `s` if present (e.g: `/foobar/`, `/foo/i`, `/bar/s`).
    pub(in crate::compiler) regexp_pool: StringPool<RegexpId>,

    /// If `true`, the regular expressions in `regexp_pool` are allowed to
    /// contain invalid escape sequences.
    pub(in crate::compiler) relaxed_re_syntax: bool,

    /// Pool with literal strings used in the rules. Each literal has its
    /// own [`LiteralId`], which can be used for retrieving the literal
    /// string as `&BStr`.
    pub(in crate::compiler) lit_pool: BStringPool<LiteralId>,

    /// WASM module already compiled into native code for the current platform.
    #[serde(
        serialize_with = "serialize_wasm_mod",
        deserialize_with = "deserialize_wasm_mod"
    )]
    pub(in crate::compiler) wasm_mod: wasmtime::Module,

    /// Vector with the names of all the imported modules. The vector contains
    /// the [`IdentId`] corresponding to the module's identifier.
    pub(in crate::compiler) imported_modules: Vec<IdentId>,

    /// Vector containing all the compiled rules. A [`RuleId`] is an index
    /// in this vector.
    pub(in crate::compiler) rules: Vec<RuleInfo>,

    /// Total number of patterns across all rules. This is equal to the last
    /// [`PatternId`] +  1.
    pub(in crate::compiler) num_patterns: usize,

    /// Vector with all the sub-patterns from all rules. A [`SubPatternId`]
    /// is an index in this vector. Each pattern is composed of one or more
    /// sub-patterns, if any of the sub-patterns matches, the pattern matches.
    ///
    /// For example, when a text pattern is accompanied by both the `ascii`
    /// and `wide` modifiers, two sub-patterns are generated for it: one for
    /// the ascii variant, and the other for the wide variant.
    ///
    /// Each sub-pattern in this vector is accompanied by the [`PatternId`]
    /// where the sub-pattern belongs to.
    pub(in crate::compiler) sub_patterns: Vec<(PatternId, SubPattern)>,

    /// Vector that contains the [`SubPatternId`] for sub-patterns that can
    /// match only at a fixed offset within the scanned data. These sub-patterns
    /// are not added to the Aho-Corasick automaton.
    pub(in crate::compiler) anchored_sub_patterns: Vec<SubPatternId>,

    /// A vector that contains all the atoms extracted from the patterns. Each
    /// atom has an associated [`SubPatternId`] that indicates the sub-pattern
    /// it belongs to.
    pub(in crate::compiler) atoms: Vec<SubPatternAtom>,

    /// A vector that contains the code for all regexp patterns (this includes
    /// hex patterns which are just a special case of regexp). The code for
    /// each regexp is appended to the vector, during the compilation process
    /// and the atoms extracted from the regexp contain offsets within this
    /// vector. This vector contains both forward and backward code.
    pub(in crate::compiler) re_code: Vec<u8>,

    /// A [`types::Struct`] in serialized form that contains all the global
    /// variables. Each field in the structure corresponds to a global variable
    /// defined at compile time using [`crate::compiler::Compiler`].
    pub(in crate::compiler) serialized_globals: Vec<u8>,

    /// Aho-Corasick automaton containing the atoms extracted from the patterns.
    /// This allows to search for all the atoms in the scanned data at the same
    /// time in an efficient manner. The automaton is not serialized during when
    /// [`Rules::serialize`] is called, it needs to be wrapped in [`Option`] so
    /// that we can use `#[serde(skip)]` on it because [`AhoCorasick`] doesn't
    /// implement the [`Default`] trait.
    #[serde(skip)]
    pub(in crate::compiler) ac: Option<AhoCorasick>,

    /// Warnings that were produced while compiling these rules. These warnings
    /// are not serialized, rules that are obtained by deserializing previously
    /// serialized rules won't have any warnings.
    #[serde(skip)]
    pub(in crate::compiler) warnings: Vec<Warning>,
}

impl Rules {
    /// An iterator that yields the name of the modules imported by the
    /// rules.
    pub fn imports(&self) -> Imports {
        Imports {
            iter: self.imported_modules.iter(),
            ident_pool: &self.ident_pool,
        }
    }

    /// Warnings produced while compiling these rules.
    pub fn warnings(&self) -> &[Warning] {
        self.warnings.as_slice()
    }

    /// Serializes the rules as a sequence of bytes.
    ///
    /// The [`Rules`] can be restored back by passing the bytes to
    /// [`Rules::deserialize`].
    pub fn serialize(&self) -> Result<Vec<u8>, SerializationError> {
        let mut bytes = Vec::new();
        self.serialize_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Deserializes the rules from a sequence of bytes produced by
    /// [`Rules::serialize`].
    pub fn deserialize<B>(bytes: B) -> Result<Self, SerializationError>
    where
        B: AsRef<[u8]>,
    {
        let bytes = bytes.as_ref();
        let magic = b"YARA-X";

        if bytes.len() < magic.len() || &bytes[0..magic.len()] != magic {
            return Err(SerializationError::InvalidFormat);
        }

        #[cfg(feature = "logging")]
        let start = Instant::now();

        // Skip the magic and deserialize the remaining data.
        let mut rules = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .deserialize::<Self>(&bytes[magic.len()..])?;

        #[cfg(feature = "logging")]
        info!("Deserialization time: {:?}", Instant::elapsed(&start));

        rules.build_ac_automaton();

        Ok(rules)
    }

    /// Serializes the rules into a `writer`.
    pub fn serialize_into<W>(
        &self,
        writer: W,
    ) -> Result<(), SerializationError>
    where
        W: Write,
    {
        let mut writer = BufWriter::new(writer);

        // Write file header.
        writer.write_all(b"YARA-X")?;

        // Serialize rules.
        Ok(bincode::DefaultOptions::new()
            .with_varint_encoding()
            .serialize_into(writer, self)?)
    }

    /// Deserializes the rules from a `reader`.
    pub fn deserialize_from<R>(
        mut reader: R,
    ) -> Result<Self, SerializationError>
    where
        R: Read,
    {
        let mut bytes = Vec::new();
        let _ = reader.read_to_end(&mut bytes)?;
        Self::deserialize(bytes)
    }

    /// Returns a [`RuleInfo`] given its [`RuleId`].
    ///
    /// # Panics
    ///
    /// If no rule with such [`RuleId`] exists.
    pub(crate) fn get(&self, rule_id: RuleId) -> &RuleInfo {
        self.rules.get(rule_id.0 as usize).unwrap()
    }

    /// Returns a regular expression by [`RegexpId`].
    ///
    /// # Panics
    ///
    /// If no regular expression with such [`RegexpId`] exists.
    #[inline]
    pub(crate) fn get_regexp(&self, regexp_id: RegexpId) -> Regex {
        let re = types::Regexp::new(self.regexp_pool.get(regexp_id).unwrap());

        let parser = re::parser::Parser::new()
            .relaxed_re_syntax(self.relaxed_re_syntax);

        let hir = parser.parse(&re).unwrap().into_inner();

        // Set a size limit for the NFA automata. The default limit (10MB) is
        // too small for certain regexps seen in YARA rules in the wild, see:
        // https://github.com/VirusTotal/yara-x/issues/85
        let config = regex_automata::meta::Config::new()
            .nfa_size_limit(Some(50 * 1024 * 1024));

        regex_automata::meta::Builder::new()
            .configure(config)
            .build_from_hir(&hir)
            .unwrap_or_else(|err| {
                panic!("error compiling regex `{}`: {:#?}", re.as_str(), err)
            })
    }

    /// Returns a sub-pattern by [`SubPatternId`].
    #[inline]
    pub(crate) fn get_sub_pattern(
        &self,
        sub_pattern_id: SubPatternId,
    ) -> &(PatternId, SubPattern) {
        unsafe { self.sub_patterns.get_unchecked(sub_pattern_id.0 as usize) }
    }

    /// Given a [`SubPatternId`], returns the [`RuleId`] corresponding to the
    /// rule that contains the sub-pattern, and the [`IdentId`] for the pattern's
    /// identifier.
    ///
    /// This operation is slow, because it implies iterating over all the rules
    /// and their sub-patterns until finding the one we are looking for.
    #[cfg(feature = "logging")]
    pub(crate) fn get_rule_and_pattern_by_sub_pattern_id(
        &self,
        sub_pattern_id: SubPatternId,
    ) -> Option<(RuleId, IdentId)> {
        let (target_pattern_id, _) = self.get_sub_pattern(sub_pattern_id);
        for (rule_id, rule) in self.rules.iter().enumerate() {
            for (ident_id, pattern_id) in &rule.patterns {
                if pattern_id == target_pattern_id {
                    return Some((rule_id.into(), *ident_id));
                };
            }
        }
        None
    }

    #[cfg(feature = "rules-profiling")]
    #[inline]
    pub(crate) fn rules(&self) -> &[RuleInfo] {
        self.rules.as_slice()
    }

    #[inline]
    pub(crate) fn atoms(&self) -> &[SubPatternAtom] {
        self.atoms.as_slice()
    }

    #[inline]
    pub(crate) fn anchored_sub_patterns(&self) -> &[SubPatternId] {
        self.anchored_sub_patterns.as_slice()
    }

    #[inline]
    pub(crate) fn re_code(&self) -> &[u8] {
        self.re_code.as_slice()
    }

    #[inline]
    pub(crate) fn num_rules(&self) -> usize {
        self.rules.len()
    }

    #[inline]
    pub(crate) fn num_patterns(&self) -> usize {
        self.num_patterns
    }

    /// Returns the Aho-Corasick automaton that allows to search for pattern
    /// atoms.
    #[inline]
    pub(crate) fn ac_automaton(&self) -> &AhoCorasick {
        self.ac.as_ref().expect("Aho-Corasick automaton not compiled")
    }

    pub(crate) fn build_ac_automaton(&mut self) {
        if self.ac.is_some() {
            return;
        }

        #[cfg(feature = "logging")]
        let start = Instant::now();

        #[cfg(feature = "logging")]
        let mut num_atoms = [0_usize; 6];

        let atoms = self.atoms.iter().map(|x| {
            #[cfg(feature = "logging")]
            {
                match x.atom.len() {
                    atom_len @ 0..=4 => num_atoms[atom_len] += 1,
                    _ => num_atoms[num_atoms.len() - 1] += 1,
                }

                if x.atom.len() < 2 {
                    let (rule_id, pattern_ident_id) = self
                        .get_rule_and_pattern_by_sub_pattern_id(
                            x.sub_pattern_id,
                        )
                        .unwrap();

                    let rule = self.get(rule_id);

                    info!(
                            "Very short atom in pattern `{}` in rule `{}:{}` (length: {})",
                            self.ident_pool.get(pattern_ident_id).unwrap(),
                            self.ident_pool
                                .get(rule.namespace_ident_id)
                                .unwrap(),
                            self.ident_pool.get(rule.ident_id).unwrap(),
                            x.atom.len()
                        );
                }
            }

            x.atom.as_ref()
        });

        self.ac = Some(
            AhoCorasick::new(atoms)
                .expect("failed to build Aho-Corasick automaton"),
        );

        #[cfg(feature = "logging")]
        {
            info!(
                "Aho-Corasick automaton build time: {:?}",
                Instant::elapsed(&start)
            );

            info!("Number of rules: {}", self.num_rules());
            info!("Number of patterns: {}", self.num_patterns());
            info!(
                "Number of anchored sub-patterns: {}",
                self.anchored_sub_patterns.len()
            );
            info!("Number of atoms: {}", self.atoms.len());
            info!("Atoms with len = 0: {}", num_atoms[0]);
            info!("Atoms with len = 1: {}", num_atoms[1]);
            info!("Atoms with len = 2: {}", num_atoms[2]);
            info!("Atoms with len = 3: {}", num_atoms[3]);
            info!("Atoms with len = 4: {}", num_atoms[4]);
            info!("Atoms with len > 4: {}", num_atoms[5]);
        }
    }

    #[inline]
    pub(crate) fn lit_pool(&self) -> &BStringPool<LiteralId> {
        &self.lit_pool
    }

    #[inline]
    pub(crate) fn ident_pool(&self) -> &StringPool<IdentId> {
        &self.ident_pool
    }

    #[inline]
    pub(crate) fn globals(&self) -> types::Struct {
        bincode::DefaultOptions::new()
            .deserialize::<types::Struct>(self.serialized_globals.as_slice())
            .expect("error deserializing global variables")
    }

    #[inline]
    pub(crate) fn wasm_mod(&self) -> &wasmtime::Module {
        &self.wasm_mod
    }
}

fn serialize_wasm_mod<S>(
    wasm_mod: &wasmtime::Module,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bytes = wasm_mod
        .serialize()
        .map_err(|err| serde::ser::Error::custom(err.to_string()))?;

    serializer.serialize_bytes(bytes.as_slice())
}

pub fn deserialize_wasm_mod<'de, D>(
    deserializer: D,
) -> Result<wasmtime::Module, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: &[u8] = Deserialize::deserialize(deserializer)?;

    unsafe {
        wasmtime::Module::deserialize(&crate::wasm::ENGINE, bytes)
            .map_err(|err| serde::de::Error::custom(err.to_string()))
    }
}

impl fmt::Debug for Rules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (id, rule) in self.rules.iter().enumerate() {
            let name = self.ident_pool.get(rule.ident_id).unwrap();
            let namespace =
                self.ident_pool.get(rule.namespace_ident_id).unwrap();
            writeln!(f, "RuleId({})", id)?;
            writeln!(f, "  namespace: {}", namespace)?;
            writeln!(f, "  name: {}", name)?;
            writeln!(f, "  patterns:")?;
            for (pattern_ident_id, pattern_id) in &rule.patterns {
                let ident = self.ident_pool.get(*pattern_ident_id).unwrap();
                writeln!(f, "    {:?} {} ", pattern_id, ident)?;
            }
        }

        for (id, (pattern_id, _)) in self.sub_patterns.iter().enumerate() {
            writeln!(f, "SubPatternId({}) -> {:?}", id, pattern_id)?;
        }

        Ok(())
    }
}

/// Metadata values.
#[derive(Serialize, Deserialize)]
pub(crate) enum MetaValue {
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(LiteralId),
    Bytes(LiteralId),
}

/// Information about each of the individual rules included in [`Rules`].
#[derive(Serialize, Deserialize)]
pub(crate) struct RuleInfo {
    /// The ID of the namespace the rule belongs to.
    pub(crate) namespace_id: NamespaceId,
    /// The ID of the rule namespace in the identifiers pool.
    pub(crate) namespace_ident_id: IdentId,
    /// The ID of the rule identifier in the identifiers pool.
    pub(crate) ident_id: IdentId,
    /// Tags associated to the rule.
    pub(crate) tags: Vec<IdentId>,
    /// Reference to the rule identifier in the source code. This field is
    /// ignored while serializing and deserializing compiles rules, as it
    /// is used only during the compilation phase, but not during the scan
    /// phase.
    #[serde(skip)]
    pub(crate) ident_ref: SourceRef,
    /// Metadata associated to the rule.
    pub(crate) metadata: Vec<(IdentId, MetaValue)>,
    /// Vector with all the patterns defined by this rule.
    pub(crate) patterns: Vec<(IdentId, PatternId)>,
    /// True if the rule is global.
    pub(crate) is_global: bool,
    /// True if the rule is private.
    pub(crate) is_private: bool,
}

/// Represents an atom extracted from a pattern and added to the Aho-Corasick
/// automata.
///
/// Each time the Aho-Corasick finds one of these atoms, it proceeds to verify
/// if the corresponding sub-pattern actually matches or not. The verification
/// process depend on the type of sub-pattern.
#[derive(Serialize, Deserialize)]
pub(crate) struct SubPatternAtom {
    /// The [`SubPatternId`] that identifies the sub-pattern this atom
    /// belongs to.
    sub_pattern_id: SubPatternId,
    /// The atom itself.
    atom: Atom,
    /// The index within `re_code` where the forward code for this atom starts.
    fwd_code: Option<FwdCodeLoc>,
    /// The index within `re_code` where the backward code for this atom starts.
    bck_code: Option<BckCodeLoc>,
}

impl SubPatternAtom {
    #[inline]
    pub(crate) fn from_atom(sub_pattern_id: SubPatternId, atom: Atom) -> Self {
        Self { sub_pattern_id, atom, bck_code: None, fwd_code: None }
    }

    pub(crate) fn from_regexp_atom(
        sub_pattern_id: SubPatternId,
        value: RegexpAtom,
    ) -> Self {
        Self {
            sub_pattern_id,
            atom: value.atom,
            fwd_code: value.fwd_code,
            bck_code: value.bck_code,
        }
    }

    #[inline]
    pub(crate) fn sub_pattern_id(&self) -> SubPatternId {
        self.sub_pattern_id
    }

    #[cfg(feature = "exact-atoms")]
    #[inline]
    pub(crate) fn is_exact(&self) -> bool {
        self.atom.is_exact()
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.atom.len()
    }

    #[inline]
    pub(crate) fn backtrack(&self) -> usize {
        self.atom.backtrack() as usize
    }

    #[inline]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.atom.as_ref()
    }

    #[inline]
    pub(crate) fn fwd_code(&self) -> Option<FwdCodeLoc> {
        self.fwd_code
    }

    #[inline]
    pub(crate) fn bck_code(&self) -> Option<BckCodeLoc> {
        self.bck_code
    }
}
