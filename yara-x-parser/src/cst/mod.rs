/*! Concrete Syntax Tree (CST) for YARA rules.

 # Example

```rust
use yara_x_parser::{Parser, GrammarRule};
let rule = r#"
 rule test {
   condition:
     true
 }
"#;

let mut cst = Parser::new().build_cst(rule).unwrap();

// The CST is an iterator that returns nodes of type CSTNode. At the top
// level the iterator returns a single node, corresponding to the grammar
// rule source_file`, which is the grammar's top-level rule.
let root = cst.next().unwrap();

// The top-level rule is always `GrammarRule::source_file`.
assert_eq!(root.as_rule(), GrammarRule::source_file);

// With the `into_inner` method we obtain a new CST with the children of
// the top-level node. At this level there are three possible grammar
// rules, `import_stmt` and `rule_decl` and `EOI` (end-of-input).
for child in root.into_inner() {
    match child.as_rule() {
        GrammarRule::import_stmt => {
            // import statement
        },
        GrammarRule::rule_decl => {
            // rule declaration
        },
        GrammarRule::EOI => {
            // end of input
        },
        _ => unreachable!()
    }
}
```

*/

use std::fmt::Debug;

use pest::iterators::Pair;

use crate::parser::GrammarRule;

/// A node in the Concrete Syntax Tree (CST).
#[derive(Debug)]
pub struct CSTNode<'src> {
    comments: bool,
    whitespaces: bool,
    pair: Pair<'src, GrammarRule>,
}

impl<'src> CSTNode<'src> {
    /// Returns the grammar rule associated to this [`CSTNode`].
    pub fn as_rule(&self) -> GrammarRule {
        self.pair.as_rule()
    }

    /// Returns the span corresponding to this [`CSTNode`].
    ///
    /// [`pest::Span`] contains the positions within the original source code
    /// where the node starts and ends.
    pub fn as_span(&self) -> pest::Span<'src> {
        self.pair.as_span()
    }

    /// Returns the string slice within the original source code that
    /// corresponds to this [`CSTNode`].
    pub fn as_str(&self) -> &'src str {
        self.pair.as_str()
    }

    /// Returns a new [`CST`] with the children of this [`CSTNode`].
    pub fn into_inner(self) -> CST<'src> {
        CST {
            comments: self.comments,
            whitespaces: self.whitespaces,
            pairs: Box::new(self.into_inner_pairs()),
        }
    }

    /// Enables or disables comments while iterating the children of this
    /// [`CSTNode`].
    ///
    /// While traversing a CST, the nodes corresponding to the grammar rule
    /// `COMMENT` will be returned only if comments are enabled, and
    /// completely ignored if otherwise. This allows traversing the CST
    /// without having to take comments into account. The default value is
    /// `false`.
    pub fn comments(self, yes: bool) -> Self {
        Self { comments: yes, whitespaces: self.whitespaces, pair: self.pair }
    }

    /// Enables or disables whitespaces while iterating the children of this
    /// [`CSTNode`].
    ///
    /// While traversing a CST, the nodes corresponding to the grammar rule
    /// `WHITESPACE` will be returned only if whitespaces are enabled, and
    /// completely ignored if otherwise. This allows traversing the CST
    /// without having to take whitespaces into account. Notice that newlines
    /// are considered whitespaces in the CST. The default value is
    /// `false`.
    pub fn whitespaces(self, yes: bool) -> Self {
        Self { whitespaces: yes, comments: self.comments, pair: self.pair }
    }
}

impl<'src> CSTNode<'src> {
    /// Similar to [`CSTNode::into_inner`] but instead of returning a [`CST`]
    /// it returns an iterator of [`pest::iterators::Pair`].
    ///
    /// Better use [`CSTNode::into_inner`] if possible, this must be used only
    /// in those cases where an iterator of pairs is required.
    pub(crate) fn into_inner_pairs(self) -> impl PairsIterator<'src> {
        self.pair.into_inner().filter(move |item| match item.as_rule() {
            GrammarRule::COMMENT => self.comments,
            GrammarRule::WHITESPACE => self.whitespaces,
            _ => true,
        })
    }

    /// Returns the underlying [`pest::iterators::Pair`] corresponding to
    /// this [`CSTNode`].
    pub(crate) fn into_pair(self) -> Pair<'src, GrammarRule> {
        self.pair
    }
}

impl<'src> From<Pair<'src, GrammarRule>> for CSTNode<'src> {
    fn from(pair: Pair<'src, GrammarRule>) -> Self {
        Self { whitespaces: false, comments: false, pair }
    }
}

pub trait PairsIterator<'src>:
    Iterator<Item = Pair<'src, GrammarRule>> + 'src
{
}

impl<'src, T> PairsIterator<'src> for T where
    T: Iterator<Item = Pair<'src, GrammarRule>> + 'src
{
}

/// A Concrete Syntax Tree (CST) for YARA rules.
///
/// A CST is a tree where each node corresponds to a grammar rule in the
/// [`GrammarRule`] enum. This structure is actually an iterator that returns
/// tree nodes as instances of [`CSTNode`]. In turn, each [`CSTNode`] has a
/// [`CSTNode::into_inner`] method that returns a [`CST`] for iterating the
/// children of that node.
pub struct CST<'src> {
    pub(crate) comments: bool,
    pub(crate) whitespaces: bool,
    pub(crate) pairs: Box<dyn PairsIterator<'src>>,
}

impl<'src> Iterator for CST<'src> {
    type Item = CSTNode<'src>;
    fn next(&mut self) -> Option<Self::Item> {
        self.pairs.next().map(|pair| CSTNode {
            pair,
            whitespaces: self.whitespaces,
            comments: self.comments,
        })
    }
}

impl<'src> CST<'src> {
    /// Disables or enables comments in a CST.
    ///
    /// Sometimes is useful to traverse the CST without having to deal with
    /// comments that may appear all over the source code. The resulting CST
    /// won't return instances of [`GrammarRule::COMMENT`] while the tree is
    /// traversed.
    pub fn comments(self, yes: bool) -> Self {
        Self {
            comments: yes,
            whitespaces: self.whitespaces,
            pairs: self.pairs,
        }
    }

    /// Disables or enables whitespaces in a CST.
    ///
    /// Sometimes is useful to traverse the CST without having to deal with
    /// whitespaces that may appear all over the source code. The resulting CST
    /// won't return instances of [`GrammarRule::WHITESPACE`] while the tree is
    /// traversed.
    pub fn whitespaces(self, yes: bool) -> Self {
        Self { comments: self.comments, whitespaces: yes, pairs: self.pairs }
    }

    /// Returns an ASCII tree that represents the CST.
    #[cfg(feature = "ascii-tree")]
    pub fn ascii_tree(&mut self) -> Vec<ascii_tree::Tree> {
        let mut vec = Vec::new();
        for node in self.by_ref() {
            let node_content = node.as_str().trim();
            let grammar_rule = node.as_rule();
            if grammar_rule == GrammarRule::EOI {
                continue;
            }
            let sub_tree = node.into_inner().ascii_tree();
            let node = if sub_tree.is_empty() {
                let leaf = format!("{:?} \"{}\"", grammar_rule, node_content);
                ascii_tree::Tree::Leaf(vec![leaf])
            } else {
                ascii_tree::Tree::Node(format!("{:?}", grammar_rule), sub_tree)
            };
            vec.push(node);
        }
        vec
    }

    /// Returns a String with an ASCII tree that represents the CST.
    #[cfg(feature = "ascii-tree")]
    pub fn ascii_tree_string(&mut self) -> String {
        let mut buf = String::new();
        for tree in self.ascii_tree() {
            ascii_tree::write_tree(&mut buf, &tree).unwrap();
        }
        buf
    }
}
