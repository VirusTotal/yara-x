use std::collections::VecDeque;
use std::iter::Peekable;
use yara_x_parser::GrammarRule;

use crate::tokens::{categories, Token, TokenStream};

// The line below could be uncommented and all occurrences of
// Iterator<Item = Token<'a>> replaced with TokenIterator<'a>, which would
// improve legibility, however, trait aliases are still experimental.
// See https://github.com/rust-lang/rust/issues/41517> for more information.
//
// trait TokenIterator<'a> = Iterator<Item = Token<'a>>;

/// Processor represents a step in a processing pipeline. Each processor
/// receives a stream of input tokens, process them one by one, and produces
/// a stream of output tokens, that could be used as the input to the next
/// processor in the pipeline. The input is provided in the form of a token
/// iterator that is passed as an argument to [`Processor::new`]. The processor
/// itself implements the Iterator trait, and this iterator will return the
/// output tokens.
///
/// The input tokens are transformed into the output tokens according to rules
/// that are added to the processor using the [`Processor::add_rule`] method.
/// Each rule consists of a condition and an action. Conditions are functions
/// that receive a [`Context`] and return a boolean, the context provides access
/// to the next and previous tokens, and the returned boolean controls whether
/// the action associated to the rule will be executed or not.
///
/// The rules are tried in the order they were added to the processor. Once a
/// condition function returns true, the corresponding action is executed and
/// no more rules are tried. If none of the conditions are true the default
/// action will be executed, which is moving the token from the input to the
/// output (i.e: executing the "copy" action).
///
/// The main idea is described in [`A Pretty Good Formatting Pipeline`], but
/// some modifications has been made.
///
/// [`A Pretty Good Formatting Pipeline`]: https://bora.uib.no/bora-xmlui/handle/1956/8915
pub(crate) struct Processor<'a, T>
where
    T: TokenStream<'a>,
{
    context: Context<'a, T>,
    rules: Vec<(ConditionFn<'a, T>, ActionFn<'a, T>)>,
}

type ConditionFn<'a, T> = Box<dyn Fn(&Context<'a, T>) -> bool + 'a>;
type ActionFn<'a, T> = Box<dyn Fn(&mut Context<'a, T>) + 'a>;

impl<'a, T> Processor<'a, T>
where
    T: TokenStream<'a>,
{
    /// Creates a new processor that will process the given input.
    pub fn new(input: T) -> Self {
        Self {
            context: Context {
                input: input.peekable(),
                output: VecDeque::new(),
                stack: Vec::new(),
                prev_tokens: VecDeque::new(),
                next_tokens: VecDeque::new(),
                passthrough: *categories::NONE,
            },
            rules: Vec::new(),
        }
    }

    /// Sets a category of tokens that are copied directly from input to output
    /// without being processed by rules. All tokens in this category will be
    /// completely invisible to rules, and rules can be created as if those
    /// tokens don't exist at all. This means that if we have the sequence
    /// *foo*, *bar*, *baz*, where *bar* belongs to the passthrough category,
    /// from the rules standpoint the input sequence is *foo*, *baz* and
    /// therefore rule conditions that checks for *baz* being right after *foo*
    /// will be true.
    pub fn set_passthrough(mut self, category: categories::Category) -> Self {
        self.context.passthrough = category;
        self
    }

    /// Add a new processing rule. The order in which this method is called is
    /// relevant, rules are tried in the order they were added.
    pub fn add_rule<C, A>(mut self, condition: C, action: A) -> Self
    where
        C: Fn(&Context<'a, T>) -> bool + 'a,
        A: Fn(&mut Context<'a, T>) + 'a,
    {
        self.rules.push((Box::new(condition), Box::new(action)));
        self
    }
}

impl<'a, T> Iterator for Processor<'a, T>
where
    T: TokenStream<'a>,
{
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // If there are pending tokens in the output buffer, return one
            // of the pending tokens.
            if let Some(output) = self.context.output.pop_front() {
                return Some(output);
            }

            // `advance` returns false if there are no more tokens in the
            // input to be processed, or in the output buffer to be
            // returned. In that case the iterator can return None, as
            // there's nothing else to do.
            if self.context.advance() {
                return None;
            }

            let mut rule_found = false;

            for (condition, action) in self.rules.iter() {
                if (condition)(&self.context) {
                    rule_found = true;
                    (action)(&mut self.context);
                    // The action produced some to output
                    if !self.context.output.is_empty() {
                        break;
                    }
                }
            }

            // If no rule matched the current state perform the default
            // action, which is moving the token from the input to the
            // output.
            if !rule_found {
                let next = self.context.pop_input_token();
                self.context.push_output_token(next);
            }
        }
    }
}

/// Context is the structure passed to condition and action functions that
/// conform a processor rule.
///
/// The context has methods that allows conditions to peek into the next
/// input tokens, and the past output tokens. It also has methods that action
/// functions use for removing a token from the input and putting tokens into
/// the output.
#[derive(Debug)]
pub(crate) struct Context<'a, T>
where
    T: TokenStream<'a>,
{
    input: Peekable<T>,
    output: VecDeque<Token<'a>>,
    stack: Vec<super::GrammarRule>,
    prev_tokens: VecDeque<Token<'a>>,
    next_tokens: VecDeque<Token<'a>>,
    passthrough: categories::Category,
}

impl<'a, T> Context<'a, T>
where
    T: TokenStream<'a>,
{
    const MAX_PREV_TOKENS: usize = 3;
    const MAX_NEXT_TOKENS: usize = 3;

    /// Returns the next non-passthrough token from the input. Returns None
    /// if the end of the input has being reached. Tokens that match the
    /// passthrough category are copied directly to the output when found.
    pub fn pop_input_token(&mut self) -> Option<Token<'a>> {
        self.advance();
        self.next_tokens.pop_front()
    }

    /// Adds a token to the output.
    ///
    /// If `token` is `None` it does nothing. The reason for accepting an
    /// [`Option`] is allowing to pass the value returned by
    /// [`Context::pop_input_token`] directly to this function.
    pub fn push_output_token(&mut self, token: Option<Token<'a>>) {
        if token.is_none() {
            return;
        }

        let token = token.unwrap();

        if let Token::End(rule) = token {
            if let Some(top) = self.stack.pop() {
                assert_eq!(top, rule);
            }
        }

        if let Token::Begin(rule) = token {
            self.stack.push(rule)
        }

        // Store outputted token in prev_tokens, but only if it is a
        // non-passthrough token.
        if !token.is(self.passthrough) {
            self.prev_tokens.push_front(token.clone());
        }

        self.output.push_back(token);

        // Keep up to MAX_PREV_TOKENS in the prev_tokens, remove the oldest
        // one if necessary.
        if self.prev_tokens.len() > Self::MAX_PREV_TOKENS {
            self.prev_tokens.pop_back();
        }
    }

    /// Allows to peek into the next tokens in the input or the tokens recently
    /// put into the output. For example token(1) returns the next token in the
    /// input while token(2) returns the one that comes after token(1). In the
    /// other hand, token(-1) returns the most recent output and token(-2) the
    /// one that was outputted before token(-1).
    ///
    /// Valid values for n are in the range [-MAX_PREV_TOKENS..MAX_NEXT_TOKENS]
    /// (both inclusive) except 0, which is not valid. Invalid values of n
    /// make the function panic.
    ///
    /// Notice that passthrough tokens are completely ignored, which means that
    /// token(1) actually returns the first non-passthrough token in the input.
    ///
    /// If the requested token can't be returned because the end of the input
    /// is reached, or no token has been outputted yet, the result will be
    /// Token::None.
    pub fn token(&self, n: i8) -> &Token<'a> {
        // n is 1,2,3,4 ... MAX_NEXT_TOKENS
        if n >= 1 && n <= Self::MAX_NEXT_TOKENS as i8 {
            // Return Nth token that is not a
            self.next_tokens
                .iter()
                .filter(|token| !token.is(self.passthrough))
                .nth((n - 1) as usize)
                .unwrap_or(&Token::None)
        }
        // n is -1,-2,-3 ... -MAX_PREV_TOKENS
        else if n <= -1 && n >= -(Self::MAX_PREV_TOKENS as i8) {
            self.prev_tokens.get((-n - 1) as usize).unwrap_or(&Token::None)
        }
        // n out of the valid range or zero.
        else {
            panic!(
                "n must be in the range [-MAX_PREV_TOKENS..MAX_NEXT_TOKENS], \
                 both inclusive, and can't be 0"
            )
        }
    }

    /// Swaps the tokens at positions i and j in the input. Passthrough tokens
    /// are ignored, which means that position i means the i-th non-passthrough
    /// token in the input.
    pub fn swap(&mut self, i: i8, j: i8) {
        if i < 1
            || i > Self::MAX_NEXT_TOKENS as i8
            || j < 1
            || j > Self::MAX_NEXT_TOKENS as i8
        {
            panic!(
                "i and j must be in the range [1..MAX_NEXT_TOKENS], both inclusive"
            )
        }

        // Compute the actual index in the input for the i-th non-passthrough
        // token. The actual index can be larger than i, as the input may
        // contain passthrough tokens that should be ignored.
        let (index_i, _) = self
            .next_tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| !token.is(self.passthrough))
            .nth((i - 1) as usize)
            .unwrap();

        // Compute the actual index in the input for the j-th non-passthrough token
        let (index_j, _) = self
            .next_tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| !token.is(self.passthrough))
            .nth((j - 1) as usize)
            .unwrap();

        self.next_tokens.swap(index_i, index_j)
    }

    /// Returns true if the the next token is within the scope of a given
    /// parsing rule. Notice that the result is true only if the token is part
    /// of the rule itself, but not if the token is part of any of its
    /// sub-rules.
    ///
    /// For example, the code "rule test { condition: true }" produces the
    /// following sequence of tokens (indentation was added for highlighting
    /// the hierarchical structure of parsing rules):
    ///
    ///   Begin(Rule::rule_decl),
    ///      Keyword("rule"),
    ///      Identifier("test"),
    ///      Grouping("{"),
    ///      Keyword("condition"),
    ///      Punctuation(":"),
    ///      Begin(Rule::boolean_expr),
    ///         Keyword("true"),
    ///      End(Rule::boolean_expr),
    ///      Grouping("}"),
    ///   End(Rule::rule_decl),
    ///
    /// In the example above *Rule::boolean_expr* is a sub-rule of
    /// *Rule::rule_decl*, if in_rule(Rule::rule_decl) is called while
    /// the next token is the "true" keyword within *Rule::boolean_expr* the
    /// result will be false, because "true" is not directly within the scope
    /// of *Rule::rule_decl*. In the other hand in_rule(Rule::boolean_expr)
    /// will return true.
    pub fn in_rule(&self, rule: GrammarRule) -> bool {
        // We are within the scope of a certain rule if that rule is currently
        // at the top of the stack. The only exception is when the next token
        // indicates the end of the rule. If next token is Token::End(some_rule)
        // the rule at the top of the stack must be some_rule, but we don't
        // want Token::End(some_rule) to be within the scope of some_rule. Both
        // Token::Begin(some_rule) and Token::End(some_rule) are within the
        // scope of their parent rule.
        if let Some(&Token::End(rule)) = self.next_tokens.front() {
            // The next token indicates the end of a rule, make sure that the
            // top of the stack is that same rule.
            debug_assert_eq!(*self.stack.last().unwrap(), rule);
            // Get the rule that was in the stack before the one at the top.
            let before_top = match self.stack.len() {
                // The stack is empty or have only one item, so there's no
                // previous item.
                0..=1 => None,
                // Return the item previous to the top.
                n => self.stack.get(n - 1),
            };
            return if let Some(rule_before_top) = before_top {
                *rule_before_top == rule
            } else {
                false
            };
        }
        // Common case, where the next token is not Token::End.
        if let Some(top) = self.stack.last() {
            *top == rule
        } else {
            false
        }
    }

    /// Helper function that reads tokens from input and puts them into
    /// `next_tokens` until we have enough non-passthrough tokens to satisfy
    /// calls to `token(n)`. The function guarantees that the first token
    /// in `next_tokens` is a non-passthrough token.
    ///
    /// Returns true if there are token in `next_tokens` or if there are
    /// any pending tokens in the output buffer.
    fn advance(&mut self) -> bool {
        // Count the number of non-passthrough tokens already in the input
        // buffer.
        let mut non_passthrough_tokens = self
            .next_tokens
            .iter()
            .filter(|token| !token.is(self.passthrough))
            .count();
        // Keep reading tokens from the input and putting them in next_tokens
        // until next_tokens contains at least MAX_NEXT_TOKENS non-passthrough
        // tokens. Break the loop if the end of the input is reached.
        while non_passthrough_tokens < Self::MAX_NEXT_TOKENS {
            if let Some(next) = self.input.next() {
                if !next.is(self.passthrough) {
                    non_passthrough_tokens += 1;
                }
                self.next_tokens.push_back(next);
            } else {
                break;
            }
        }
        // Check if the tokens at the front of the input queue are passthrough
        // tokens. In that case copy them directly to the output until the we
        // have a non-passthrough token at the front of the queue.
        while let Some(token) = self.next_tokens.front() {
            if token.is(self.passthrough) {
                let token = self.next_tokens.pop_front().unwrap();
                // Adjust the stack if the passthrough token indicates the
                // start or the end of a rule.
                if let Token::Begin(rule) = token {
                    self.stack.push(rule)
                } else if let Token::End(rule) = token {
                    if let Some(top) = self.stack.pop() {
                        assert_eq!(top, rule);
                    }
                }
                self.output.push_back(token);
            } else {
                break;
            }
        }
        self.next_tokens.is_empty() && self.output.is_empty()
    }
}

pub(crate) mod actions {
    use crate::processor::{ActionFn, Context};
    use crate::tokens::{Token, TokenStream};

    /// Action that removes the next token from the input without producing
    /// any output.
    pub(crate) fn drop<'a, I>(ctx: &mut Context<'a, I>)
    where
        I: TokenStream<'a>,
    {
        // Removes next input token...
        ctx.pop_input_token();
        // ...but does not put it in the output, so it's dropped.
    }

    /// Action that removes the next token from the input and puts it into
    /// the output. Notice that this action is named as "move" in
    /// [`A Pretty Good Formatting Pipeline`], but "move" is reserved keyword
    /// in Rust.
    pub(crate) fn copy<'a, I>(ctx: &mut Context<'a, I>)
    where
        I: TokenStream<'a>,
    {
        // Removes next input token and returns it, so it gets copied to the
        // output.
        let token = ctx.pop_input_token();
        ctx.push_output_token(token);
    }

    /// Action that puts an space token into the output without removing
    /// the next token from the input.
    pub(crate) fn space<'a, I>(ctx: &mut Context<'a, I>)
    where
        I: TokenStream<'a>,
    {
        ctx.push_output_token(Some(Token::Whitespace));
    }

    /// Action that puts a line break token into the output without
    /// removing the next token from the input.
    pub(crate) fn newline<'a, I>(ctx: &mut Context<'a, I>)
    where
        I: TokenStream<'a>,
    {
        ctx.push_output_token(Some(Token::Newline));
    }

    /// Action that puts the specified token into the output without
    /// removing the next token from the input.
    pub(crate) fn insert<'a, I>(token: Token<'a>) -> ActionFn<'a, I>
    where
        I: TokenStream<'a>,
    {
        Box::new(move |ctx| ctx.push_output_token(Some(token.clone())))
    }

    /// Action that swaps the tokens at positions i and j in the input.
    /// Both i and j most be in the range [1..MAX_NEXT_TOKENS].
    pub(crate) fn swap<'a, I>(i: i8, j: i8) -> ActionFn<'a, I>
    where
        I: TokenStream<'a>,
    {
        Box::new(move |ctx| ctx.swap(i, j))
    }
}

#[cfg(test)]
mod tests;
