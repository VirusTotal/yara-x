/*! A regexp compiler using the [Thompson's construction][1] algorithm that
produces code for the Pike VM described in Russ Cox's article
[Regular Expression Matching: the Virtual Machine Approach][2].

[1]: https://en.wikipedia.org/wiki/Thompson%27s_construction
[2]: https://swtch.com/~rsc/regexp/regexp2.html
*/

pub(crate) mod pikevm;

mod compiler;
mod instr;
#[cfg(test)]
mod tests;

pub(crate) use compiler::Compiler;
