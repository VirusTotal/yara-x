/*!
This module implements a regexp compiler and matching engine based on the Pike's
VM described in https://swtch.com/~rsc/regexp/regexp2.html
*/

pub mod compiler;
pub mod instr;
pub mod pikevm;

#[cfg(test)]
mod tests;
