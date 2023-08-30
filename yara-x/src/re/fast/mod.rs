pub(crate) mod fastvm;

mod compiler;
mod instr;

#[cfg(test)]
mod tests;

pub(crate) use compiler::Compiler;
