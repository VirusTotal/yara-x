/*! A regexp compiler based on the [Thompson's construction][1] algorithm that
produces code for the Pike VM described in Russ Cox's article
[Regular Expression Matching: the Virtual Machine Approach][2].

The only fundamental difference with the algorithms described in the cited
articles are the way in which repetitions are handled. In the original
algorithm a repetition like `abc{3}` is actually implemented by repeating
the pattern three times, as in `abcabcabc`. A pattern like `abc{2,4}` is
expressed like `abcabc(abc)?(abc)?`.

This approach is simple, but the size of the code produced for the Pike VM
is very large when the number of repetitions is large. Also, the number of
active threads can become very large, which has an important impact on
performance.

In this implementation we introduce two new instructions for the Pike VM:
REPEAT_GREEDY and REPEAT_UNGREEDY, which are used for expressing some of the
repetitions found in the regular expression. Particularly those that are
repeated a large number of times. This also implies that each thread not only
has an instruction pointer, it also has a repetition count. Both the
instruction pointer and the repetition count are part of the thread's state.

[1]: https://en.wikipedia.org/wiki/Thompson%27s_construction
[2]: https://swtch.com/~rsc/regexp/regexp2.html
*/

pub(crate) use compiler::Compiler;
pub(crate) use pikevm::PikeVM;

mod compiler;
mod instr;
mod pikevm;

#[cfg(test)]
mod tests;
