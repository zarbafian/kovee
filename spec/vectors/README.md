# Golden vectors

Implementation-independent test vectors, one `family/name.json` file per
case, each an object with `name` (equal to `family/name`), `description`,
`input`, and `expected`. The K0 spec extraction populates this tree;
`python3 xcheck/run.py spec/vectors` and the `tscheck/` suite re-derive every
expected value with implementations that share no code with the Rust
workspace.
