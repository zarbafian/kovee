# Golden vectors

Implementation-independent test vectors, one `family/name.json` file per
case, each an object with `name` (equal to `family/name`), `description`,
`input`, and `expected`. The K0 spec extraction populates this tree;
`python3 xcheck/run.py spec/vectors` and the `tscheck/` suite re-derive every
expected value with implementations that share no code with the Rust
workspace.

Acceptance vectors take their input as `raw` (UTF-8 text) or `synthetic`
(`oversized_request` with `target_bytes`, or the family PROFILE section 8
`json_synth` repetition: `prefix` + `repeat`×`count` + `suffix`), with an
optional `cap` of `request` (default) or `response` selecting the §11.8
byte-cap context. `expected.valid` is always asserted; when
`expected.error_class` is present both rederivers must also report exactly
that class from the pinned acceptance order (family PROFILE section 1 plus
the kovee contextual classes `over-list-items` / `over-inline-content`).
