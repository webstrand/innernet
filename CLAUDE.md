# innernet

Only the last tagged release has users: anything added after it may change without migrations or
compatibility shims.

## Writing style

Write in an impersonal register, in the style of Diátaxis reference documentation. Use third person and indicative mood; never address the reader as "you". When an action's agent matters, in particular who can or must perform it, name the agent as the subject using a generic role (the operator, the server, an admin client). Prefer passive voice only when the agent is unknown or irrelevant, and keep the topic of each sentence as its subject. State obligations with modals (must, should) rather than imperatives.

## Commits

- Every new commit should pass `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo test --workspace` (use `--offline`; dependencies are in the local cache). Rewriting history only need check commits that did not apply cleanly and were changed.
- A commit whose subject starts with `WIP` holds a change that the fork keeps but has not
  committed to upstreaming.
- `WIP PRIVATE:` marks a deviation from upstream: a local preference, a feature that upstream may
  not want, or a change not yet in a form that upstream would take. Such a commit is never
  dropped. Later commits may build on it, and nobody checks whether they do, so a commit meant for
  upstream may depend on WIP PRIVATE commits.
- `WIP TODO:` marks scratchpad notes about the work itself, never meant for upstream. A change to
  the notes may be a new WIP TODO commit or a fixup of an existing one.
