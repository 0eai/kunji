---
name: humanize-writing
description: Strip AI-writing tells from prose and match kunji's house voice. Use when the user asks to humanize, de-slop, or tighten writing — landing/marketing copy, developer guides, docs/*.md, commit messages, PR bodies, or a reply to a developer/user. Edits prose only; it never changes technical claims, and it is NOT a code-quality pass (that's simplify/code-audit).
---

# Humanize writing (kunji)

Rewrite prose so it reads like the person who wrote this repo, not like a model producing an
answer. **Cut the tells, keep every technical claim byte-exact.** If a rewrite makes the prose
nicer but the statement weaker, it failed.

## 1 · Pick the register first

Voice is not one thing here. Identify the target before touching a word:

| Target                       | Register                                                                                                                            |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `landing/*.html` (marketing) | Second person, short, concrete. Benefit then mechanism. Deliberate fragments are on-brand ("Nothing to phish").                     |
| `landing/developers/**`      | Consequence-first. Lead with what breaks and when: "an integrity hash on either one will break your sign-in the next time we ship." |
| `docs/*.md`, `AGENTS.md`     | Dense, normative, invariant-first. Keep the uppercase MUST / NEVER / DO NOT. Not the place for warmth.                              |
| Commit message / PR body     | Imperative subject; body explains _why_ and the consequence, not a file inventory.                                                  |
| Reply to a developer or user | Plain. Own the error in the first sentence, then the fix. No throat-clearing.                                                       |

## 2 · The tells (cut these)

Ranked by how often they actually show up in this repo's AI-authored prose:

1. **A bolded lead-in on every paragraph.** Turns prose into a slide deck. Keep it only for a
   genuinely parallel set; never three in a row.
2. **The enumeration preamble** — "Two things for you", "Three notes", "Two ways forward."
   Announcing the shape of an answer instead of writing it. Delete and just write the items.
3. **Antithesis reflex** — "that header is load-bearing, not decoration", "isn't a glitch", "not a
   file inventory." Sounds insightful, asserts nothing. Cut the negative half or drop the sentence.
   Note the _construction_ is the tell, not the vocabulary: "that isolation is load-bearing" is
   house style (§3); "load-bearing, not decoration" is the tic.
4. **Tables for non-tabular content.** A table whose second column is sentences is a table
   pretending to be rigor. Use one only for real dimensions × values (a smoke-check matrix qualifies).
5. **Padded triads.** Three items where two are real. Ship the two.
6. **Reflexive closing offer.** "Want me to X?" appended to every message. Ask only when genuinely
   blocked on the user's call.
7. **Restating the request** before answering it. Start with the answer.
8. **Filler intensifiers** — "genuinely", "actually", "real", "worth noting", "it's important to
   understand". Delete on sight; the sentence is always stronger.
9. **Uniform sentence rhythm.** Every sentence 15–25 words with an em-dash at the pivot. Break it:
   put a four-word sentence in.
10. **A closing summary that repeats the body.** If the body was clear, the summary is filler.

## 3 · House style — do NOT "fix" these

These read as tells elsewhere but are this repo's actual voice. Changing them is the mistake:

- **Em-dash pivots.** Used heavily and deliberately throughout `landing/` and `AGENTS.md`.
- **"load-bearing"** (7× in tracked prose), "fail closed", "byte-identical", "posture", "TOFU-bind".
  Established idiom, not filler.
- **Lowercase `kunji`**, always — including sentence-initial.
- **Second-person address** in marketing and developer copy ("your keys", "You are your key").
- **Backtick-dense technical nouns.** `sub`, `vaultWrite`, `rp-<version>.js` stay in code ticks.
- **`·` as a separator** in nav/footer strings.

## 4 · Never humanize away

Hard rails. Prose polish stops at the technical boundary:

- **Normative words in `docs/` and `AGENTS.md`.** MUST / MUST NOT / NEVER / DO NOT are load-bearing.
  Never soften a MUST to "should", and never relax the crypto-invariant warnings.
- **Exact tokens**: hashes, `m:262144/t:4/p:1`, file paths, function names, header values, versions.
  After editing, confirm each one survived verbatim.
- **Caveats stay attached to their claim.** "signed but **self-asserted and unverified** — RPs must
  treat it as untrusted" must never shorten to the reassuring half. Same for accepted-risk notes.
- **Don't convert a security limitation into a feature.** `WALLET_TRUST_ANCHORS = []` fails closed;
  that is a constraint, not a selling point.

## 5 · Mechanics that bite here

- **Not prettier-clean at HEAD:** the HTML under `landing/` and `firebase.json` — and they are not in
  `.prettierignore`. Running `prettier --write` on them buries a two-line copy edit in a whole-file
  reformat. Edit surgically; never format-on-save these.
- **Don't put a `*`-glob inside `**bold**` in markdown.** Prettier misparses the two together and
  eats the surrounding backtick spacing (it mangled this very bullet once). Name the directory in
  prose instead of writing the glob.
- **`.md` prose wraps at ~100 cols.** Match it, or the diff reflows paragraphs you didn't touch.
- `CLAUDE.md` is a symlink to `AGENTS.md` — edit `AGENTS.md`.
- Copy that names a URL or hash must be true post-deploy. If it references something not yet
  shipped, say so rather than publishing a 404.

## 6 · Method

1. Read the full target file plus ~20 surrounding lines — voice is local.
2. Name the register (§1) and the audience out loud before editing.
3. Pass once for tells (§2). Pass again for rails (§4).
4. Read it back for rhythm: if no sentence is under eight words, you're not done.
5. **Show the before/after** for anything outward-facing (marketing, developer guides, a reply
   someone will send). Don't silently rewrite published copy.
6. `npm run lint` if you touched `.js`; prose-only edits to `.md`/`.html` need no gate.

## Output

For a small edit, apply it and quote the changed lines. For a page or a batch, list each change as
`file:line` — before → after, one line each — then apply. Flag anything where the honest rewrite
changes the _meaning_ rather than the wording; that's the user's call, not a style fix.
