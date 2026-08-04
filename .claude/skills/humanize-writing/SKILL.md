---
name: humanize-writing
description: Strip AI-writing tells from prose and match kunji's house voice. Use when the user asks to humanize, de-slop, or tighten writing — landing/marketing copy, developer guides, docs/*.md, commit messages, PR bodies, or a reply to a developer/user. Edits prose only; it never changes technical claims, and it is NOT a code-quality pass (that's simplify/code-audit).
---

# Humanize writing (kunji)

Rewrite prose so it reads like the person who wrote this repo, not like a model producing an
answer. **Cut the tells, keep every technical claim byte-exact.** If a rewrite makes the prose
nicer but the statement weaker, it failed.

§2 is consolidated from five external references (listed at the end). §3 then carves out the few
patterns those sources flag that are genuine kunji decisions, and §3 wins on conflict — the sources
describe generic web prose, not a security-audited protocol codebase.

**Do not arbitrate by looking at existing prose.** Almost everything in this repo was written with AI
assistance, so the tree is evidence of habit, not of intent. §3 lists only what traces to a product
or brand decision; everything else in §2 applies here as written.

## 1 · Pick the register first

Voice is not one thing here. Identify the target before touching a word:

| Target                       | Register                                                                                                                            |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `landing/*.html` (marketing) | Second person, short, concrete. Benefit then mechanism. Deliberate fragments are on-brand ("Nothing to phish").                     |
| `landing/developers/**`      | Consequence-first. Lead with what breaks and when: "an integrity hash on either one will break your sign-in the next time we ship." |
| `docs/*.md`, `AGENTS.md`     | Dense, normative, invariant-first. Keep the uppercase MUST / NEVER / DO NOT. Not the place for warmth.                              |
| Commit message / PR body     | Imperative subject; body explains _why_ and the consequence, not a file inventory.                                                  |
| Reply to a developer or user | Plain. Own the error in the first sentence, then the fix. No throat-clearing.                                                       |

Two sources prescribe "inject personal voice and emotion" as the cure for AI flatness. That applies
to the **reply** register only. In `docs/` and `AGENTS.md`, flat and normative is correct — warmth
there is the defect, not the fix.

## 2 · The tells

### A · Structural rhetoric

1. **The antithesis family.** All five sources flag this; it is the most common tell in this repo's
   AI-authored prose. Four templates, all the same move: `not just X but also Y` · `not X, but Y` ·
   `X rather than Y` · `isn't just X — it's Y`. Sounds insightful, asserts nothing. Cut the negative
   half and keep the claim. The _construction_ is the tell, not the vocabulary: "that isolation is
   load-bearing" is house style (§3); "load-bearing, not decoration" is the tic.
2. **The inspirational pivot.** Zooming from the specific to the universal for borrowed weight:
   "This isn't just about caching. It's about trust." Delete the pivot; stay on the topic.
3. **Rhetorical question asked and answered.** "What changed? The math did." Delete the question,
   keep the answer. (Questions that route a real reader branch are house style — see §3.)
4. **Padded triads.** Three items where two are real, often rhythm- or alliteration-driven: "Not for
   advertising. Not for distribution. For AI training." Ship the two that are true.
5. **Canned significance.** Asserting importance instead of demonstrating it: "marks a pivotal
   moment", "represents a significant shift", "underscores the enduring importance of". If the fact
   matters, the consequence shows it.
6. **Outline-shaped closing.** "Despite these challenges… Future improvements could enhance…" A
   challenges-and-future-prospects paragraph that says nothing checkable.

### B · Padding and hedging

7. **Filler intensifiers** — "genuinely", "actually", "real", "quietly", "worth noting", "it's
   important to note that", "it's important to understand". Delete on sight.
8. **Disclaimer overload.** "This might potentially work in some circumstances." Stacked qualifiers
   read as evasion. State it, or state the actual limit — hedging is not the same as precision.
9. **Transitional scaffolding** — "Furthermore", "Additionally", "Moreover", "generally speaking",
   "to some extent", "In conclusion". Usually deletable with no loss.
10. **Restating the request** before answering. Start with the answer.
11. **The enumeration preamble** — "Two things for you", "Three notes", "Two ways forward."
    Announcing the shape instead of writing it.
12. **A closing summary that repeats the body.** If the body was clear, the summary is filler.

### C · Vocabulary

13. **The AI-vocabulary set.** Density is the signal, not any single word: `delve` `tapestry`
    `testament` `underscore` `pivotal` `showcase` `vibrant` `intricate` `meticulous` `boasts`
    `bolstered` `garner` `fostering` `interplay` `enduring` `realm` `beacon` `illuminate` `harness`
    `seamless` `leverage` `elevate` `unlock` `empower` `navigate` `align with` `crucial`.

    ```bash
    git grep -inE '\b(delve|tapestry|testament|underscore|pivotal|showcase|vibrant|intricate|meticulous|boasts|garner|seamless|elevate|empower|realm)\b' \
      -- '*.md' '*.html' ':!.claude/skills/humanize-writing/SKILL.md'
    ```

    Excluding this file is not cosmetic — without it the pattern matches its own word list and
    reports ~30 phantom hits. On a clean tree the real count is **1** (`showcase` in
    `docs/push-relay.md`). A near-zero result means the prose is clean, not that the check is broken.

    **Repo exemptions — do not purge these:** `unlock` is the single most important one. "Unlock your
    vault" is this product's core verb (6 legitimate uses in tracked prose); the source lists call it
    a marketing buzzword, which it is not here. Also exempt: `key` (a cryptographic noun), `robust`,
    `enhance`, `landscape`, `highlight`, `valuable`. Judge by density and by whether the word works.

14. **Copula avoidance.** Reaching for `serves as` · `stands as` · `functions as` · `represents` ·
    `features` · `maintains` · `boasts` where `is` would do. "`vaultWrite` serves as the write path"
    → "`vaultWrite` **is** the write path."
15. **Elegant variation.** Rotating synonyms for one thing because repetition feels inelegant —
    "capability token… delegation credential… scoped grant" for the same object. Pick the term the
    code uses and repeat it. In a protocol doc, a synonym reads as a second concept.
16. **Clichéd openers** — "In today's fast-paced digital landscape", "In the dynamic world of",
    "As the world continues to evolve".
17. **Forced sass.** "But here's the thing:", "The result?", "Hot take:", "And honestly?",
    "Here's why that matters", "Here's the deal", "That's the real unlock". Manufactured edge.

### D · Shape and rhythm

18. **Uniform rhythm.** Every sentence 15–25 words with a dash at the pivot. Break it: put a
    four-word sentence in.
19. **Overly perfect structure.** Every paragraph the same length, every transition smooth. Vary
    paragraph length too, not only sentence length.
20. **Generic examples.** "Consider a developer who needs to pin a script." Use the real thing —
    the actual hash, the actual file path, the actual demo URL. This repo always has one.

### E · Markup and formatting

21. **Title Case In Headings.** This repo is sentence case (`## Standing constraints`,
    `## What kunji is`). Title case is a reliable tell here.
22. **Mechanical boldface.** Bolding every instance of a term, or bolding so much that nothing
    stands out. (Bold as a paragraph lead-in is sometimes house style — see §3.)
23. **Em-dash density — the dominant tell in this repo's published prose.** `landing/` runs one em
    dash per **36 words** (126 across 4,581). Do not cite that as a house rate: every commit that
    wrote those pages carries a `Co-Authored-By: Claude` trailer, so it measures the model's habit,
    not a human's. An earlier version of this skill made exactly that mistake and codified the rate
    as a standard to protect.

    Reserve the dash for a genuine aside or a hard pivot. If a comma, colon, or full stop reads the
    same, use it — and one of those almost always does. Never use a dash as the default connector
    between independent clauses; that is the "Swiss Army knife" tell all five sources describe. When
    you do use one, kunji's **spaced** em dash is the house convention.

24. **Curly quotes and apostrophes.** The tracked `.md` uses none. Beyond being a tell, a curly
    apostrophe or quote pasted into a code sample **breaks the code** — check any `<pre>` or fenced
    block you touched.
25. **Emoji as decoration** on headings or bullets. (`AGENTS.md` uses exactly one ⚠️ deliberately;
    that is the budget.)
26. **Thematic break before a heading** (`---` then `##`). Markdown-generator habit; this repo
    doesn't.
27. **Skipped heading levels** — jumping to `###` without an intervening `##`.
28. **Tables for non-tabular content.** A table whose second column is sentences is a table
    pretending to be rigor. Use one for real dimensions × values (a smoke-check matrix qualifies).

### F · Assistant residue

29. **Chat pleasantries in a document** — "I hope this helps", "Certainly!", "Of course!", "You're
    absolutely right!", "Would you like me to…", "let me know", "is there anything else".
30. **Reflexive closing offer.** "Want me to X?" appended to every message. Ask only when genuinely
    blocked on the user's call.
31. **Self-reference and cutoff disclaimers** — "As a large language model", "as of my last update".
32. **Placeholder text left in** — `[insert version]`, `[your app name]`, `TODO`, `XXX`. In this repo
    a stray placeholder in `landing/` ships to the web.

## 3 · House style — do NOT "fix" these

These appear on the source lists as tells but are this repo's actual voice. Changing them is the
mistake, and §3 overrides §2 on conflict.

**First, a limit on what counts as "house voice."** Nearly all prose in this repo — `landing/`
included — was written with AI assistance (`git log` shows a Claude co-author trailer on every
commit that touched the landing copy). So existing prose is **not** self-justifying: "the site
already writes it this way" is not evidence that it should. What survives below are the items
traceable to a deliberate product or brand decision, not merely to prevailing habit. Frequency
patterns — dash rate, sentence rhythm, paragraph shape — earn no protection at all; check `git log`
before granting authority to anything you find in the tree.

- **Spaced em dashes** as the dash _style_ when a dash is warranted. This is a typographic
  convention, not a licence for the density in §2·23.
- **Inline-header vertical lists** — `- **Deterministic derivation.** …`. Retained for reference docs
  (`AGENTS.md`, `docs/`) on **utility** grounds, not frequency: they are scanned for a specific
  invariant, not read start to finish, and the bold key is the index. (`AGENTS.md` is 23-for-23
  AI-authored, so its 12 uses prove nothing on their own.) In chat prose and marketing copy this is
  the tell Wikipedia describes — judge it there.
- **Rhetorical questions that route the reader.** "On Firebase?" and "Rather not depend on our origin
  at all?" hand the reader a branch they might actually be on. That is not the ask-and-answer tell in
  §2·3 — the difference is whether the reader, not the writer, supplies the answer.
- **"load-bearing"** (7× in tracked prose), "fail closed", "byte-identical", "posture", "TOFU-bind".
  Established idiom.
- **Lowercase `kunji`**, always — including sentence-initial.
- **Second-person address** in marketing and developer copy ("your keys", "You are your key").
- **Deliberate fragments** in marketing — "Nothing to phish", "Nothing to breach".
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
- **No authority without a referent.** The sources call this "universal authority without source"
  ("Studies show…") and fabricated quotes. The kunji form is asserting a security property with
  nothing behind it. Point at the code, the spec section, or the test — or drop the claim.

## 5 · Mechanics that bite here

- **Not prettier-clean at HEAD:** the HTML under `landing/` and `firebase.json` — and they are not in
  `.prettierignore`. Running `prettier --write` on them buries a two-line copy edit in a whole-file
  reformat. Edit surgically; never format-on-save these.
- **Don't put a `*`-glob inside `**bold**` in markdown.** Prettier misparses the two together and
  eats the surrounding backtick spacing (it mangled this very bullet once). Name the directory in
  prose instead of writing the glob.
- **`.md` prose wraps at ~100 cols.** Match it, or the diff reflows paragraphs you didn't touch.
- `CLAUDE.md` is a symlink to `AGENTS.md` — edit `AGENTS.md`.
- Generated files carry prose too. `rp.versions.json`'s `$comment` is emitted by
  `widget/publish.js` — edit the script, or the next build discards your rewrite.
- Copy that names a URL or hash must be true post-deploy. If it references something not yet
  shipped, say so rather than publishing a 404.

## 6 · Method

1. Read the full target file plus ~20 surrounding lines — voice is local, and §3 conflicts are
   usually visible in the neighbouring paragraph.
2. Name the register (§1) and the audience before editing.
3. Pass for structural rhetoric (§2·A) — highest yield. Then padding (B), vocabulary (C), shape (D).
4. Pass for markup (§2·E) and residue (§2·F); run the §2·13 grep on prose files.
5. Pass for the rails (§4). Confirm exact tokens survived.
6. Read it back for rhythm: if no sentence is under eight words, you're not done.
7. **Show the before/after** for anything outward-facing. Don't silently rewrite published copy.
8. `npm run lint` if you touched `.js`; prose-only `.md`/`.html` edits need no gate.

## Output

For a small edit, apply it and quote the changed lines. For a page or a batch, list each change as
`file:line` — before → after, one line each — then apply. Flag anything where the honest rewrite
changes the _meaning_ rather than the wording; that's the user's call, not a style fix.

## Sources

Consolidated in §2, arbitrated by §3:

- Wikipedia, [Signs of AI writing](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing) —
  the most thorough; contributed the content, language, style, and markup tells.
- Hunting the Muse, [How to tell if writing is AI](https://huntingthemuse.net/library/how-to-tell-if-writing-is-ai)
  — forced sass, clichéd openers, buzzword surges.
- The Augmented Educator,
  [Ten telltale signs](https://www.theaugmentededucator.com/p/the-ten-telltale-signs-of-ai-generated) —
  hedging, structural monotony, em dash as universal punctuation. (Paywalled after sign 5.)
- Medium, [The only 5 signs of AI writing](https://medium.com/@soibifaa98/the-only-5-signs-of-ai-writing-you-need-to-remove-in-your-text-now-8cb0d7ac00dd)
  — overly perfect structure, generic examples, disclaimer overload.
- Forbes, [The seven tells of AI writing](https://www.forbes.com/sites/charliefink/2025/06/12/the-seven-tells-of-ai-writing/)
  — contrastive framing, rhetorical Q&A, the inspirational pivot, unsourced authority.
