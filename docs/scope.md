# kunji scope vocabulary — design

**Status:** Implemented (Phase 1) — the grammar, reserved core, `scopeSatisfies`, and delegation-chain
attenuation ship in `src/lib/capability.js` (mirrored RP-side in `examples/*/capability.js`) with the
wallet's per-item consent UI. Deferred: macaroon/biscuit attenuation and richer constraint types.
Before Phase 1, `scope` was a flat list of strings
(`["login"]` for capabilities, `["profile"]` for the optional profile share). This doc defines the
grammar, the reserved core, and how it's requested, displayed, and enforced — **backendless**, like
the rest of the protocol. Companion docs: [`verified-credentials.md`](./verified-credentials.md)
(the `vc:` family) and [`push-relay.md`](./push-relay.md) (asking a connected app for more scope
later). Extends [`discoverable-login.md`](./discoverable-login.md) §5/§6 and
[`agentic-delegation.md`](./agentic-delegation.md).

## 1. Where scope appears today

- **Login QR** (`discoverable-login.md` §5.1): optional `scope: ["profile"]`; the wallet checks
  `requestsProfile()` (`src/services/identity.js`) and offers the profile share (default off).
- **Agent capability** (`src/lib/capability.js`): `scope` is a required non-empty string array baked
  into the EdDSA-JWT and returned by `verifyCapabilityAssertion` for the RP to enforce.
- Current validation: each item a string `≤64` chars, `≤16` items (`src/services/capability.js`).

So `scope` is already the **request channel** (an RP/agent says what it wants) and `profile` is the
first "scope → optional disclosure" example. This design generalizes that without breaking either.

## 2. Principle — a grammar, not a registry

kunji defines a **grammar** plus a **tiny reserved core**; everything else is **RP-namespaced**.
kunji must never become a central scope registry, for the same reason it is not an app registry: a
registry re-centralizes meaning and trust. The wallet renders reserved scopes with vetted text and
all other scopes as **untrusted, RP-attributed** strings — the same trust posture as the
self-asserted `claims` in `discoverable-login.md` §6.8.

## 3. The grammar

A scope **item** is either a string (shorthand) or an object (when it needs constraints):

```jsonc
// these two are equivalent
"payments:charge"
{ "id": "payments:charge" }

// with caveats the RP enforces:
{ "id": "payments:charge", "max": "50USD", "resource": "acct_123" }
```

- `id` (required) — the scope identifier (§3.1).
- Any other key is a **constraint** the **RP** interprets and enforces. kunji treats constraints as
  opaque except for display. Reserved-by-convention constraint keys: `max` (a `"<amount><CCY>"`
  ceiling), `resource` (an opaque id or `glob`), `maxUses`/`rateBudget` (folds in the per-capability
  ceiling already noted in `agentic-delegation.md`).

`scope` is a non-empty **array** of items. A plain-string array (today's shape) stays valid forever.

### 3.1 Identifier namespaces

| Kind | Form | Examples | Wallet rendering |
|---|---|---|---|
| **Reserved core** | bare, kunji-defined | `login`, `profile`, `offline_access`, `vc:<type>[#claim]` | vetted, localized text |
| **RP extension** | namespaced (contains `:`) | `read:orders`, `example.com:orders.read`, `https://example.com/scopes/orders.read` | raw id + the RP's own (untrusted) label |

Reserved core (the only ids kunji assigns meaning to):

- `login` — prove control of the per-app key (the default; what every assertion already does).
- `profile` — offer the optional self-asserted name/avatar (`claims`, already shipped).
- `offline_access` — request a longer-lived / re-presentable capability (agent keeps acting without
  a fresh approval each time, within `exp`).
- `vc:<type>[@<issuer>][#<claim>,…]` — request a **verified credential** of that type, optionally
  pinned to an issuer, optionally selecting which claims to disclose — e.g. `vc:age#age_over_16` to
  prove the 16+ predicate without revealing the DOB. See [`verified-credentials.md`](./verified-credentials.md).

Everything else **MUST** be namespaced — its id must **contain a `:`** (a `verb:resource` form, a host
prefix, or an `https://` URL on the RP's domain). Bare non-core ids are rejected by the wallet
(prevents an RP from squatting a generic word like `admin`).

### 3.2 Human labels for custom scopes

A request MAY include `scopeLabels: { "<id>": "<text>" }`. The wallet shows the text **attributed to
the RP** ("example.com says: *Read your orders*") and never as kunji's own words — labels are
unverified RP input, treated like `claims`.

## 4. Consent rendering (wallet)

- Reserved scopes → vetted, localized strings + an explanatory line.
- Custom scopes → the raw `id` + the RP's `scopeLabels` text, clearly marked untrusted.
- **Per-item toggles, default-deny** for anything beyond `login` (generalizes the single profile
  toggle in `AuthorizeAgentSheet`/the approval sheet). The user may approve a subset; the minted
  capability/assertion carries only what was approved, so the RP must treat any requested scope as
  *possibly declined* (same rule as `profile` today).
- Constraints are shown in plain language ("up to **$50**", "for **acct_123**").

## 5. Backendless enforcement (with parity)

The RP enforces scope locally — no kunji server. Ship a pure helper in the **shared verifier lib**
(the one already mirrored across wallet / RP / tests, e.g. `examples/*/capability.js`) so all sides
agree:

```js
// granted: the scope[] inside the verified capability/assertion
// required: what this request needs, e.g. [{ id:'payments:charge', max:'30USD' }]
scopeSatisfies(granted, required) -> boolean
```

Rules:

1. **Match** — a required `id` must be present in `granted` (exact), OR covered by a granted
   **wildcard** `verb:*` (`read:*` ⊇ `read:orders`). A bare `*` god-scope is **not** allowed.
2. **Constraints** — a granted item satisfies a required one only if every required constraint is
   met by the granted constraint (granted `max:"50USD"` covers a required charge of `30USD`; granted
   `resource:"acct_123"` covers required `resource:"acct_123"`; a granted item with **no** constraint
   on a dimension is treated as unbounded on that dimension — so RPs should always grant the
   narrowest item they need).
3. `login` is implied by any successful assertion; it never needs to be listed to authenticate.

`verifyCapabilityAssertion` already returns `scope`; the RP calls `scopeSatisfies(result.scope, …)`
per protected action.

## 6. Attenuation (narrowing) — delegation chains

An agent should be able to **narrow** a capability and sub-delegate (e.g. hand a sub-task to another
process) but **never widen** it. Rather than switch token formats (macaroon/biscuit — see §8), reuse
the existing JWS primitive: a holder mints a **child capability** signed by **its own `cnf` key**.

```
parent  = kunji-cap+jwt   signed by per-app key,   cnf = agentA      scope = S_parent
child   = kunji-capdel+jwt signed by agentA's key,  cnf = agentB      scope ⊆ S_parent, parent = <parent.jti>
```

RP verification of a chain (still local):

1. Verify the **root** capability exactly as today (signature → per-app key → `sub`).
2. For each delegation link: signature verifies against the **previous link's `cnf` key**;
   `link.scope ⊆ previous.scope` (via `scopeSatisfies`); `link.exp ≤ previous.exp`.
3. Holder-of-key against the RP challenge is proven by the **leaf** `cnf` key.
4. Bound the chain depth (e.g. ≤4) to cap verification cost.

This gives **offline narrowing** with zero new crypto. (Re-minting via the wallet — the user
approves a different scope — remains the path to *widen* or change audience.)

## 7. Request channels

Scope is requested in three places, all already-existing or designed elsewhere:

- **At login** — the QR's `scope[]` (`discoverable-login.md` §5.1).
- **At capability issuance** — the agent's request `scope[]` (`agentic-delegation.md`).
- **Later, from a connected app/agent** (step-up — implemented) — a protected action returns
  `403 { error:"insufficient_scope", need, have }`; the client re-requests the missing scope on the
  existing relay and the user approves the **delta** in the wallet (a `?authorize=` deep link opens the
  re-consent sheet directly). No new kunji infra. See [`push-relay.md`](./push-relay.md) §4/§11.

## 8. Open decisions

- **Token format for richer caveats** — EdDSA-JWT + delegation chains (this doc) vs adopting
  **biscuit/macaroon** for first-class offline attenuation. Recommendation: ship chains first; revisit
  biscuit only if caveat expressiveness demands it.
- **Constraint vocabulary** — how far kunji standardizes constraint keys (`max`, `resource`,
  `maxUses`) vs leaving them fully RP-defined. Recommendation: standardize only the few above for
  consistent display; everything else opaque.
- **Wildcard policy** — allow `verb:*` only, never bare `*` (proposed); confirm.

## 9. Where it will live (when built)

- Grammar + `scopeSatisfies` + chain verification → the shared verifier lib (mirrored in
  `src/lib/capability.js` and `examples/*/capability.js`), with parity tests in `tests/`.
- Wallet consent rendering → `AuthorizeAgentSheet.jsx` + the login approval sheet.
- Request parsing/validation → `src/services/identity.js` (QR) and `src/services/capability.js`
  (agent request), relaxing the flat-string check to the item grammar (back-compatibly).
