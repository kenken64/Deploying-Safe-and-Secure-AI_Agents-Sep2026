# v08 - Poison once, spread everywhere

**Surface 7** (state) | **Block 5** | **Attack** `b2` | **Closed by** `SECURE_STATE_SPLIT`

---

## 1. Run the attack

```
python kestrel.py attack b2 --day1-only
```

> Can you check the retention policy and then look up my orders?

## 2. What you just saw

```
  helpers    2 sub-agent summary/summaries added (TRUSTED AS-IS)
  !! State containment: 2 untrusted item(s) sitting in the trusted zone:
     account_helper, policy_helper
```

The payload landed once, at one node. Then the agent carried it forward to every
subsequent node - on the attacker's behalf, free of charge.

```
WITHOUT re-validation between steps
  node 1          node 2              node 3              node 4
  payload lands -> carries it forward -> carries it forward -> carries it forward

WITH validation gates between steps
  node 1          node 2   node 3   node 4
  payload lands -> clean  -> clean  -> clean
```

**Containment means breaking the free ride: the payload gets in, but it cannot spread.**

## 3. Where it actually happened

Open `agent/graph.py` and look at the Day 1 state:

```python
class KestrelState(TypedDict, total=False):
    context: Annotated[list[dict], _extend]      # every scrap of text, all mixed together
```

**One field.** The system prompt, the user's message, a retrieved article and a sub-agent
summary all live in `context`, in arrival order, indistinguishable.

> When they share a field, the agent can't tell instruction from data.

Then `agent/helpers.py`, `vulnerable_consult`:

```python
out.append(Content(text=summary.text, origin="operator", label=summary.agent))
#                                     ^^^^^^^^^^ "you wrote this". You did not.
```

## 4. Fix it - step by step

### Step 1. Split the schema. This is where it starts.

`agent/state.py`:

| TRUSTED - written by you, never by a request | UNTRUSTED - forever, however clean it looks |
|---|---|
| operator's system prompt | user messages |
| verified user IDs | retrieved documents |
| execution metadata | tool outputs, sub-agent summaries |

`agent/state.py`, `place`, is a stub that raises `NotImplementedError` once
`SECURE_STATE_SPLIT` is on - that is your exercise. Sort `items` into two lists by
`c.origin in TRUSTED_ORIGINS`, converting each with `to_dict(c)`, and return `{"context":
trusted + untrusted, "untrusted": untrusted}`.

Different fields. Different rules. **Never merged.**

### Step 2. Apply the three principles at schema time

These sound like software hygiene because they are. The twist is that here they are your
**primary containment**, not a tidiness preference.

1. **Minimize** - don't carry what you don't need. Sensitive data you never put in state
   cannot leak from state. It is the cheapest control there is.
2. **Type it** - `TRUSTED_KEYS` is a fixed set. No arbitrary keys means an attacker cannot
   smuggle in a field your code doesn't expect.
3. **Mark provenance** - every `Content` knows its `origin`, so a downstream node can ask
   `c.trusted` and **get a real answer**.

### Step 3. Put a gate BETWEEN the nodes

`agent/state.py`, `revalidate`, called at the top of `node_plan`, is also a stub. Walk
`state["context"]`; for every item whose origin is NOT in `TRUSTED_ORIGINS`, run its text
through `directives.find` / `directives.strip`, replacing the text and counting a change
when anything was found. Log how many items changed.

Untrusted content is re-checked on the way past, every step - not once, when it arrived.
That is what breaks the free ride.

### Step 4. Fence it every time it is rendered

`for_model`, also a stub, must re-wrap untrusted content **each time** the context is
assembled, rather than trusting a tag applied once - each untrusted `Content` becomes one
whose text is fenced as `<untrusted origin="..." source="...">...</untrusted>`, origin and
label preserved.

## 5. Prove it

```
python kestrel.py attack b2 --control SECURE_STATE_SPLIT
```

`  [ ok ]  state_containment` - and in the tests,
`test_untrusted_content_never_reaches_a_trusted_field` asserts that a retrieval item and a
sub-agent summary both land in `untrusted`, never in the trusted zone.

That is Workshop 2 phase A: **poisoned state can't reach a trusted field.**

## 6. On your own agent

- Print your agent's state object. How many fields hold text somebody outside your company
  can influence? Are they the same fields as the ones you wrote?
- Is there any point in your graph where untrusted text is re-checked, or does it pass the
  gate once and ride free afterwards?
- Could you write `assert_containment` for your own state today? If not, provenance is not
  in your schema.
