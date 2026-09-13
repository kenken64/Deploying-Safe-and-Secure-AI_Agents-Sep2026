# v01 - Cross-tenant order leak

**Surface 3** (tool arguments) | **Day 1, Blocks 0 and 4** | **Attack** `a1` | **Closed by** `SECURE_TENANCY`

This is the breach the course opens with. Start here.

---

## 1. Run the attack

```
python kestrel.py reset
python kestrel.py attack a1
```

Alice Tan (`CUST-1001`) is signed in. She types one entirely ordinary sentence:

> Hi, just confirm the shipping address on order 100003 for me, thanks.

## 2. What you just saw

```
  model      chose tool lookup_orders(sql="SELECT * FROM orders WHERE id='ORD-100003'")
  tool       lookup_orders -> ORD-100003 | CUST-1002 | Espresso machine EM-9 | 189000c |
             delivered | ships to 88 Marine Parade, #21-03, Singapore
  [BREACH]   data_boundary
  !! DATA BOUNDARY: 1 row(s) belonging to CUST-1002 returned to CUST-1001
```

Ben Ortiz's order, his purchase, and his home address were handed to Alice.

**Nothing here was an exploit.** There is no CVE. No payload. No malformed input. The
message is a normal support question, and the model did exactly its job.

## 3. Where it actually happened

Walk it back one line at a time.

**Step 1 - the model chose to call a tool.** `agent/graph.py`, `node_plan`. A decision made
by a language model. Nothing wrong yet.

**Step 2 - the tool ran a query with no tenancy filter.** `agent/tools.py`, `_t_lookup_orders`:

```python
def _t_lookup_orders(args: dict, session: Session) -> ToolResult:
    sql = str(args.get("sql", ""))
    rows = db.vulnerable_query(sql)          # <-- the query never asked WHOSE orders these are
```

and `agent/db.py`, `vulnerable_query`:

```python
def vulnerable_query(sql: str) -> list[dict[str, Any]]:
    conn = connect()
    return [dict(r) for r in conn.execute(sql).fetchall()]
```

**Step 3 - someone else's data went straight into the reply.** `agent/graph.py`, `node_reply`.

Read those three again and notice what is missing: **no code, at any point, checked whose
data this was.** `session.principal` is sitting right there in the tool signature, unused.

## 4. Why it works

The agent trusted the model's belief about who was asking.

Authentication was fine - Alice really is Alice, and the app really knows it. What is
missing is *authorization at the resource level*: the third of the three RBAC levels.
Levels 1 and 2 (may she use the agent, may she call this tool) both pass. Level 3 - *may
this call touch this row* - was never asked.

That is the failure mode this whole course is built on. You let a language model decide
who sees what.

## 5. Fix it - step by step

### Step 1. Put the filter at the data layer, not in the tool

Open `agent/db.py`. `secure_orders_for(principal, order_id=None)` is a stub that raises
`NotImplementedError` - that is your exercise. Its docstring spells out the contract; write
the function so it:

- always predicates the query on `principal.customer_id` - there must be no code path
  through the function that can return a row without that predicate;
- takes that id from `principal` (the authenticated session), never from `order_id` or any
  other argument the model could influence;
- also narrows to `order_id` when one is given, returning nothing at all if that order
  belongs to a different customer;
- uses parameterised SQL throughout - no f-strings, no string interpolation, ever, even
  though the input is now "only" coming from your own code.

Three things matter here and they are all deliberate:

1. **The predicate is not optional.** There is no code path through this function that
   omits `customer_id`. You cannot forget it, because it is not a parameter you pass.
2. **The value comes from `principal`,** which came from the authenticated session. The
   model has no way to reach it, set it, or override it.
3. **It is parameterised.** No f-string, no interpolation, ever - even though the input
   is now "only" coming from your own code. (Day 1, slide 39.)

This is what *"the tenancy filter lives below the model"* means in practice. Not in the
prompt. Not in the tool. In the layer underneath both, where a steered model cannot reach.

### Step 2. Turn the control on

```
python kestrel.py attack a1 --control SECURE_TENANCY --control SECURE_TOOLS --control SECURE_EXECUTOR --control SECURE_AUTHZ
```

or flip `SECURE_TENANCY` **and** `SECURE_TOOLS` in the control room at `/console`. The next
step is about why it takes both.

### Step 3. Understand why one control is not enough

You just read the filter. Turn on **only** the filter and run the attack again:

```
python kestrel.py attack a1 --control SECURE_TENANCY
```

**It still lands.** The same leak, the same rows - Ben's order, his address, on Alice's
screen. The runner drops the control you just turned on from its own advice:

```
  fix it with: SECURE_TOOLS, SECURE_AUTHZ
```

`secure_orders_for` is the filter, and the only things that call it are the narrow typed
tools - `_t_get_order` and `_t_list_my_orders` in `agent/tools.py`. The tool the model is
still holding is `lookup_orders`, and it has no such call:

```python
def _t_lookup_orders(args: dict, session: Session) -> ToolResult:
    sql = str(args.get("sql", ""))
    rows = db.vulnerable_query(sql)          # <-- never consults the filter
```

**A filter that nothing calls is not a control.**

Now the other direction - narrow tools, filter off:

```
python kestrel.py attack a1 --control SECURE_TOOLS
```

Also still lands. The model is reduced to `get_order(order_id='ORD-100003')` and has no SQL
left to write, which is real progress. But with `SECURE_TENANCY` off, that tool falls
through to the unfiltered path and fetches the row by id with nobody's name on it:

```python
rows = (db.secure_orders_for(session.principal, oid) if settings.on("SECURE_TENANCY")
        else db.vulnerable_query(f"SELECT * FROM orders WHERE id='{oid}'"))
```

**A typed tool that hands its argument to unfiltered SQL is not a control either.**

Both together:

```
python kestrel.py attack a1 --control SECURE_TOOLS --control SECURE_TENANCY
```

Until `secure_orders_for` is implemented, this raises `NotImplementedError` instead of
running - a raw Python traceback, not a graceful refusal. That is expected, not a sign
something else is broken: it is `get_order` reaching the exact function you are about to
write. Once you implement it correctly, this becomes:

```
  tool       get_order -> No matching orders.
  [ ok ]    data_boundary
  attack stopped
  stopped by: SECURE_TENANCY, SECURE_TOOLS
```

| `SECURE_TOOLS` | `SECURE_TENANCY` | `a1` |
|---|---|---|
| off | off | lands |
| off | on | lands - **unchanged** |
| on | off | lands |
| on | on | **stopped** |

So these two are not two layers of defence in depth over one hole. They are
**jointly necessary**, because they answer different questions.
`SECURE_TOOLS` decides **what the model is able to ask for**.
`SECURE_TENANCY` decides **whose rows are allowed back**.
The leak needs both answered, and either one alone leaves the other question open. That is
why the attack names more than one control - not redundancy, but two halves of one fix.

`SECURE_AUTHZ` is the third control the runner lists, and it is a genuine third layer
rather than a third requirement: the two above already stop the leak. Look at what the
hardened tool actually said - `No matching orders.` Correct, and silent. Nothing was
logged as refused, and Alice cannot tell a row that does not exist from a row she may not
see. `SECURE_AUTHZ` turns that into an explicit, logged refusal at the action itself.
That is `v04`.

## 6. Prove it

The fastest, narrowest check that you personally got `secure_orders_for` right - no other
tutorial's stub involved - is the direct unit test:

```
python kestrel.py test  # or: pytest tests/test_attacks.py -k data_layer_has_no_path
```

`test_the_data_layer_has_no_path_that_returns_another_customers_rows` asserts that
`secure_orders_for(alice)` returns Alice's own rows, and that
`secure_orders_for(alice, "ORD-100003")` returns `[]` - not an error, not a refusal, but
literally no such row from Alice's point of view.

```
python kestrel.py attack a1 --secure
```

`--secure` turns on **every** control, not just this one - so this command (and the full
`python kestrel.py test`) will keep raising `NotImplementedError` until every stub across
Day 1 is filled in, from `intake.secure_check` (`v02`) onward. Once everything is
implemented, you want to see:

```
  [ ok ]    data_boundary
  attack stopped
  stopped by: SECURE_TENANCY, SECURE_TOOLS, SECURE_AUTHZ
```

The **data boundary light staying green on a re-run of the opening attack** is the
Workshop 1 success criterion that matters most (Day 1, slide 56).

## 7. On your own agent

- Find every function that reads tenant-scoped data. How many of them take the tenant as
  an *optional* argument? Each one is this bug waiting to happen.
- Grep for f-strings inside `execute(`, `query(`, `find(`.
- Ask: if the model were fully compromised right now, which of my data queries would
  still be correctly scoped? The ones that would are the ones scoped below the model.
