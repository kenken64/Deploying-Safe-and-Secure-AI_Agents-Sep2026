# v09 - Thread IDs, and the data store you forgot you had

**Surface 7** (checkpoints) | **Block 5** | **Attack** `b3` | **Closed by** `SECURE_THREAD_IDS`

---

## 1. Run the attack

```
python kestrel.py attack b3 --day1-only
```

Ben has a support conversation. Alice then guesses thread ids one digit either side of
her own - and reads his.

```
  Ben's session was stored under thread id: thread-1002
  Alice (CUST-1001) tries: thread-1002, thread-1001, thread-1003
  READ thread-1002: 1 checkpoint(s) of Ben's conversation
        Where is my espresso machine, ORD-100003?
        ORD-100003 | CUST-1002 | Espresso machine EM-9 | 189000c | ships to 88 Marine Parade...
```

Yesterday's tenancy filter is on. It did nothing, because **this is not a live query.**

## 2. The slide that makes people sit up

Every checkpoint is a **full copy of state, saved**. LangGraph snapshots at each step so
the agent can pause, resume and support human-in-the-loop. Powerful - and quietly
cumulative:

- months of every input, every tool result, every reply
- for **every** user
- back to day one

> If a credential ever sat in state, it is in a checkpoint now.

That is Day 1's rule 1 - *credentials never in the context window* - and this is why it
exists. **Context becomes checkpoint.**

Most teams have never threat-modelled this store. It is one of the most sensitive they own.

## 3. Where it actually happened

`agent/memory.py`:

```python
def vulnerable_thread_id(principal: Principal) -> str:
    _SEQ["n"] += 1
    return f"thread-{_SEQ['n']}"          # sequential, and bound to nobody
```

and the read path, with nothing between the caller and the data:

```python
else:
    board.light("state_containment", "red",
                f"{principal.id} read checkpoint history for {thread_id} "
                f"with no ownership check")
```

Two defects, and you need to fix both:

1. the id is **guessable** - change one digit
2. the id is **unbound** - nothing anywhere records who owns it, so no check is possible
   even if you wanted one

## 4. Fix it - step by step

### Step 1 & 2. Make the id unguessable, and bind it at creation

`agent/memory.py`, `secure_thread_id`, is a stub that raises `NotImplementedError` - that
is your exercise. Generate a token with `secrets.token_urlsafe(24)` (not a counter, not a
UUIDv1, which encodes time and MAC), prefix it, insert a row into the `threads` table
binding it to `principal.id`, and return the id.

Unguessable alone is *security by obscurity*. A leaked URL, a shared screenshot, a
referrer header, a log aggregator - and the id is no longer secret. The binding is what
makes it a control.

### Step 3. Check ownership on EVERY access

`read_thread`'s `SECURE_THREAD_IDS` branch is also a stub. Look up the `owner_id` for
`thread_id` against the `threads` table; raise `Denied("thread", ...)` unless it matches
`principal.id`.

Every access. Not at creation, not at login - the same lesson as Day 1's
*check at the action, not at the start.*

> Same wall as yesterday's tenancy filter - different room. Live queries then; stored
> state now.

## 5. Prove it

```
python kestrel.py attack b3 --control SECURE_THREAD_IDS
```

```
  refused thr_...: denied at level=thread CUST-1001 does not own thr_...
  attack stopped
```

`test_thread_ids_are_random_and_ownership_is_checked_every_access` asserts both halves:
the id does not start with `thread-`, and Ben is refused with `level == "thread"`.

## 6. Activity: threat-model the vault

For Kestrel's checkpoint store **as it stands today**, write three things. This is the
exercise most teams never do.

1. **What's in it** - what sensitive data actually accumulates over months?
2. **Who can read it** - how is ownership enforced, or isn't it?
3. **Blast radius** - what would one unauthorized read expose?

Open `/console` and look at the "What the agent persists" panel while you do it.

## 7. On your own agent

- Where do your checkpoints live? Who has read access to that database? Is it in your
  data-retention policy? Your DPIA? Your backup encryption scope?
- How are your thread/session/conversation ids generated? Go and look, do not assume.
- How long do they persist, and who decided that number?
