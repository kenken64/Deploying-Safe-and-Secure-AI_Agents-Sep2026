# The workshop model

`kenken64/Llama-3.1-8B-Kestrel` - `llama3.1:8b` with the lab's runtime settings
pinned into the model itself.

Built with Llama. Derived from Meta's Llama 3.1 8B Instruct and distributed under the
[Llama 3.1 Community License](https://llama.meta.com/llama3_1/license/), which travels
with the model (`ollama show --license`).

## Why it exists

The lab reaches Ollama over the OpenAI chat-completions API, and that API has no field
for `num_ctx`. The context window is therefore whatever the host decided and the lab
has no say in it. When the poisoned help-centre article plus a turn's tool results
overflow it, Ollama drops the front of the context silently - the indirect injection
stops landing on one laptop and keeps landing on the next, with nothing in the console
to explain the difference. A control that looks non-deterministic teaches the opposite
of the lesson.

To be straight about how big that risk is: **Ollama 0.34 defaults
`OLLAMA_CONTEXT_LENGTH` to 32768**, so a current install needs no help. This pin is
insurance against the hosts you do not control - an older Ollama, a machine where that
variable was lowered, a shared server configured by someone else - and it caps KV cache
at a size a student laptop can hold. 8192 is chosen to be comfortably enough for this
lab, not to be large; on a modern default it is a reduction, deliberately.

`num_ctx` cannot be set from the client at all, so the model is the only place it can
live. Everything else here is pinned for the same reason: one `ollama pull`, one
behaviour, twenty laptops.

| Setting | Value | Why |
|---|---|---|
| `num_ctx` | 8192 | Fits Day 1 + Day 2 context and 12 steps of tool results, and caps KV cache at ~1GB on top of the 4.7GB model. Insurance against hosts you do not control, not a fix for a broken default - see above. |
| `temperature` | 0 | The lab sends this per request too; this covers `ollama run`. |
| `top_p` | 1 | Same. |
| `seed` | 42 | Reproducible sampling. |
| `SYSTEM` | the operator prompt | Verbatim from `agent/graph.py`. A per-request system message overrides it, so the lab is unaffected - it is here so `ollama run` reproduces the lab's starting conditions for hand probing. |

Tool calling is intact (`ollama show` lists the `tools` capability). The lab is useless
without it - check this first if you swap the base model.

## Use it

```bash
ollama pull kenken64/Llama-3.1-8B-Kestrel

cd workshop-day1     # or workshop-day2
LLM_PROVIDER=ollama OLLAMA_MODEL=kenken64/Llama-3.1-8B-Kestrel python kestrel.py doctor
```

## Rebuild it

```bash
ollama create kenken64/Llama-3.1-8B-Kestrel -f model/Modelfile
ollama push   kenken64/Llama-3.1-8B-Kestrel
```

## What this is not

This is a **registry** model, not an Ollama Cloud model. Students `ollama pull` it and it
runs on their own hardware. Ollama's cloud catalogue (the `-cloud` suffixed models) is
curated by Ollama and holds no Llama of any size; there is no self-serve way to put your
own weights on their inference GPUs. If you want a *hosted* Llama 3.1 8B, that is the
OpenRouter path the lab already ships: `LLM_PROVIDER=openrouter`, which defaults to
`meta-llama/llama-3.1-8b-instruct`.
