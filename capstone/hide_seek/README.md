# hide_seek: reversible masking for AI prompts

A local layer on top of the DLP proxy. It replaces private values in a
prompt with realistic fakes before the prompt leaves the machine, remembers
each pair per chat, and puts the real values back into the AI's reply.

The AI provider only ever receives the fakes. The user only ever sees the
real values. Based on the Hide-and-Seek design (Chen et al., 2023), with
code-generated fakes and a lookup table in place of the paper's two
fine-tuned models, so it runs on CPU.

```
Rahul Sharma, +91 98765 43210      user types this
        |  Hide (hide.py)          detect, swap for fakes, record in the vault
Nikhil Rao, +91 87214 55902        the provider receives and stores this
        |  provider replies using the fakes
        |  Seek (seek.py)          swap fakes back, also mid-stream
Rahul Sharma, +91 98765 43210      user reads this
```

## Status (2026-11-16)

Verified on live claude.ai with synthetic data: prompt masking, restore in
the streamed reply, consistency across turns, and (by opening the same chat
on a device that bypasses the proxy) that the provider's copy holds only
fakes.

Supported today: **claude.ai web app, typed text only.**

Three fixes made after the last live run are covered by tests but not yet
re-checked live: settings in the send request are no longer altered, names
with an attached "s" are restored, and a typed value that equals a fake
gets its own fake.

## Run it on one machine

```
cd /d <repo>\capstone
start_local.bat
```

1. The proxy listens on `127.0.0.1:8888`.
2. Trust the mitmproxy CA, `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer`.
   Chrome and Edge: install it into the *Current User, Trusted Root
   Certification Authorities* store (not "automatically select").
   Firefox: import it under Certificates, Authorities.
3. Send the browser's `claude.ai` traffic to the proxy, for example with a
   FoxyProxy pattern `*://claude.ai/*`.

The proxy prints one decision per message: `ALLOW`, `MASK` or `BLOCK`.

`start_proxy.bat` (the VM demo) still runs the original one-way redaction
in `mitm_dlp.py`. See "Known limitations" for why that no longer works on
claude.ai.

## See what was masked

```
python -m hide_seek.audit                    one line per conversation
python -m hide_seek.audit 4525e51a           types masked in that conversation
python -m hide_seek.audit 4525e51a --reveal  also original and fake values
```

Nothing is decrypted or printed without `--reveal`.

## Tests

```
python -m unittest test_hide_seek test_claude_rpc
```

60 tests. Two use the real ONNX model and are skipped if it is absent.

## How detection works

Three sources are combined; a value found by any of them is masked.

| Source | What it finds |
|---|---|
| Format rules | AWS and GitHub keys, whole private-key blocks, Aadhaar and card numbers that pass their checksum |
| ONNX model (`onnx_quantized_all17`) | The 17 trained entity types, scanned in overlapping windows so long text is covered |
| Session memory | Any value already masked in this chat, wherever it reappears, ignoring case, spacing and (for IDs and phones) separators; also single parts of a masked name |

A request that cannot be inspected is refused, not forwarded.

## Files

| File | Role |
|---|---|
| `hide.py` | Detection and replacement |
| `surrogates.py` | Fake-value generators per entity type |
| `vault.py` | Encrypted per-chat store of original and fake pairs (SQLite + Fernet) |
| `matching.py` | Tolerant matching of known values |
| `seek.py` | Restore, including text that arrives in pieces |
| `proto.py` | Protobuf reader that needs no schema |
| `providers/claude_rpc.py` | claude.ai's current interface (Connect RPC, protobuf) |
| `providers/claude_web.py` | claude.ai's earlier JSON interface |
| `proxy.py`, `../mitm_has.py` | mitmproxy hooks and entry point |
| `trace.py` | Structure-only traffic trace for diagnosis (`data\trace.log`) |
| `audit.py` | What-was-masked report |

`data\` holds the vault, its key and the trace. It is git-ignored. Anyone
with both `vault.sqlite3` and `vault.key` can read every masked value.

## Known limitations

### The detector model (the main weakness)

The model is unchanged from the original project and is the weakest part.

- Measured before this work: about 9% of sensitive spans leak on unseen
  prompts, and 8 of 19 clean prompts get false positives. The training
  notebook's own 100-prompt test shows 58% precision and 71% recall.
- Cause: it was trained on short template sentences (6 to 237 characters,
  at most 4 entities), which do not resemble real prompts.
- Seen live: ordinary Hinglish words tagged as passwords; connector IDs
  tagged as API keys, IP addresses and usernames.
- Consequence: the **first mention** of a value depends on the model alone.
  If it is missed there, it leaks, and because fakes look real the leak is
  not visible on screen.

How this is handled:

- Already in place: session memory catches every repeat of a value once it
  has been masked; checksums and key patterns catch some values the model
  misses; reversible fakes make a false positive mostly harmless, because
  it is restored on the way back.
- Planned: retrain on realistic, prompt-shaped data and tune for recall on
  first mentions. Until then, treat the leak rate above as current.

### Coverage

- Only claude.ai, and only typed text. File attachments and pasted files
  are **not inspected** on the current interface.
- Edit and retry, projects, artifacts and tool use are untested.
- ChatGPT still goes through the old one-way path and is unverified.
- `api.anthropic.com` and every other provider pass through uninspected.
- claude.ai changed its interface some time after October 2026: messages
  now travel as protobuf over `/claudeai-rpc/`. The old `mitm_dlp.py`
  matches the previous address and therefore masks nothing on claude.ai.
  The field numbers in `claude_rpc.py` were read from captured traffic and
  will break when the app changes again.

### Inherent to fakes

- Anything the AI derives from a fake cannot be restored: last four
  digits, initials, the gender or region a name implies, whether an ID
  number is valid.
- Tasks that need the true value (look this person up, validate this ID)
  get an answer about the fake.
- Browser push notifications bypass the proxy and show the fake.
- Addresses, and dates in formats that are not recognised, fall back to a
  numbered placeholder such as `[ADDRESS_1]`.
- A name part that is also an ordinary word is replaced wherever it
  appears later in that chat.

### Not measured yet

Leak rate and answer quality with fakes, against the tag-based baseline in
`_grading`. The earlier figures describe the old pipeline.
