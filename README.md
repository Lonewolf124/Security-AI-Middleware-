# AI Prompt DLP Proxy

A small security lab project that sits between a browser and AI services
and checks prompts for sensitive information before the request reaches
the AI service.

Currently tested with ChatGPT and Claude, using mitmproxy, regex-based
secret detection, and a local BERT PII model running through ONNX
Runtime.

## Architecture

``` text
Browser
   |
   v
mitmproxy
   |
   v
DLP Engine
   |
   +--> Regex secret detection
   |
   +--> BERT ONNX PII detection
   |
   v
Sanitized request
   |
   +--> ChatGPT
   +--> Claude
```

Use this only on systems, accounts, traffic, and networks you are
authorized to inspect. All example secrets and PII in this README are
synthetic test data.

## New: reversible masking (`capstone/hide_seek/`)

The redaction below is one-way: the AI sees `[PERSON_NAME_REDACTED]` and
the user gets an answer about a tag. `hide_seek` replaces private values
with realistic fakes instead, remembers each pair per chat in an encrypted
local vault, and puts the real values back into the AI's reply, also while
it streams. It runs on one machine, without the VM.

- Works today on the claude.ai web app (typed text). claude.ai changed to
  a protobuf interface, so the old `mitm_dlp.py` no longer masks anything
  there; see section 11.
- Leak rate on unseen test prompts: about 5.5%, down from about 9% with
  the old redaction and the same model. Restored replies match the
  original exactly.
- Adjustable sensitivity and masking profiles (credentials, financial,
  government ID, contact, identity).
- The detector model is still the weakest part; a retrained model covering
  23 types is in preparation.

Setup, settings, measurements and known limitations:
[`capstone/hide_seek/README.md`](capstone/hide_seek/README.md). Quick
start: `cd capstone`, then `start_local.bat`.

------------------------------------------------------------------------

## 1. Project structure

``` text
capstone/
|
├── dlp_engine/
│   ├── __init__.py
│   ├── detectors.py
│   ├── engine.py
│   └── providers/
│       ├── __init__.py
│       ├── chatgpt.py
│       └── claude.py
|
├── onnx_quantized_all17/
│   ├── config.json
│   ├── model_quantized.onnx
│   ├── ort_config.json
│   ├── special_tokens_map.json
│   ├── tokenizer.json
│   ├── tokenizer_config.json
│   ├── vocab.txt
│   └── pii_model.py
|
├── inspect_chatgpt.py
├── inspect_claude.py
├── inspect_gemini.py
├── mitm_dlp.py
└── test_engine.py
```

The ONNX model is intentionally kept outside the Git repository.

------------------------------------------------------------------------

## 2. Requirements

Tested setup:

-   Windows host
-   Kali Linux VM
-   VirtualBox
-   Python 3.10
-   mitmproxy / mitmdump
-   ONNX Runtime
-   Transformers
-   Firefox/Edge/Chromium-based browser

Install the main Python dependencies:

``` cmd
pip install mitmproxy onnxruntime transformers numpy
```

The ONNX model is executed with ONNX Runtime, so PyTorch is not
required.

You may see:

``` text
[transformers] PyTorch was not found...
```

That is okay for this setup.

------------------------------------------------------------------------

# 3. Network setup

The proxy runs on the Windows host and the browser/test machine runs in
Kali.

I used a VirtualBox Host-Only network.

Example:

``` text
Windows host: 192.168.56.1
Kali VM:      192.168.56.103
Proxy port:   8888
```

The topology is:

``` text
                 Windows Host
                 192.168.56.1
                      |
                      |
              Host-Only Network
                      |
                      |
                 Kali VM
                192.168.56.103
```

These exact IPs are not mandatory. You can use another private subnet,
but the Kali VM must be able to reach the Windows host on the proxy
port.

### VirtualBox

For Kali:

``` text
Adapter 1 -> NAT
Adapter 2 -> Host-only Adapter
```

After starting Kali:

``` bash
ip addr
```

The Host-Only adapter should have an address similar to:

``` text
192.168.56.103
```

On Windows:

``` cmd
ipconfig
```

Find the VirtualBox Host-Only adapter. In my setup it was:

``` text
192.168.56.1
```

Once mitmproxy is running, test connectivity from Kali:

``` bash
nc -vz 192.168.56.1 8888
```

------------------------------------------------------------------------

# 4. Download the ONNX model

Download the model package here:

https://drive.google.com/file/d/1SXWDmPVhIjwEGTKFDVlydqdTiEXDRLNe/view?usp=sharing

Place/extract it inside:

``` text
capstone/onnx_quantized_all17/
```

The directory should contain:

``` text
onnx_quantized_all17/
├── config.json
├── model_quantized.onnx
├── ort_config.json
├── special_tokens_map.json
├── tokenizer.json
├── tokenizer_config.json
└── vocab.txt
```

The important model file is:

``` text
model_quantized.onnx
```

Do not commit the large model file to GitHub unless you have a reason to
and have checked the repository size and licensing requirements.

------------------------------------------------------------------------

# 5. Test the model

From the model directory:

``` cmd
cd /d F:\capstone\onnx_quantized_all17
python test_pii_model.py
```

You should see:

``` text
[PII] Loading tokenizer...
[PII] Loading ONNX model...
[PII] Model loaded successfully
```

A test such as:

``` text
My name is Rahul Sharma. My email is rahul@example.com. My IP address is 192.168.1.50.
```

should produce redactions such as:

``` text
My name is [PERSON_NAME_REDACTED]. My email is [EMAIL_REDACTED]. My IP address is [IP_ADDRESS_REDACTED].
```

------------------------------------------------------------------------

# 6. Test the combined DLP engine

From the project root:

``` cmd
cd /d F:\capstone
python test_engine.py
```

Example input:

``` text
My name is Rahul Sharma. My email is rahul@example.com. My IP is 192.168.1.50. My AWS test key is AKIA1234567890ABCDEF.
```

Expected:

``` text
My name is [PERSON_NAME_REDACTED]. My email is [EMAIL_REDACTED]. My IP is [IP_ADDRESS_REDACTED]. My AWS test key is [AWS_KEY_REDACTED].
```

The engine runs regex detection first and the ONNX PII model second.

Already-redacted regex placeholders are protected from the ML model so
that a placeholder such as:

``` text
[AWS_KEY_REDACTED]
```

does not get detected again as an API key.

------------------------------------------------------------------------

# 7. Start mitmproxy

On Windows:

``` cmd
mitmdump --listen-host 192.168.56.1 --listen-port 8888 --set connection_strategy=lazy -s F:\capstone\mitm_dlp.py
```

Change the path if your project is stored somewhere else.

You should see:

``` text
[PII] Loading tokenizer...
[PII] Loading ONNX model...
[PII] Model loaded successfully
HTTP(S) proxy listening at 192.168.56.1:8888
```

------------------------------------------------------------------------

# 8. Configure the browser proxy

The browser on the test machine needs to use the Windows host as its
proxy.

Use:

``` text
Proxy host: 192.168.56.1
Proxy port: 8888
```

For Firefox:

``` text
Settings
 -> Network Settings
 -> Manual proxy configuration
```

Set the HTTP proxy to:

``` text
192.168.56.1
```

Port:

``` text
8888
```

Configure HTTPS to use the same proxy.

------------------------------------------------------------------------

# 9. Install the mitmproxy certificate

With the browser configured to use the proxy, open:

``` text
http://mitm.it
```

Download the mitmproxy CA certificate.

### Firefox

Go to:

``` text
Settings
 -> Privacy & Security
 -> Certificates
 -> View Certificates
 -> Authorities
 -> Import
```

Import the mitmproxy CA.

When asked about trust, enable the option to trust the CA for
identifying websites.

After this, HTTPS traffic should be interceptable without browser
certificate warnings.

For Edge/Chromium, install the certificate into the appropriate
operating-system/browser trusted certificate store.

------------------------------------------------------------------------

# 10. ChatGPT integration

The current ChatGPT web flow used by the project sends the message to:

``` text
POST /backend-api/f/conversation
```

The user prompt is inside:

``` text
messages[0].content.parts[0]
```

The proxy extracts that prompt and passes it through:

``` text
Regex DLP
    |
    v
ONNX PII model
    |
    v
Redaction
```

Then it puts the sanitized prompt back into the JSON request.

### Test

Send this through ChatGPT:

``` text
My name is Rahul Sharma and my email is rahul@example.com.
My IP is 192.168.1.50.
My AWS test key is AKIA1234567890ABCDEF.
```

The mitmproxy terminal should show something similar to:

``` text
[DLP] ChatGPT conversation request detected
[DLP] ChatGPT prompt detected
[DLP] ChatGPT Findings: [...]
[DLP] ChatGPT Decision: REDACT
[DLP] Sanitized prompt: ...
```

------------------------------------------------------------------------

# 11. Claude integration

Claude has a different request structure, so it uses its
provider-specific handler.

The provider passes the relevant JSON through the same DLP engine.

Test with:

``` text
CLAUDE REDACT TEST

Fake AWS credential:
AKIA1234567890ABCDEF

Name: Rahul Sharma
Email: rahul@example.com
IP: 192.168.1.50
```

You should see a Claude detection and redaction decision in mitmdump.

**Note (November 2026):** claude.ai now sends messages as protobuf over
`/claudeai-rpc/`, which this handler does not recognise, so nothing is
redacted on claude.ai through `mitm_dlp.py`. Use `hide_seek`
(`capstone/hide_seek/README.md`), which supports the new interface.

------------------------------------------------------------------------

# 12. Sample test prompts

All values below are fake/synthetic and are only for testing.

### Multiple PII values

``` text
Rahul Sharma emailed Priya Mehta at rahul@example.com and priya@example.com. Rahul connected from 10.0.0.5 and Priya connected from 10.0.0.8.
```

### Punctuation handling

``` text
Name: Rahul Sharma, Email: rahul@example.com, IP: 192.168.1.50. Phone: +91 9876543210.
```

### PII mixed with technical information

``` text
I'm debugging an authentication problem in our application. The affected user is Rahul Sharma, email rahul@example.com, username rahul_dev. The request came from 192.168.10.25 and the application returned HTTP 401.
```

### Regex + ML together

``` text
Adhar card is ACAGP1028LDLP.
CLAUDE REDACT TEST — fake AWS credential: AKIA1234567890ABCDEF and my company name is Burger King.
```

### Internal-looking configuration data

``` text
Internal configuration details - BKIND10451 and DNS server hosted at bkindia.rbal.group.net. Name Shashwat. Adhar card AJENG10515.
```

These are synthetic values for the lab. Do not test with real
credentials, real customer data, or real secrets.

### Repeated entities

``` text
Rahul Sharma emailed Priya Mehta at rahul@example.com and priya@example.com. Rahul connected from 10.0.0.5 and Priya connected from 10.0.0.8.
```

------------------------------------------------------------------------

# 13. Clean prompt / ALLOW test

Not every prompt should be modified.

Try:

``` text
Explain how an HTTP reverse proxy works, including TLS termination, certificate validation, request forwarding, and response handling.
```

Expected behavior:

``` text
[DLP] ChatGPT Decision: ALLOW
```

The prompt should pass through unchanged.

------------------------------------------------------------------------

# 14. How the DLP engine works

The central pipeline is:

``` text
Incoming AI prompt
        |
        v
Regex detection
        |
        +---- secret found ----> redact
        |
        v
Separate existing redactions
        |
        v
BERT ONNX PII detection
        |
        v
B/I entity grouping
        |
        v
Character span extraction
        |
        v
PII redaction
        |
        v
Reassemble prompt
        |
        v
Sanitized AI request
```

The engine also recursively handles dictionaries and lists, which is
useful for JSON API requests.

------------------------------------------------------------------------

# 15. Troubleshooting

### Port 8888

Check whether the port is already being used:

``` cmd
netstat -ano | findstr :8888
```

If you use another port, update both mitmproxy and the browser proxy
settings.

### Certificate errors

Check:

-   Browser is using `192.168.56.1:8888`
-   `http://mitm.it` opens through the proxy
-   mitmproxy CA is imported
-   Firefox trusts the CA for website identification

### ONNX model does not load

Check that this file exists:

``` text
onnx_quantized_all17/model_quantized.onnx
```

and that the tokenizer/configuration files are in the same directory.

### ChatGPT is not intercepted

The web application can change its internal request routes.

The current implementation expects:

``` text
chatgpt.com
/backend-api/f/conversation
```

and:

``` text
messages[0].content.parts[0]
```

If ChatGPT changes its request format, capture the new request with
mitmproxy and update the ChatGPT provider handler.

### Claude is not intercepted

Check:

``` text
dlp_engine/providers/claude.py
```

and make sure the browser is still using the proxy.

------------------------------------------------------------------------

# 16. Start the whole project from scratch

The short version:

``` text
1. Configure VirtualBox Host-Only networking
2. Give Windows a Host-Only IP
3. Give Kali a Host-Only IP
4. Verify Kali -> Windows:8888 connectivity
5. Download the ONNX model
6. Put it inside onnx_quantized_all17/
7. Install Python dependencies
8. Run test_pii_model.py
9. Run test_engine.py
10. Start mitmdump
11. Configure the browser proxy
12. Install/trust the mitmproxy CA
13. Open ChatGPT or Claude
14. Send synthetic test data
15. Check the mitmproxy terminal
```

------------------------------------------------------------------------

# 17. GitHub

Before pushing the project, create a `.gitignore`:

``` gitignore
__pycache__/
*.pyc
.venv/
venv/
.env

# Large model
onnx_quantized_all17/model_quantized.onnx

# Logs
*.log
```

Then:

``` cmd
git init
git add .
git commit -m "Initial DLP proxy implementation"
```

Create a GitHub repository and then:

``` cmd
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

Before pushing, check:

``` cmd
git status
git diff --cached
```

Make sure you did not accidentally add:

-   API keys
-   passwords
-   cookies
-   browser session data
-   authorization headers
-   private certificates
-   real personal information
-   real customer data
-   mitmproxy private keys
-   large temporary logs

------------------------------------------------------------------------

# 18. Current status

At the time of writing, the lab has been tested for:

-   HTTPS interception through mitmproxy
-   Local ONNX BERT inference
-   Regex secret detection
-   PII detection and redaction
-   Multiple PII entities
-   Punctuation-aware redaction
-   Regex + ML interaction
-   ChatGPT prompt interception
-   Claude prompt interception
-   Recursive JSON inspection
-   ALLOW and REDACT decisions

The provider-specific request formats may change as the AI services
update their web applications, so those handlers may need maintenance
over time. This has already happened for claude.ai (see section 11).

Reversible masking (`capstone/hide_seek/`) has been tested live on
claude.ai for masking, streamed restore, consistency across turns and
provider-side storage of fakes only. Its current numbers and limitations
are in its own README.
