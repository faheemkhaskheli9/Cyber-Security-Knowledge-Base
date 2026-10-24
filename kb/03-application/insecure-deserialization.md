# Insecure Deserialization

## What
**Insecure deserialization** (CWE-502, Deserialization of Untrusted Data) is when an application turns attacker-controlled bytes back into live objects with a format that can choose *which* classes to build. Native object formats call constructors, setters, magic methods or `__reduce__` while they rebuild the graph, so the input decides what code runs.

Formats that can instantiate arbitrary types:

| Language | Dangerous | Safe or safer alternative |
|---|---|---|
| Java | `ObjectInputStream.readObject`, `XMLDecoder`, XStream without an allowlist, Jackson with default/polymorphic typing, SnakeYAML `Constructor` (CVE-2022-1471) | JSON to fixed DTOs, Protocol Buffers; if native is unavoidable, an `ObjectInputFilter` allowlist; SnakeYAML `SafeConstructor` or 2.x defaults |
| .NET | `BinaryFormatter` (obsolete; implementation removed in .NET 9), `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, Json.NET `TypeNameHandling` other than `None` | `System.Text.Json` to fixed types, `DataContractSerializer` with known types |
| Python | `pickle`, `shelve`, `dill`, `joblib.load`, `yaml.load` with an unsafe loader, `torch.load(weights_only=False)` | `json` plus schema validation, `yaml.safe_load`, `safetensors` for model weights |
| PHP | `unserialize()` on user data, `phar://` paths reaching file functions (metadata deserialization; no longer automatic since PHP 8.0) | `json_decode`; `unserialize($s, ['allowed_classes' => false])` as a last resort |
| Ruby | `Marshal.load`, `YAML.unsafe_load` (Psych 4 made `YAML.load` safe by default) | `JSON.parse`, `YAML.safe_load` |
| Node.js | `node-serialize` (CVE-2017-5941), `funcster`, `eval`-based parsers | `JSON.parse` plus schema validation; watch for prototype pollution when merging the result |

A **gadget chain** is a sequence of classes already on the classpath whose deserialization side effects, chained together, reach command execution, file write or JNDI/network lookups. The vulnerable application does not need to contain the payload class itself; any library it ships can supply gadgets (Frohoff and Lawrence, "Marshalling Pickles", AppSecCali 2015; the Apache Commons Collections chain).

It sits in OWASP Top 10:2021 A08 Software and Data Integrity Failures (`kb/03-application/owasp-top10.md`).

## Why it matters
- **Pre-authentication RCE**: serialized objects often arrive before login, in cookies, ViewState, RMI/JMX/T3 ports, message queues and session stores. Exploited examples include Microsoft SharePoint "ToolShell" (CVE-2025-53770, deserialization of untrusted data in on-premises SharePoint; in CISA KEV) and Oracle WebLogic T3/IIOP deserialization flaws.
- **Leaked signing keys turn integrity checks into RCE**: ASP.NET ViewState is signed with the machine key; Microsoft Threat Intelligence reported in 2025 attackers using publicly disclosed machine keys (copied from code samples and repositories) to send malicious ViewState and run code.
- **Hidden entry points**: caches (Redis/Memcached values), job queues (Celery with pickle, Java RMI), ML model files, and "remember me" cookies all deserialize data that someone other than the app may be able to write.
- **Scanner blind spot**: the payload is a binary blob, often base64, so WAF signatures and generic DAST rarely catch it.

## Attacks
*For authorized testing only. Each technique lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Gadget chain RCE (Java, .NET) | Public tools (ysoserial, ysoserial.net) build serialized objects from common libraries that run a command when deserialized | Do not deserialize untrusted native objects; JEP 290 `ObjectInputFilter` allowlist; remove unused libraries; patch |
| Python pickle `__reduce__` | A pickle can call any importable callable (for example `os.system`) during `pickle.loads` | Never unpickle untrusted data; use JSON or `safetensors`; Python docs state pickle is not secure |
| Polymorphic JSON/YAML typing | `"@class"`, `"$type"` or `!!python/object` tags pick a gadget type inside an otherwise "safe" text format | Disable default typing (Jackson), `TypeNameHandling.None` (Json.NET), safe YAML loaders; bind to concrete DTOs |
| Signed blob with a leaked key | ViewState, signed cookies or session blobs are accepted because the attacker has the HMAC or machine key | Rotate and never publish keys; unique keys per app; prefer server-side state; treat a key leak as an incident |
| Tampered cache or queue data | Attacker with write access to Redis, a queue or shared storage plants a serialized payload the consumer trusts | Authenticate and restrict cache/queue access (`kb/04-cloud-infra/database-security.md`); data-only formats for messages |
| Malicious model or data file | `torch.load`, `joblib.load` or `numpy.load(allow_pickle=True)` on a downloaded file runs pickle code | `safetensors`; `torch.load(..., weights_only=True)` (the default since PyTorch 2.6); scan model files; trusted registries (`kb/10-emerging/ai-llm-security.md`) |
| PHP object injection and phar | `unserialize()` on a cookie triggers `__wakeup`/`__destruct` gadgets (PHPGGC); on PHP 7, file functions on a `phar://` path deserialize metadata | `json_decode`; `allowed_classes => false`; upgrade to PHP 8; block `phar://` in user-supplied paths |
| Denial of service | Deeply nested or self-referencing graphs, huge collections (for example Java `HashSet` chains) exhaust CPU or memory | Depth, array-length and total-bytes limits in the filter (`maxdepth`, `maxarray`, `maxbytes`); size caps before parsing |

## Defenses

### 1. Do not deserialize untrusted native objects
- Exchange **data, not objects**: JSON, Protocol Buffers, CBOR or Avro parsed into fixed, concrete types, then validated with a schema (pydantic, JSON Schema, Bean Validation).
- Keep session and workflow state **server-side** and send the client an opaque random ID instead of a serialized object.
- Inventory every deserialization point in code review: `readObject`, `XMLDecoder`, `BinaryFormatter`, `pickle.loads`, `yaml.load`, `unserialize`, `Marshal.load` (grep patterns in `kb/06-secure-sdlc/secure-code-review.md`).

### 2. If you must, restrict the types
- **Java**: set a process-wide filter (JEP 290, Java 9+ and 8u121+) and, on Java 17+, a filter factory for per-stream context (JEP 415). Allowlist your own packages and reject everything else:
  ```bash
  java -Djdk.serialFilter='com.example.dto.*;java.base/*;maxdepth=20;maxrefs=1000;maxbytes=500000;!*' -jar app.jar
  ```
  Jackson: never `enableDefaultTyping()`; if polymorphism is needed use `activateDefaultTyping` with a strict `PolymorphicTypeValidator`. XStream 1.4.18+ applies an allowlist by default; keep it.
- **.NET**: migrate off `BinaryFormatter` and friends (Microsoft's BinaryFormatter migration guide); Json.NET `TypeNameHandling.None`, or a custom `SerializationBinder` allowlist if types must travel.
- **Python**: `yaml.safe_load`, `json.loads`; a restricted `Unpickler.find_class` reduces risk but the Python docs still treat pickle as unsafe for untrusted input.
- **PHP**: `unserialize($data, ['allowed_classes' => false])` or a short explicit class list.
- **Ruby**: `YAML.safe_load(data, permitted_classes: [])`, never `Marshal.load` on client data.

### 3. Integrity is not safety, but it helps
Signing (HMAC) serialized data you issued stops tampering, as long as the key stays secret and is checked *before* parsing. It does not make a dangerous parser safe if the key leaks. Minimal stdlib example (Python 3): data-only JSON, signed, verified before parsing, then validated:

```python
import base64, hashlib, hmac, json, os

KEY = os.environ.get("STATE_KEY", "EXAMPLE_KEY_32_BYTES_CHANGE_ME!!").encode()
ALLOWED = {"user_id": int, "cart": list}          # expected fields and types

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def dump_state(state: dict) -> str:
    body = json.dumps(state, separators=(",", ":"), sort_keys=True).encode()
    mac = hmac.new(KEY, body, hashlib.sha256).digest()
    return b64(body) + "." + b64(mac)

def load_state(token: str, max_len=4096) -> dict:
    if len(token) > max_len or token.count(".") != 1:
        raise ValueError("malformed")
    body_s, mac_s = token.split(".")
    body = unb64(body_s)
    if not hmac.compare_digest(hmac.new(KEY, body, hashlib.sha256).digest(), unb64(mac_s)):
        raise ValueError("bad signature")              # check before parsing
    data = json.loads(body)                            # data only, no types
    if not isinstance(data, dict) or set(data) != set(ALLOWED):
        raise ValueError("unexpected fields")
    for k, t in ALLOWED.items():
        if not isinstance(data[k], t):
            raise ValueError(f"bad type for {k}")
    return data

tok = dump_state({"user_id": 42, "cart": ["sku-1"]})
assert load_state(tok) == {"user_id": 42, "cart": ["sku-1"]}
forged = b64(b'{"cart":[],"user_id":1}') + "." + tok.split(".")[1]
try:
    load_state(forged); raise SystemExit("forgery accepted")
except ValueError:
    pass
```

### 4. Reduce blast radius
- Remove unused libraries that supply gadgets, keep frameworks patched (KEV-driven; `kb/09-governance/vulnerability-management.md`), and do not expose RMI, JMX, T3/IIOP or .NET Remoting ports to untrusted networks.
- Run deserializing services with least privilege, read-only file systems and restricted egress, so a gadget that runs a command or a JNDI lookup has little to reach (`kb/04-cloud-infra/containers-kubernetes-iac.md`).
- Keep machine keys and signing keys in a secret store, unique per app and environment, and rotate after any exposure (`kb/05-identity-crypto/secrets-management.md`).

### 5. Detect
- Alert on deserialization filter rejections (the JDK `java.io.serialization` logger records each filter decision, including `REJECTED`), on app processes spawning shells, and on unexpected outbound LDAP/RMI/DNS from app servers (`kb/08-defensive/endpoint-security-and-edr.md`).
- For SharePoint and ASP.NET, follow vendor guidance to rotate machine keys after compromise; patching alone does not remove stolen keys.

## How to verify
- **Find serialized data in traffic and storage**: look in cookies, hidden fields, headers, queue messages and cache values for these signatures:

  | Format | Raw bytes | Base64 starts with |
  |---|---|---|
  | Java serialization | `AC ED 00 05` | `rO0AB` |
  | .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////` |
  | Python pickle protocol 2 / 4 / 5 | `80 02` / `80 04 95` / `80 05 95` | `gAJ` / `gASV` / `gAWV` |
  | Ruby Marshal | `04 08` | `BAh` (typically) |
  | PHP serialize | text such as `O:8:"stdClass":` or `a:2:{` | n/a |
- **Static analysis**: CodeQL (`java/unsafe-deserialization`, `py/unsafe-deserialization`, `cs/unsafe-deserialization`) and Semgrep rules; grep patterns in `kb/06-secure-sdlc/secure-code-review.md`.
- **Dependency check**: list gadget-bearing libraries (Commons Collections, older XStream, SnakeYAML 1.x, Json.NET with type handling) via SCA and confirm versions and settings.
- **Authorized dynamic test**: send a harmless out-of-band payload (for example ysoserial's `URLDNS` chain, which only triggers a DNS lookup) to each suspected endpoint and watch a callback host you control; never use command-execution chains outside written scope.
- **Filter test**: confirm the Java filter is active (`-Djdk.serialFilter` or `jdk.serialFilter` in `java.security`) and that a serialized object of a non-allowlisted class is rejected.

## References
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- CWE-502, Deserialization of Untrusted Data: https://cwe.mitre.org/data/definitions/502.html
- OWASP Top 10:2021 A08 Software and Data Integrity Failures: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
- Oracle, Serialization Filtering (JEP 290 / JEP 415): https://docs.oracle.com/en/java/javase/21/core/java-serialization-filters.html
- Microsoft, BinaryFormatter security guide: https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide
- Microsoft Threat Intelligence, Code injection attacks using publicly disclosed ASP.NET machine keys (2025): https://www.microsoft.com/en-us/security/blog/2025/02/06/code-injection-attacks-using-publicly-disclosed-asp-net-machine-keys/
- Microsoft, Customer guidance for SharePoint vulnerability CVE-2025-53770: https://www.microsoft.com/msrc/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770/
- Python `pickle` documentation (security warning): https://docs.python.org/3/library/pickle.html
- PHP `unserialize` documentation: https://www.php.net/manual/en/function.unserialize.php
- PortSwigger Web Security Academy, Insecure deserialization: https://portswigger.net/web-security/deserialization
- ysoserial (gadget chain research tool, authorized testing only): https://github.com/frohoff/ysoserial
- Hugging Face safetensors: https://huggingface.co/docs/safetensors/index
- See also `kb/03-application/owasp-top10.md`, `kb/06-secure-sdlc/secure-code-review.md`, `kb/03-application/api-security.md`, `kb/10-emerging/ai-llm-security.md`, `kb/05-identity-crypto/secrets-management.md`, `kb/03-application/file-upload-security.md`
