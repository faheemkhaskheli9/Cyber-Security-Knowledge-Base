# File Upload Security

## What
Any feature that accepts a file from a user: avatars, documents, imports (CSV, XLSX, ZIP), attachments, media, firmware or plugin uploads, and direct-to-storage uploads with pre-signed URLs. The risk is not the upload itself but what happens next: where the file is stored, what parses it (image libraries, office and PDF converters, unzip, XML parsers, antivirus), and how it is served back. CWE-434 (Unrestricted Upload of File with Dangerous Type) is the core weakness; OWASP Top 10 covers it under injection and insecure design. This file covers the attacks and controls in depth.

## Why it matters
- **Remote code execution**: a script file (`.php`, `.jsp`, `.aspx`) written into a web root, or a server config file (`.htaccess`, `web.config`), runs on the server with the application's privileges.
- **Parser attack surface**: thumbnailers, converters and archive extractors are complex native code processing untrusted input; ImageTragick (CVE-2016-3714) gave RCE through ImageMagick with a crafted image.
- **Stored XSS and phishing**: an HTML or SVG file served from the application's origin runs script with the user's session; a hosted PDF or HTML page lends your domain to a phishing campaign.
- **Path traversal and overwrite**: a filename like `../../app/config.py` or an archive entry with `../` writes outside the upload directory (Zip Slip).
- **Resource exhaustion and cost**: decompression bombs, huge files and unthrottled uploads exhaust disk, memory, CPU or cloud spend.
- **Malware distribution**: the service stores and redistributes malicious files to other users or internal staff.

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Attack | How it works | Defense |
|---|---|---|
| Web shell upload | Server trusts the client's extension or `Content-Type` and stores `shell.php` where the web server executes it | Extension allowlist plus content check; store outside the web root or in object storage; never execute from the upload location |
| Extension tricks | Double extensions (`shell.php.jpg` with a permissive handler), case (`.PhP`), alternative executable extensions (`.phtml`, `.phar`), trailing dots/spaces or NTFS `::$DATA` on Windows, legacy null byte (`shell.php%00.jpg`) | Generate the stored name server-side (random ID); map the validated type to a fixed extension; reject everything else |
| Config file upload | Upload of `.htaccess` or `web.config` changes how the directory is handled, making later uploads executable | Uploads go to storage the web server does not interpret; disable per-directory overrides (`AllowOverride None`) |
| Content-type / magic byte spoofing | Attacker sets `Content-Type: image/png` or prepends `GIF89a` to a script | Treat client `Content-Type` as untrusted; detect type from content; re-encode images; the content check is defense in depth, not the only control |
| Polyglot files | One file valid as two formats (image + HTML/JS, image + archive) passes an image check and is later interpreted as the other | Re-encode (decode and write a fresh image) to strip trailing and embedded data; serve with a fixed safe `Content-Type`, `X-Content-Type-Options: nosniff` |
| Stored XSS via HTML/SVG | SVG is XML that can contain `<script>`; HTML or XHTML uploads render in the app origin | Do not accept SVG/HTML unless required; sanitize SVG server-side; serve user content from a separate sandbox domain with `Content-Disposition: attachment` and a restrictive CSP |
| XXE in document formats | SVG, XML and Office files (DOCX, XLSX are ZIPs of XML) parsed with external entities enabled read local files or reach internal URLs | Disable DTDs/external entities in every XML parser (`kb/03-application/owasp-top10.md`); patch converters |
| Parser / converter exploits | Crafted image, PDF or video exploits ImageMagick, Ghostscript, LibreOffice, FFmpeg or similar | Process in an isolated, unprivileged sandbox with no network and no secrets; restrict formats and coders (ImageMagick `policy.xml`); patch fast |
| Path traversal in filename | `filename="../../etc/cron.d/x"` in the multipart header is used to build the path | Never use the client filename in a path; store under a generated key; keep the original name only as escaped metadata |
| Zip Slip / archive traversal | Archive entries named `../../x` or absolute paths, or symlink entries, write outside the extraction directory | Validate every entry's resolved path stays inside the target; reject symlinks and hard links; use safe extraction APIs (Python `tarfile` `filter="data"`) |
| Decompression bomb | Small ZIP or image expands to huge size or pixel count (nested archives, "pixel flood") | Limits on compressed size, total uncompressed size, file count, nesting depth, compression ratio and image dimensions; Pillow `Image.MAX_IMAGE_PIXELS` |
| Malware hosting | Uploaded malware is later downloaded by users or staff | Antivirus / sandbox scan before release to others; quarantine until scanned; content disarm and reconstruction (CDR) for office/PDF where risk warrants |
| Pre-signed URL abuse | Pre-signed upload URL with no size, type or key constraints lets the client overwrite other objects or upload unlimited data | Short expiry; fixed object key per request; size range and content-type conditions in the policy; separate quarantine bucket |
| Formula (CSV) injection | Uploaded or exported CSV cells starting with `=`, `+`, `-`, `@` execute as formulas when opened in a spreadsheet | Escape leading formula characters on export; warn on import; see OWASP CSV Injection |
| Metadata leakage | Uploaded photos keep EXIF GPS location, device and author data that is then shown to other users | Strip metadata on re-encode |

## Defenses

### 1. Accept less
- Allowlist extensions and types per feature (avatars: `jpg`, `png`, `webp`); deny by default. Blocklists of "dangerous" extensions always miss one.
- Authenticate and authorize uploads; rate limit per user; set a maximum request and file size at the proxy and in the application.
- Ask whether the feature needs arbitrary files at all; a structured form is safer than a spreadsheet import.

### 2. Validate the content
- Check the extension, then detect the type from the content (magic bytes) and require both to agree with the allowlist. Do not trust the multipart `Content-Type`.
- For images, decode and **re-encode** to a fresh file with a maintained library, capped dimensions and metadata stripped; this removes most polyglot and trailing payloads.
- For archives, enforce entry count, total uncompressed size, ratio and depth limits while streaming, and check each resolved path:

```python
import os, zipfile

MAX_FILES, MAX_TOTAL = 1000, 200 * 1024 * 1024  # example limits

def safe_extract(zip_path: str, dest: str) -> None:
    dest = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_TOTAL:
            raise ValueError("archive too large")
        for info in infos:
            target = os.path.realpath(os.path.join(dest, info.filename))
            if os.path.commonpath([dest, target]) != dest:
                raise ValueError(f"path traversal: {info.filename!r}")
        zf.extractall(dest)
```

`file_size` is declared by the archive, so also cap bytes actually written when streaming. For tar files use `tarfile.extractall(dest, filter="data")` (Python 3.12+, also in security releases of older versions; the default from 3.14), which rejects absolute paths, traversal, links outside the destination and device files.

### 3. Store safely
- Store outside the web root, preferably in object storage, under a server-generated key (UUID). Keep the original filename only as metadata, encoded on output.
- Upload directory or bucket has no execute permission and no script handler; the web server never interprets it.
- Separate **quarantine** and **clean** locations: new uploads land in quarantine, a scanner or processor promotes them.
- Encrypt at rest; apply retention and deletion rules (`kb/09-governance/data-security-and-dlp.md`).
- Pre-signed uploads: expiry of minutes, fixed key, content-length range and content-type conditions, quarantine bucket, server-side processing on the storage event.

### 4. Process in isolation
- Run thumbnailing, conversion, OCR, unzip and scanning in a separate worker: unprivileged user, read-only filesystem except a scratch directory, no outbound network, no cloud credentials or database secrets, CPU/memory/time limits (container or serverless sandbox, seccomp).
- Restrict libraries to the formats you need (ImageMagick `policy.xml` disabling unneeded coders such as `MVG`, `MSL`, `PS`, `EPS`, `PDF` when not required).
- Keep parsers patched; they belong in the dependency inventory (`kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`).
- Scan with antivirus and, for high-risk flows, detonate in a sandbox or apply CDR; scanning reduces but does not remove risk.

### 5. Serve safely
- Serve user content from a separate domain (not a subdomain sharing cookies with the app) or via short-lived signed URLs.
- Response headers: the validated `Content-Type`, `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` for anything not meant to render inline, and `Content-Security-Policy: sandbox` or `default-src 'none'` on user content (`kb/03-application/browser-client-side.md`).
- Check authorization on download, not just on upload (IDOR on `/files/<id>`).

### 6. Monitor
- Log uploader, size, detected type, hash, scan verdict and storage key (`kb/06-secure-sdlc/security-logging-and-monitoring.md`).
- Alert on rejected types, scan detections, archive limit violations and executable content in upload storage.

## How to verify
- Upload `test.php`, `test.php.jpg`, `test.pHp`, `test.phtml`, `.htaccess` and `web.config`; each must be rejected or stored under a random name that is never executed. Request the stored URL and confirm it is served as a download or static type, never executed.
- Send a valid extension with a mismatched content (`GIF89a` + script) and a valid image with appended HTML; confirm rejection or that the re-encoded output no longer contains the payload.
- Upload an SVG containing `<script>` and an HTML file; open the served URL and confirm no script runs in the application origin.
- Upload an archive with a `../` entry and with a symlink entry; nothing may be written outside the extraction directory.
- Upload an archive and an image that exceed the configured uncompressed size and pixel limits; the worker must refuse them without crashing.
- Upload the EICAR test file; it must be quarantined and never served to another user.
- Check response headers on served files (`curl -sI`): `X-Content-Type-Options: nosniff`, correct `Content-Type`, `Content-Disposition`.
- Request another user's file ID; it must be refused.
- Review the processing worker: its user, network egress, mounted secrets and resource limits.

## References
- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP WSTG, Test Upload of Unexpected File Types: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types
- OWASP WSTG, Test Upload of Malicious Files: https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
- OWASP XML External Entity Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- OWASP CSV Injection: https://owasp.org/www-community/attacks/CSV_Injection
- CWE-434, Unrestricted Upload of File with Dangerous Type: https://cwe.mitre.org/data/definitions/434.html
- CWE-22, Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- CWE-409, Improper Handling of Highly Compressed Data: https://cwe.mitre.org/data/definitions/409.html
- CVE-2016-3714 (ImageTragick): https://nvd.nist.gov/vuln/detail/CVE-2016-3714
- PortSwigger Web Security Academy, File upload vulnerabilities: https://portswigger.net/web-security/file-upload
- PEP 706, Filter for `tarfile.extractall`: https://peps.python.org/pep-0706/
- EICAR anti-malware test file: https://www.eicar.org/
- See also `kb/03-application/owasp-top10.md`, `kb/03-application/api-security.md`, `kb/03-application/browser-client-side.md`, `kb/04-cloud-infra/serverless-security.md`, `kb/07-offensive/pentest-methodology.md`
