# Memory Safety (Memory-Safe Languages and C/C++ Hardening)

## What
Memory-safety bugs let a program read or write memory it should not: out-of-bounds write and read (CWE-787, CWE-125), use after free (CWE-416), double free (CWE-415), use of uninitialized memory (CWE-457), integer overflow that leads to a bad size (CWE-190), and type confusion (CWE-843). They are typical of C, C++ and assembly, where the programmer manages memory by hand. **Memory-safe languages** (MSLs) such as Rust, Go, Java, C#, Swift, Kotlin and Python prevent most of these by construction, through bounds checks, garbage collection or ownership rules, and safe defaults. A **memory safety roadmap** is a producer's published plan for moving its products to MSLs and reducing the remaining risk in unsafe code. Code review patterns for C sinks are in `kb/06-secure-sdlc/secure-code-review.md`.

## Why it matters
- Memory-safety bugs are a large share of serious vulnerabilities in large C/C++ code bases: Microsoft reported (2019) that about 70% of the CVEs it assigns each year are memory-safety issues, and the Chromium project reports a similar share of its serious security bugs.
- They are often exploitable for remote code execution, which is why they dominate browser, OS kernel, VPN appliance and parser exploits.
- Moving new code to an MSL works without rewriting everything: Google reported that memory-safety issues fell from 76% of Android vulnerabilities in 2019 to 24% in 2024, mainly by writing new code in memory-safe languages while existing C/C++ stayed in place.
- Governments now expect it. CISA and partner agencies' *The Case for Memory Safe Roadmaps* (December 2023) asks producers to publish roadmaps, and CISA and FBI *Product Security Bad Practices* (October 2024) calls it a bad practice for software that supports critical infrastructure when an existing product written in a memory-unsafe language has no published memory safety roadmap by January 1, 2026 (products with end of support before January 1, 2030 are excepted) (`kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`).

## Attacks
*For authorized testing only. Each pattern lists its main defense.*

| Bug class | Typical cause | Exploitation | Defense |
|---|---|---|---|
| Out-of-bounds write (stack or heap overflow) | `memcpy` / `strcpy` with an attacker-controlled length; off-by-one | Overwrite return addresses, function pointers or heap metadata to gain code execution | MSL; bounded APIs and `std::span`; `_FORTIFY_SOURCE`; stack protector; fuzzing with ASan |
| Out-of-bounds read | Length field in a packet trusted without checking it against the buffer | Leak memory (keys, session data) or defeat ASLR | Bounds-checked parsing; MSL for parsers |
| Use after free / double free | Object freed while another reference still uses it | Attacker reallocates the freed memory with controlled data (type confusion, code execution) | Ownership in Rust, smart pointers in C++, hardened allocators, MTE where available |
| Integer overflow / truncation | `count * size` wraps, so a small buffer is allocated | Leads to an out-of-bounds write | Checked arithmetic (`__builtin_mul_overflow`, `checked_mul` in Rust), `calloc`, compiler warnings |
| Uninitialized memory | Stack variable or padding sent to the user or used as a pointer | Information leak or control of a pointer | `-ftrivial-auto-var-init=zero`, MSan, compiler warnings as errors |
| Data race | Unsynchronized shared state in threads | Use after free or corrupted state | Rust's `Send` / `Sync` rules, TSan, avoid shared mutable state |
| Unsafe escape hatches in an MSL | Rust `unsafe`, Go `unsafe` / cgo, C# `unsafe`, JNI, FFI to C libraries | Same bugs as C, in a small region | Keep unsafe code small and encapsulated, review and fuzz it, track it per crate / module |

## Defenses

### 1. Plan: a memory safety roadmap
- Inventory components by language and by exposure. Prioritize code that parses untrusted input, runs with high privilege or faces the network (parsers, codecs, network daemons, kernel drivers).
- Write **new** components and new parsers in an MSL. Rewrite the riskiest existing components when they are being reworked anyway; leave stable, low-exposure code in place with the hardening below.
- Publish the roadmap with dates and owners, and measure the share of exposed code in MSLs over time.

### 2. Use the language safely
- Rust: forbid `unsafe` by default (`#![forbid(unsafe_code)]` in crates that do not need it), require review for every `unsafe` block with a written safety comment, and use `cargo audit` / `cargo deny` for dependencies.
- Go, Java, C#: avoid `unsafe` packages and native interop except in reviewed modules; treat cgo / JNI / P/Invoke boundaries as trust boundaries.
- Keep MSL dependencies patched: memory safety removes one class of bugs, not logic, injection or authorization bugs (`kb/03-application/owasp-top10.md`).

### 3. Harden remaining C and C++
- Modern C++: `std::vector`, `std::string`, `std::span`, `std::unique_ptr` / `std::shared_ptr`, no raw owning pointers or manual `new` / `delete`; enable library hardening (`-D_GLIBCXX_ASSERTIONS` for libstdc++, `_LIBCPP_HARDENING_MODE` for libc++).
- Compiler and linker options (GCC/Clang; follow the OpenSSF Compiler Options Hardening Guide for current flags):
  ```bash
  CFLAGS="-O2 -Wall -Wextra -Wformat -Wformat=2 -Werror=format-security \
    -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection \
    -fcf-protection=full -ftrivial-auto-var-init=zero -fPIE"
  LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"
  ```
  (`-fcf-protection` is x86-64; on AArch64 use `-mbranch-protection=standard`.) MSVC: `/GS`, `/guard:cf`, `/CETCOMPAT`, `/DYNAMICBASE`, `/NXCOMPAT`.
- Keep OS-level mitigations on: ASLR, DEP/NX, Control Flow Guard, CET shadow stacks, and hardware memory tagging (Arm MTE) where the platform supports it (`kb/04-cloud-infra/os-hardening.md`).

### 4. Find bugs before attackers do
- Run unit and integration tests under sanitizers in CI: AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) on every build; MemorySanitizer (MSan) and ThreadSanitizer (TSan) where relevant.
- Fuzz every parser and every API that takes untrusted bytes (libFuzzer, AFL++, `cargo fuzz`, Go native fuzzing); open-source projects can join OSS-Fuzz (`kb/06-secure-sdlc/cicd-security.md`).
- Use SAST rules for dangerous functions (`strcpy`, `sprintf`, `gets`) and enable compiler warnings as errors.

### 5. Contain what cannot be fixed yet
- Sandbox risky C/C++ components: run parsers in a separate low-privilege process, use seccomp, AppContainer, or a WebAssembly sandbox, and drop privileges early.

## How to verify
- Inventory: a report lists each component's language, exposure and roadmap status; new network-facing components are in an MSL or have a documented exception.
- Binary hardening (Linux): `checksec --file=<binary>` shows Full RELRO, canary found, NX enabled, PIE enabled and FORTIFY; or `readelf -lW <binary> | grep GNU_STACK` shows `RW` (not `RWE`) and `readelf -d <binary> | grep -E 'BIND_NOW|FLAGS'` shows `BIND_NOW`.
- Windows binaries: `dumpbin /headers <file>` shows Dynamic base, NX compatible and Guard in the DLL characteristics.
- CI: sanitizer jobs and fuzzing jobs exist and run on every change to parsing code; crashes open tickets.
- Rust: `grep -rn "unsafe" src/` matches only reviewed modules; `cargo audit` reports no known-vulnerable crates.
- Trend: the share of memory-safety CVEs in your products (by CWE) goes down release over release.

## References
- CISA, NSA, FBI and international partners, *The Case for Memory Safe Roadmaps* (December 2023): https://www.cisa.gov/case-memory-safe-roadmaps
- CISA and NSA, *Memory Safe Languages: Reducing Vulnerabilities in Modern Software Development* (June 2025): https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development
- NSA Cybersecurity Information Sheet, *Software Memory Safety* (November 2022, updated April 2023)
- CISA and FBI, *Product Security Bad Practices*: https://www.cisa.gov/resources-tools/resources/product-security-bad-practices
- OpenSSF, Compiler Options Hardening Guide for C and C++: https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html
- Microsoft Security Response Center, "A proactive approach to more secure code" (2019): https://msrc.microsoft.com/blog/2019/07/a-proactive-approach-to-more-secure-code/
- Chromium, Memory safety: https://www.chromium.org/Home/chromium-security/memory-safety/
- Google Security Blog, "Eliminating Memory Safety Vulnerabilities at the Source" (September 2024): https://security.googleblog.com/2024/09/eliminating-memory-safety-vulnerabilities-Android.html
- MITRE CWE-787: https://cwe.mitre.org/data/definitions/787.html · CWE-416: https://cwe.mitre.org/data/definitions/416.html · CWE-125: https://cwe.mitre.org/data/definitions/125.html
- OSS-Fuzz: https://google.github.io/oss-fuzz/ · Clang AddressSanitizer: https://clang.llvm.org/docs/AddressSanitizer.html
- See also `kb/06-secure-sdlc/secure-code-review.md`, `kb/06-secure-sdlc/secure-sdlc-and-supply-chain.md`, `kb/04-cloud-infra/os-hardening.md`, `kb/09-governance/vulnerability-management.md`
