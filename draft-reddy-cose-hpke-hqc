---
title: Hamming Quasi-Cyclic (HQC) Ciphersuites for COSE-HPKE
abbrev: HQC for COSE-HPKE
docname: draft-reddy-cose-hpke-hqc-latest
category: std
ipr: trust200902
submissiontype: IETF
v: 3
area: Security
workgroup: COSE
keyword:
- HQC
- COSE
- HPKE
- Post-Quantum Cryptography
author:
- fullname: Hannes Tschofenig
  organization: University of the Bundeswehr Munich
  abbrev: UniBw M.
  city: Neubiberg
  code: '85577'
  country: Germany
  email: hannes.tschofenig@gmx.net
- fullname: Tirumaleswar Reddy
  organization: Nokia
  city: Bangalore
  region: Karnataka
  country: India
  email: kondtir@gmail.com
normative:
  RFC8949:
  RFC9052:
  RFC9964:
  HPKE: I-D.ietf-hpke-hpke
  PQ-HPKE: I-D.ietf-hpke-pq
  HQC-HPKE:
    title: HQC Key Encapsulation for Hybrid Public Key Encryption (HPKE)
    author:
    - fullname: Hannes Tschofenig
    - fullname: Tirumaleswar Reddy
    date: 2026-10-10
    seriesinfo:
      Internet-Draft: draft-tschofenig-hpke-hqc-00
    target: https://datatracker.ietf.org/doc/html/draft-tschofenig-hpke-hqc-00
  COSE-HPKE: I-D.ietf-cose-hpke
informative:
  COSE-IANA:
    title: CBOR Object Signing and Encryption (COSE)
    author:
    - org: IANA
    target: https://www.iana.org/assignments/cose/

--- abstract

This document specifies Hamming Quasi-Cyclic (HQC)-based ciphersuites
for use with COSE-HPKE.
It defines fully specified COSE algorithms for HPKE Integrated
Encryption and HPKE Key Encryption, using HQC key encapsulation,
SHAKE256 key derivation, and AES-256-GCM authenticated encryption.
It specifies their AKP key representation and requests six COSE
algorithm registrations. Message processing and context binding are
inherited from COSE-HPKE.

--- middle

# Introduction

COSE-HPKE {{COSE-HPKE}} embeds Hybrid Public Key Encryption {{HPKE}}
in CBOR Object Signing and Encryption (COSE) {{RFC9052}}. A COSE-HPKE
algorithm identifier selects a complete HPKE ciphersuite and a COSE
usage mode.

This document adds ciphersuites using the HQC KEMs of {{HQC-HPKE}}.
Each of HQC-1, HQC-3, and HQC-5 is combined with the SHAKE256 KDF of
{{PQ-HPKE}} and AES-256-GCM. Separate COSE algorithms identify
Integrated Encryption and Key Encryption.

The document does not change the COSE-HPKE message formats, HPKE key
schedule, or existing header parameters. It does not define a hybrid
combination of HQC and another KEM. It is also separate from direct
PQ-KEM-for-COSE constructions using an external KDF and AES Key Wrap;
their algorithm identifiers and key-use conventions do not apply here.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

The notation of {{HPKE}} and {{COSE-HPKE}} applies. `enc` is the HPKE
encapsulation output. The COSE `ek` header carries that output and
not a recipient public key. `ct` is the HPKE AEAD ciphertext. A CEK
is a content-encryption key used in the next lower COSE layer.

"Integrated" and "Key Encryption" refer to the two COSE-HPKE usage
modes. "Base" and "PSK" refer to HPKE authentication modes. These
are independent choices; a COSE usage-mode identifier does not select
between Base and PSK.

# Ciphersuites {#suites}

The six ciphersuites are defined in {{suite-table}}. Each row selects
exactly one COSE usage mode and one HPKE triple `(kem_id, kdf_id,
aead_id)`. Implementations MUST NOT substitute another KDF, AEAD, or
HQC parameter set under the same COSE algorithm identifier.

| COSE name | COSE value | Mode | HPKE KEM |
|:----------|:-----------|:-----|:---------|
| HPKE-HQC-1 | TBD-COSE-HQC-1 | Integrated | HQC-1 |
| HPKE-HQC-3 | TBD-COSE-HQC-3 | Integrated | HQC-3 |
| HPKE-HQC-5 | TBD-COSE-HQC-5 | Integrated | HQC-5 |
| HPKE-HQC-1-KE | TBD-COSE-HQC-1-KE | Key Encryption | HQC-1 |
| HPKE-HQC-3-KE | TBD-COSE-HQC-3-KE | Key Encryption | HQC-3 |
| HPKE-HQC-5-KE | TBD-COSE-HQC-5-KE | Key Encryption | HQC-5 |
{: #suite-table title="HQC COSE-HPKE algorithms"}

For every row, the HPKE KDF is SHAKE256 (`kdf_id = 0x0011`) as defined
in {{PQ-HPKE}}, and the HPKE AEAD is AES-256-GCM (`aead_id = 0x0002`)
as defined in {{HPKE}}. The `kem_id` is the corresponding HQC-1,
HQC-3, or HQC-5 allocation requested by {{HQC-HPKE}}.

The selection of SHAKE256 and AES-256-GCM limits the initial suite
count while allowing all three HQC parameter sets.

# Key Representation {#keys}

Keys MUST use the Algorithm Key Pair (AKP) key type of {{RFC9964}} and
the raw HPKE key mapping specified in Section 3.4 of {{COSE-HPKE}}.

| Parameter | Label | Requirement |
|:----------|------:|:------------|
| kty | 1 | Integer 7 (AKP) |
| alg | 3 | COSE algorithm value |
| pub | -1 | HPKE SerializePublicKey output, bstr |
| priv | -2 | HPKE SerializePrivateKey output, bstr, private keys only |
{: #key-fields title="HQC COSE_Key parameters"}

The `alg` field MUST be present and MUST identify the ciphersuite for
which the key is used. It MUST match the selected COSE-HPKE algorithm.
This is a complete ciphersuite binding, not merely a KEM binding:
HPKE-HQC-1 and HPKE-HQC-1-KE identify different key objects.

The `pub` value has length 2241, 4514, or 7237 octets for HQC-1,
HQC-3, or HQC-5, respectively. The `priv` value, when present, is the
32-octet seed serialization defined by {{HQC-HPKE}}. Expanded private
keys MUST NOT be placed in `priv`. Public-key objects MUST NOT contain
`priv`. No `crv` parameter is used.

Implementations MUST perform the deserialization and consistency checks
specified by {{HQC-HPKE}}, including rejection of an imported seed and
public-key pair that do not match. The parameter set MUST be determined
from `alg`, not inferred from a byte-string length alone.

If `key_ops` (label 4) is present, it MUST be `[8]` (derive bits) for
a private key and `[]` for a public key, as required by Section 3.4
of {{COSE-HPKE}}. This is not a `deriveKey` permission and does not
authorize use of the HQC key as a symmetric key.

AKP thumbprints follow Section 6 of {{RFC9964}}. They include the
COSE algorithm value, so two ciphersuite bindings do not have the same
thumbprint merely because their public-key bytes are identical.

# Processing Requirements {#processing}

The processing of {{COSE-HPKE}} applies with the algorithms from
{{suites}} and the key mapping in {{keys}}. Only the HPKE Single-Shot
APIs are used. A new HPKE operation, with fresh encapsulation randomness,
MUST be used for each independently encrypted message or recipient.
Reusing a provisioned recipient public key is distinct from reusing
encapsulation randomness or an HPKE encryption context.

If the `alg` header is present, it MUST be protected and MUST match
the selected suite. When it is omitted as permitted by {{COSE-HPKE}},
the suite MUST be unambiguously established by the application context
and MUST still match the key's mandatory `alg`. A receiver MUST NOT
try different suites until one decrypts successfully.

The `ek` header MUST contain the raw HPKE `enc` output as a byte
string in the unprotected header of the structure performing HPKE.
Its expected length is 4433, 8978, or 14421 octets for HQC-1, HQC-3,
or HQC-5. A missing header, incorrect type, or incorrect length MUST
be rejected before invoking decapsulation. The checks of {{HQC-HPKE}}
apply in addition to these COSE checks.

## Integrated Encryption {#integrated}

The algorithms without the `-KE` suffix MUST be used only with the
Integrated Encryption processing of Section 3.2 of {{COSE-HPKE}}.
This mode uses COSE_Encrypt0 and has one recipient.

HPKE encrypts the raw content. The inputs and outputs are mapped as
specified by the base document:

* `info` is empty unless the application supplies the same external
  value to both parties.
* `aad` is the encoded COSE Enc_structure with context `Encrypt0`,
  the protected-header byte string, and the application's external AAD.
* `pt` is the content to encrypt.
* `enc` is carried in the unprotected `ek` header.
* `ct` is the COSE_Encrypt0 ciphertext, or the detached ciphertext
  when that field is `null`.

HPKE manages the AEAD key and nonce internally.

## Key Encryption {#key-encryption}

The algorithms with the `-KE` suffix MUST be used only with the Key
Encryption processing of Section 3.3 of {{COSE-HPKE}}. A COSE_Encrypt
contains the content encrypted with an independently generated CEK.
Each COSE_Recipient uses HPKE to encrypt that CEK for its recipient.

The `info` input is the Recipient_structure of the base document,
encoded according to the Core Deterministic Encoding Requirements in
Section 4.2.1 of {{RFC8949}}. Its four members bind the HPKE recipient
context, the algorithm of the next lower COSE layer, the exact recipient
protected-header bytes, and any agreed recipient extra information.
The `next_layer_alg` value MUST match the algorithm of that lower
layer. Deterministic encoding applies to the structure, not to
re-encoding the protected-header bytes it contains.

The HPKE `aad` input SHOULD be empty, with any additional data handled
as specified in Section 3.3.4 of {{COSE-HPKE}}. The HPKE plaintext is
the CEK. The encapsulation output is placed in the recipient's
unprotected `ek` header, and the HPKE ciphertext is placed in that
recipient's ciphertext field.

The HPKE AEAD of these suites is always AES-256-GCM and encrypts the
CEK. The selected outer algorithm determines the CEK length and its own
nonce and usage requirements. There is no AES Key Wrap step and no
COSE_KDF_Context in this processing.

The receiver uses HPKE Open to recover the CEK, checks that its length
is appropriate for the next layer, and processes that layer according
to COSE. A failed HPKE Open or failed content authentication MUST NOT
result in plaintext release. Each recipient receives an independent
encapsulation and encrypted copy of the CEK.

## Base and PSK Authentication Modes {#modes}

Both COSE usage modes support HPKE Base and PSK. Following
{{COSE-HPKE}}, a protected `psk_id` selects PSK mode; its absence
selects Base mode. The PSK is provided externally and MUST NOT be
included in the COSE structure. Its provisioning, entropy, and matching
requirements are those of {{HPKE}}.

No additional COSE algorithm identifiers are required for PSK mode.

## Failure Handling

The explicit errors and implicit-rejection behavior of {{HQC-HPKE}}
and {{HPKE}} apply. Implementations MUST NOT turn the internal HQC
consistency check into a distinguishable COSE rejection signal.
Implicit rejection continues through HPKE; authentication failure is
handled through the normal Open path. Explicit parse or KEM failures
stop the operation without releasing content or a CEK.

# Security Considerations

The security considerations of {{HQC-HPKE}}, {{HPKE}}, {{PQ-HPKE}},
{{COSE-HPKE}}, and {{RFC9052}} apply. This document selects and encodes
ciphersuites; it does not supply an independent proof of HQC or HPKE.
Its publication depends on the HQC-to-HPKE review identified in
{{HQC-HPKE}}.

The protected headers, Recipient_structure, and the distinction
between HPKE `info` and `aad` MUST be handled exactly as specified by
{{COSE-HPKE}}. Replacing that structure with the context from another
COSE key-distribution mechanism can remove intended algorithm binding
and produces a different construction.

Applications MUST constrain algorithm selection by policy and MUST NOT
silently fall back to another KEM, ciphersuite, or HQC revision after
decryption failure. Selection of a high-category KEM does not remove
limits imposed by a content algorithm, KDF, AEAD, PSK, or implementation.

Multiple recipients do not form a hybrid KEM. If HQC and ML-KEM
recipients independently protect the same CEK, either recipient's
private key is sufficient to recover it. Confidentiality therefore
depends on every enabled recovery path. Applications requiring security
when one KEM fails need a separately specified and analyzed hybrid
construction.

Base mode does not authenticate the sender. A `kid` is a lookup hint,
not a substitute for authenticated public-key distribution. Sender
authentication can be provided by the PSK mode or suitable COSE-native
mechanisms as described by the base document. Long-term recipient
key compromise permits recovery of recorded messages.

Fresh randomness is required for encapsulation and for CEK generation
in Key Encryption mode. The 32-octet private seed is secret key
material and implementations MUST protect it and
all expanded keys and intermediate shared secrets against disclosure.

Message-size limits need to account for the entire encoded COSE
object, not just the plaintext. In Key Encryption mode, each HQC
recipient adds its KEM ciphertext and an encrypted CEK. Implementations
SHOULD bound parsing, reassembly, memory allocation, and decapsulation
work. Detached content does not eliminate the per-recipient KEM
ciphertext overhead.

# IANA Considerations {#iana}

IANA is requested to add the following six entries to the "COSE
Algorithms" registry {{COSE-IANA}}. The entries are fully specified
by {{suites}}. For every entry, the KDF is HPKE SHAKE256 (0x0011)
and the AEAD is HPKE AES-256-GCM (0x0002).

| Name | Value | Description |
|:-----|:------|:------------|
| HPKE-HQC-1 | TBD-COSE-HQC-1 | Integrated Encryption: HQC-1, SHAKE256, AES-256-GCM |
| HPKE-HQC-3 | TBD-COSE-HQC-3 | Integrated Encryption: HQC-3, SHAKE256, AES-256-GCM |
| HPKE-HQC-5 | TBD-COSE-HQC-5 | Integrated Encryption: HQC-5, SHAKE256, AES-256-GCM |
| HPKE-HQC-1-KE | TBD-COSE-HQC-1-KE | Key Encryption: HQC-1, SHAKE256, AES-256-GCM |
| HPKE-HQC-3-KE | TBD-COSE-HQC-3-KE | Key Encryption: HQC-3, SHAKE256, AES-256-GCM |
| HPKE-HQC-5-KE | TBD-COSE-HQC-5-KE | Key Encryption: HQC-5, SHAKE256, AES-256-GCM |

The following fields apply to every row:

* Capabilities: `[kty]`
* Change Controller: IESG
* Reference: this document, {{suites}}, {{keys}}, and {{processing}}
* Recommended: No

The corresponding HPKE KEM ID in each description is the HQC-1,
HQC-3, or HQC-5 identifier assigned to {{HQC-HPKE}}. Those values
MUST be resolved in {{suites}} before publication.

The existing AKP key type and the `ek` and `psk_id` parameters
defined by {{COSE-HPKE}} are reused.

--- back

# Example {#examples}

These examples are pseudocode, not executable CBOR diagnostic notation
or cryptographic test vectors. `encode` denotes CBOR encoding,
`bstr(name)` denotes the byte string held in `name`, and symbolic
algorithm and header identifiers stand for integer assignments.
`EK` and `PSK_ID` denote the header labels assigned by {{COSE-HPKE}}.

A future version of this specification will provide working
examples.

## AKP Public Key

~~~
{
   1: 7,                         / AKP /
   3: TBD-COSE-HQC-1,
   4: [],                        / optional key_ops /
  -1: bstr(pk)                   / 2241 octets /
}
~~~

A corresponding private-key object includes `-2: bstr(seed)` with
32 octets and, if `key_ops` is present, replaces `[]` with `[8]`.
A Key Encryption object uses its own matching `-KE` algorithm binding.

## Integrated Encryption in Base Mode

~~~
16([
  encode({1: TBD-COSE-HQC-1}),
  {4: bstr(kid), EK: bstr(enc)},
  bstr(ct)
])
~~~

The tag is the optional COSE_Encrypt0 tag. `enc` has 4433 octets.
The protected bytes shown are also used in Enc_structure, which is
passed as HPKE AAD. `ct` contains the encrypted content and its
16-octet AES-GCM authentication tag. No external COSE IV is needed
for the HPKE operation.

## Key Encryption in Base Mode

~~~
96([
  encode({1: 3}),                 / outer A256GCM /
  {5: bstr(content_iv)},
  bstr(encrypted_content),
  [
    [
      encode({1: TBD-COSE-HQC-5-KE, 4: bstr(kid)}),
      {EK: bstr(enc)},
      bstr(encrypted_cek)
    ]
  ]
])
~~~

Here the independent CEK has 32 octets and `content_iv` has 12 octets.
For the HQC-5 recipient, `enc` has 14421 octets. `encrypted_cek` has
48 octets: the encrypted 32-octet CEK followed by the 16-octet HPKE
AES-GCM tag. The recipient's `info` is the deterministic encoding of:

~~~
[
  "HPKE Recipient",
  3,
  encode({1: TBD-COSE-HQC-5-KE, 4: bstr(kid)}),
  h''
]
~~~

The protected-header byte string MUST be the same one transmitted in
the recipient, not a separately re-encoded equivalent map. To use PSK
mode, add `PSK_ID: bstr(psk_id)` to that protected map and supply the
corresponding PSK externally. This also changes the bytes in `info`.
