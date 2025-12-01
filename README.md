# KEMTLS with McTiny

## High Level Points

- KEMTLS needs 2 shared secrets

  - 1 generated from ephemeral keypair
    - client generates ephemeral kp, sends pk_e to server
    - server does encap, sends ct_e
    - client does decap to get ss_e
  - 1 generated from server static keypair
    - client knows server static pk_s
    - client does encap, sends ct_s
    - server does decap to get ss_s

- McTiny covers:
  - client generates kp_e and stores it
  - client encaps server static pk pk_s to get ct_s and ss_s
  - server decaps ct_s to get ss_s
  - client sends pk_e in parts to server
  - eventually server can generate ss_e
  - sends ct_e back to client
  - who decaps ct_e to get ss_e

### Encryption

#### KEMTLS

- pk_e sent unencrypted
- ct_e sent unencrypted, certificate sent encrypted with K_1 derived from ss_e
- ct_s sent encrypted with K_1' derived from ss_e
- subsequent messages encrypted with keys derived from both ss_e and ss_s

#### McTiny

- extensions sent encrypted with ss_s
- ct_e sent unencrypted
- c_0 sent back encrypted with ss_s
- everything else is encrypted with keys derived from ss_s

## Problems

- KEMTLS ClientHello wants us to send pk_e but it's too big
- **solution?** so we do the McTiny-ing in ClientHello phase
- this introduces a new problem: the mctiny flow generates both shared secrets at once
  - we have less control over eg the keys we use for which encryption
  - the order of encryption is different - KEMTLS expects most initial messages to be encrypted with the ephemeral shared secret, whereas Mctiny encrypts everything with the static shared secret
  - is this a problem?
    - sort of. it means that until we have derived ss_e / Z, we don't have true forward secrecy
    - therefore we should only send the bare minimum up until this point
    - solution: rearrange packet order, for example send EncryptedExtensions later

# Plan

- We merge the McTiny Phase0 with the KEMTLS ClientHello phase
  - `ClientHello` contains the encapsulation of the server static key (ct_s) instead of the ephemeral public key (pk_e), along with `ClientRandom` which is used as the McTiny nonce R
  - server responds with `ServerHello` containing the cookie C*0 \_encrypted with the static shared secret* (ss_s), plus its own `ServerRandom`/Nonce N
- then the McTiny flow continues as normal with 1 difference:

  - we use the KEMTLS KDF to derive keys from the ss_s instead of the McTiny constant shared secret S

    - I don't think this adds much security but it means that the different flows are more clearly separated and matches the KEMTLS spec better

    - **Details**:
      - Reply0 (i.e. ServerHello) is encrypted with just $ss_s$
      - both parties derive $dES$ from $ss_s$
      - then both parties can derive CHTS and STCS keys from $dES$ and $ss_s$ - NOT ss_e like KEMTLS would
      - [Query/Reply][1/2/3] are encrypted with CHTS and STCS as normal

- We use TLS version 0x03AC to indicate that this isn't a standard TLS Server and only supports KEMTLS with McTiny

  - 03 looks like the TLS major version
  - AC = Advanced Cryptology :)

- To simplify the implementation we only support pre-distributed keys, which McTiny also assumes
  - adding support for certificates would be possible but is out of scope of this proof-of-concept
