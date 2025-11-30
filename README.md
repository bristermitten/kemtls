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
    - client generates kp_e and sending pk_e to server
    - client encaps server static pk pk_s to get ct_s and ss_s
    - server decaps ct_s to get ss_s
    - client sends pk_e in parts to server
    - eventually server can generate ss_e
    - sends ct_e back to client
    - who decaps ct_e to get ss_e
    
