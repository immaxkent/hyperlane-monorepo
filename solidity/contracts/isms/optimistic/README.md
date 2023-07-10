## Solidity Challenge

This repo contains the submission for the Hyperlane solidity challenge, being an implementation of the OptimisticISM.

*The optimistic security model separates **message verification** and **message delivery** into two separate transactions. Specifically, verification and delivery are separated by a configurable fraud window. In other words, messages are **verified first, and then after the fraud window has elapsed, they may be delivered**.*

# Running Notes on Challenge and Codebase

1   This architecture runs on the premise that each relayer can only send 1 message at a time 
            through the OptimisticISM.

2   All trust is put in the hands of watchers, who don't seem to be incentivised at this stage.

3   Any and all watchers can flag submodules and messages as fraudulent.

4   Anyone can relay messages to the ISM.

5   What degree of privacy each operator (owner) and/or relayer of the OptimisticIsm wants is unclear. For the sake
            of security and clarity, all modifications to message, state and fraudulence have been 
            emitted as events.

6   To ensure long term compatibility, the deliver() function has been made payable to allow passing ETH
            forward depending on the reciever of the message.

7   I couldn't be clear on how implementing a seperate contract via StaticMOfNAddressSetFactory may save gas when
            __configuring watchers__ as compared to the configureWatchers() implementation shown here. Always learning, though.

8   Consideration could be given to the premise that *if a submodule is modified after it or a message sent through it has been pre-verified, and this results in a missed security flaw, the fraud window alone may not provide enough time for good watchers to flag anything as compromised*. After all, it's not like these modules are represented by a CID or something similar.
