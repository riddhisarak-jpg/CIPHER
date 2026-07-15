### doubts:
* how client side would decide no. of chunks
* we are asking forr mekle root in hex - does it mean we would advertise it with content
* How should a provider's libp2p PeerID become associated with its Ethereum wallet in a way that clients can verify?
* Will each provider have a wallet file (similar to PrivKeyPath)?
* Will the wallet be generated automatically?
* Will the user supply a private key?
* Will the smart contract register (PeerID, Wallet) pairs beforehand?
* Are providers expected to register their PeerID ↔ Ethereum wallet mapping in the smart contract before serving clients, or is that mapping supposed to be established dynamically during the libp2p connection?

### obsevations
* we do have proof of the libp2p PeerID identity.that proof is only inside the libp2p world. It does not prove which Ethereum wallet should be paid or penalized
* opening newstream per chunk 
* one stream can carry multiple message
* Right now, every chunk opens a new stream to the same providerID because RequestChunk() takes a single: [ providerID peer.ID ]

### ideation
* Is A already in verifiedProviders --> [ verifiedProviders := map[peer.ID]WalletInfo ] ?
####  Yes → Skip identity handshake.
#### No → Perform handshake, verify, store the result. 
#### Provider identity (PeerID ↔ Wallet) → verify once per provider (and cache while valid).
* so have to add after NewStream [ IdentityChallenge -> <- IdentityResponse ] before the first ChunkRequest
* if your protocol has a registration/discovery layer. In that case, you may not need to exchange the wallet address during every connection.
Provider registers
        │
        ▼
Smart Contract

stores

PeerID
Wallet
Stake
Reputation

Client

↓

Query contract

↓

Get

PeerID
Wallet
Price
Stake

↓

Connect to that PeerID

* Ethereum signature verification (ECDSA) --> This is the actual cryptographic primitive Ethereum wallets use to sign and verify messages.
* Challenge-response authentication	 --> This is the protocol pattern: client sends a nonce (challenge), provider signs it (response). It prevents replay attacks.

Client
   │
   ├── Generates random nonce
   │
   └── Sends challenge
          nonce
          peerID

↓

Provider

Signs

hash(nonce || peerID)

using Ethereum private key

↓

Provider returns

Wallet
Signature

↓

Client

Uses Ethereum ECDSA verification

↓

If valid

PeerID ↔ Wallet verified
