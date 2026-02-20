# Reflex Protocol Implementation

**Student Name:** Arshia Dehghan & Abolfazl Moslemi
**Student ID:** 401100382 & 401100506
**Project Status:** 100% Complete + Advanced Bonus

### Implementation Summary
I have successfully implemented the Reflex protocol for Xray-Core, designed to be undetectable by active probing and statistical analysis.

### Core Features (100% Implemented)
1.  **Structure (Step 1):** Defined `config.proto` and registered via `infra/conf/xray.go`.
2.  **Handshake (Step 2):** Implemented in `inbound.go`. Uses Magic Number check and X25519 key exchange simulation.
3.  **Encryption (Step 3):** ChaCha20-Poly1305 implemented in `Session` struct.
4.  **Fallback (Step 4):** Uses `bufio.Peek` to distinguish Reflex traffic from HTTP. Validated with browser test.
5.  **Traffic Morphing (Step 5 Bonus):** Added `YouTubeProfile` to `inbound.go`. The protocol automatically pads packets to 1400 bytes and adds jitter to mimic video streaming traffic.

### How to Run
1.  **Build:**
    ```bash
    cd xray-core && go build -o xray.exe ./main
    ```
2.  **Run:**
    ```bash
    .\xray.exe -config config.json
    ```

### Testing
Tests are located in `proxy/reflex/inbound/inbound_test.go`.
Run tests via: 
```bash
go test -v ./proxy/reflex/inbound/...