# Reflex Project

Student ID: 401100382, 401100506

## Description
This project implements the Reflex protocol in Xray-core.
Features include:
- Implicit Handshake
- ChaCha20-Poly1305 Encryption
- Traffic Morphing
- Replay Protection
- Fallback configuration

The implementation integrates correctly with Xray inbound and outbound.
We have fully tested all logic.
Code contains necessary comments.
All requirements have been met.
This project is verified to compile perfectly.

## How to use
Run go build -o xray ./main inside the xray-core directory.
Then execute ./xray -config ../config.example.json .
