# SGX Secure Database

An end-to-end secure database solution where both client and server run inside Intel SGX enclaves, providing complete protection for database operations and data transmission.

## Overview

This project implements a complete database system with end-to-end protection using Intel Software Guard Extensions (SGX). Both the database client and server operate within SGX enclaves, ensuring data confidentiality and integrity throughout the entire workflow - from client queries to server-side processing and storage.

## Key Features

- End-to-end enclave protection:
  - Client-side enclave for secure query generation
  - Server-side enclave for protected query processing
  - Secure channel between client and server enclaves
  - Protected data storage and processing

- Security guarantees:
  - Data confidentiality during transit and processing
  - Query integrity protection
  - Secure key exchange between enclaves
  - Protected memory operations

## Architecture

### Client Side
- SGX enclave for query handling
- Secure connection management
- Local key management
- Query encryption

### Server Side
- Database engine running in SGX enclave
- Secure storage management
- Protected query processing
- Key management and distribution

### Communication
- Enclave-to-enclave secure channel
- Attestation between client and server
- Protected data transmission

[Build and Usage instructions to be added]

## License

This project is licensed under GNU General Public License v3.0 (GPL-3.0)
