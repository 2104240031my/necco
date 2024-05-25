# necco: Nimble and Evolvable Channel Control

## Abstract
This document defines properties common to all versions of the necco protocol, as well as specifications for version 1.

## 1. Overview
"necco" (Nimble and Evolvable Channel Control) is a simple, lightweight, secure, and evolvable communication protocol that encrypts transmission channels within or above the transport layer.

## 2. Notational Conventions

## 2.1. Pseudo Language
This document uses the following Rust-like notation for defining arithmetic procedures and data structures.

```
operator {
    =  // assignment
    +  // addition
    -  // subtraction
    *  // multiplication
    /  // division
    %  // modulo operation
    << // logical left shift
    >> // logical right shift
    |  // bitwise OR
    &  // bitwise AND
    ^  // bitwise XOR (exclusive OR)
    !  // bitwise NOT
    || // logical OR
    && // logical AND
    !  // logical NOT
}

scalar-type {
    u8   //  8-bit unsigned integer
    u16  // 16-bit unsigned integer
    u32  // 32-bit unsigned integer
    u64  // 64-bit unsigned integer
    i8   //  8-bit signed integer
    i16  // 16-bit signed integer
    i32  // 32-bit signed integer
    i64  // 64-bit signed integer
    vl64 // 64-bit unsigned integer that encode to QUIC variable-length integer in transmission
}

keyword {
    type
    struct
    enum
    space
}

```

## 2.2. Byte and Bit Endian
In this document, octet sequences are represented in big endian (i.e., network byte order) format. Also, the 8 bits in one octet are expressed in little endian.
An example of representing a 32-bit unsigned integer is shown below.

## 3. Version-Independent Properties
The necco will have many versions in the future. Therefore, we define properties that are static and constant, independent of all versions.

## 3.1. Design Concept
- lightweight
    - minimize packet size as possible（lightweightness of data size）
    - make it as simple as possible（lightweightness of operation）
- secure
    - design protocol securely
    - secure cryptographically
    - secure implementability
- evolvable
    - has flexibility to update protocols without being bound by the requirements of past versions

## 3.2. Version Identifier
Every necco version has a "VersionID" that uniquely identifies the version.

```
enum VersionID: vl64 {
    Null         = vl64::u8(0x00),
    Version_1    = vl64::u8(0x01),
    Reserved1Min = vl64::u64(0xff00000000000000),
    Reserved1Max = vl64::u64(0xffffffffffffffff),
};
```


## 3.2. Channel

```
enum Phase: u8 {
    Null    = 0x00,
    PreMew  = 0x01, // pre synchronization phase
    Mew     = 0x02, // synchronization phase
    Walk    = 0x03, // application data exchanging phase
};

enum AeadAlgorithm: vl64 {
    Null         = vl64::u8(0x00),
    AES_128_CCM  = vl64::u8(0x01),
    AES_192_CCM  = vl64::u8(0x02),
    AES_256_CCM  = vl64::u8(0x03),
    PrivUseMin   = vl64::u64(0xfe00000000000000),
    PrivUseMax   = vl64::u64(0xfeffffffffffffff),
    Reserved1Min = vl64::u64(0xff00000000000000),
    Reserved1Max = vl64::u64(0xffffffffffffffff),
};

enum HashAlgorithm: vl64 {
    Null         = vl64::u8(0x00),
    SHA3_256     = vl64::u8(0x01),
    SHA3_384     = vl64::u8(0x02),
    SHA3_512     = vl64::u8(0x03),
    PrivUseMin   = vl64::u64(0xfe00000000000000),
    PrivUseMax   = vl64::u64(0xfeffffffffffffff),
    Reserved1Min = vl64::u64(0xff00000000000000),
    Reserved1Max = vl64::u64(0xffffffffffffffff),
};

enum KeyShareAlgorithm: vl64 {
    Null         = vl64::u8(0x00),
    X25519       = vl64::u8(0x01),
    PrivUseMin   = vl64::u64(0xfe00000000000000),
    PrivUseMax   = vl64::u64(0xfeffffffffffffff),
    Reserved1Min = vl64::u64(0xff00000000000000),
    Reserved1Max = vl64::u64(0xffffffffffffffff),
};

enum AuthAlgorithm: vl64 {
    Null         = vl64::u8(0x00),
    PrivUseMin   = vl64::u64(0xfe00000000000000),
    PrivUseMax   = vl64::u64(0xfeffffffffffffff),
    Reserved1Min = vl64::u64(0xff00000000000000),
    Reserved1Max = vl64::u64(0xffffffffffffffff),
};

struct PreMewPacket {
    pkt_phase: Phase = Phase::Mew,

    // ... and, if role is server,
    if role == Role::Server {
        ver_list:       [VersionID],
        aead_list:      [AeadAlgorithm],
        hash_list:      [HashAlgorithm],
        kx_list:        [KeyShareAlgorithm],
        auth_list:      [AuthAlgorithm],
        kx_pubkey_list: [KeySharePubkey],
        chan_id:        [u8], // Array length is variable length encoding
        sync_cookie:    [u8],
    }
};

struct MewPacket {
    pkt_phase: Phase = Phase::Mew,
    version:   VersionID,
    chan_id:   [u8],
    aead:      AeadAlgorithm,
    hash:      HashAlgorithm,
    kx:        KeyShareAlgorithm,
    auth:      AuthAlgorithm,

    // ... and, if role is client,
    if role == Role::Client {
        sync_cookie: [u8],
    }
};

struct WalkPacket {
    pkt_phase: Phase = Phase::Walk,
    chan_id:   [u8],
    pkt_seq:   vl64,
};

```