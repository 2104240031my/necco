# necco: Nimble and Elastic Channel Control

## Abstract
This document defines properties common to all versions of the necco protocol, as well as specifications for version 1.

## 1. Overview
"necco" (Nimble and Elastic Channel Control) is a simple, lightweight, secure, elastic, and evolvable communication protocol that encrypts transmission channels within or above the transport layer.

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
    u8     //  8-bit unsigned integer
    u16    // 16-bit unsigned integer
    u32    // 32-bit unsigned integer
    u64    // 64-bit unsigned integer
    i8     //  8-bit signed integer
    i16    // 16-bit signed integer
    i32    // 32-bit signed integer
    i64    // 64-bit signed integer
    vl64   // 64-bit unsigned integer that encode to QUIC variable-length integer in transmission
    [T; N] // array of type T with N elements
    [T]    // array of type T with opaque length; the length is encoded to vl64 type and prepended to the array
}

keyword {
    type
    struct
    enum
    fn
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
- elastic
    - the number and scale of required functions can be flexibly expanded and contracted (sometimes rich, sometimes compact)
- evolvable
    - has flexibility to update protocols without being bound by the requirements of past versions


## 3.2. Definition Space
In Mew, all versions share one definition space.

## 3.5. Version Identifier
Every necco version has a "VersionID" that uniquely identifies the version.

```
enum VersionID: vl64 {
    Null       = vl64::u8(0x00),
    Version_1  = vl64::u8(0x01),
    Resrvd1Min = vl64::u64(0xff00000000000000),
    Resrvd1Max = vl64::u64(0xffffffffffffffff),
};
```

## 3.4. Channel
"Channel" is the connection in necco (often abbreviated as "chan" or "necco chan").


## 3.5. Mew
"Mew" is the basic transmission unit of necco, similar to a datagram, packet, segment, etc.
All Mew follow byte boundaries.

## 3.5.1. Call and Response
necco is a partially-stateless communication protocol.
Specifically, each Mew has a counterpart, and one pair is independent from the other.

## 3.5.2. Types of Mew
Mew has several types, and each type identified by MewType value.
All Mews MUST have NewType type field in its first field.

```
enum MewType: u8 {
    Dial  = 0x00, // address validation
    Hello = 0x01, // handshake (connecting)
    Talk  = 0x02, // application data exchanging
    Bye   = 0x03, // handshake (disconnecting)
};

struct Mew {
    mew_type: MewType,

    // followed by type-specific fields ...
};
```

## 3.5.2.1. Dial Mew

```
struct DialMew {
    mew_type: MewType = MewType::Dial,
    pad:      [u8]
};

struct DialMewReply {
    mew_type:      MewType = MewType::Dial,
    dialing_token: [u8],
    version_list:  [VersionID]
};
```

## 3.5.2.2. Hello Mew
```
struct HelloMew {
    mew_type:      MewType = MewType::Hello,
    src_chan_id:   [u8],
    dst_chan_id:   [u8],
    dialing_token: [u8],
    version:       VersionID,
    aead_list:     [AeadAlgorithm],
    hash_list:     [HashAlgorithm],
    key_ex_list:   [KeyShareAlgorithm],
    peer_au_list:  [PeerAuthAlgorithm]
};

struct HelloMewReply {
    mew_type:    MewType = MewType::Hello,
    src_chan_id: [u8],
    dst_chan_id: [u8],
    aead:        AeadAlgorithm,
    hash:        HashAlgorithm,
    key_ex:      KeyShareAlgorithm,
    peer_au:     PeerAuthAlgorithm
};
```

## 3.5.2.3. Talk Mew
```
struct TalkMew {
    mew_type:    MewType = MewType::Talk,
    dst_chan_id: [u8],
    call_id:     vl64
};

struct TalkMewReply { // works like ACK
    mew_type:    MewType = MewType::Talk,
    dst_chan_id: [u8],
    call_id:     vl64
};
```

## 3.5.2.4. Bye Mew
```
struct ByeMew {
    mew_type: MewType = MewType::Bye,
    chan_id:  [u8],
    call_id:  vl64
};

struct ByeMewReply {
    mew_type: MewType = MewType::Bye,
    chan_id:  [u8],
    call_id:  vl64
};
```






## Cipher Suite

```
enum AeadAlgorithm: vl64 {
    Null        = vl64::u8(0x00),
    AES_128_CCM = vl64::u8(0x01),
    AES_192_CCM = vl64::u8(0x02),
    AES_256_CCM = vl64::u8(0x03),
    PrivUseMin  = vl64::u64(0xfe00000000000000),
    PrivUseMax  = vl64::u64(0xfeffffffffffffff),
    Resrvd1Min  = vl64::u64(0xff00000000000000),
    Resrvd1Max  = vl64::u64(0xffffffffffffffff),
};

enum HashAlgorithm: vl64 {
    Null       = vl64::u8(0x00),
    SHA_256    = vl64::u8(0x01),
    SHA_384    = vl64::u8(0x02),
    SHA_512    = vl64::u8(0x03),
    PrivUseMin = vl64::u64(0xfe00000000000000),
    PrivUseMax = vl64::u64(0xfeffffffffffffff),
    Resrvd1Min = vl64::u64(0xff00000000000000),
    Resrvd1Max = vl64::u64(0xffffffffffffffff),
};

enum KeyShareAlgorithm: vl64 {
    Null       = vl64::u8(0x00),
    PSK        = vl64::u8(0x01),
    X25519     = vl64::u8(0x02),
    PrivUseMin = vl64::u64(0xfe00000000000000),
    PrivUseMax = vl64::u64(0xfeffffffffffffff),
    Resrvd1Min = vl64::u64(0xff00000000000000),
    Resrvd1Max = vl64::u64(0xffffffffffffffff),
};

enum PeerAuthAlgorithm: vl64 {
    Null       = vl64::u8(0x00),
    PSK        = vl64::u8(0x01),
    PrivUseMin = vl64::u64(0xfe00000000000000),
    PrivUseMax = vl64::u64(0xfeffffffffffffff),
    Resrvd1Min = vl64::u64(0xff00000000000000),
    Resrvd1Max = vl64::u64(0xffffffffffffffff),
};

```