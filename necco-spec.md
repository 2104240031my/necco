# necco: Naturally Encrypted Channel Control

## Abstract
This document defines properties common to all versions of the necco protocol, as well as specifications for version 1.

## 1. Overview
The "necco" is a communication protocol within or above the transport layer.
It is simple, lightweight, and encrypts and multiplexes streams.

## 2. Notational Conventions

## 2.1. Pseudo Language
This document uses the following Go-like notation for defining arithmetic procedures and data structures.

```
operator {
    := // assignment
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
}

primitive-type {
    uint8  //  8-bit unsigned integer
    uint16 // 16-bit unsigned integer
    uint32 // 32-bit unsigned integer
    uint64 // 64-bit unsigned integer
    int8   //  8-bit signed integer
    int16  // 16-bit signed integer
    int32  // 32-bit signed integer
    int64  // 64-bit signed integer
}

keyword {
    type
    struct
    enum
}

```

## 2.2. Byte and Bit Endian
In this document, octet sequences are represented in big endian (i.e., network byte order) format. Also, the 8 bits in one octet are expressed in little endian.

An example of representing a 32-bit unsigned integer is shown below.

```

u32   := 0x0f1e2d3c;
bytes := [4]uint8{ 0x0f, 0x1e, 0x2d, 0x3c };
bits  := [32]bit{ 
    0, 0, 0, 0, 1, 1, 1, 1, 
    0, 0, 0, 1, 1, 1, 1, 0, 
    0, 0, 1, 0, 1, 1, 0, 1, 
    0, 0, 1, 1, 1, 1, 0, 0
};

MSByte                 LSByte
+------+------+------+------+
| 0x0f | 0x1e | 0x2d | 0x3c |
+------+------+------+------+
:      :
:      :.........................
:                               :
MSBit                       LSBit
+---+---+---+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 1 | 1 | 1 | 1 |
+---+---+---+---+---+---+---+---+

```


## 3. Version-Independent Properties
The necco will have many versions in the future. Therefore, we define properties that are static and constant, independent of all versions.

## 3.1. Version Identifier
Every necco version has a "VersionID" that uniquely identifies the version.


```
type Version = uint64;

type VersionID = enum: uint64 {
    Null     := 0x0000000000000000,
    Reserved := 0xff00000000000000..0xffffffffffffffff
};

```

Version1 := 0x0000000000000001,