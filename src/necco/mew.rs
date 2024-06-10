
enum MewType {
    Dial  = 0x00, // address validation
    Hello = 0x01, // handshake (connecting)
    Talk  = 0x02, // application data exchanging
    Bye   = 0x03, // handshake (disconnecting)
};

struct DialMew {
    mew_type: MewType = MewType::Dial,
    pad:      [u8]
};

struct DialMewReply {
    mew_type:      MewType = MewType::Dial,
    dialing_token: [u8],
    version_list:  [VersionID]
};

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