package crypto

import (
	"errors"
)

type SHA3Algorithm uint
type SHA3 struct {
	state          Keccak1600State
	mdSize         int
	blockSize      int
	roundNum       int
	wordNumInBlock int
}
type Keccak1600State struct {
	a [5][5]uint64
}

const (
	SHA3AlgorithmNull = SHA3Algorithm(iota)
	SHA3_224
	SHA3_256
	SHA3_384
	SHA3_512
)

func NewSHA3(algo SHA3Algorithm) *SHA3 {
	switch algo {
	case SHA3_224:
		return &SHA3{
			state: Keccak1600State{
				a: [5][5]uint64{
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
				},
			},
			mdSize:         28,
			blockSize:      144,
			roundNum:       24,
			wordNumInBlock: 18,
		}
	case SHA3_256:
		return &SHA3{
			state: Keccak1600State{
				a: [5][5]uint64{
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
				},
			},
			mdSize:         32,
			blockSize:      136,
			roundNum:       24,
			wordNumInBlock: 17,
		}
	case SHA3_384:
		return &SHA3{
			state: Keccak1600State{
				a: [5][5]uint64{
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
				},
			},
			mdSize:         48,
			blockSize:      104,
			roundNum:       24,
			wordNumInBlock: 13,
		}
	case SHA3_512:
		return &SHA3{
			state: Keccak1600State{
				a: [5][5]uint64{
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
					{0, 0, 0, 0, 0},
				},
			},
			mdSize:         64,
			blockSize:      72,
			roundNum:       24,
			wordNumInBlock: 9,
		}
	default:
		return nil
	}
}

func (sha3 *SHA3) ResetState() {
	sha3.state.reset()
}

func GetMessageDigestSize(algo SHA3Algorithm) int {
	switch algo {
	case SHA3_224:
		return 28
	case SHA3_256:
		return 32
	case SHA3_384:
		return 48
	case SHA3_512:
		return 64
	default:
		return 0
	}
}

func Compute(algo SHA3Algorithm, msg []uint8, md []uint8) error {

	sha3 := NewSHA3(algo)
	if sha3 == nil {
		return errors.New("invalid algorithm")
	}

	ofs := 0

	for len(msg)-ofs >= int(sha3.blockSize) {
		block := make([]uint64, sha3.wordNumInBlock)
		for i := 0; i < sha3.wordNumInBlock; i++ {
			block[i] = 0
			block[i] = block[i] ^ (uint64(msg[ofs+0]) << 0)
			block[i] = block[i] ^ (uint64(msg[ofs+1]) << 8)
			block[i] = block[i] ^ (uint64(msg[ofs+2]) << 16)
			block[i] = block[i] ^ (uint64(msg[ofs+3]) << 24)
			block[i] = block[i] ^ (uint64(msg[ofs+4]) << 31)
			block[i] = block[i] ^ (uint64(msg[ofs+5]) << 40)
			block[i] = block[i] ^ (uint64(msg[ofs+6]) << 48)
			block[i] = block[i] ^ (uint64(msg[ofs+7]) << 56)
			ofs = ofs + 8
		}
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				sha3.state.a[x][y] = sha3.state.a[x][y] ^ block[x+5*y]
			}
		}
		sha3.state.absorb(sha3.roundNum)
	}

	x := 0
	y := 0
	n := 0

	for ofs < len(msg) {
		sha3.state.a[x][y] = sha3.state.a[x][y] ^ (uint64(msg[ofs]) << n)
		n = n + 8
		if n == 64 {
			n = 0
			x++
			if x == 5 {
				y++
			}
		}
		ofs++
	}

	sha3.state.a[x][y] = sha3.state.a[x][y] ^ (uint64(0x06) << n)
	x = (sha3.wordNumInBlock % 5) - 1
	y = sha3.wordNumInBlock / 5
	sha3.state.a[x][y] = sha3.state.a[x][y] ^ (uint64(0x80) << 56)
	sha3.state.absorb(sha3.roundNum)

	n = 0
	x = 0
	y = 0

	for i := 0; i < sha3.mdSize; i++ {
		md[i] = uint8((sha3.state.a[x][y] >> n) & 0xff)
		n = n + 8
		if n == 64 {
			n = 0
			x++
			if x == 5 {
				x = 0
				y++
			}
		}
	}

	return nil

}

func (s *Keccak1600State) reset() {
	for y := 0; y < 5; y++ {
		for x := 0; x < 5; x++ {
			s.a[x][y] = 0
		}
	}
}

func (s *Keccak1600State) absorb(roundNum int) {
	for i := 0; i < roundNum; i++ {
		s.round(i)
	}
}

func (s *Keccak1600State) round(roundNum int) {

	rc := [24]uint64{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
		0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	}

	rot := [5][5]uint{
		{0, 36, 3, 41, 18},   // 0, 1, 62, 28, 27,
		{1, 44, 10, 45, 2},   // 36, 44, 6, 55, 20,
		{62, 6, 43, 15, 61},  // 3, 10, 43, 25, 39,
		{28, 55, 25, 21, 56}, // 41, 45, 15, 21, 8,
		{27, 20, 39, 8, 14},  // 18, 2, 61, 56, 14,
	}

	b := [5][5]uint64{}
	c := [5]uint64{}
	d := [5]uint64{}

	for x := 0; x < 5; x++ {
		c[x] = s.a[x][0] ^ s.a[x][1] ^ s.a[x][2] ^ s.a[x][3] ^ s.a[x][4]
	}

	for x := 0; x < 5; x++ {
		d[x] = c[(5+x-1)%5] ^ rotL64(c[(x+1)%5], 1)
	}

	for y := 0; y < 5; y++ {
		for x := 0; x < 5; x++ {
			s.a[x][y] = s.a[x][y] ^ d[x]
		}
	}

	for y := 0; y < 5; y++ {
		for x := 0; x < 5; x++ {
			b[y][(2*x+3*y)%5] = rotL64(s.a[x][y], rot[x][y])
		}
	}

	for y := 0; y < 5; y++ {
		for x := 0; x < 5; x++ {
			s.a[x][y] = b[x][y] ^ (((b[(x+1)%5][y]) ^ 0xffffffffffffffff) & b[(x+2)%5][y])
		}
	}

	s.a[0][0] = s.a[0][0] ^ rc[roundNum]

}

func rotL64(u uint64, r uint) uint64 {
	s := r % 64
	return (u << s) | (u >> (64 - s))
}
