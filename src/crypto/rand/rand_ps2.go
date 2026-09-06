//go:build ps2

package rand

import (
	"encoding/binary"
	_ "unsafe"
)

// The PS2 has no hardware random number generator. Reader is a ChaCha20
// generator keyed from the runtime's entropy (bus timer, COP0 Count, the
// RTC offset), stirred again with it on every Read. Best-effort entropy,
// not a certified source.

//go:linkname runtimeRand runtime.rand
func runtimeRand() uint64

func init() {
	Reader = &reader{}
}

type reader struct {
	s *state
}

// The generator's state lives on the heap, allocated on first use: a
// global would be a compile-time object in the scanned globals, and its
// random words would pin heap objects as false roots.
type state struct {
	key     [8]uint32
	counter uint32
	block   [64]byte
	used    int // bytes of block handed out
}

func (r *state) stir() {
	for i := 0; i < 8; i += 2 {
		v := runtimeRand()
		r.key[i] ^= uint32(v)
		r.key[i+1] ^= uint32(v >> 32)
	}
	r.used = 64 // start a fresh block after a stir
}

func (g *reader) Read(b []byte) (int, error) {
	if g.s == nil {
		g.s = new(state)
	}
	r := g.s
	r.stir()
	for i := range b {
		if r.used == 64 {
			chacha20Block(&r.key, r.counter, &r.block)
			r.counter++
			r.used = 0
		}
		b[i] = r.block[r.used]
		r.used++
	}
	return len(b), nil
}

func quarterRound(x *[16]uint32, a, b, c, d int) {
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = x[d]<<16 | x[d]>>16
	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = x[b]<<12 | x[b]>>20
	x[a] += x[b]
	x[d] ^= x[a]
	x[d] = x[d]<<8 | x[d]>>24
	x[c] += x[d]
	x[b] ^= x[c]
	x[b] = x[b]<<7 | x[b]>>25
}

// chacha20Block writes the ChaCha20 keystream block for key/counter
// (nonce zero) into out.
func chacha20Block(key *[8]uint32, counter uint32, out *[64]byte) {
	var x [16]uint32
	x[0], x[1], x[2], x[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	copy(x[4:12], key[:])
	x[12] = counter
	s := x
	for i := 0; i < 10; i++ {
		quarterRound(&x, 0, 4, 8, 12)
		quarterRound(&x, 1, 5, 9, 13)
		quarterRound(&x, 2, 6, 10, 14)
		quarterRound(&x, 3, 7, 11, 15)
		quarterRound(&x, 0, 5, 10, 15)
		quarterRound(&x, 1, 6, 11, 12)
		quarterRound(&x, 2, 7, 8, 13)
		quarterRound(&x, 3, 4, 9, 14)
	}
	for i := range x {
		binary.LittleEndian.PutUint32(out[i*4:], x[i]+s[i])
	}
}
