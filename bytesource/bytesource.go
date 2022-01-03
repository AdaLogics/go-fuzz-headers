package bytesource

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
)

type ByteSource struct {
	*bytes.Reader
	fallback rand.Source
}

// New returns a new ByteSource from a given slice of bytes.
func New(input []byte) *ByteSource {
	s := &ByteSource{
		Reader:   bytes.NewReader(input),
		fallback: rand.NewSource(0),
	}
	if len(input) > 0 {
		s.fallback = rand.NewSource(int64(s.consumeUint64()))
	}
	return s
}

func (s *ByteSource) Uint64() uint64 {
	// Return from input if it was not exhausted.
	if s.Len() > 0 {
		return s.consumeUint64()
	}

	// Input was exhausted, return random number from fallback (in this case fallback should not be
	// nil). Try first having a Uint64 output (Should work in current rand implementation),
	// otherwise return a conversion of Int63.
	if s64, ok := s.fallback.(rand.Source64); ok {
		return s64.Uint64()
	}
	return uint64(s.fallback.Int63())
}

func (s *ByteSource) Int63() int64 {
	return int64(s.Uint64() >> 1)
}

func (s *ByteSource) Seed(seed int64) {
	s.fallback = rand.NewSource(seed)
	s.Reader = bytes.NewReader(nil)
}

// consumeUint64 reads 8 bytes from the input and convert them to a uint64. It assumes that the the
// bytes reader is not empty.
func (s *ByteSource) consumeUint64() uint64 {
	var bytes [8]byte
	_, err := s.Read(bytes[:])
	if err != nil && err != io.EOF {
		panic("failed reading source") // Should not happen.
	}
	return binary.BigEndian.Uint64(bytes[:])
}
