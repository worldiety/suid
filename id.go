/*
 * Copyright 2020 Torben Schinke
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package suid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// The length in bytes for the secure id.
const Size = 32

// A SUID is a secure identifier with 256 bit of entropy.
type SUID [Size]byte

// IsEmpty returns  true, if the SUID contains also zeroes.
func (id SUID) IsEmpty() bool {
	return id == SUID{}
}

// New returns a new random SUID or panics if a secure generation is not possible.
// It is guaranteed that in no case an empty SUID is returned. crypto/rand is used.
// However it is not guaranteed that each call generates a unique SUID, but it is very
// unlikely.
func New() SUID {
	id := SUID{}

	for {
		n, err := rand.Read(id[:])
		if n != Size {
			panic("invalid entropy")
		}

		if err != nil {
			panic(err)
		}

		if !id.IsEmpty() {
			return id
		}
	}
}

// FromBytes expects that the slice has the correct Size of the SUID.
func FromBytes(b []byte) (SUID, error) {
	id := SUID{}

	if len(b) != Size {
		return id, fmt.Errorf("invalid slice length: expected %d but got %d", Size, len(b))
	}

	copy(id[:], b)

	return id, nil
}

// Parse tries to interpret the given string as SUID. It supports hex and base64 encodings and raw bytes
func Parse(s string) (SUID, error) {
	id := SUID{}

	if hex.EncodedLen(Size) == len(s) {
		data, err := hex.DecodeString(s)
		if err != nil {
			return id, fmt.Errorf("invalid hex format: %w", err)
		}

		copy(id[:], data)

		return id, nil
	}

	if base64.URLEncoding.EncodedLen(Size) == len(s) {
		data, err := base64.URLEncoding.DecodeString(s)
		if err != nil {
			return id, fmt.Errorf("failed to decode Secure SUID: %w", err)
		}

		if len(data) != Size {
			return id, fmt.Errorf("invalid Secure SUID: expected length %d but got %d", Size, len(data))
		}

		copy(id[:], data)

		return id, nil
	}

	if len(s) == Size {
		copy(id[:], s)
		return id, nil
	}

	return id, fmt.Errorf("invalid SUID format: '%s'", s)
}

// HexString returns a Hex variant
func (id SUID) HexString() string {
	return hex.EncodeToString(id[:])
}

// String returns the base64 encoding
func (id SUID) String() string {
	return base64.URLEncoding.EncodeToString(id[:])
}

// Must panics if err is not nil
func Must(suid SUID, err error) SUID {
	if err != nil {
		panic(err)
	}

	return suid
}
