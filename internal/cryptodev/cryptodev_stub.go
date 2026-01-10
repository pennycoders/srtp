// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !linux || !arm

// Package cryptodev provides hardware-accelerated cryptographic operations.
// This stub file is used on platforms without hardware crypto support.
package cryptodev

import "errors"

// ErrNotAvailable is returned when hardware crypto is not available.
var ErrNotAvailable = errors.New("cryptodev: hardware crypto not available on this platform")

// Available returns true if hardware crypto is available.
// Always returns false on non-ARM Linux platforms.
func Available() bool {
	return false
}

// Stats returns hardware crypto usage statistics.
type Stats struct {
	SessionsCreated uint64
	SessionsClosed  uint64
	OpsPerformed    uint64
	OpsErrors       uint64
	HasRockchipCTR  bool
	HasRockchipHMAC bool
}

// GetStats returns current hardware crypto statistics.
// Returns zero values on non-ARM Linux platforms.
func GetStats() Stats {
	return Stats{}
}

// CTRCipher provides hardware-accelerated AES-CTR encryption.
type CTRCipher struct{}

// NewCTRCipher creates a hardware AES-CTR cipher.
// Always returns ErrNotAvailable on non-ARM Linux platforms.
func NewCTRCipher(key []byte) (*CTRCipher, error) {
	return nil, ErrNotAvailable
}

// XORKeyStream encrypts src into dst using the given IV.
func (c *CTRCipher) XORKeyStream(dst, src, iv []byte) error {
	return ErrNotAvailable
}

// Close releases the hardware session.
func (c *CTRCipher) Close() error {
	return nil
}

// HMACSHA1 provides hardware-accelerated HMAC-SHA1.
type HMACSHA1 struct{}

// NewHMACSHA1 creates a hardware HMAC-SHA1 instance.
// Always returns ErrNotAvailable on non-ARM Linux platforms.
func NewHMACSHA1(key []byte) (*HMACSHA1, error) {
	return nil, ErrNotAvailable
}

// Sum computes HMAC-SHA1 of data and writes the result to dst.
func (h *HMACSHA1) Sum(dst, data []byte) (int, error) {
	return 0, ErrNotAvailable
}

// Close releases the hardware session.
func (h *HMACSHA1) Close() error {
	return nil
}
