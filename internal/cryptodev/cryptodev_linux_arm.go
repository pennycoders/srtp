// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build linux && arm

// Package cryptodev provides hardware-accelerated cryptographic operations
// via Linux cryptodev (/dev/crypto) for ARM platforms with hardware crypto
// engines.
//
// This package automatically detects available hardware acceleration:
//   - Rockchip crypto engine (RV1106, RK3288, RK3399, RK3588, etc.)
//   - Standard cryptodev implementations
//
// Falls back gracefully if hardware is unavailable.
package cryptodev

import (
	"bufio"
	"errors"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// ErrNotAvailable is returned when hardware crypto is not available.
var ErrNotAvailable = errors.New("cryptodev: hardware crypto not available")

// Cipher IDs for cryptodev.
// Standard IDs are from cryptodev-linux; Rockchip extends these with vendor-specific IDs.
const (
	// Standard cryptodev cipher IDs
	cryptoAESCTR   = 21 // Standard AES-CTR
	cryptoSHA1HMAC = 7  // Standard HMAC-SHA1

	// Rockchip-specific cipher IDs (starting at 150)
	cryptoRKAESCTR   = 174 // Rockchip AES-CTR
	cryptoRKSHA1HMAC = 189 // Rockchip HMAC-SHA1
)

// Standard cryptodev ioctl commands for 32-bit ARM.
const (
	ciocgsession = 0xc01c6366 // Create session
	ciocfsession = 0x40046367 // Free session
	cioccrypt    = 0xc0286364 // Perform crypto operation
)

// Operation types.
const (
	copEncrypt = 0
	copDecrypt = 1
)

// Flags for crypto operations.
const (
	copFlagNone  = 0
	copFlagFinal = 1 << 1 // Finalize hash operation
)

// Hardware detection state.
var (
	detectOnce       sync.Once
	hasRockchipCTR   bool
	hasRockchipHMAC  bool
	hasStandardCTR   bool
	hasStandardHMAC  bool
	hardwareDetected bool

	cryptodev     *os.File
	cryptodevOnce sync.Once
	cryptodevErr  error

	// Statistics for monitoring
	sessionsCreated atomic.Uint64
	sessionsClosed  atomic.Uint64
	opsPerformed    atomic.Uint64
	opsErrors       atomic.Uint64
)

// sessionOp is the structure for creating a crypto session.
// Must match struct session_op in cryptodev.h exactly.
type sessionOp struct {
	cipher    uint32
	mac       uint32
	keylen    uint32
	key       unsafe.Pointer
	mackeylen uint32
	mackey    unsafe.Pointer
	ses       uint32
}

// cryptOp is the structure for cipher/hash operations.
// Must match struct crypt_op in cryptodev.h exactly.
type cryptOp struct {
	ses   uint32
	op    uint16
	flags uint16
	len   uint32
	src   unsafe.Pointer
	dst   unsafe.Pointer
	mac   unsafe.Pointer
	iv    unsafe.Pointer
}

// detectHardware probes /proc/crypto to determine available hardware acceleration.
func detectHardware() {
	detectOnce.Do(func() {
		file, err := os.Open("/proc/crypto")
		if err != nil {
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var currentName, currentDriver string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if strings.HasPrefix(line, "name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					currentName = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "driver") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					currentDriver = strings.TrimSpace(parts[1])
				}

				// Check for hardware-accelerated algorithms
				isRockchip := strings.HasSuffix(currentDriver, "-rk")

				switch currentName {
				case "ctr(aes)":
					if isRockchip {
						hasRockchipCTR = true
					}
					hasStandardCTR = true
				case "hmac(sha1)":
					if isRockchip {
						hasRockchipHMAC = true
					}
					hasStandardHMAC = true
				}
			}
		}

		// Hardware is available if we have both CTR and HMAC
		hardwareDetected = (hasRockchipCTR || hasStandardCTR) && (hasRockchipHMAC || hasStandardHMAC)
	})
}

func getCryptodev() (*os.File, error) {
	cryptodevOnce.Do(func() {
		cryptodev, cryptodevErr = os.OpenFile("/dev/crypto", os.O_RDWR|syscall.O_CLOEXEC, 0)
	})
	return cryptodev, cryptodevErr
}

func ioctl(fd uintptr, op uintptr, data unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, op, uintptr(data))
	if errno != 0 {
		return errno
	}
	return nil
}

// Available returns true if hardware crypto is available on this system.
// This performs a one-time detection by probing /proc/crypto.
func Available() bool {
	detectHardware()
	if !hardwareDetected {
		return false
	}
	_, err := getCryptodev()
	return err == nil
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
func GetStats() Stats {
	detectHardware()
	return Stats{
		SessionsCreated: sessionsCreated.Load(),
		SessionsClosed:  sessionsClosed.Load(),
		OpsPerformed:    opsPerformed.Load(),
		OpsErrors:       opsErrors.Load(),
		HasRockchipCTR:  hasRockchipCTR,
		HasRockchipHMAC: hasRockchipHMAC,
	}
}

// CTRCipher provides hardware-accelerated AES-CTR encryption.
// It is safe for concurrent use.
type CTRCipher struct {
	fd      uintptr
	session uint32
	closed  atomic.Bool
	mu      sync.Mutex
}

// NewCTRCipher creates a hardware AES-CTR cipher.
// Returns ErrNotAvailable if hardware crypto is not available.
// The caller must call Close() when done to release hardware resources.
func NewCTRCipher(key []byte) (*CTRCipher, error) {
	if !Available() {
		return nil, ErrNotAvailable
	}

	handle, err := getCryptodev()
	if err != nil {
		return nil, err
	}
	fd := handle.Fd()

	// Determine which cipher ID to use
	cipherID := uint32(cryptoAESCTR)
	if hasRockchipCTR {
		cipherID = cryptoRKAESCTR
	}

	// Keep key alive during session creation
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	sess := &sessionOp{
		cipher: cipherID,
		keylen: uint32(len(keyCopy)),
		key:    unsafe.Pointer(&keyCopy[0]),
	}

	if err := ioctl(fd, ciocgsession, unsafe.Pointer(sess)); err != nil {
		// Try fallback to standard ID if Rockchip failed
		if cipherID == cryptoRKAESCTR && hasStandardCTR {
			sess.cipher = cryptoAESCTR
			if err2 := ioctl(fd, ciocgsession, unsafe.Pointer(sess)); err2 != nil {
				return nil, err2
			}
		} else {
			return nil, err
		}
	}

	sessionsCreated.Add(1)

	c := &CTRCipher{
		fd:      fd,
		session: sess.ses,
	}

	// Set finalizer as safety net for leaked sessions
	runtime.SetFinalizer(c, func(c *CTRCipher) {
		if !c.closed.Load() {
			_ = c.Close()
		}
	})

	return c, nil
}

// XORKeyStream encrypts/decrypts src into dst using the given IV.
// dst and src may be the same slice (in-place operation).
// The IV must be exactly 16 bytes (AES block size).
func (c *CTRCipher) XORKeyStream(dst, src, iv []byte) error {
	if len(src) == 0 {
		return nil
	}
	if c.closed.Load() {
		return errors.New("cryptodev: cipher closed")
	}
	if len(iv) != 16 {
		return errors.New("cryptodev: IV must be 16 bytes")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring lock
	if c.closed.Load() {
		return errors.New("cryptodev: cipher closed")
	}

	// Make IV copy to ensure memory safety during syscall
	ivCopy := make([]byte, 16)
	copy(ivCopy, iv)

	op := &cryptOp{
		ses:   c.session,
		op:    copEncrypt, // CTR mode: encrypt == decrypt
		flags: copFlagNone,
		len:   uint32(len(src)),
		src:   unsafe.Pointer(&src[0]),
		dst:   unsafe.Pointer(&dst[0]),
		iv:    unsafe.Pointer(&ivCopy[0]),
	}

	err := ioctl(c.fd, cioccrypt, unsafe.Pointer(op))

	// Keep slices alive until ioctl completes
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(ivCopy)

	if err != nil {
		opsErrors.Add(1)
		return err
	}

	opsPerformed.Add(1)
	return nil
}

// Close releases the hardware session.
// It is safe to call Close multiple times.
func (c *CTRCipher) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	runtime.SetFinalizer(c, nil)

	if c.session != 0 {
		err := ioctl(c.fd, ciocfsession, unsafe.Pointer(&c.session))
		c.session = 0
		sessionsClosed.Add(1)
		return err
	}
	return nil
}

// HMACSHA1 provides hardware-accelerated HMAC-SHA1.
// It is safe for concurrent use.
type HMACSHA1 struct {
	fd      uintptr
	session uint32
	closed  atomic.Bool
	mu      sync.Mutex
}

// NewHMACSHA1 creates a hardware HMAC-SHA1 instance.
// Returns ErrNotAvailable if hardware crypto is not available.
// The caller must call Close() when done to release hardware resources.
func NewHMACSHA1(key []byte) (*HMACSHA1, error) {
	if !Available() {
		return nil, ErrNotAvailable
	}

	handle, err := getCryptodev()
	if err != nil {
		return nil, err
	}
	fd := handle.Fd()

	// Determine which MAC ID to use
	macID := uint32(cryptoSHA1HMAC)
	if hasRockchipHMAC {
		macID = cryptoRKSHA1HMAC
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	sess := &sessionOp{
		mac:       macID,
		mackeylen: uint32(len(keyCopy)),
		mackey:    unsafe.Pointer(&keyCopy[0]),
	}

	if err := ioctl(fd, ciocgsession, unsafe.Pointer(sess)); err != nil {
		// Try fallback to standard ID if Rockchip failed
		if macID == cryptoRKSHA1HMAC && hasStandardHMAC {
			sess.mac = cryptoSHA1HMAC
			if err2 := ioctl(fd, ciocgsession, unsafe.Pointer(sess)); err2 != nil {
				return nil, err2
			}
		} else {
			return nil, err
		}
	}

	sessionsCreated.Add(1)

	h := &HMACSHA1{
		fd:      fd,
		session: sess.ses,
	}

	runtime.SetFinalizer(h, func(h *HMACSHA1) {
		if !h.closed.Load() {
			_ = h.Close()
		}
	})

	return h, nil
}

// Sum computes HMAC-SHA1 of data and writes the 20-byte result to dst.
// dst must have capacity for at least 20 bytes.
// Returns the number of bytes written (always 20 on success).
func (h *HMACSHA1) Sum(dst, data []byte) (int, error) {
	if len(dst) < 20 {
		return 0, errors.New("cryptodev: dst too small for HMAC-SHA1 (need 20 bytes)")
	}
	if h.closed.Load() {
		return 0, errors.New("cryptodev: HMAC closed")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed.Load() {
		return 0, errors.New("cryptodev: HMAC closed")
	}

	op := &cryptOp{
		ses:   h.session,
		flags: copFlagFinal,
		len:   uint32(len(data)),
		mac:   unsafe.Pointer(&dst[0]),
	}

	if len(data) > 0 {
		op.src = unsafe.Pointer(&data[0])
	}

	err := ioctl(h.fd, cioccrypt, unsafe.Pointer(op))

	runtime.KeepAlive(data)
	runtime.KeepAlive(dst)

	if err != nil {
		opsErrors.Add(1)
		return 0, err
	}

	opsPerformed.Add(1)
	return 20, nil
}

// Close releases the hardware session.
// It is safe to call Close multiple times.
func (h *HMACSHA1) Close() error {
	if h.closed.Swap(true) {
		return nil // Already closed
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	runtime.SetFinalizer(h, nil)

	if h.session != 0 {
		err := ioctl(h.fd, ciocfsession, unsafe.Pointer(&h.session))
		h.session = 0
		sessionsClosed.Add(1)
		return err
	}
	return nil
}
