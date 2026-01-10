// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"crypto/subtle"
	"encoding/binary"
	"io"
	"sync"

	"github.com/pion/rtp"
	"github.com/pion/srtp/v3/internal/cryptodev"
)

// Buffer pool for HMAC input to avoid allocations in hot path.
// Most SRTP packets are under 1500 bytes (MTU).
var hmacInputPool = sync.Pool{
	New: func() any {
		// Allocate enough for typical MTU + ROC
		buf := make([]byte, 0, 1600)
		return &buf
	},
}

// srtpCipherAesCmHmacSha1HW is a hardware-accelerated implementation of
// AES-CM-HMAC-SHA1 for SRTP. It uses Linux cryptodev on ARM platforms
// with hardware crypto engines (e.g., Rockchip RV1106).
//
// This cipher automatically releases hardware resources when Close() is called.
// If Close() is not called, resources are released via finalizer during GC.
type srtpCipherAesCmHmacSha1HW struct {
	protectionProfileWithArgs

	srtpCTR         *cryptodev.CTRCipher
	srtpHMAC        *cryptodev.HMACSHA1
	srtpSessionSalt []byte
	srtpEncrypted   bool

	srtcpCTR         *cryptodev.CTRCipher
	srtcpHMAC        *cryptodev.HMACSHA1
	srtcpSessionSalt []byte
	srtcpEncrypted   bool

	mki        []byte
	useCryptex bool

	// Pre-allocated buffers to avoid allocations in hot path.
	// These are protected by the cipher mutex in the Context.
	authTagBuf  [20]byte     // SHA1 output buffer
	rocBuf      [4]byte      // ROC buffer for auth tag
	counterBuf  [16]byte     // AES counter buffer
}

// newSrtpCipherAesCmHmacSha1HW creates a hardware-accelerated cipher.
// Returns nil, error if hardware is unavailable (caller should fall back to software).
func newSrtpCipherAesCmHmacSha1HW(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (*srtpCipherAesCmHmacSha1HW, error) {
	if !cryptodev.Available() {
		return nil, cryptodev.ErrNotAvailable
	}

	switch profile.ProtectionProfile {
	case ProtectionProfileNullHmacSha1_80, ProtectionProfileNullHmacSha1_32:
		encryptSRTP = false
		encryptSRTCP = false
	default:
	}

	// Derive SRTP keys
	srtpSessionKey, err := aesCmKeyDerivation(labelSRTPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	}

	srtpSessionSalt, err := aesCmKeyDerivation(labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt))
	if err != nil {
		return nil, err
	}

	authKeyLen, err := profile.AuthKeyLen()
	if err != nil {
		return nil, err
	}

	srtpAuthKey, err := aesCmKeyDerivation(labelSRTPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		return nil, err
	}

	// Derive SRTCP keys
	srtcpSessionKey, err := aesCmKeyDerivation(labelSRTCPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	}

	srtcpSessionSalt, err := aesCmKeyDerivation(labelSRTCPSalt, masterKey, masterSalt, 0, len(masterSalt))
	if err != nil {
		return nil, err
	}

	srtcpAuthKey, err := aesCmKeyDerivation(labelSRTCPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		return nil, err
	}

	// Create hardware cipher instances
	srtpCTR, err := cryptodev.NewCTRCipher(srtpSessionKey)
	if err != nil {
		return nil, err
	}

	srtpHMAC, err := cryptodev.NewHMACSHA1(srtpAuthKey)
	if err != nil {
		srtpCTR.Close()
		return nil, err
	}

	srtcpCTR, err := cryptodev.NewCTRCipher(srtcpSessionKey)
	if err != nil {
		srtpCTR.Close()
		srtpHMAC.Close()
		return nil, err
	}

	srtcpHMAC, err := cryptodev.NewHMACSHA1(srtcpAuthKey)
	if err != nil {
		srtpCTR.Close()
		srtpHMAC.Close()
		srtcpCTR.Close()
		return nil, err
	}

	c := &srtpCipherAesCmHmacSha1HW{
		protectionProfileWithArgs: profile,
		srtpCTR:                   srtpCTR,
		srtpHMAC:                  srtpHMAC,
		srtpSessionSalt:           srtpSessionSalt,
		srtpEncrypted:             encryptSRTP,
		srtcpCTR:                  srtcpCTR,
		srtcpHMAC:                 srtcpHMAC,
		srtcpSessionSalt:          srtcpSessionSalt,
		srtcpEncrypted:            encryptSRTCP,
		useCryptex:                useCryptex,
	}

	if len(mki) > 0 {
		c.mki = make([]byte, len(mki))
		copy(c.mki, mki)
	}

	return c, nil
}

// Close releases hardware resources. Must be called when done.
// It is safe to call Close multiple times.
func (s *srtpCipherAesCmHmacSha1HW) Close() error {
	var firstErr error

	if s.srtpCTR != nil {
		if err := s.srtpCTR.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.srtpCTR = nil
	}
	if s.srtpHMAC != nil {
		if err := s.srtpHMAC.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.srtpHMAC = nil
	}
	if s.srtcpCTR != nil {
		if err := s.srtcpCTR.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.srtcpCTR = nil
	}
	if s.srtcpHMAC != nil {
		if err := s.srtcpHMAC.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.srtcpHMAC = nil
	}

	return firstErr
}

// generateCounter creates the AES-CTR counter for SRTP/SRTCP.
// Uses the pre-allocated counter buffer to avoid allocation.
func (s *srtpCipherAesCmHmacSha1HW) generateCounterRTP(seq uint16, roc uint32, ssrc uint32, salt []byte) []byte {
	// Counter format (RFC 3711):
	// [0-3]:   SSRC XOR salt[0:4]
	// [4-5]:   0x0000
	// [6-7]:   ROC high 16 bits XOR salt[4:6]
	// [8-9]:   ROC low 16 bits XOR salt[6:8]
	// [10-11]: Sequence number XOR salt[8:10]
	// [12-15]: Block counter (starts at 0)

	binary.BigEndian.PutUint32(s.counterBuf[0:4], ssrc)
	binary.BigEndian.PutUint32(s.counterBuf[4:8], roc)
	binary.BigEndian.PutUint32(s.counterBuf[8:12], uint32(seq)<<16)
	s.counterBuf[12] = 0
	s.counterBuf[13] = 0
	s.counterBuf[14] = 0
	s.counterBuf[15] = 0

	for i := 0; i < len(salt) && i < 14; i++ {
		s.counterBuf[i] ^= salt[i]
	}

	return s.counterBuf[:]
}

func (s *srtpCipherAesCmHmacSha1HW) encryptRTP(
	dst []byte,
	header *rtp.Header,
	headerLen int,
	plaintext []byte,
	roc uint32,
	rocInAuthTag bool,
) (ciphertext []byte, err error) {
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}
	payloadLen := len(plaintext) - headerLen
	dstLen := headerLen + payloadLen + len(s.mki) + authTagLen

	insertEmptyExtHdr := needsEmptyExtensionHeader(s.useCryptex, header)
	if insertEmptyExtHdr {
		dstLen += extensionHeaderSize
	}

	dst = growBufferSize(dst, dstLen)
	sameBuffer := isSameBuffer(dst, plaintext)

	if insertEmptyExtHdr {
		plaintext = insertEmptyExtensionHeader(dst, plaintext, sameBuffer, header)
		sameBuffer = true
		headerLen += extensionHeaderSize
	}

	// Copy header
	if !sameBuffer {
		copy(dst, plaintext[:headerLen])
	}

	// Encrypt payload using hardware CTR
	if s.srtpEncrypted && payloadLen > 0 {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, s.srtpSessionSalt)
		if err := s.srtpCTR.XORKeyStream(dst[headerLen:headerLen+payloadLen], plaintext[headerLen:headerLen+payloadLen], counter[:]); err != nil {
			return nil, err
		}
	} else if !sameBuffer && payloadLen > 0 {
		copy(dst[headerLen:], plaintext[headerLen:headerLen+payloadLen])
	}

	n := headerLen + payloadLen

	// Generate auth tag using hardware HMAC
	authTag, err := s.generateSrtpAuthTag(dst[:n], roc, rocInAuthTag, authTagLen)
	if err != nil {
		return nil, err
	}

	// Append MKI if present
	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += len(s.mki)
	}

	copy(dst[n:], authTag)
	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1HW) decryptRTP(
	dst, ciphertext []byte,
	header *rtp.Header,
	headerLen int,
	roc uint32,
	rocInAuthTag bool,
) ([]byte, error) {
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}

	actualTag := ciphertext[len(ciphertext)-authTagLen:]
	ciphertextWithoutTag := ciphertext[:len(ciphertext)-len(s.mki)-authTagLen]

	expectedTag, err := s.generateSrtpAuthTag(ciphertextWithoutTag, roc, rocInAuthTag, authTagLen)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}

	dst = growBufferSize(dst, len(ciphertextWithoutTag))
	sameBuffer := isSameBuffer(dst, ciphertext)

	if !sameBuffer {
		copy(dst, ciphertextWithoutTag[:headerLen])
	}

	payloadLen := len(ciphertextWithoutTag) - headerLen
	if s.srtpEncrypted && payloadLen > 0 {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, s.srtpSessionSalt)
		if err := s.srtpCTR.XORKeyStream(dst[headerLen:headerLen+payloadLen], ciphertextWithoutTag[headerLen:], counter[:]); err != nil {
			return nil, err
		}
	} else if !sameBuffer && payloadLen > 0 {
		copy(dst[headerLen:], ciphertextWithoutTag[headerLen:])
	}

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1HW) encryptRTCP(dst, decrypted []byte, srtcpIndex uint32, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	decryptedLen := len(decrypted)
	encryptedLen := decryptedLen + authTagLen + mkiLen + srtcpIndexSize

	dst = growBufferSize(dst, encryptedLen)
	sameBuffer := isSameBuffer(dst, decrypted)

	if !sameBuffer {
		copy(dst, decrypted[:srtcpHeaderSize])
	}

	if s.srtcpEncrypted {
		counter := generateCounter(uint16(srtcpIndex&0xffff), srtcpIndex>>16, ssrc, s.srtcpSessionSalt) //nolint:gosec
		payloadLen := decryptedLen - srtcpHeaderSize
		if payloadLen > 0 {
			if err := s.srtcpCTR.XORKeyStream(dst[srtcpHeaderSize:decryptedLen], decrypted[srtcpHeaderSize:], counter[:]); err != nil {
				return nil, err
			}
		}
		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
		dst[decryptedLen] |= srtcpEncryptionFlag
	} else {
		if !sameBuffer {
			copy(dst[srtcpHeaderSize:], decrypted[srtcpHeaderSize:])
		}
		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
	}

	n := decryptedLen + srtcpIndexSize

	authTag, err := s.generateSrtcpAuthTag(dst[:n], authTagLen)
	if err != nil {
		return nil, err
	}

	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += mkiLen
	}

	copy(dst[n:], authTag)
	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1HW) decryptRTCP(dst, encrypted []byte, index, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	encryptedLen := len(encrypted)
	decryptedLen := encryptedLen - (authTagLen + mkiLen + srtcpIndexSize)
	if decryptedLen < 8 {
		return nil, errTooShortRTCP
	}

	expectedTag, err := s.generateSrtcpAuthTag(encrypted[:encryptedLen-mkiLen-authTagLen], authTagLen)
	if err != nil {
		return nil, err
	}

	actualTag := encrypted[encryptedLen-authTagLen:]
	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}

	dst = growBufferSize(dst, decryptedLen)
	sameBuffer := isSameBuffer(dst, encrypted)

	if !sameBuffer {
		copy(dst, encrypted[:srtcpHeaderSize])
	}

	isEncrypted := encrypted[decryptedLen]&srtcpEncryptionFlag != 0
	if isEncrypted {
		counter := generateCounter(uint16(index&0xffff), index>>16, ssrc, s.srtcpSessionSalt) //nolint:gosec
		payloadLen := decryptedLen - srtcpHeaderSize
		if payloadLen > 0 {
			if err := s.srtcpCTR.XORKeyStream(dst[srtcpHeaderSize:decryptedLen], encrypted[srtcpHeaderSize:decryptedLen], counter[:]); err != nil {
				return nil, err
			}
		}
	} else if !sameBuffer {
		copy(dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:])
	}

	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1HW) generateSrtpAuthTag(buf []byte, roc uint32, rocInAuthTag bool, authTagLen int) ([]byte, error) {
	// Get buffer from pool
	bufPtr := hmacInputPool.Get().(*[]byte)
	combined := (*bufPtr)[:0]

	// Append packet data + ROC
	combined = append(combined, buf...)
	binary.BigEndian.PutUint32(s.rocBuf[:], roc)
	combined = append(combined, s.rocBuf[:]...)

	// Compute HMAC
	_, err := s.srtpHMAC.Sum(s.authTagBuf[:], combined)

	// Return buffer to pool
	*bufPtr = combined[:0]
	hmacInputPool.Put(bufPtr)

	if err != nil {
		return nil, err
	}

	if rocInAuthTag {
		// Return ROC + truncated hash
		result := make([]byte, 4+authTagLen)
		copy(result[:4], s.rocBuf[:])
		copy(result[4:], s.authTagBuf[:authTagLen])
		return result, nil
	}

	return s.authTagBuf[:authTagLen], nil
}

func (s *srtpCipherAesCmHmacSha1HW) generateSrtcpAuthTag(buf []byte, authTagLen int) ([]byte, error) {
	_, err := s.srtcpHMAC.Sum(s.authTagBuf[:], buf)
	if err != nil {
		return nil, err
	}
	return s.authTagBuf[:authTagLen], nil
}

func (s *srtpCipherAesCmHmacSha1HW) getRTCPIndex(in []byte) uint32 {
	authTagLen, _ := s.AuthTagRTCPLen()
	tailOffset := len(in) - (authTagLen + srtcpIndexSize + len(s.mki))
	srtcpIndexBuffer := in[tailOffset : tailOffset+srtcpIndexSize]
	return binary.BigEndian.Uint32(srtcpIndexBuffer) &^ (1 << 31)
}

// Ensure srtpCipherAesCmHmacSha1HW implements srtpCipher and io.Closer.
var (
	_ srtpCipher = (*srtpCipherAesCmHmacSha1HW)(nil)
	_ io.Closer  = (*srtpCipherAesCmHmacSha1HW)(nil)
)
