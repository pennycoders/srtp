// SPDX-FileCopyrightText: 2024 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import (
	"github.com/pion/logging"
	"github.com/pion/srtp/v3/internal/cryptodev"
)

var factoryLogger = logging.NewDefaultLoggerFactory().NewLogger("srtp")

// newSrtpCipherAesCmHmacSha1WithHWFallback creates an AES-CM-HMAC-SHA1 cipher,
// attempting hardware acceleration first and falling back to software.
//
// On platforms with hardware crypto support (e.g., ARM Linux with Rockchip
// crypto engine), this can significantly reduce CPU usage for SRTP encryption.
func newSrtpCipherAesCmHmacSha1WithHWFallback(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (srtpCipher, error) {
	// Try hardware first if available
	if cryptodev.Available() {
		hw, err := newSrtpCipherAesCmHmacSha1HW(profile, masterKey, masterSalt, mki, encryptSRTP, encryptSRTCP, useCryptex)
		if err == nil {
			factoryLogger.Info("Using hardware-accelerated SRTP cipher")
			return hw, nil
		}
		factoryLogger.Warnf("Hardware SRTP cipher failed, falling back to software: %v", err)
	}

	// Fall back to software implementation
	factoryLogger.Debug("Using software SRTP cipher")
	return newSrtpCipherAesCmHmacSha1(profile, masterKey, masterSalt, mki, encryptSRTP, encryptSRTCP, useCryptex)
}
