// Copyright © 2017-2018 The IPFN Developers. All Rights Reserved.
// Copyright © 2014-2018 The go-ethereum Authors. All Rights Reserved.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package sealbox

import (
	"crypto/aes"
	"encoding/hex"

	"golang.org/x/crypto/scrypt"

	"github.com/ipfn/go-digesteve/digesteve/keccak256sum"
	"github.com/ipfn/go-entropy/entropy"
)

const (
	// StandardScryptN is the N parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptN = 1 << 18

	// StandardScryptP is the P parameter of Scrypt encryption algorithm, using 256MB
	// memory and taking approximately 1s CPU time on a modern processor.
	StandardScryptP = 1

	// LightScryptN is the N parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptN = 1 << 12

	// LightScryptP is the P parameter of Scrypt encryption algorithm, using 4MB
	// memory and taking approximately 100ms CPU time on a modern processor.
	LightScryptP = 6
)

// EncryptStandard - Encrypts a box using standard scrypt parameters.
func EncryptStandard(body, pwd []byte, scryptN, scryptP int) (_ SealedBox, err error) {
	return Encrypt(body, pwd, StandardScryptN, StandardScryptP)
}

// EncryptLight - Encrypts a box using light scrypt parameters.
func EncryptLight(body, pwd []byte, scryptN, scryptP int) (_ SealedBox, err error) {
	return Encrypt(body, pwd, LightScryptN, LightScryptP)
}

// Encrypt - Encrypts a box using the specified scrypt parameters.
func Encrypt(body, pwd []byte, scryptN, scryptP int) (_ SealedBox, err error) {
	salt, err := entropy.New(32)
	if err != nil {
		return
	}
	derivedKey, err := scrypt.Key(pwd, salt, scryptN, scryptR, scryptP, scryptDKLen)
	if err != nil {
		return
	}
	iv, err := entropy.New(aes.BlockSize)
	if err != nil {
		return
	}
	cipherText, err := aesCTRXOR(derivedKey[:16], body, iv)
	if err != nil {
		return
	}
	return SealedBox{
		Version: version,
		Crypto: Crypto{
			Cipher:     "aes-128-ctr",
			CipherText: hex.EncodeToString(cipherText),
			CipherParams: CipherParams{
				IV: hex.EncodeToString(iv),
			},
			KDF: keyHeaderKDF,
			KDFParams: KDFParams{
				N:     scryptN,
				R:     scryptR,
				P:     scryptP,
				DKLen: scryptDKLen,
				Salt:  hex.EncodeToString(salt),
			},
			MAC: hex.EncodeToString(keccak256sum.Bytes(derivedKey[16:32], cipherText)),
		},
	}, nil
}
