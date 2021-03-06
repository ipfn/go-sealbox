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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"

	"github.com/ipfn/go-digesteve/digesteve/keccak256sum"
)

// ErrDecrypt - Error returned on failed decryption attempt.
var ErrDecrypt = errors.New("could not decrypt key with given passphrase")

// Decrypt - Decrypts a key from a json blob, returning the private key itself.
func (box *SealedBox) Decrypt(pwd string) ([]byte, error) {
	switch box.Version {
	case 1:
		return decryptV1(&box.Crypto, pwd)
	case 3:
		return decryptV3(&box.Crypto, pwd)
	default:
		return nil, fmt.Errorf("sealbox: invalid version %d", box.Version)
	}
}

func getKDFKey(box *Crypto, pwd string) ([]byte, error) {
	pwdArray := []byte(pwd)
	salt, err := hex.DecodeString(box.KDFParams.Salt)
	if err != nil {
		return nil, err
	}
	switch box.KDF {
	case keyHeaderKDF:
		return scrypt.Key(
			pwdArray, salt,
			box.KDFParams.N,
			box.KDFParams.R,
			box.KDFParams.P,
			box.KDFParams.DKLen,
		)
	case "pbkdf2":
		if box.KDFParams.PRF != "hmac-sha256" {
			return nil, fmt.Errorf("Unsupported PBKDF2 PRF: %s", box.KDFParams.PRF)
		}
		return pbkdf2.Key(pwdArray, salt, box.KDFParams.C, box.KDFParams.DKLen, sha256.New), nil
	default:
		return nil, fmt.Errorf("Unsupported KDF: %s", box.KDF)
	}
}

func decryptV3(box *Crypto, pwd string) (keyBytes []byte, err error) {
	if box.Cipher != "aes-128-ctr" {
		return nil, fmt.Errorf("Cipher not supported: %v", box.Cipher)
	}

	mac, err := hex.DecodeString(box.MAC)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(box.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	cipherText, err := hex.DecodeString(box.CipherText)
	if err != nil {
		return nil, err
	}

	derivedKey, err := getKDFKey(box, pwd)
	if err != nil {
		return nil, err
	}

	calculatedMAC := keccak256sum.Bytes(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, ErrDecrypt
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, err
	}
	return plainText, err
}

func decryptV1(box *Crypto, pwd string) (keyBytes []byte, err error) {
	mac, err := hex.DecodeString(box.MAC)
	if err != nil {
		return nil, err
	}

	iv, err := hex.DecodeString(box.CipherParams.IV)
	if err != nil {
		return nil, err
	}

	cipherText, err := hex.DecodeString(box.CipherText)
	if err != nil {
		return nil, err
	}

	derivedKey, err := getKDFKey(box, pwd)
	if err != nil {
		return nil, err
	}

	calculatedMAC := keccak256sum.Bytes(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, ErrDecrypt
	}

	plainText, err := aesCBCDecrypt(keccak256sum.Bytes(derivedKey[:16])[:16], cipherText, iv)
	if err != nil {
		return nil, err
	}
	return plainText, err
}
