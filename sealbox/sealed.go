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

// Package sealbox implements web3 secrets storage.
//
// https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
package sealbox

const version = 3

// SealedBox - Sealed box JSON structure version 3.
type SealedBox struct {
	Version int    `json:"version,omitempty"`
	Crypto  Crypto `json:"crypto,omitempty"`
}

// Crypto - Sealed JSON structure.
type Crypto struct {
	Cipher       string       `json:"cipher,omitempty"`
	CipherText   string       `json:"ciphertext,omitempty"`
	CipherParams CipherParams `json:"cipherparams,omitempty"`
	KDF          string       `json:"kdf,omitempty"`
	KDFParams    KDFParams    `json:"kdfparams,omitempty"`
	MAC          string       `json:"mac,omitempty"`
}

// CipherParams - Sealed box params JSON structure.
type CipherParams struct {
	IV string `json:"iv,omitempty"`
}

// KDFParams - Sealed box KDF parameters.
type KDFParams struct {
	N     int    `json:"n,omitempty"`
	R     int    `json:"r,omitempty"`
	P     int    `json:"p,omitempty"`
	C     int    `json:"c,omitempty"`
	DKLen int    `json:"dklen,omitempty"`
	Salt  string `json:"salt,omitempty"`
	PRF   string `json:"prf,omitempty"`
}
