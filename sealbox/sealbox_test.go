// Copyright © 2018 The IPFN Developers. All Rights Reserved.
// Copyright © 2016-2018 The go-ethereum Authors. All Rights Reserved.
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

// Implements #TST-crypto-sealed

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	veryLightScryptN = 2
	veryLightScryptP = 1
)

func TestGetKDFKey(t *testing.T) {
	keyjson, err := ioutil.ReadFile("testdata/very-light-scrypt.json")
	var box SealedBox
	err = json.Unmarshal(keyjson, &box)
	assert.NoError(t, err)
	key, err := getKDFKey(&box.Crypto, "")
	assert.NoError(t, err)
	assert.Equal(t, "5d815789adee8991e2a02a69c53ef76202ed5b0ee7fb5d510c653a6b0c0b6880", hex.EncodeToString(key))
}

// Tests that a json key file can be decrypted and encrypted in multiple rounds.
func TestKeyEncryptDecrypt(t *testing.T) {
	keyjson, err := ioutil.ReadFile("testdata/very-light-scrypt.json")
	assert.NoError(t, err)
	password := ""

	// Do a few rounds of decryption and encryption
	for i := 0; i < 3; i++ {
		var box SealedBox
		err = json.Unmarshal(keyjson, &box)
		assert.NoError(t, err)
		_, err = box.Decrypt(password + "bad")
		assert.Errorf(t, err, "test %d: json key decrypted with bad password", i)
		// Decrypt with the correct password
		body, err := box.Decrypt(password)
		assert.NoErrorf(t, err, "test %d: json key failed to decrypt", i)
		// Recrypt with a new password and start over
		password += "new data appended"
		box, err = Encrypt(body, []byte(password), veryLightScryptN, veryLightScryptP)
		assert.NoErrorf(t, err, "test %d: failed to encrypt", i)
		keyjson, err = json.Marshal(box)
		assert.NoErrorf(t, err, "test %d: failed to marshal json", i)
	}
}
