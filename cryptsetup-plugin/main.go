package main

// #cgo pkg-config: libcryptsetup
// #cgo LDFLAGS: "-Wl,--version-script=cryptsetup_token.map"
// #include <errno.h>
// #include <stdlib.h>
// #include <libcryptsetup.h>
import "C"

// CGO disables use of `-Wl,--version-script=...` compile flag (see https://go.dev/s/invalidflag)
// build this library with
//      export CGO_LDFLAGS_ALLOW='-Wl,--version-script=cryptsetup_token.map'
//      go build

import (
	"encoding/json"
	"fmt"
	"unsafe"

	"github.com/anatol/clevis.go"
)

var ver = C.CString("0.1")

func cryptLog(dev *C.struct_crypt_device, level C.int, msg string) {
	cmsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cmsg))
	C.crypt_log(dev, level, cmsg)
}

type clevisToken struct {
	Jwe json.RawMessage
}

//export cryptsetup_token_version
func cryptsetup_token_version() *C.char {
	return ver
}

//export cryptsetup_token_open
func cryptsetup_token_open(dev *C.struct_crypt_device, tokenID C.int, password **C.char, passwordLen *C.size_t, usrptr *C.char) C.int {
	return cryptsetup_token_open_pin(dev, tokenID, nil, 0, password, passwordLen, usrptr)
}

//export cryptsetup_token_open_pin
func cryptsetup_token_open_pin(dev *C.struct_crypt_device, tokenID C.int, pin *C.char, pinSize C.size_t, password **C.char, passwordLen *C.size_t, usrptr *C.char) C.int {
	var cjson *C.char

	cerr := C.crypt_token_json_get(dev, tokenID, &cjson)
	if cerr < 0 {
		cryptLog(dev, C.CRYPT_LOG_ERROR, fmt.Sprintf("token get failed: errno %v\n", -cerr))
		return cerr
	}

	var node clevisToken
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &node); err != nil {
		cryptLog(dev, C.CRYPT_LOG_ERROR, fmt.Sprintf("token json unmarshal failed: %v\n", err))
		return -C.EINVAL
	}

	pwd, err := clevis.Decrypt(node.Jwe)
	if err != nil {
		cryptLog(dev, C.CRYPT_LOG_ERROR, fmt.Sprintf("clevis decryption failed: %v\n", err))
		return -C.EINVAL
	}

	*password = C.CString(string(pwd))
	*passwordLen = C.size_t(len(pwd))

	return 0
}

//export cryptsetup_token_dump
func cryptsetup_token_dump(cd *C.struct_crypt_device, cjson *C.char) {
	var config clevisToken
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		cryptLog(cd, C.CRYPT_LOG_NORMAL, fmt.Sprintf("\tInvalid JSON config:%v\n", err))
		return
	}
}

//export cryptsetup_token_validate
func cryptsetup_token_validate(cd *C.struct_crypt_device, cjson *C.char) C.int {
	var config clevisToken
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		cryptLog(cd, C.CRYPT_LOG_NORMAL, fmt.Sprintf("\tInvalid JSON config:%v\n", err))
		return -C.EINVAL
	}

	// TODO: do extra validation

	cryptLog(cd, C.CRYPT_LOG_DEBUG, "Validated Clevis Token Config.\n")

	return 0
}

func main() {
}
