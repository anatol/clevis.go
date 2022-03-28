package main

// #cgo pkg-config: libcryptsetup
// #cgo LDFLAGS: "-Wl,--version-script=cryptsetup_token.map"
// #include <errno.h>
// #include <libcryptsetup.h>
import "C"
import (
	"encoding/json"
	"fmt"
	"github.com/anatol/clevis.go"
)

var ver = C.CString("0.1")

type clevisToken struct {
	Jwe      json.RawMessage
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
		C.crypt_log(dev, C.CRYPT_LOG_ERROR, C.CString(fmt.Sprintf("token get failed: errno %v\n", -cerr)))
		return cerr
	}

	var node clevisToken
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &node); err != nil {
		C.crypt_log(dev, C.CRYPT_LOG_ERROR, C.CString(fmt.Sprintf("token json unmarshal failed: %v\n", err)))
		return -C.EINVAL
	}

	pwd, err := clevis.Decrypt(node.Jwe)
	if err != nil {
		C.crypt_log(dev, C.CRYPT_LOG_ERROR, C.CString(fmt.Sprintf("clevis decryption failed: %v\n", err)))
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
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("\tInvalid JSON config:%v\n", err)))
		return
	}
}

//export cryptsetup_token_validate
func cryptsetup_token_validate(cd *C.struct_crypt_device, cjson *C.char) C.int {
	var config clevisToken
	if err := json.Unmarshal([]byte(C.GoString(cjson)), &config); err != nil {
		C.crypt_log(cd, C.CRYPT_LOG_NORMAL, C.CString(fmt.Sprintf("\tInvalid JSON config:%v\n", err)))
		return -C.EINVAL
	}

	// TODO: do extra validation

	C.crypt_log(cd, C.CRYPT_LOG_DEBUG, C.CString("Validated Clevis Token Config.\n"))

	return 0
}

func main() {
}
