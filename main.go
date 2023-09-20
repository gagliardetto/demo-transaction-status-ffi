package main

// NOTE: There should be NO space between the comments and the `import "C"` line.
// The -ldl is necessary to fix the linker errors about `dlsym` that would otherwise appear.

/*
#cgo LDFLAGS: -L./lib -lsolana_transaction_status_wrapper
#cgo LDFLAGS: ./lib/libsolana_transaction_status_wrapper.a -ldl
#include "./lib/transaction_status.h"
*/
import "C"

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	bin "github.com/gagliardetto/binary"
)

func randomBytes(len int) []byte {
	slice := make([]byte, len)

	_, err := io.ReadFull(crand.Reader, slice)
	if err != nil {
		panic(err)
	}

	return slice
}

func HashWithSha256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func main() {
	C.hello_from_rust()

	{
		buf := new(bytes.Buffer)
		instructionParams := bin.NewBinEncoder(buf)
		instructionParams.Write(randomBytes(32))
		fmt.Println("[golang] sending instruction:", buf.Bytes())
		cs := (*C.u_char)(C.CBytes(buf.Bytes()))
		defer C.free(unsafe.Pointer(cs))

		got := C.parse_instruction(cs, C.ulong(len(buf.Bytes())))
		fmt.Println("[golang] got status:", got.status)

		parsedInstructionJSON := C.GoBytes(unsafe.Pointer(got.buf.data), C.int(got.buf.len))
		fmt.Println("[golang] got back:", spew.Sdump(parsedInstructionJSON))
	}
	// // {
	// // 	got := C.accept_vec(cs, C.ulong(len(origin)))
	// // 	fmt.Println("[golang] got back:", cb(got))
	// // }
	// {
	// 	{
	// 		j := `{"name":"John Smith","age":42}`
	// 		gotJson := C.accept_json(C.CString(j))
	// 		fmt.Println("[golang] got back json:", C.GoString(gotJson))
	// 	}
	// }
}

func bc(b []byte) *C.uint8_t {
	return (*C.uint8_t)(C.CBytes(b))
}

// read back the bytes from the C-side
func cb(p *C.uint8_t) []byte {
	return C.GoBytes(unsafe.Pointer(p), 32)
}

func Open(regionName string, flags int, perm os.FileMode) (*os.File, error) {
	filename := filepath.Join("/dev/shm", regionName)
	file, err := os.OpenFile(filename, flags, perm)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func Unlink(regionName string) error {
	path := regionName
	if !filepath.IsAbs(path) {
		path = filepath.Join("/dev/shm", regionName)
	}
	return os.Remove(path)
}
