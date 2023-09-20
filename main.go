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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
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
		{
			// .program_id:
			programId := randomBytes(32)
			_, err := instructionParams.Write(programId)
			if err != nil {
				panic(err)
			}
			fmt.Println("[golang] programId:", solana.PublicKeyFromBytes(programId).String())
			// .compiled_instruction:
			{
				{
					// .compiled_instruction.program_id_index as uint8
					program_id_index := uint8(1)
					err := instructionParams.WriteUint8(program_id_index)
					if err != nil {
						panic(err)
					}
					// .compiled_instruction.accounts:
					accounts := []uint8{1, 2, 3}
					{
						// len uint8
						err = instructionParams.WriteUint8(uint8(len(accounts)))
						if err != nil {
							panic(err)
						}
						// values:
						for _, accountIndex := range accounts {
							err = instructionParams.WriteUint8(accountIndex)
							if err != nil {
								panic(err)
							}
						}
					}
					// .compiled_instruction.data:
					data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
					{
						// len uint8
						err = instructionParams.WriteUint8(uint8(len(data)))
						if err != nil {
							panic(err)
						}
						// value:
						_, err = instructionParams.Write(data)
						if err != nil {
							panic(err)
						}
					}
				}
			}
			{
				// .account_keys:
				{
					// account_keys.static_keys:
					{
						staticKeys := []solana.PublicKey{
							solana.TokenLendingProgramID,
							solana.PublicKeyFromBytes(randomBytes(32)),
							solana.PublicKeyFromBytes(randomBytes(32)),
						}
						{
							// len uint8
							err := instructionParams.WriteUint8(uint8(len(staticKeys)))
							if err != nil {
								panic(err)
							}
							// keys:
							for _, key := range staticKeys {
								// key
								_, err := instructionParams.Write(key[:])
								if err != nil {
									panic(err)
								}
							}
						}
					}
					// account_keys.dynamic_keys:
					hasDynamicKeys := true
					if hasDynamicKeys {
						err := instructionParams.WriteOption(true)
						if err != nil {
							panic(err)
						}
					} else {
						err := instructionParams.WriteOption(false)
						if err != nil {
							panic(err)
						}
					}
					{
						// account_keys.dynamic_keys.writable:
						writable := []solana.PublicKey{
							solana.PublicKeyFromBytes(randomBytes(32)),
							solana.PublicKeyFromBytes(randomBytes(32)),
							solana.PublicKeyFromBytes(randomBytes(32)),
							solana.PublicKeyFromBytes(randomBytes(32)),
						}
						{
							// len uint8
							err := instructionParams.WriteUint8(uint8(len(writable)))
							if err != nil {
								panic(err)
							}
							// keys:
							for _, key := range writable {
								_, err := instructionParams.Write(key[:])
								if err != nil {
									panic(err)
								}
							}
						}
						// account_keys.dynamic_keys.readonly:
						readonly := []solana.PublicKey{
							solana.PublicKeyFromBytes(randomBytes(32)),
						}
						{
							// len uint8
							err := instructionParams.WriteUint8(uint8(len(readonly)))
							if err != nil {
								panic(err)
							}
							// keys:
							for _, key := range readonly {
								_, err := instructionParams.Write(key[:])
								if err != nil {
									panic(err)
								}
							}
						}

					}
				}
			}
			// stack_height:
			{
				has := true
				stackHeight := uint32(123)
				if has {
					err := instructionParams.WriteOption(true)
					if err != nil {
						panic(err)
					}
					err = instructionParams.WriteUint32(stackHeight, binary.LittleEndian)
					if err != nil {
						panic(err)
					}
				} else {
					err := instructionParams.WriteOption(false)
					if err != nil {
						panic(err)
					}
				}
			}
		}
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
