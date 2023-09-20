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

type Parameters struct {
	ProgramID   solana.PublicKey
	Instruction CompiledInstruction
	AccountKeys AccountKeys
	StackHeight *uint32
}

func (inst Parameters) MarshalWithEncoder(encoder *bin.Encoder) error {
	_, err := encoder.Write(inst.ProgramID[:])
	if err != nil {
		return fmt.Errorf("failed to write ProgramID: %w", err)
	}
	err = inst.Instruction.MarshalWithEncoder(encoder)
	if err != nil {
		return fmt.Errorf("failed to write Instruction: %w", err)
	}
	err = inst.AccountKeys.MarshalWithEncoder(encoder)
	if err != nil {
		return fmt.Errorf("failed to write AccountKeys: %w", err)
	}
	if inst.StackHeight != nil {
		err = encoder.WriteOption(true)
		if err != nil {
			return fmt.Errorf("failed to write Option(StackHeight): %w", err)
		}
		err = encoder.WriteUint32(*inst.StackHeight, binary.LittleEndian)
		if err != nil {
			return fmt.Errorf("failed to write StackHeight: %w", err)
		}
	} else {
		err = encoder.WriteOption(false)
		if err != nil {
			return fmt.Errorf("failed to write Option(StackHeight): %w", err)
		}
	}
	return nil
}

type CompiledInstruction struct {
	ProgramIDIndex uint8
	Accounts       []uint8
	Data           []byte
}

func (inst CompiledInstruction) MarshalWithEncoder(encoder *bin.Encoder) error {
	{
		// .compiled_instruction.program_id_index as uint8
		err := encoder.WriteUint8(inst.ProgramIDIndex)
		if err != nil {
			return fmt.Errorf("failed to write ProgramIDIndex: %w", err)
		}
		// .compiled_instruction.accounts:
		{
			// len uint8
			err := encoder.WriteUint8(uint8(len(inst.Accounts)))
			if err != nil {
				return fmt.Errorf("failed to write len(Accounts): %w", err)
			}
			// values:
			_, err = encoder.Write(inst.Accounts)
			if err != nil {
				return fmt.Errorf("failed to write Accounts: %w", err)
			}
		}
		// .compiled_instruction.data:
		{
			// len uint8
			err := encoder.WriteUint8(uint8(len(inst.Data)))
			if err != nil {
				return fmt.Errorf("failed to write len(Data): %w", err)
			}
			// value:
			_, err = encoder.Write(inst.Data)
			if err != nil {
				return fmt.Errorf("failed to write Data: %w", err)
			}
		}
	}
	return nil
}

type AccountKeys struct {
	StaticKeys  []solana.PublicKey
	DynamicKeys *LoadedAddresses
}

func (inst AccountKeys) MarshalWithEncoder(encoder *bin.Encoder) error {
	{
		// account_keys.static_keys:
		{
			// len uint8
			err := encoder.WriteUint8(uint8(len(inst.StaticKeys)))
			if err != nil {
				return fmt.Errorf("failed to write len(StaticKeys): %w", err)
			}
			// keys:
			for keyIndex, key := range inst.StaticKeys {
				// key
				_, err := encoder.Write(key[:])
				if err != nil {
					return fmt.Errorf("failed to write StaticKeys[%d]: %w", keyIndex, err)
				}
			}
		}
		// account_keys.dynamic_keys:
		if inst.DynamicKeys != nil {
			err := encoder.WriteOption(true)
			if err != nil {
				return fmt.Errorf("failed to write Option(DynamicKeys): %w", err)
			}
			err = inst.DynamicKeys.MarshalWithEncoder(encoder)
			if err != nil {
				return fmt.Errorf("failed to write DynamicKeys: %w", err)
			}
		} else {
			err := encoder.WriteOption(false)
			if err != nil {
				return fmt.Errorf("failed to write Option(DynamicKeys): %w", err)
			}
		}
	}
	return nil
}

type LoadedAddresses struct {
	Writable []solana.PublicKey
	Readonly []solana.PublicKey
}

func (inst LoadedAddresses) MarshalWithEncoder(encoder *bin.Encoder) error {
	{
		// account_keys.dynamic_keys.writable:
		{
			// len uint8
			err := encoder.WriteUint8(uint8(len(inst.Writable)))
			if err != nil {
				return fmt.Errorf("failed to write len(Writable): %w", err)
			}
			// keys:
			for keyIndex, key := range inst.Writable {
				_, err := encoder.Write(key[:])
				if err != nil {
					return fmt.Errorf("failed to write Writable[%d]: %w", keyIndex, err)
				}
			}
		}
		// account_keys.dynamic_keys.readonly:
		{
			// len uint8
			err := encoder.WriteUint8(uint8(len(inst.Readonly)))
			if err != nil {
				return fmt.Errorf("failed to write len(Readonly): %w", err)
			}
			// keys:
			for keyIndex, key := range inst.Readonly {
				_, err := encoder.Write(key[:])
				if err != nil {
					return fmt.Errorf("failed to write Readonly[%d]: %w", keyIndex, err)
				}
			}
		}
	}
	return nil
}

func main() {
	C.hello_from_rust()

	{
		buf := new(bytes.Buffer)
		instructionParams := bin.NewBinEncoder(buf)
		{
			// .program_id:
			program_id := solana.Secp256k1ProgramID
			_, err := instructionParams.Write(program_id[:])
			if err != nil {
				panic(err)
			}
			fmt.Println("[golang] programId:", program_id.String())
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
