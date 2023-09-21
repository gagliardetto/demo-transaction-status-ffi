package main

/*
#cgo LDFLAGS: -L./lib -lsolana_transaction_status_wrapper
#include "./lib/transaction_status.h"
*/
import "C"

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58/base58"
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
		buf.Grow(1024)
		instructionParams := bin.NewBinEncoder(buf)
		data, err := base58.Decode("Fk63PRyGqZAwDVvZPKBn2ZUTURZRgny7KaLrZEaea2N6u7orpV3UUGet4jCzvtuVpr1TUmDgi7AsEgQE4VjahYaZ5HtxwnoVq4SSxK65SatJYkW4AQEfT7peCRRHbEXTGPegaSRjxMYDguks8kyEHbgWfB1H3m")
		if err != nil {
			panic(err)
		}
		demoInstruction := Parameters{
			ProgramID: solana.VoteProgramID,
			Instruction: CompiledInstruction{
				ProgramIDIndex: 2,
				Accounts:       []uint8{1, 0},
				Data:           data,
			},
			AccountKeys: AccountKeys{
				StaticKeys: []solana.PublicKey{
					solana.MPK("6Rp3vYN1L1ym3hz79ZqDHbpAFP8W1eB6ja47se2sDaCx"),
					solana.MPK("CqZt8CTQfNVH6SYWp1HdWXoBhkFqdT8nEFbSM5bB5hvN"),
					solana.MPK("Vote111111111111111111111111111111111111111"),
				},
				// DynamicKeys: &LoadedAddresses{
				// 	Writable: []solana.PublicKey{},
				// 	Readonly: []solana.PublicKey{
				// 		solana.TokenLendingProgramID,
				// 	},
				// },
			},
			StackHeight: nil,
		}
		spew.Dump(demoInstruction)
		startedMarshallingParametersAt := time.Now()
		err = demoInstruction.MarshalWithEncoder(instructionParams)
		if err != nil {
			panic(err)
		}
		fmt.Println("[golang] marshalled instruction parameters in:", time.Since(startedMarshallingParametersAt))
		cs := (*C.u_char)(C.CBytes(buf.Bytes()))
		defer C.free(unsafe.Pointer(cs))

		startedParsingAt := time.Now()
		got := C.parse_instruction(cs, C.ulong(len(buf.Bytes())))
		if got.status == 0 {
			fmt.Println("[golang] got status (OK):", got.status)
		} else {
			fmt.Println("[golang] got status (ERR):", got.status)
		}
		fmt.Println("[golang] got parsed instruction in:", time.Since(startedParsingAt))

		parsedInstructionJSON := C.GoBytes(unsafe.Pointer(got.buf.data), C.int(got.buf.len))
		fmt.Println("[golang] got parsed instruction as json:", spew.Sdump(parsedInstructionJSON))
		fmt.Println("[golang] got parsed instruction as json:", string(parsedInstructionJSON))
		{
			var dst any
			err := json.Unmarshal(parsedInstructionJSON, &dst)
			if err != nil {
				panic(err)
			}
			spew.Dump(dst)
		}
	}
}
