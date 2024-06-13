package zk_sha2_hash

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

func TZkSha2Hash() {
	bts := make([]byte, 32)
	//fmt.Println(bts)
	dgst := sha256.Sum256(bts)

	dgst = sha256.Sum256(dgst[:])
	//fmt.Println(dgst)
	circuit := sha2Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(circuit.Expected[:], uints.NewU8Array(dgst[:]))
	//
	fmt.Println(circuit.In)

	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(r1cs)
	//

	assignment := sha2Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(assignment.Expected[:], uints.NewU8Array(dgst[:]))

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(r1cs, pk, witness)
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("invalid proof")
	}
}
