package zk_merkle_tree

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

func TZkMerkleTree(numLeaves uint64, proofIndex uint64) {
	if proofIndex >= numLeaves {
		//error
		return
	}
	h := sha256.New()

	_merkle := merkletree.New(h)
	err := _merkle.SetIndex(proofIndex)

	if err != nil {
		return
	}

	for i := uint64(0); i < numLeaves; i++ {
		data := make([]byte, 32)
		_, _ = rand.Read(data)
		_merkle.Push(data[:])
	}

	merkleRoot, proofSet, _, _ := _merkle.Prove()
	//res := merkletree.VerifyProof(h, merkleRoot, proofSet, pindx, numl)
	//fmt.Println(res)
	//
	//fmt.Println(merkleRoot)

	circuit := merkleTreeCircuit{
		MerkleRoot: uints.NewU8Array(merkleRoot),
		ProofSet:   make([][]uints.U8, len(proofSet)),
		ProofIndex: proofIndex,
		NumLeaves:  numLeaves,
	}
	for i := 0; i < len(proofSet); i++ {
		circuit.ProofSet[i] = uints.NewU8Array(proofSet[i])
	}

	//fmt.Println(assignment)

	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(r1cs)
	assignment := merkleTreeCircuit{
		MerkleRoot: uints.NewU8Array(merkleRoot),
		ProofSet:   make([][]uints.U8, len(proofSet)),
		ProofIndex: proofIndex,
		NumLeaves:  numLeaves,
	}
	for i := 0; i < len(proofSet); i++ {
		assignment.ProofSet[i] = uints.NewU8Array(proofSet[i])
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(r1cs, pk, witness)
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("invalid proof")
	}

}
