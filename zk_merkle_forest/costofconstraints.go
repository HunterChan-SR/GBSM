package zk_merkle_forest

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

func TZkMerkleForest(numAllLeaves uint64, proofIndex uint64, numTree uint64) {
	if proofIndex >= numAllLeaves {
		//error
		return
	}

	numOneTreeLeaves := numAllLeaves / numTree
	proofTreeId := proofIndex / numOneTreeLeaves
	proofIndexOnTree := proofIndex % numOneTreeLeaves
	_merkleTrees := make([]*merkletree.Tree, numTree)
	var proofSet [][]byte

	for i := uint64(0); i < numTree; i++ {
		_merkleTrees[i] = merkletree.New(sha256.New())
		if i == proofTreeId {
			err := _merkleTrees[i].SetIndex(proofIndexOnTree)
			if err != nil {
				return
			}
		}
		for j := uint64(0); j < numOneTreeLeaves; j++ {
			data := make([]byte, 32)
			_, _ = rand.Read(data)
			_merkleTrees[i].Push(data[:])
		}
		if i == proofTreeId {
			_, proofSet, _, _ = _merkleTrees[i].Prove()
		}
	}

	circuit := merkleForestCircuit{
		AllRoots:   make([][]uints.U8, numTree),
		ProofSet:   make([][]uints.U8, len(proofSet)),
		ProofIndex: proofIndexOnTree,
		NumLeaves:  numOneTreeLeaves,
	}
	for i := 0; i < len(proofSet); i++ {
		circuit.ProofSet[i] = uints.NewU8Array(proofSet[i])
	}
	for i := 0; i < len(_merkleTrees); i++ {
		circuit.AllRoots[i] = uints.NewU8Array(_merkleTrees[i].Root())
	}

	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(r1cs)
	assignment := merkleForestCircuit{
		AllRoots:   make([][]uints.U8, numTree),
		ProofSet:   make([][]uints.U8, len(proofSet)),
		ProofIndex: proofIndexOnTree,
		NumLeaves:  numOneTreeLeaves,
	}
	for i := 0; i < len(proofSet); i++ {
		assignment.ProofSet[i] = uints.NewU8Array(proofSet[i])
	}
	for i := 0; i < len(_merkleTrees); i++ {
		assignment.AllRoots[i] = uints.NewU8Array(_merkleTrees[i].Root())
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(r1cs, pk, witness)
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("invalid proof")
	}

}
