package zk_merkle_tree

import (
	"GBSM/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type merkleTreeCircuit struct {
	MerkleRoot []uints.U8 `gnark:",public"`
	ProofSet   [][]uints.U8
	ProofIndex uint64
	NumLeaves  uint64
}

func (c *merkleTreeCircuit) Define(api frontend.API) error {
	root := utils.GetRootByPoof(api, c.ProofSet, c.ProofIndex, c.NumLeaves)
	uintApi, _ := uints.New[uints.U32](api)
	for i := range root {
		uintApi.ByteAssertEq(root[i], c.MerkleRoot[i])
	}
	return nil
}
