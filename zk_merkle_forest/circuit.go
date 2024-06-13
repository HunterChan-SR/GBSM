package zk_merkle_forest

import (
	"GBSM/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type merkleForestCircuit struct {
	AllRoots   [][]uints.U8 `gnark:",public"`
	ProofSet   [][]uints.U8
	ProofIndex uint64
	NumLeaves  uint64
}

func (c *merkleForestCircuit) Define(api frontend.API) error {
	//curvepara := ecctedwards.BN254
	//curve, err := twistededwards.NewEdCurve(api, curvepara)

	root := utils.GetRootByPoof(api, c.ProofSet, c.ProofIndex, c.NumLeaves)
	//api.Println(root)

	rootVal := utils.U8ArrayToValue(api, root)
	res := frontend.Variable(0)
	//api.Println(res)
	for i := 0; i < len(c.AllRoots); i++ {
		//flag := frontend.Variable(1)
		//api.Println(flag)
		AllRootsIVal := utils.U8ArrayToValue(api, c.AllRoots[i])
		//for j := 0; j < len(root); j++ {
		//	ok := api.IsZero(api.Cmp(root[j].Val, c.AllRoots[i][j].Val))
		//	flag = api.And(flag, ok)
		//}
		//api.Println(flag)
		flag := api.IsZero(api.Cmp(rootVal, AllRootsIVal))
		res = api.Or(res, flag)
	}
	api.AssertIsEqual(res, frontend.Variable(1))
	return nil
}
