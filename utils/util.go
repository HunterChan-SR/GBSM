package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func U8ArrayToValue(api frontend.API, a []uints.U8) frontend.Variable {
	v := make([]frontend.Variable, len(a))
	for i := range v {
		v[i] = api.Mul(a[i].Val, 1<<(i*8))
	}
	vv := api.Add(v[0], v[1], v[2:]...)
	return vv
}
