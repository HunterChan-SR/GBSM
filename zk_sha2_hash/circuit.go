package zk_sha2_hash

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type sha2Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8 `gnark:",public"`
}

func (c *sha2Circuit) Define(api frontend.API) error {

	h, err := sha2.New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()

	h2, _ := sha2.New(api)
	h2.Write(res)
	rres := h2.Sum()

	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], rres[i])
	}
	return nil
}
