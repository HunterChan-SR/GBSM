package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

func leafSum(api frontend.API, data []uints.U8) []uints.U8 {
	h, _ := sha2.New(api)
	h.Write(data)
	res := h.Sum()
	return res
}
func nodeSum(api frontend.API, a, b []uints.U8) []uints.U8 {
	h, _ := sha2.New(api)
	h.Write(a)
	h.Write(b)
	res := h.Sum()
	return res
}

func GetRootByPoof(api frontend.API, proofSet [][]uints.U8, proofIndex uint64, numLeaves uint64) []uints.U8 {
	if proofIndex >= numLeaves {
		return nil
	}
	height := 0
	if len(proofSet) <= height {
		return nil
	}
	sum := leafSum(api, proofSet[height])

	height++
	stableEnd := proofIndex
	for {
		subTreeStartIndex := (proofIndex / (1 << uint(height))) * (1 << uint(height))
		subTreeEndIndex := subTreeStartIndex + (1 << (uint(height))) - 1
		if subTreeEndIndex >= numLeaves {
			break
		}
		stableEnd = subTreeEndIndex
		if len(proofSet) <= height {
			return nil
		}
		if proofIndex-subTreeStartIndex < 1<<uint(height-1) {
			sum = nodeSum(api, sum, proofSet[height])
		} else {
			sum = nodeSum(api, proofSet[height], sum)
		}
		height++
	}
	if stableEnd != numLeaves-1 {
		if len(proofSet) <= height {
			return nil
		}
		sum = nodeSum(api, sum, proofSet[height])
		height++
	}
	for height < len(proofSet) {
		sum = nodeSum(api, proofSet[height], sum)
		height++
	}

	return sum

	//uintApi, _ := uints.New[uints.U32](api)
	//for i := range sum {
	//	uintApi.ByteAssertEq(sum[i], merkleRoot[i])
	//}
	//return nil
}
