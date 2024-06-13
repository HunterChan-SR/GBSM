package main

import (
	"GBSM/zk_merkle_forest"
	"GBSM/zk_merkle_tree"
	"fmt"
	"math/rand"
	"time"
)

func Test1() {
	rand.Seed(time.Now().UnixNano())
	for i := 16; i <= 24; i++ {
		fmt.Println("2^", i)
		numLeaves := uint64(1) << uint64(i)
		fmt.Println("numLeaves:", numLeaves)
		zk_merkle_tree.TZkMerkleTree(numLeaves, uint64(rand.Intn(int(numLeaves))))
	}
}

func Test2() {
	rand.Seed(time.Now().UnixNano())
	for i := 16; i <= 24; i++ {
		fmt.Println("2^", i)
		numLeaves := uint64(1) << uint64(i)
		fmt.Println("numLeaves:", numLeaves)
		for j := 5; j <= 10; j++ {
			fmt.Println("2^", j)
			numTree := uint64(1) << uint64(j)
			fmt.Println("numTree:", numTree)
			zk_merkle_forest.TZkMerkleForest(numLeaves, uint64(rand.Intn(int(numLeaves))), numTree)
		}
	}
}

func main() {
	//zk_sha2_hash.T_sha_merkle()
	//zk_merkle_tree.TZkMerkleTree(16, 1)
	//zk_merkle_forest.TZkMerkleForest(16, 1, 1)
	//Test1()
	//Test2()
}
