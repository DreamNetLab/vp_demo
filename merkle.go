package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/cbergoon/merkletree"
)

type MerkleTreeNode struct {
	Key string
	Val string
}

func (m MerkleTreeNode) CalculateHash() ([]byte, error) {
	return CalCombineHash([]byte(m.Key), []byte(m.Val))
}

func CalCombineHash(left, right []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(append(left, right...)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (m MerkleTreeNode) Equals(other merkletree.Content) (bool, error) {
	otherCtx, ok := other.(MerkleTreeNode)
	if !ok {
		return false, errors.New("value is not of type MerkleTreeNode")
	}
	return (m.Key == otherCtx.Key) && (m.Val == otherCtx.Val), nil
}

func SPV(merkleRoot []byte, merklePath [][]byte, index []int64, treeNode MerkleTreeNode) (bool, error) {
	nodeHash, err := treeNode.CalculateHash()
	if err != nil {
		return false, err
	}

	currentHash := nodeHash
	for i := 0; i < len(merklePath); i++ {
		if index[i] == 0 { // path 中哈希是左节点
			currentHash, _ = CalCombineHash(merklePath[i], currentHash)
		} else {
			currentHash, _ = CalCombineHash(currentHash, merklePath[i])
		}
	}
	if !bytes.Equal(merkleRoot, currentHash) {
		return false, nil
	}
	return true, nil
}

func InitSeed() []byte {
	// 创建一个 64 位的随机数
	var b [8]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return []byte{0}
	}

	// 将随机字节转为 int64 类型
	//seed := int64(binary.LittleEndian.Uint64(b[:]))
	return b[:]
}

func GenSeedList(seed []byte, n int) [][]byte {
	var seedList [][]byte
	curSeed := sha256.Sum256(seed)
	for i := 0; i < n; i++ {
		seedList = append(seedList, curSeed[:])
		curSeed = sha256.Sum256(curSeed[:])
	}
	return seedList
}
