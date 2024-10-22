package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/cbergoon/merkletree"
)

const (
	ValDID     = "did:unitrust:88bEzHraJifHm5jGhV2d4TqF9neD"
	ValOsbiID  = "ep:Bdid:unitrust:88bEzHraJifHm5jGhV2d4TqF9neD00617728"
	ValLoginID = "jjchen"
)

var PrivateKey *ecdsa.PrivateKey
var PublicKey *ecdsa.PublicKey

func init() {
	PrivateKey = GenPrivateKey()
	PublicKey = GenPublicKey(PrivateKey)
}

type VCCredentialSubject struct {
	DID string

	// 全量信息
	LoginID string
	OsbiID  string

	// Merkle树
	MerkleRoot     []byte
	MerkleRootSign []byte
	Signer         *ecdsa.PublicKey
	Seed           []byte
}

type VPSubject struct {
	DID string

	// 选择性披露的内容
	OsbiID string

	//  Merkle树
	MerkleRoot     []byte
	MerkleRootSign []byte
	Signer         *ecdsa.PublicKey
	Seed           []byte
	// merkle 验证数据
	MerkleSibling [][]byte
	DataIndex     []int64
}

func initVCData() (*VC, *merkletree.MerkleTree) {

	seed := InitSeed()
	tree := buildMerkleTree(seed)
	treeRootHash := tree.MerkleRoot()
	treeRootSign := Sign(treeRootHash, PrivateKey).ToByte()

	return &VC{
		BasicVC: BasicVC{
			Context: []string{"https://www.w3.org/2018/credentials/v1"},
			ID:      "vc.528664930874818703",
			Types:   []string{"OTHER"},
			CredentialSubject: VCCredentialSubject{
				DID: ValDID,

				LoginID: ValLoginID,
				OsbiID:  ValOsbiID,

				MerkleRoot:     treeRootHash,
				MerkleRootSign: treeRootSign,
				Signer:         PublicKey,
				Seed:           seed,
			},
			Issuer:         ValDID,
			IssuanceDate:   "2024-08-26T10:14:14Z",
			ExpirationDate: "2286-11-21T01:46:39Z",
			VCTmplID:       "vctmpl.528664773890408591",
		},
		Proof: VcProof{
			Type:               "SM3WithSM2",
			Created:            "2024-08-26T10:14:14Z",
			VerificationMethod: "did:unitrust:88bEzHraJifHm5jGhV2d4TqF9neD#key-1",
			ProofPurpose:       "assertionMethod",
			ProofValue:         "AN1rKvtGSDhArLuSAmR6ddoATfbP8TSkxLjD1XB1xqGEHaLsPK4TwZ69tFcizA4SQAG7jsJDcjz1aU3p9SW5rxcZbYp1sQ6UW",
		},
	}, tree
}

func buildMerkleTree(seed []byte) *merkletree.MerkleTree {
	seedList := GenSeedList(seed, 2)
	var merkleTree []merkletree.Content
	merkleTree = append(merkleTree,
		MerkleTreeNode{"LoginID", string(seedList[0]) + ValLoginID},
		MerkleTreeNode{"OsbiID", string(seedList[1]) + ValOsbiID})

	tree, err := merkletree.NewTree(merkleTree)
	if err != nil {
		panic(fmt.Sprintf("build merkle tree fail:%s", err))
	}
	return tree
}

func generateVp(vc *VC, tree *merkletree.MerkleTree) *VP {
	vcCredentialSubject, _ := vc.CredentialSubject.(VCCredentialSubject)
	seed := vcCredentialSubject.Seed
	seedList := GenSeedList(seed, 2)

	path, index, err := tree.GetMerklePath(MerkleTreeNode{"OsbiID", string(seedList[1]) + ValOsbiID})
	if err != nil {
		panic("get merkle path fail:" + err.Error())
	}

	return &VP{
		BasicVP: BasicVP{
			VerifiableCredential: []BasicVC{
				{
					CredentialSubject: VPSubject{
						DID: ValDID,

						OsbiID: ValOsbiID,

						MerkleRoot:     vcCredentialSubject.MerkleRoot,
						MerkleRootSign: vcCredentialSubject.MerkleRootSign,
						Signer:         PublicKey,
						Seed:           seed,
						DataIndex:      index,
						MerkleSibling:  path,
					},
				},
			},
		},
	}
}

func verifyVP(vp *VP) bool {
	vpSubject, _ := vp.BasicVP.VerifiableCredential[0].CredentialSubject.(VPSubject)
	seed := vpSubject.Seed
	seedList := GenSeedList(seed, 2)

	// verify root
	var signature = new(Signature)
	signature.ByteToSign(vpSubject.MerkleRootSign)
	if !Verify(vpSubject.MerkleRoot, *signature, vpSubject.Signer) {
		return false
	}

	// verify content
	verified, _ := SPV(vpSubject.MerkleRoot, vpSubject.MerkleSibling, vpSubject.DataIndex, MerkleTreeNode{"OsbiID", string(seedList[1]) + vpSubject.OsbiID})
	return verified
}

func main() {
	vc, tree := initVCData()
	vp := generateVp(vc, tree)
	verified := verifyVP(vp)
	fmt.Println("verified:", verified)
}
