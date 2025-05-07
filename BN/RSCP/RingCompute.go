package RSCP

import (
	"crypto/rand"   // 产生随机数
	"crypto/sha256" // SHA-256 哈希函数
	"math/big"      // 大整数运算

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// hashToZp 对 (U || M || 环成员公钥列表) 进行 SHA-256 哈希，映射到 Z_p。
//
//	U：单个 G1 群元素
//	M：消息字节串
//	ring：公钥列表
//	order：群的阶 p
func hashToZp(U *bn256.G1, M []byte, ring []*bn256.G1, order *big.Int) *big.Int {
	// 将 U 序列化为字节
	uBytes := U.Marshal()
	h := sha256.New()
	h.Write(uBytes)
	h.Write(M)
	for _, pk := range ring {
		h.Write(pk.Marshal())
	}
	digest := h.Sum(nil)
	z := new(big.Int).SetBytes(digest)
	return z.Mod(z, order) // 返回 digest mod p
}

// sumHiPKiPlusUi 计算 ∑[h_i * PK_i + U_i]，在 G1 群内累加。
//
//	ring：公钥列表
//	his：哈希值列表 h_i
//	Us：随机元素列表 U_i
func sumHiPKiPlusUi(ring []*bn256.G1, his []*big.Int, Us []*bn256.G1) *bn256.G1 {
	S := new(bn256.G1) // 初始化为群单位元
	for i := range ring {
		// 仅对已生成的 (h_i, U_i) 项进行累加，跳过 nil 条目
		if his[i] == nil || Us[i] == nil {
			continue
		}
		// tmp1 = h_i * PK_i
		tmp1 := new(bn256.G1).ScalarMult(ring[i], his[i])
		// tmp = tmp1 + U_i
		tmp := new(bn256.G1).Add(tmp1, Us[i])
		// 累加到 S
		S.Add(S, tmp)
	}
	return S
}

// randomScalar 返回一个模 p 的随机数，用于生成私钥或内部随机值。
func randomScalar(order *big.Int) (*big.Int, error) {
	r, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	return r, nil
}
