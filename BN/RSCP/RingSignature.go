package RSCP

import (
	"crypto/rand" // 产生随机数
	"fmt"
	"math/big" // 大整数运算

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// GenerateParams 初始化系统参数，生成 G1、G2 的生成元及群阶。
func GenerateParams() *Params {
	order := bn256.Order
	P := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	Q := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	return &Params{P: P, Q: Q, Order: order}
}

// GenerateSignerKey 生成一个签名者的密钥对。
// 返回 Signer 结构，包含私钥 SK_I 与公钥 PK_I。
func GenerateSignerKey(params *Params) (*Signer, error) {
	x, err := randomScalar(params.Order)
	if err != nil {
		return nil, err
	}
	pub := new(bn256.G1).ScalarMult(params.P, x)
	return &Signer{SK_I: x, PK_I: pub}, nil
}

// Sign 在给定环成员公钥列表和签名者私钥下，对消息 M 生成环签名。
//
//	params：系统参数
//	ring：所有成员的公钥列表
//	signer：签名者结构，包含 SK_I 与 PK_I
//	M：待签名消息
//	sIdx：签名者在环中的索引
func Sign(params *Params, ring []*bn256.G1, signer *Signer, M []byte, sIdx int) (*Signature, error) {
	n := len(ring)
	if sIdx < 0 || sIdx >= n {
		return nil, fmt.Errorf("签名者索引越界：%d", sIdx)
	}
	// 1. 为 i != sIdx 随机生成 U_i，并计算 h_i
	Us := make([]*bn256.G1, n)
	his := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		if i != sIdx {
			// 随机生成 U_i：调用 RandomG1
			_, U, err := bn256.RandomG1(rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("生成 U_i 失败: %v", err)
			}
			Us[i] = U
			his[i] = hashToZp(U, M, ring, params.Order)
		}
	}

	// 2. 随机选取 r
	r, err := randomScalar(params.Order)
	if err != nil {
		return nil, err
	}
	// 3. 计算 U_s = rP - ∑_{i≠s}(h_iPK_i + U_i)
	sumAll := sumHiPKiPlusUi(ring, his, Us)
	rP := new(bn256.G1).ScalarMult(params.P, r)
	U_s := new(bn256.G1).Add(rP, new(bn256.G1).Neg(sumAll))
	Us[sIdx] = U_s

	// 4. 计算 h_s
	his[sIdx] = hashToZp(U_s, M, ring, params.Order)

	// 5. 计算 V = (r + h_s * SK_I) * Q
	tmp := new(big.Int).Mul(his[sIdx], signer.SK_I)
	rv := new(big.Int).Add(r, tmp)
	V := new(bn256.G2).ScalarMult(params.Q, rv)
	return &Signature{U: Us, V: V}, nil
}

// Verify 对消息 M 和环签名进行验证。
//
//	params：系统参数
//	ring：所有成员的公钥列表
//	sig：待验证签名
//	M：原始消息
//
// 返回 true 则签名合法，否则非法。
func Verify(params *Params, ring []*bn256.G1, sig *Signature, M []byte) bool {
	n := len(ring)
	his := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		his[i] = hashToZp(sig.U[i], M, ring, params.Order)
	}
	left := bn256.Pair(params.P, sig.V)   // e(P, V)
	s := sumHiPKiPlusUi(ring, his, sig.U) // ∑[h_iPK_i + U_i]
	right := bn256.Pair(s, params.Q)      // e(sum, Q)
	return left.String() == right.String()
}
