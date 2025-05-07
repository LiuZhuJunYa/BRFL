package RSCP

import (
	"math/big" // 大整数运算

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// Params 保存系统公用参数：
//
//	P：G1 群的生成元
//	Q：G2 群的生成元
//	Order：群的阶 p
//
// 注意：bn256.Order 为内置阶。
type Params struct {
	P     *bn256.G1
	Q     *bn256.G2
	Order *big.Int
}

// Signer 表示环签名方案中的签名者结构：
//
//	SK_I：私钥 x_i （Z_p 中的随机值）
//	PK_I：公钥 PK_i = x_i * P
//
// 名称对应公式中常用记法，可增强可读性。
type Signer struct {
	SK_I *big.Int  // 私钥 x_i
	PK_I *bn256.G1 // 公钥 PK_i = x_i * P
}

// Signature 表示环签名结果：
//
//	U：长度为 n 的 G1 元素列表（U_1, U_2, ..., U_n）
//	V：G2 群中的元素
//
// 最终签名为 (U, V)，用于验证参数完整性与签名者匿名性。
type Signature struct {
	U []*bn256.G1
	V *bn256.G2
}
