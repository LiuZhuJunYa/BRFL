package BRFL

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// -------------------- 全局参数 --------------------

// Sigma 签名结果结构体
type Sigma struct {
	RM *bn256.G1
	UI []*bn256.G1
	V  *big.Int
	C  *big.Int
	T  *bn256.G1
	Pi *big.Int
}

// Signer 签名者结构体
type Signer struct {
	PrivateKey *big.Int
	PublicKey  *bn256.G1
}

// -------------------- 工具函数 --------------------

// CompareBigInts 判断 a 和 b 在数值上是否相等
func CompareBigInts(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}

// InvZq 计算有限域标量 a 的乘法逆元 a^{-1}（模 Order）
// 如果 a 与 Order 不互素，则返回 nil
func InvZq(a *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(a, bn256.Order)
	return inv
}

// SubG1 计算两个 G1 群元素 p1 和 p2 的差值 p1 - p2，等价于 p1 + (-p2)
func SubG1(p1, p2 *bn256.G1) *bn256.G1 {
	negP2 := new(bn256.G1).Neg(p2)
	return new(bn256.G1).Add(p1, negP2)
}

// AddG1 计算两个 G1 群元素 p1 和 p2 的相加，返回结果落回 G1 域
func AddG1(p1, p2 *bn256.G1) *bn256.G1 {
	return new(bn256.G1).Add(p1, p2)
}

// CompareG1 比较两个 G1 群元素在字节序列上的相等性，如果完全相同则返回 true
func CompareG1(p1, p2 *bn256.G1) bool {
	b1 := p1.Marshal()
	b2 := p2.Marshal()
	return bytes.Equal(b1, b2)
}

// RandomPointG1 随机生成一个 G1 群元素，返回点。实现：随机标量 k * G
func RandomPointG1() *bn256.G1 {
	k := RandomZq()
	return new(bn256.G1).ScalarBaseMult(k)
}

// AddZq 计算两个有限域标量 a 和 b 的和，并对 Order 取模
func AddZq(a, b *big.Int) *big.Int {
	sum := new(big.Int).Add(a, b)
	return sum.Mod(sum, bn256.Order)
}

// SubZq 计算两个有限域标量 a 和 b 的差值 a - b，并对 Order 取模
func SubZq(a, b *big.Int) *big.Int {
	difference := new(big.Int).Sub(a, b)
	return difference.Mod(difference, bn256.Order)
}

// ScalarMulG1 计算给定 G1 点 p 与标量 k 的乘积，返回新的群元素
func ScalarMulG1(p *bn256.G1, k *big.Int) *bn256.G1 {
	return new(bn256.G1).ScalarMult(p, k)
}

// MulZq 计算两个有限域标量 a 和 b 的乘积，并对 Order 取模
func MulZq(a, b *big.Int) *big.Int {
	prod := new(big.Int).Mul(a, b)
	return prod.Mod(prod, bn256.Order)
}

// RandomZq 在 Zq* 的有限域内取一个随机数
func RandomZq() *big.Int {
	k, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		fmt.Println("在 Zq* 的有限域内取随机数失败：", err)
		return nil
	}
	return k
}

// NewSigner 用于系统中生成 Signer (sk_i, pk_i)
func NewSigner() *Signer {
	// 1. 随机生成私钥标量
	privateKey := RandomZq()

	// 2. 通过基点做标量乘法得到公钥
	pub := new(bn256.G1).ScalarBaseMult(privateKey)
	return &Signer{
		PrivateKey: privateKey,
		PublicKey:  pub,
	}
}

// HashToZq 将任意若干字节切片拼接做 SHA256，然后结果映射到 Z_q
func HashToZq(args ...interface{}) *big.Int {
	// 初始化拼接的字节数组
	var concatenated []byte

	// 遍历输入参数
	for _, arg := range args {
		switch v := arg.(type) {
		case []byte:
			// 如果是 []byte 类型，直接拼接
			concatenated = append(concatenated, v...)
		case *bn256.G1:
			// 如果是 *bn256.G1 类型，序列化后拼接
			concatenated = append(concatenated, v.Marshal()...)
		case []*bn256.G1:
			// 如果是 []bn256.G1 类型，逐个序列化后拼接
			for _, g1 := range v {
				concatenated = append(concatenated, g1.Marshal()...)
			}
		case *big.Int:
			// 如果是 *big.Int 类型，将其字节表示拼接
			concatenated = append(concatenated, v.Bytes()...)
		case []*big.Int:
			// 如果是 []*big.Int 类型，逐个序列化后拼接
			for _, bi := range v {
				concatenated = append(concatenated, bi.Bytes()...)
			}
		default:
			// 如果遇到未知类型，抛出错误
			panic(fmt.Sprintf("不支持的类型: %T", v))
		}
	}

	// 使用 SHA256 对拼接结果进行哈希
	hash := sha256.Sum256(concatenated)

	// 将哈希结果转换为有限域中的元素
	hashInt := new(big.Int).SetBytes(hash[:])
	hashMod := new(big.Int).Mod(hashInt, bn256.Order) // 取模，确保在有限域内

	return hashMod
}
