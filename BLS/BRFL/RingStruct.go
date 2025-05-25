package BRFL

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	bls "github.com/kilic/bls12-381"
)

// -------------------- 全局参数 --------------------
var (
	// G1 group instance and group order
	g1    = bls.NewG1()
	Order = g1.Q()
)

// Sigma 签名结果结构体
type Sigma struct {
	RM *bls.PointG1
	UI []*bls.PointG1
	V  *big.Int
	C  *big.Int
	T  *bls.PointG1
	Pi *big.Int
}

// Signer 签名者结构体
type Signer struct {
	PrivateKey *big.Int
	PublicKey  *bls.PointG1
}

// -------------------- 工具函数 --------------------

// CompareBigInts 判断 a 和 b 在数值上是否相等
func CompareBigInts(a, b *big.Int) bool {
	return a.Cmp(b) == 0
}

// InvZq 计算有限域标量 a 的乘法逆元 a^{-1}（模 Order）
// 如果 a 与 Order 不互素，则返回 nil
func InvZq(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, Order)
}

// SubG1 计算两个 G1 群元素 p1 和 p2 的差值 p1 - p2，等价于 p1 + (-p2)
func SubG1(p1, p2 *bls.PointG1) *bls.PointG1 {
	n := g1.New()
	g1.Neg(n, p2)
	r := g1.New()
	g1.Add(r, p1, n)
	return r
}

// AddG1 计算两个 G1 群元素 p1 和 p2 的相加，返回结果落回 G1 域
func AddG1(p1, p2 *bls.PointG1) *bls.PointG1 {
	r := g1.New()
	g1.Add(r, p1, p2)
	return r
}

// CompareG1 比较两个 G1 群元素在字节序列上的相等性，如果完全相同则返回 true
func CompareG1(p1, p2 *bls.PointG1) bool {
	b1 := g1.ToBytes(p1)
	b2 := g1.ToBytes(p2)
	return bytes.Equal(b1, b2)
}

// RandomPointG1 随机生成一个 G1 群元素，返回点。实现：随机标量 k * G
func RandomPointG1() *bls.PointG1 {
	// 生成随机标量 k
	k, err := rand.Int(rand.Reader, Order)
	if err != nil {
		panic(fmt.Sprintf("生成随机标量失败: %v", err))
	}
	// 基点
	base := g1.One()
	r := g1.New()
	// 标量乘
	g1.MulScalarBig(r, base, k)
	return r
}

// AddZq 计算两个有限域标量 a 和 b 的和，并对 Order 取模
func AddZq(a, b *big.Int) *big.Int {
	sum := new(big.Int).Add(a, b)
	return sum.Mod(sum, Order)
}

// SubZq 计算两个有限域标量 a 和 b 的差值 a - b，并对 Order 取模
func SubZq(a, b *big.Int) *big.Int {
	difference := new(big.Int).Sub(a, b)
	return difference.Mod(difference, Order)
}

// ScalarMulG1 计算给定 G1 点 p 与标量 k 的乘积，返回新的群元素
func ScalarMulG1(p *bls.PointG1, k *big.Int) *bls.PointG1 {
	r := g1.New()
	g1.MulScalarBig(r, p, k)
	return r
}

// MulZq 计算两个有限域标量 a 和 b 的乘积，并对 Order 取模
func MulZq(a, b *big.Int) *big.Int {
	prod := new(big.Int).Mul(a, b)
	return prod.Mod(prod, Order)
}

// RandomZq 在 Zq* 的有限域内取一个随机数
func RandomZq() *big.Int {
	k, err := rand.Int(rand.Reader, Order)
	if err != nil {
		fmt.Println("在 Zq* 的有限域内取随机数失败：", err)
		return nil
	}
	return k
}

// NewSigner 用于系统中生成 Signer (sk_i, pk_i)
func NewSigner() *Signer {
	// 私钥
	sk := RandomZq()
	// 公钥 = sk * G
	base := g1.One()
	pk := g1.New()
	g1.MulScalarBig(pk, base, sk)
	return &Signer{PrivateKey: sk, PublicKey: pk}
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
		case *bls.PointG1:
			// 如果是 *bn256.G1 类型，序列化后拼接
			concatenated = append(concatenated, g1.ToBytes(v)...)
		case []*bls.PointG1:
			// 如果是 []bn256.G1 类型，逐个序列化后拼接
			for _, p := range v {
				concatenated = append(concatenated, g1.ToBytes(p)...)
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
	hashMod := new(big.Int).Mod(hashInt, Order) // 取模，确保在有限域内

	return hashMod
}
