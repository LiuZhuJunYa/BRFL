package RSCP

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	bls "github.com/kilic/bls12-381"
)

// -------------------- 全局参数 --------------------

var (
	// 建议在初始化时全局只创建一次 G1, G2 实例
	// kilic 的说明：同一个 Engine/G1/G2 对象不适合并发，需要多线程时应分别创建
	blsG1   = bls.NewG1()
	blsG2   = bls.NewG2()
	blsPair = bls.NewEngine()

	// BLS12-381 的群阶（与 Fr、G1、G2 同阶）
	blsOrder = blsG1.Q()
)

// Sigma 签名结果结构体
type Sigma struct {
	UI []*bls.PointG1
	V  *bls.PointG2
}

// Signer 签名者结构体
type Signer struct {
	PrivateKey *big.Int
	PublicKey  *bls.PointG1
}

// -------------------- 工具函数 --------------------

// SubG1 计算 p1 - p2
func SubG1(p1, p2 *bls.PointG1) *bls.PointG1 {
	ret := blsG1.New()
	blsG1.Sub(ret, p1, p2)
	return ret
}

// AddG1 计算 p1 + p2
func AddG1(p1, p2 *bls.PointG1) *bls.PointG1 {
	ret := blsG1.New()
	blsG1.Add(ret, p1, p2)
	return ret
}

// ScalarMulG1 计算 k * p
func ScalarMulG1(p *bls.PointG1, k *big.Int) *bls.PointG1 {
	ret := blsG1.New()
	blsG1.MulScalarBig(ret, p, k)
	return ret
}

// RandomPointG1 随机生成一个 G1 群元素 (即随机标量乘生成元)
func RandomPointG1() *bls.PointG1 {
	k := RandomZq()
	p := blsG1.New()
	// G1.One() 是生成元，MulScalarBig 做标量乘法
	blsG1.MulScalarBig(p, blsG1.One(), k)
	return p
}

// CompareG1 比较两个 G1 群元素是否相等
func CompareG1(p1, p2 *bls.PointG1) bool {
	return blsG1.Equal(p1, p2)
}

// RandomZq 在 Zq 中取一个随机数
func RandomZq() *big.Int {
	k, err := rand.Int(rand.Reader, blsOrder)
	if err != nil {
		panic(fmt.Sprintf("随机取数失败: %v", err))
	}
	return k
}

// NewSigner 生成 (sk, pk)
func NewSigner() *Signer {
	sk := RandomZq()
	pk := blsG1.New()
	blsG1.MulScalarBig(pk, blsG1.One(), sk) // pk = sk * G
	return &Signer{
		PrivateKey: sk,
		PublicKey:  pk,
	}
}

// HashToZq 将任意若干字节切片拼接做 SHA256，然后结果映射到 Z_q
func HashToZq(args ...interface{}) *big.Int {
	var buf []byte
	for _, arg := range args {
		switch v := arg.(type) {
		case []byte:
			buf = append(buf, v...)
		case *bls.PointG1:
			// ToUncompressed / ToBytes 都可以，这里用 ToUncompressed()
			b := blsG1.ToUncompressed(v)
			buf = append(buf, b...)
		case []*bls.PointG1:
			for _, g1 := range v {
				b := blsG1.ToUncompressed(g1)
				buf = append(buf, b...)
			}
		case *bls.PointG2:
			b := blsG2.ToUncompressed(v)
			buf = append(buf, b...)
		case *big.Int:
			buf = append(buf, v.Bytes()...)
		case []*big.Int:
			for _, bi := range v {
				buf = append(buf, bi.Bytes()...)
			}
		default:
			panic(fmt.Sprintf("不支持的类型: %T", v))
		}
	}

	h := sha256.Sum256(buf)
	hInt := new(big.Int).SetBytes(h[:])
	hInt.Mod(hInt, blsOrder) // 映射到有限域
	return hInt
}
