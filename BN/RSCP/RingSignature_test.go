package RSCP

import (
	"testing"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// TestRingSignature 基于 bn256 曲线测试环签名的正确性
func TestRingSignature(t *testing.T) {
	params := GenerateParams()
	n := 5

	// 生成环成员签名者结构
	signers := make([]*Signer, n)
	ringPubs := make([]*bn256.G1, n)
	for i := 0; i < n; i++ {
		s, err := GenerateSignerKey(params)
		if err != nil {
			t.Fatalf("生成Signer失败: %v", err)
		}
		signers[i] = s
		ringPubs[i] = s.PK_I
	}

	// 指定签名者索引
	sIdx := 2
	message := []byte("Hello BRFL Ring Signature")

	// 生成签名
	sig, err := Sign(params, ringPubs, signers[sIdx], message, sIdx)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 验证签名
	if !Verify(params, ringPubs, sig, message) {
		t.Error("签名验证失败")
	}
}
