package RSCP

import (
	"fmt"
	bls "github.com/kilic/bls12-381"
	"testing"
)

var MessageTrue = []byte("这是用来正确签名的信息。")
var MessageFalse = []byte("这是用来错误验证的信息。")

func TestRingSignature(t *testing.T) {
	fmt.Println("=== 开始测试 BRFL 环签名方案 ===")

	// 构造一个大小为4的环
	n := 4
	var L []*Signer
	var List []*bls.PointG1 // 环签名的公钥列表
	SignerS := 2
	for i := 0; i < n; i++ {
		signer := NewSigner()
		L = append(L, signer)
		List = append(List, signer.PublicKey)
	}
	fmt.Printf("已生成 %d 个签名者\n", n)

	// 开始签名
	SignerResult := Sign(MessageTrue, List, L[SignerS])

	//fmt.Println("签名结果 Sigma 为：")
	//fmt.Println("UI 为：", SignerResult.UI)
	//fmt.Println("V 为：", SignerResult.V)

	Verify1 := Verify(MessageTrue, List, SignerResult)
	fmt.Println(Verify1)

	Verify2 := Verify(MessageFalse, List, SignerResult)
	fmt.Println(Verify2)
}
