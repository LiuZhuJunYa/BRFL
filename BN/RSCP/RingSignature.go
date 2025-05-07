package RSCP

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
	"math/big"
)

func Verify(Message []byte, PKList []*bn256.G1, SignerResult *Sigma) bool {

	// 1. 计算 Hi 列表
	HiList := make([]*big.Int, len(PKList))
	for i, v := range SignerResult.UI {
		HiList[i] = HashToZq(v, Message, PKList)
	}

	// 2. 验证 e(P,V)=e(i=1∑n[hi⋅PKi+Ui],Q).
	P := new(bn256.G1).ScalarBaseMult(big.NewInt(1)) // G1 的生成元
	Q := new(bn256.G2).ScalarBaseMult(big.NewInt(1)) // G2 的生成元
	tmp1 := bn256.Pair(P, SignerResult.V)
	tmpSum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i, v := range HiList {
		tmp2 := ScalarMulG1(PKList[i], v)
		tmp3 := AddG1(tmp2, SignerResult.UI[i])
		tmpSum = AddG1(tmpSum, tmp3)
	}
	tmp4 := bn256.Pair(tmpSum, Q)

	var flag bool

	if tmp1.String() == tmp4.String() {
		flag = true
	} else {
		flag = false
	}

	return flag
}

// Sign 签名函数
func Sign(Message []byte, PKList []*bn256.G1, SignerS *Signer) (SignResult *Sigma) {

	var flag int // 记住公钥位置下标
	UiList := make([]*bn256.G1, len(PKList))
	HiList := make([]*big.Int, len(PKList))

	// 1、除了 i=s 以外，选择随机的 U_i 属于 G1

	for i, v := range PKList {
		if CompareG1(v, SignerS.PublicKey) {
			flag = i
			continue
		}
		Ui := RandomPointG1()
		UiList[i] = Ui
	}

	for i, v := range PKList {
		if CompareG1(v, SignerS.PublicKey) {
			continue
		}
		HiList[i] = HashToZq(UiList[i], Message, PKList)
	}

	// 3. 生成随机数 $r$
	r := RandomZq()

	// 4. 计算 US
	US := ComputeUS(r, HiList, PKList, UiList, flag)
	UiList[flag] = US

	// 5. 计算 hS
	hS := HashToZq(US, Message, PKList)

	// 6. 计算 V
	V := ComputeV(r, hS, SignerS.PrivateKey)

	return &Sigma{
		UI: UiList,
		V:  V,
	}
}
