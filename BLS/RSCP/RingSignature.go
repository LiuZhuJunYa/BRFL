package RSCP

import (
	bls "github.com/kilic/bls12-381"
	"math/big"
)

// Verify 验证环签名
func Verify(Message []byte, PKList []*bls.PointG1, SignerResult *Sigma) bool {
	n := len(PKList)

	// 1. 计算 Hi 列表
	HiList := make([]*big.Int, n)
	for i := range PKList {
		HiList[i] = HashToZq(SignerResult.UI[i], Message, PKList)
	}

	// 2. 验证 e(P, V) = e( \sum_i [Hi * PKi + Ui], Q )
	//
	// 这里的 P 相当于 G1 的生成元
	// 但是在 BN256 代码里写的是 new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	// 在 BLS12-381 下，可直接用 blsG1.One()
	P := blsG1.One()
	Q := blsG2.One()

	// left = e(P, V)
	engine := bls.NewEngine()
	engine.AddPair(P, SignerResult.V)
	leftGT := engine.Result()

	// 右边: tmpSum = Σ (Hi*PKi + Ui)
	tmpSum := blsG1.New()
	for i := range PKList {
		tmpPart1 := ScalarMulG1(PKList[i], HiList[i])
		tmpPart2 := AddG1(tmpPart1, SignerResult.UI[i])
		blsG1.Add(tmpSum, tmpSum, tmpPart2)
	}

	// right = e(tmpSum, Q)
	engine.Reset()
	engine.AddPair(tmpSum, Q)
	rightGT := engine.Result()

	// 比较配对结果
	return leftGT.Equal(rightGT)
}

// Sign 签名
func Sign(Message []byte, PKList []*bls.PointG1, SignerS *Signer) *Sigma {
	n := len(PKList)
	UiList := make([]*bls.PointG1, n)
	HiList := make([]*big.Int, n)

	// 找到签名者的公钥在 PKList 中的下标
	var flag int
	for i, pk := range PKList {
		if CompareG1(pk, SignerS.PublicKey) {
			flag = i
			break
		}
	}

	// 1. 除了 i = s 以外，选择随机的 U_i
	for i := 0; i < n; i++ {
		if i == flag {
			continue
		}
		UiList[i] = RandomPointG1()
	}

	// 2. 计算 Hi = HashToZq(Ui, Message, PKList) (i != s)
	for i := 0; i < n; i++ {
		if i == flag {
			continue
		}
		HiList[i] = HashToZq(UiList[i], Message, PKList)
	}

	// 3. 生成随机数 r
	r := RandomZq()

	// 4. 计算 U_s
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
