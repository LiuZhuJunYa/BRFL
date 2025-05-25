package RSCP

import (
	bls "github.com/kilic/bls12-381"
	"math/big"
)

// ComputeV 计算 V = (r + h_s * sk_s) * Q
func ComputeV(R, H_s, SK_S *big.Int) *bls.PointG2 {
	sum := new(big.Int).Add(R, new(big.Int).Mul(H_s, SK_S))
	sum.Mod(sum, blsOrder)

	// V = sum * Q (Q为G2的生成元)
	v := blsG2.New()
	blsG2.MulScalarBig(v, blsG2.One(), sum)
	return v
}

// ComputeUS 计算 U_s
func ComputeUS(
	r *big.Int,
	HiList []*big.Int,
	PKList []*bls.PointG1,
	UiList []*bls.PointG1,
	flag int,
) (US *bls.PointG1) {

	// 1. tmp1 = r * G1
	tmp1 := blsG1.New()
	blsG1.MulScalarBig(tmp1, blsG1.One(), r)

	// 2. 计算 \sum_{i != s} (U_i + H_i * pk_i)
	tmpSum := blsG1.New() // 先置为零点
	for i, Ui := range UiList {
		if i == flag {
			continue
		}
		tmp2 := ScalarMulG1(PKList[i], HiList[i]) // H_i * pk_i
		tmpSumPart := AddG1(Ui, tmp2)             // U_i + tmp2
		blsG1.Add(tmpSum, tmpSum, tmpSumPart)
	}

	// 3. U_s = tmp1 - tmpSum
	US = SubG1(tmp1, tmpSum)

	return
}
