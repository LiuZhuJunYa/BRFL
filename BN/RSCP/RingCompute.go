package RSCP

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
	"math/big"
)

func ComputeV(R, H_s, SK_S *big.Int) *bn256.G2 {
	// 计算 h_s * sk_s
	h_s_sk_s := new(big.Int).Mul(H_s, SK_S)

	// 计算 r + h_s * sk_s
	sum := new(big.Int).Add(R, h_s_sk_s)

	// 模群阶 (bn256.Order)
	sum.Mod(sum, bn256.Order)

	// 使用 G2 的生成元计算 v = sum * Q
	v := new(bn256.G2).ScalarBaseMult(sum)

	return v
}

func ComputeUS(r *big.Int, HiList []*big.Int, PKList []*bn256.G1, UiList []*bn256.G1, flag int) (US *bn256.G1) {

	// 1. 计算 tmp1 = r \cdot P
	tmp1 := new(bn256.G1).ScalarBaseMult(r)

	// 2. 计算 tmpSum = \sum_{i \ne s}\Bigl(U_i + H_i \cdot \mathit{pk}_i\Bigr)
	tmpSum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	for i, v := range UiList {
		if flag == i {
			continue
		}
		// 计算 tmp2 = H_i \cdot \mathit{pk}_i
		tmp2 := ScalarMulG1(PKList[i], HiList[i])
		// 计算 tmpSumPart = U_i + tmp2
		tmpSumPart := AddG1(v, tmp2)

		tmpSum = AddG1(tmpSum, tmpSumPart)
	}

	// 3. 计算 tmp1 - tmpSum
	US = SubG1(tmp1, tmpSum)

	return
}
