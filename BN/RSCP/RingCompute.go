package RSCP

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
	"math/big"
)

// ComputeSum 排除 signer_index 后计算 H_i * PK_i + U_i 的和
func ComputeSum(H_i []*big.Int, PK_List []*bn256.G1, U_i []*bn256.G1, signer_index int) *bn256.G1 {
	// 初始化结果为 G1 群中的零点
	sum := new(bn256.G1)

	// 遍历所有 H_i, PK_List 和 U_i
	for i := 0; i < len(H_i); i++ {
		if i == signer_index {
			// 跳过 signer_index
			continue
		}

		// 计算 H_i * PK_i
		H_PK := new(bn256.G1).ScalarMult(PK_List[i], H_i[i])

		// 计算 H_i * PK_i + U_i
		partialSum := new(bn256.G1).Add(H_PK, U_i[i])

		// 将结果累加到 sum
		sum.Add(sum, partialSum)
	}

	return sum
}

// VerifyPairing 验证 e(P, V) 是否等于 e(Sum, Q)
func VerifyPairing(Sum *bn256.G1, V *bn256.G2) bool {
	// 计算 e(P, V)，其中 P 是 G1 的生成元
	P := new(bn256.G1).ScalarBaseMult(big.NewInt(1)) // G1 的生成元
	pairing1 := bn256.Pair(P, V)

	// 计算 e(Sum, Q)，其中 Q 是 G2 的生成元
	Q := new(bn256.G2).ScalarBaseMult(big.NewInt(1)) // G2 的生成元
	pairing2 := bn256.Pair(Sum, Q)

	// 比较两者是否相等
	return pairing1.String() == pairing2.String()
}

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
