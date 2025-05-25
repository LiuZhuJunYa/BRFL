package BRFL

import (
	bls "github.com/kilic/bls12-381"
	"math/big"
)

func ComputePi(t *big.Int, e *big.Int, SS *big.Int) (Pi *big.Int) {

	// 1. 计算 tmp1 = e \cdot S_s
	tmp1 := MulZq(e, SS)

	Pi = SubZq(t, tmp1)
	return
}

func ComputeC(rS *big.Int, skS *big.Int, pkS *bls.PointG1, CS *big.Int, RM *bls.PointG1, SS *big.Int) (C *big.Int) {

	// 1. 计算 tmp1 = r_s \cdot \mathit{sk}_s
	tmp1 := MulZq(rS, skS)

	// 2. 计算 tmp2 = tmp1 \cdot \mathit{pk}_s
	tmp2 := ScalarMulG1(pkS, tmp1)

	// 3. 计算 tmp3 = C_s \cdot R_M
	tmp3 := ScalarMulG1(RM, CS)

	// 4. 计算 tmp4 = S_s \cdot P
	base := g1.One()
	tmp4 := g1.New()
	g1.MulScalarBig(tmp4, base, SS)

	// 5. 计算 tmp3 + tmp4
	tmp5 := AddG1(tmp3, tmp4)

	C = HashToZq(tmp2, tmp5)

	return
}

func ComputeV(rS *big.Int, skS *big.Int, rS_ *big.Int, HS *big.Int) (V *big.Int) {

	// 1. 计算 tmp1 = r_s \cdot \mathit{sk}_s
	tmp1 := MulZq(rS, skS)

	// 2. 计算 tmp2 = (r'_s + H_s)^\top
	tmp := AddZq(rS_, HS)
	tmp2 := InvZq(tmp)

	V = MulZq(tmp1, tmp2)
	return
}

func ComputeUS(rS_ *big.Int, pkS *bls.PointG1, UiList []*bls.PointG1, HiList []*big.Int, PKList []*bls.PointG1, flag int) (US *bls.PointG1) {

	// 1. 计算 tmp1 = r'_s \cdot \mathit{pk}_s
	tmp1 := ScalarMulG1(pkS, rS_)

	// 2. 计算 tmpSum = \sum_{i \ne s}\Bigl(U_i + H_i \cdot \mathit{pk}_i\Bigr)
	tmpSum := g1.New()
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

func ComputeSS(rS *big.Int, CS *big.Int, rM *big.Int) (SS *big.Int) {

	// 1. 计算 tmp1 = C_s \cdot r_M
	tmp1 := MulZq(CS, rM)

	// 2. 计算 \quad S_s = r_s - C_s \cdot r_M
	SS = SubZq(rS, tmp1)
	return
}

func ComputeCS(rS *big.Int, skS *big.Int, pkS *bls.PointG1, RS *bls.PointG1) (CS *big.Int) {

	// 1. 计算 tmp1 = r_s \cdot \mathit{sk}_s
	tmp1 := MulZq(rS, skS)

	// 2. 计算 tmp2 = tmp1 \cdot \mathit{pk}_s
	tmp2 := ScalarMulG1(pkS, tmp1)

	// 3. 计算 C_s = H\bigl(r_s \cdot \mathit{sk}_s \cdot \mathit{pk}_s \,\|\, R_s\bigr)
	CS = HashToZq(tmp2, RS)

	return
}
