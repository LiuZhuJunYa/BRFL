package BRFL

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
	"math/big"
	"sync"
)

func ComputePi(t *big.Int, e *big.Int, SS *big.Int) (Pi *big.Int) {

	// 1. 计算 tmp1 = e \cdot S_s
	tmp1 := MulZq(e, SS)

	Pi = SubZq(t, tmp1)
	return
}

func ComputeC(rS *big.Int, skS *big.Int, pkS *bn256.G1, CS *big.Int, RM *bn256.G1, SS *big.Int) (C *big.Int) {

	// 1. 计算 tmp1 = r_s \cdot \mathit{sk}_s
	tmp1 := MulZq(rS, skS)

	// 2. 计算 tmp2 = tmp1 \cdot \mathit{pk}_s
	tmp2 := ScalarMulG1(pkS, tmp1)

	// 3. 计算 tmp3 = C_s \cdot R_M
	tmp3 := ScalarMulG1(RM, CS)

	// 4. 计算 tmp4 = S_s \cdot P
	tmp4 := new(bn256.G1).ScalarBaseMult(SS)

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

func ComputeUS(rS_ *big.Int, pkS *bn256.G1, UiList []*bn256.G1, HiList []*big.Int, PKList []*bn256.G1, flag int) (US *bn256.G1) {

	// 1. 计算 tmp1 = r'_s \cdot \mathit{pk}_s
	tmp1 := ScalarMulG1(pkS, rS_)

	// 2. 计算 tmpSum = \sum_{i \ne s}\Bigl(U_i + H_i \cdot \mathit{pk}_i\Bigr)
	tmpSum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	var wg sync.WaitGroup // 并发同步
	var lock sync.Mutex   // 资源互斥锁，确保并发写入安全
	for i, v := range UiList {
		if flag == i {
			continue
		}
		wg.Add(1)

		go func(index int, value *bn256.G1) {
			defer wg.Done()

			// 计算 tmp2 = H_i \cdot \mathit{pk}_i
			tmp2 := ScalarMulG1(PKList[index], HiList[index])
			// 计算 tmpSumPart = U_i + tmp2
			tmpSumPart := AddG1(value, tmp2)
			lock.Lock()
			tmpSum = AddG1(tmpSum, tmpSumPart)
			lock.Unlock()
		}(i, v)
	}
	wg.Wait() // 等待所有进程结束

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

func ComputeCS(rS *big.Int, skS *big.Int, pkS *bn256.G1, RS *bn256.G1) (CS *big.Int) {

	// 1. 计算 tmp1 = r_s \cdot \mathit{sk}_s
	tmp1 := MulZq(rS, skS)

	// 2. 计算 tmp2 = tmp1 \cdot \mathit{pk}_s
	tmp2 := ScalarMulG1(pkS, tmp1)

	// 3. 计算 C_s = H\bigl(r_s \cdot \mathit{sk}_s \cdot \mathit{pk}_s \,\|\, R_s\bigr)
	CS = HashToZq(tmp2, RS)

	return
}
