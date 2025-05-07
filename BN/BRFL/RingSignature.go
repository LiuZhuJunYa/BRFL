package BRFL

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
	"math/big"
	"sync"
)

func Verify(Message []byte, PKList []*bn256.G1, SignerResult *Sigma) (Verify bool) {

	// 1. 计算 Hi 列表
	HiList := make([]*big.Int, len(PKList))
	for i, v := range SignerResult.UI {
		HiList[i] = HashToZq(Message, PKList, v)
	}

	// 2. 计算 e、S_{\text{sum}}、S_{\text{pt}}
	e := HashToZq(PKList, Message, SignerResult.T, SignerResult.C)

	sSum := new(bn256.G1).ScalarBaseMult(big.NewInt(0))
	var wg sync.WaitGroup // 并发同步
	var lock sync.Mutex   // 资源互斥锁，确保并发写入安全
	for i, v := range SignerResult.UI {
		wg.Add(1)

		go func(index int, value *bn256.G1) {
			defer wg.Done()

			// 计算 tmp2 = H_i \cdot \mathit{pk}_i
			tmp1 := ScalarMulG1(PKList[index], HiList[index])
			// 计算 tmpSumPart = U_i + tm1
			tmpSumPart := AddG1(value, tmp1)

			lock.Lock()
			sSum = AddG1(sSum, tmpSumPart)
			lock.Unlock()
		}(i, v)

	}
	wg.Wait() // 等待所有进程结束

	tmp2 := ScalarMulG1(SignerResult.RM, SignerResult.C)
	tmp3 := InvZq(e)
	tmp4 := new(bn256.G1).ScalarBaseMult(SignerResult.Pi)
	tmp5 := SubG1(SignerResult.T, tmp4)
	tmp6 := ScalarMulG1(tmp5, tmp3)
	sPt := AddG1(tmp2, tmp6)

	// 3. 比较 C_{\text{check}} = H\bigl(V \cdot S_{\text{sum}} \;\|\; S_{\text{pt}}\bigr)
	tmp7 := ScalarMulG1(sSum, SignerResult.V)
	cCheck := HashToZq(tmp7, sPt)

	Verify = CompareBigInts(SignerResult.C, cCheck)

	return
}

// Sign 签名函数
func Sign(Message []byte, PKList []*bn256.G1, SignerS *Signer) *Sigma {

	// 1.生成随机数 $r_M$ 并计算 $R_M = r_M \cdot P$，以混淆后续签名的可追踪性
	rM := RandomZq()
	RM := new(bn256.G1).ScalarBaseMult(rM)

	// 2. 生成随机数 $r_S$ ，得到中间值 $R_S = r_S \cdot P$ ，并基于哈希函数计算 $C_S$ 和 $S_S$
	rS := RandomZq()
	RS := new(bn256.G1).ScalarBaseMult(rS)
	CS := ComputeCS(rS, SignerS.PrivateKey, SignerS.PublicKey, RS)
	SS := ComputeSS(rS, CS, rM)

	// 3. 为环内其他成员（ $i \neq s$ ）随机分配辅助量 $U_i \in G$ ，并计算 H_i
	UiList := make([]*bn256.G1, len(PKList))
	HiList := make([]*big.Int, len(PKList))
	var flag int          // 记住公钥位置下标
	var wg sync.WaitGroup // 并发同步
	var lock sync.Mutex   // 资源互斥锁，确保并发写入安全
	for i, v := range PKList {
		if CompareG1(v, SignerS.PublicKey) {
			flag = i
			continue
		}
		wg.Add(1)

		go func(index int) {
			defer wg.Done()

			Ui := RandomPointG1()
			lock.Lock()
			UiList[index] = Ui
			HiList[index] = HashToZq(Message, PKList, Ui)
			lock.Unlock()
		}(i)
	}
	wg.Wait() // 等待所有进程结束

	// 4. 选择一个随机数 $r'_s \in (Z_q)^*$ ，计算  $U_s$ 和 $H_s$ 用于构造签名者自身的环量，并计算 V
	rS_ := RandomZq()
	US := ComputeUS(rS_, SignerS.PublicKey, UiList, HiList, PKList, flag)
	UiList[flag] = US
	HS := HashToZq(Message, PKList, US)
	V := ComputeV(rS, SignerS.PrivateKey, rS_, HS)

	// 5. 通过再一次随机数 $t \in (Z_q)^*$ 构造 $T = t \cdot P$ ，并计算 C、e、Pi
	t := RandomZq()
	T := new(bn256.G1).ScalarBaseMult(t)
	C := ComputeC(rS, SignerS.PrivateKey, SignerS.PublicKey, CS, RM, SS)
	e := HashToZq(PKList, Message, T, C)
	Pi := ComputePi(t, e, SS)

	return &Sigma{
		RM: RM,
		UI: UiList,
		V:  V,
		C:  C,
		T:  T,
		Pi: Pi,
	}
}
