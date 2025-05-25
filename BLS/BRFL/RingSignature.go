package BRFL

import (
	bls "github.com/kilic/bls12-381"
	"math/big"
)

func Verify(Message []byte, PKList []*bls.PointG1, SignerResult *Sigma) (Verify bool) {

	// 1. 计算 Hi 列表
	HiList := make([]*big.Int, len(PKList))
	for i, v := range SignerResult.UI {
		HiList[i] = HashToZq(Message, PKList, v)
	}

	// 2. 计算 e、S_{\text{sum}}、S_{\text{pt}}
	e := HashToZq(PKList, Message, SignerResult.T, SignerResult.C)

	sSum := g1.New()
	for i, v := range SignerResult.UI {
		// 计算 tmp2 = H_i \cdot \mathit{pk}_i
		tmp1 := ScalarMulG1(PKList[i], HiList[i])
		// 计算 tmpSumPart = U_i + tm1
		tmpSumPart := AddG1(v, tmp1)

		sSum = AddG1(sSum, tmpSumPart)
	}

	tmp2 := ScalarMulG1(SignerResult.RM, SignerResult.C)
	tmp3 := InvZq(e)
	base := g1.One()
	tmp4 := g1.New()
	g1.MulScalarBig(tmp4, base, SignerResult.Pi)
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
func Sign(Message []byte, PKList []*bls.PointG1, SignerS *Signer) *Sigma {

	// 1.生成随机数 $r_M$ 并计算 $R_M = r_M \cdot P$，以混淆后续签名的可追踪性
	rM := RandomZq()
	base := g1.One()
	RM := g1.New()
	g1.MulScalarBig(RM, base, rM)

	// 2. 生成随机数 $r_S$ ，得到中间值 $R_S = r_S \cdot P$ ，并基于哈希函数计算 $C_S$ 和 $S_S$
	rS := RandomZq()
	RS := g1.New()
	g1.MulScalarBig(RS, base, rS)
	CS := ComputeCS(rS, SignerS.PrivateKey, SignerS.PublicKey, RS)
	SS := ComputeSS(rS, CS, rM)

	//var wg sync.WaitGroup
	//var t *big.Int
	//var T *bls.PointG1
	//var C *big.Int
	//var e *big.Int
	//var Pi *big.Int
	//wg.Add(1) // 需要等待 n 个并发任务完成
	//go func() {
	//	defer wg.Done()
	//	// 执行任务
	//	t = RandomZq()
	//	T = g1.New()
	//	g1.MulScalarBig(T, base, t)
	//	C = ComputeC(rS, SignerS.PrivateKey, SignerS.PublicKey, CS, RM, SS)
	//	e = HashToZq(PKList, Message, T, C)
	//	Pi = ComputePi(t, e, SS)
	//}()

	// 3. 为环内其他成员（ $i \neq s$ ）随机分配辅助量 $U_i \in G$ ，并计算 H_i
	UiList := make([]*bls.PointG1, len(PKList))
	HiList := make([]*big.Int, len(PKList))
	var flag int // 记住公钥位置下标
	for i, v := range PKList {
		if CompareG1(v, SignerS.PublicKey) {
			flag = i
			continue
		}
		Ui := RandomPointG1()
		UiList[i] = Ui
		HiList[i] = HashToZq(Message, PKList, Ui)
	}

	// 4. 选择一个随机数 $r'_s \in (Z_q)^*$ ，计算  $U_s$ 和 $H_s$ 用于构造签名者自身的环量，并计算 V
	rS_ := RandomZq()
	US := ComputeUS(rS_, SignerS.PublicKey, UiList, HiList, PKList, flag)
	UiList[flag] = US
	HS := HashToZq(Message, PKList, US)
	V := ComputeV(rS, SignerS.PrivateKey, rS_, HS)

	// 5. 通过再一次随机数 $t \in (Z_q)^*$ 构造 $T = t \cdot P$ ，并计算 C、e、Pi
	//wg.Wait() // 阻塞，直到全部任务完成
	t := RandomZq()
	T := g1.New()
	g1.MulScalarBig(T, base, t)
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
