package main

import (
	"fmt"
	"time"

	// 假设在 go.mod 中，您已经声明了 module "BRFL"
	// 并且 BN/BRFL 和 BN/RSCP 这两个子包正好对应下面的 import
	brfl "BRFL/BN/BRFL"
	rscp "BRFL/BN/RSCP"

	"crypto/rand"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/google"
)

// messageSize 指定要签名的消息大小（字节数），仅作示例
const messageSize = 128

func main() {
	// ------------------------------
	// 1. 参数可根据需要自行调整
	// ------------------------------
	ringSize := 100 // 环大小 n
	trials := 10    // 每种方案重复签名-验证测试的次数，以便取平均值

	// 生成随机消息（也可以用固定字符串）
	msg := make([]byte, messageSize)
	rand.Read(msg) // 用随机数填充

	// ------------------------------
	// 2. 生成 ringSize 个签名者 (Signers)，并收集公钥
	// ------------------------------
	var brflSigners []*brfl.Signer
	var brflPubKeys []*bn256.G1

	var rscpSigners []*rscp.Signer
	var rscpPubKeys []*bn256.G1

	for i := 0; i < ringSize; i++ {
		// BRFL
		s1 := brfl.NewSigner()
		brflSigners = append(brflSigners, s1)
		brflPubKeys = append(brflPubKeys, s1.PublicKey)

		// RSCP
		s2 := rscp.NewSigner()
		rscpSigners = append(rscpSigners, s2)
		rscpPubKeys = append(rscpPubKeys, s2.PublicKey)
	}

	// 设定本次演示中，要让“第0号签名者”实际执行签名（仅示例）
	signerIndex := 0

	// 为了减少干扰，这里只固定一个签名者，可以改成随机选
	signerBRFL := brflSigners[signerIndex]
	signerRSCP := rscpSigners[signerIndex]

	// ------------------------------
	// 3. 测试 BRFL 环签名的时间与大小
	// ------------------------------
	var totalSignTimeBRFL time.Duration
	var totalVerifyTimeBRFL time.Duration
	var totalSigSizeBRFL int64

	for t := 0; t < trials; t++ {
		// （a）签名
		startSign := time.Now()
		sigBRFL := brfl.Sign(msg, brflPubKeys, signerBRFL)
		endSign := time.Now()

		signTime := endSign.Sub(startSign)
		totalSignTimeBRFL += signTime

		// （b）序列化签名，统计大小
		// 这里可以根据您自己的需要，简单地把签名中的各字段做序列化加总
		// 例如把每个G1点 marshal 后长度求和，big.Int 则转成 Bytes() 长度。
		size := estimateBRFLSigSize(sigBRFL)
		totalSigSizeBRFL += int64(size)

		// （c）验证
		startVerify := time.Now()
		verified := brfl.Verify(msg, brflPubKeys, sigBRFL)
		endVerify := time.Now()
		verifyTime := endVerify.Sub(startVerify)
		totalVerifyTimeBRFL += verifyTime

		if !verified {
			fmt.Printf("[BRFL] 第 %d 次验证失败\n", t)
		}
	}

	avgSignTimeBRFL := totalSignTimeBRFL / time.Duration(trials)
	avgVerifyTimeBRFL := totalVerifyTimeBRFL / time.Duration(trials)
	avgSigSizeBRFL := float64(totalSigSizeBRFL) / float64(trials)

	// ------------------------------
	// 4. 测试 RSCP 环签名的时间与大小
	// ------------------------------
	var totalSignTimeRSCP time.Duration
	var totalVerifyTimeRSCP time.Duration
	var totalSigSizeRSCP int64

	for t := 0; t < trials; t++ {
		// （a）签名
		startSign := time.Now()
		sigRSCP := rscp.Sign(msg, rscpPubKeys, signerRSCP)
		endSign := time.Now()

		signTime := endSign.Sub(startSign)
		totalSignTimeRSCP += signTime

		// （b）计算签名大小
		size := estimateRSCPSigSize(sigRSCP)
		totalSigSizeRSCP += int64(size)

		// （c）验证
		startVerify := time.Now()
		verified := rscp.Verify(msg, rscpPubKeys, sigRSCP)
		endVerify := time.Now()
		verifyTime := endVerify.Sub(startVerify)
		totalVerifyTimeRSCP += verifyTime

		if !verified {
			fmt.Printf("[RSCP] 第 %d 次验证失败\n", t)
		}
	}

	avgSignTimeRSCP := totalSignTimeRSCP / time.Duration(trials)
	avgVerifyTimeRSCP := totalVerifyTimeRSCP / time.Duration(trials)
	avgSigSizeRSCP := float64(totalSigSizeRSCP) / float64(trials)

	// ------------------------------
	// 5. 打印结果
	// ------------------------------
	fmt.Println("============ 实验配置 ============")
	fmt.Printf("环大小 (n) = %d\n", ringSize)
	fmt.Printf("测试轮数 (trials) = %d\n", trials)
	fmt.Printf("消息大小 (bytes) = %d\n\n", messageSize)

	fmt.Println("========= BRFL (免双线性对) =========")
	fmt.Printf("平均签名时间 = %v\n", avgSignTimeBRFL)
	fmt.Printf("平均验证时间 = %v\n", avgVerifyTimeBRFL)
	fmt.Printf("平均签名大小 = %.2f 字节\n", avgSigSizeBRFL)

	fmt.Println("========= RSCP (含双线性对) =========")
	fmt.Printf("平均签名时间 = %v\n", avgSignTimeRSCP)
	fmt.Printf("平均验证时间 = %v\n", avgVerifyTimeRSCP)
	fmt.Printf("平均签名大小 = %.2f 字节\n", avgSigSizeRSCP)
}

// ---------------------------
// 以下是简单的签名大小估计函数
// 您可根据实际需要更精细地序列化
// ---------------------------
func estimateBRFLSigSize(sig *brfl.Sigma) int {
	// 以 G1 点为例，每个 Marshal() 大约 128 字节 (bn256 curve)；
	// big.Int 转 bytes 长度视阶大小而定，这里简单处理。
	size := 0

	// 1. RM: *bn256.G1
	size += len(sig.RM.Marshal())

	// 2. UI: []*bn256.G1
	for _, ui := range sig.UI {
		size += len(ui.Marshal())
	}

	// 3. V (big.Int)
	size += len(sig.V.Bytes())

	// 4. C (big.Int)
	size += len(sig.C.Bytes())

	// 5. T: *bn256.G1
	size += len(sig.T.Marshal())

	// 6. Pi (big.Int)
	size += len(sig.Pi.Bytes())

	return size
}

func estimateRSCPSigSize(sig *rscp.Sigma) int {
	size := 0

	// UI: []*bn256.G1
	for _, ui := range sig.UI {
		size += len(ui.Marshal())
	}

	// V: *bn256.G2
	size += len(sig.V.Marshal())

	return size
}
