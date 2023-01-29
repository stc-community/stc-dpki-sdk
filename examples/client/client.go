package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/flowshield/casdk/caclient"
	"github.com/flowshield/casdk/contract"
	"github.com/flowshield/casdk/keygen"
	"github.com/flowshield/casdk/pkg/logger"
	"github.com/flowshield/casdk/pkg/spiffe"
	"github.com/flowshield/cfssl/hook"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
)

var (
	caAddr       = flag.String("ca", "https://127.0.0.1:8081", "CA Server")
	contractAddr = flag.String("contract", "0x7396fbfa3192325162ca39da7ab7b43bd587750a", "contract address")
	rpcAddr      = flag.String("rpc", "https://wallaby.node.glif.io/rpc/v0", "rpc address")
	authKey      = flag.String("auth-key", "0739a645a7d6601d9d45f6b237c4edeadad904f2fce53625dfdd541ec4fc8134", "Auth Key")
)

func init() {
	_ = logger.GlobalConfig(logger.Conf{
		Debug: true,
		Level: zapcore.DebugLevel,
	})
}

func main() {
	flag.Parse()
	err := NewClient()
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

// NewClient 测试示例
func NewClient() error {
	cai := caclient.NewCAI(
		caclient.WithCAServer(caclient.RoleDefault, *caAddr),
		caclient.WithAuthKey(*authKey),
	)
	cm, err := cai.NewCertManager()
	if err != nil {
		logger.Errorf("cert manager 创建错误: %s", err)
		return err
	}
	caPEMBytes, err := cm.CACertsPEM()
	if err != nil {
		logger.Errorf("mgr.CACertsPEM() err : %v", err)
		return err
	}
	logger.Info("根证书:\n", string(caPEMBytes))

	_, keyPEM, _ := keygen.GenKey(keygen.EcdsaSigAlg)
	logger.Info("生成私钥:\n", string(keyPEM))

	csrBytes, err := keygen.GenCustomExtendCSR(keyPEM, &spiffe.IDGIdentity{
		SiteID:    "test_site",
		ClusterID: "test_cluster",
		UniqueID:  "idg_registy_0001",
	}, &keygen.CertOptions{
		CN: "test",
	}, []pkix.Extension{})
	if err != nil {
		return err
	}

	// 申请证书
	certBytes, err := cm.SignPEM(csrBytes, map[string]interface{}{
		hook.MetadataUniqueID: "test_111",
	})
	if err != nil {
		logger.Errorf("申请证书失败: %s", err)
		return err
	}
	logger.Infof("从 CA 申请证书: \n%s", string(certBytes))

	ctx := context.Background()
	contractClient, err := contract.NewEthClient(ctx, &contract.Config{
		Address: *contractAddr,
		RpcUrl:  *rpcAddr,
	})
	if err != nil {
		logger.Errorf("初始化合约失败:%s", err)
		return err
	}
	cert, err := tls.X509KeyPair(certBytes, keyPEM)
	if err != nil {
		return err
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("empty certificates chain")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("unable to parse certificate: %w", err)
			}
			certc, err := contractClient.Instance.Verify(&bind.CallOpts{Pending: true}, cert.SerialNumber.String())
			if err != nil {
				return fmt.Errorf("unable to parse certificate: %w", err)
			}
			fmt.Println(certc)
			return nil
		},
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:6666", cfg)
	if err != nil {
		log.Fatal(err)
	}
	//预先准备消息缓冲区
	buffer := make([]byte, 1024)

	//准备命令行标准输入
	reader := bufio.NewReader(os.Stdin)

	for {
		lineBytes, _, _ := reader.ReadLine()
		if err != nil {
			log.Println(err)
			continue
		}
		if len(lineBytes) <= 0 {
			continue
		}
		_, err := conn.Write(lineBytes)
		if err != nil {
			log.Println(err)
			continue
		}
		n, err := conn.Read(buffer)
		if err != nil {
			log.Println(err.Error())
			continue
		}

		serverMsg := string(buffer[0:n])
		fmt.Println("服务端msg", serverMsg)
		if serverMsg == "bye" {
			break
		}

	}
	return nil
}
