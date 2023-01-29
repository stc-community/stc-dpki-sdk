package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/flowshield/cfssl/hook"
	"github.com/stc-community/stc-dpki-casdk/caclient"
	"github.com/stc-community/stc-dpki-casdk/contract"
	"log"
	"net"
	"os"
	"strings"

	"github.com/stc-community/stc-dpki-casdk/keygen"
	"github.com/stc-community/stc-dpki-casdk/pkg/logger"
	"github.com/stc-community/stc-dpki-casdk/pkg/spiffe"
	"go.uber.org/zap/zapcore"
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
	err := NewIDGRegistry()
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

// NewIDGRegistry
func NewIDGRegistry() error {
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
	}, []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 1},
			Critical: true,
			Value:    []byte("fake data"),
		},
		{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 2},
			Critical: true,
			Value:    []byte("fake data"),
		},
	})
	if err != nil {
		return err
	}
	//logger.Infof("生成自定义 CSR: \n%s", string(csrBytes))

	// 申请证书
	certBytes, err := cm.SignPEM(csrBytes, map[string]interface{}{
		hook.MetadataUniqueID: "test_111",
	})
	if err != nil {
		logger.Errorf("申请证书失败: %s", err)
		return err
	}
	logger.Infof("从 CA 申请证书: \n%s", string(certBytes))
	err = RunServer(certBytes, keyPEM)
	if err != nil {
		logger.Errorf("Run Server Error:%s", err)
		return err
	}
	return nil
}

func RunServer(certPEM, keytPEM []byte) error {
	ctx := context.Background()
	contractClient, err := contract.NewEthClient(ctx, &contract.Config{
		Address: *contractAddr,
		RpcUrl:  *rpcAddr,
	})
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keytPEM)
	if err != nil {
		return err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert, // 要求客户端证书, 但不要求有效
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

	ln, err := tls.Listen("tcp4", "0.0.0.0:6666", cfg)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}

	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Failed to accept connection: ", err.Error())
			continue
		}
		//开辟独立协程与该客聊天
		go ChatWith(conn)
	}
}

// ChatWith 在conn网络专线中与客户端对话
func ChatWith(conn net.Conn) {
	var packet = make([]byte, 1420)
	for {
		connReader := bufio.NewReader(conn)
		n, err := connReader.Read(packet)
		if err != nil {
			fmt.Println("err:", err)
			return
		}
		clientMsg := string(packet[:n])
		fmt.Println("接收", clientMsg)

		///---一个完整的消息回合
		msg := strings.Trim(clientMsg, "\r\n")
		if msg != "exit" {
			conn.Write([]byte("已读:" + clientMsg))
		} else {
			conn.Write([]byte("bye"))
			break
		}
	}
	conn.Close()
	fmt.Println("客户端断开连接", conn.RemoteAddr())

}
