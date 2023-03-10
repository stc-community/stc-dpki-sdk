package test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/flowshield/cfssl/helpers"
	"github.com/flowshield/cfssl/hook"
	"github.com/stc-community/stc-dpki-casdk/caclient"
	"github.com/stc-community/stc-dpki-casdk/contract"
	"github.com/stc-community/stc-dpki-casdk/keygen"
	"github.com/stc-community/stc-dpki-casdk/pkg/spiffe"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	CaAddr       = "https://127.0.0.1:8081"                                           // CA Server
	ContractAddr = "0x7bFb4c993F851690B253e51327ABCD7f045cd477"                       // contract address
	RpcAddr      = "https://api.hyperspace.node.glif.io/rpc/v1"                       // rpc address
	AuthKey      = "0739a645a7d6601d9d45f6b237c4edeadad904f2fce53625dfdd541ec4fc8134" // Auth Key
)

func TestIssueCert(t *testing.T) {
	_, _, err := NewCert()
	if err != nil {
		log.Fatalf("Failed to issue certificate:%v", err)
	}
}

func TestServer(t *testing.T) {
	RunServer()
	//go RunClient()
}

func TestClient(t *testing.T) {
	//RunServer()
	RunClient()
}

func RunClient() {
	certPem, keyPem, err := NewCert()
	if err != nil {
		log.Fatalf("Failed to issue certificate:%v", err)
	}
	err = HandleClient(certPem, keyPem)
	if err != nil {
		log.Fatalf("Run Client Error:%v", err)
	}
}

func RunServer() {
	certPem, keyPem, err := NewCert()
	if err != nil {
		log.Fatalf("New Cert Error:%v", err)
	}
	err = HandleServer(certPem, keyPem)
	if err != nil {
		log.Fatalf("Run Server Error:%v", err)
	}
}

func NewCert() ([]byte, []byte, error) {
	cai := caclient.NewCAI(
		caclient.WithCAServer(caclient.RoleDefault, CaAddr),
		caclient.WithAuthKey(AuthKey),
	)
	cm, err := cai.NewCertManager()
	if err != nil {
		return nil, nil, err
	}
	//caPem, err := cm.CACertsPEM()
	//if err != nil {
	//	return nil, nil, err
	//
	//}
	//log.Println("Root Ca:\n", string(caPem))

	_, keyPem, _ := keygen.GenKey(keygen.EcdsaSigAlg)
	log.Println("Gen Key:\n", string(keyPem))

	csrBytes, err := keygen.GenCustomExtendCSR(keyPem, &spiffe.IDGIdentity{
		SiteID:    "test_site",
		ClusterID: "test_cluster",
		UniqueID:  "idg_registy_0001",
	}, &keygen.CertOptions{
		CN: "test",
	}, nil)
	if err != nil {
		return nil, nil, err
	}
	log.Println("Request for certificate....")
	// Sign cert
	certPem, err := cm.SignPEM(csrBytes, map[string]interface{}{
		hook.MetadataUniqueID: "test_111",
	})
	if err != nil {
		return nil, nil, err
	}
	log.Println("Cert: \n", string(certPem))
	return certPem, keyPem, nil
}

func HandleClient(certPEM, keyPEM []byte) error {
	ctx := context.Background()
	contractClient, err := contract.NewEthClient(ctx, &contract.Config{
		Address: ContractAddr,
		RpcUrl:  RpcAddr,
	})
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
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
			log.Println("Certificate information verified successfully: ", certc)
			return nil
		},
	}
	certInfo, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	log.Println("Waiting for the information to be uploaded to the blockchain ... ")
retry:
	certVC, err := contractClient.Instance.Get(&bind.CallOpts{Pending: true}, certInfo.SerialNumber.String())
	if err != nil {
		return fmt.Errorf("unable to parse certificate vc: %v", err)
	}
	if certVC.Status == 0 {
		time.Sleep(time.Second)
		goto retry
	}
	log.Println("self certificate VC: ", certVC)
	log.Println("Dial to 127.0.0.1:6666 ...")
	_, err = tls.Dial("tcp", "127.0.0.1:6666", cfg)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}

func HandleServer(certPEM, keyPEM []byte) error {
	ctx := context.Background()
	contractClient, err := contract.NewEthClient(ctx, &contract.Config{
		Address: ContractAddr,
		RpcUrl:  RpcAddr,
	})
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert, // The client certificate is required. The verification process is built as follows
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
			log.Println("Certificate information verified successfully: ", certc)
			return nil
		},
	}
	certInfo, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		return err
	}
	log.Println("Waiting for the information to be uploaded to the blockchain ... ")
retry:
	certVC, err := contractClient.Instance.Get(&bind.CallOpts{Pending: true}, certInfo.SerialNumber.String())
	if err != nil {
		return fmt.Errorf("unable to parse certificate vc: %v", err)
	}
	if certVC.Status == 0 {
		time.Sleep(time.Second)
		goto retry
	}
	log.Println("self certificate VC: ", certVC)
	log.Println("Server Running on 0.0.0.0:6666")
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
		//Open an independent route to chat with the customer
		go ChatWith(conn)
	}
}

// ChatWith Talk to clients in the conn network leased line
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
		fmt.Println("receive:", clientMsg)

		///---一个完整的消息回合
		msg := strings.Trim(clientMsg, "\r\n")
		if msg != "exit" {
			conn.Write([]byte("Read:" + clientMsg))
		} else {
			conn.Write([]byte("bye"))
			break
		}
	}
	conn.Close()
	fmt.Println("Client disconnected", conn.RemoteAddr())
}
