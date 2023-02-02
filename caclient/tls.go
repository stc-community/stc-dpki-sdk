package caclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stc-community/stc-dpki-casdk/contract"
	"log"

	"github.com/pkg/errors"
)

// ClientTLSConfig ...
func (ex *Exchanger) ClientTLSConfig(client contract.EthClient) (*tls.Config, error) {
	lo := ex.logger
	lo.Debug("client tls started.")
	if _, err := ex.Transport.GetCertificate(); err != nil {
		return nil, errors.Wrap(err, "Client certificate acquisition error")
	}
	c, err := ex.Transport.TLSClientConfig()
	if err != nil {
		return nil, err
	}
	c.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("empty certificates chain")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("unable to parse certificate: %w", err)
		}
		certc, err := client.Instance.Verify(&bind.CallOpts{Pending: true}, cert.SerialNumber.String())
		if err != nil {
			return fmt.Errorf("unable to parse certificate: %w", err)
		}
		log.Println("Certificate information verified successfully: ", certc)
		return nil
	}
	return c, nil
}

// ServerTLSConfig ...
func (ex *Exchanger) ServerTLSConfig(client contract.EthClient) (*tls.Config, error) {
	lo := ex.logger
	lo.Debug("server tls started.")
	if _, err := ex.Transport.GetCertificate(); err != nil {
		return nil, errors.Wrap(err, "Server certificate acquisition error")
	}
	c, err := ex.Transport.TLSServerConfig()
	if err != nil {
		return nil, err
	}
	c.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("empty certificates chain")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("unable to parse certificate: %w", err)
		}
		certc, err := client.Instance.Verify(&bind.CallOpts{Pending: true}, cert.SerialNumber.String())
		if err != nil {
			return fmt.Errorf("unable to parse certificate: %w", err)
		}
		log.Println("Certificate information verified successfully: ", certc)
		return nil
	}
	return c, nil
}
