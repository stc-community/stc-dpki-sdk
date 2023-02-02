package caclient

import (
	"github.com/cloudflare/backoff"
	"github.com/flowshield/cfssl/hook"
	"github.com/flowshield/cfssl/transport"
	"github.com/flowshield/cfssl/transport/roots"
	"github.com/pkg/errors"
	"github.com/stc-community/stc-dpki-casdk/keyprovider"
	"github.com/stc-community/stc-dpki-casdk/pkg/spiffe"
	"go.uber.org/zap"
	"net/url"
	"reflect"
)

const (
	// CertRefreshDurationRate Certificate cycle time rate
	CertRefreshDurationRate int = 2
)

// Exchanger ...
type Exchanger struct {
	Transport   *Transport
	IDGIdentity *spiffe.IDGIdentity

	caAddr string
	logger *zap.SugaredLogger

	caiConf *Conf
}

func init() {
	// Cfssl API client connects to API server without certificate verification (one-way TLS)
	hook.ClientInsecureSkipVerify = true
}

// NewExchanger ...
func (cai *CAInstance) NewExchanger(id *spiffe.IDGIdentity, metaData ...map[string]interface{}) (*Exchanger, error) {
	tr, err := cai.NewTransport(id, nil, nil)
	if err != nil {
		return nil, err
	}
	if len(metaData) > 0 {
		// 元数据
		tr.MetaData = metaData[0]
	}
	return &Exchanger{
		Transport:   tr,
		IDGIdentity: id,
		logger:      cai.Logger.Sugar().Named("ca"),
		caAddr:      cai.CaAddr,

		caiConf: &cai.Conf,
	}, nil
}

// NewTransport ...
func (cai *CAInstance) NewTransport(id *spiffe.IDGIdentity, keyPEM []byte, certPEM []byte) (*Transport, error) {
	l := cai.Logger.Sugar()

	l.Debug("NewTransport Start")

	if _, err := url.Parse(cai.CaAddr); err != nil {
		return nil, errors.Wrap(err, "CA ADDR Error")
	}

	var tr = &Transport{
		CertRefreshDurationRate: CertRefreshDurationRate,
		Identity:                cai.CFIdentity,
		Backoff:                 &backoff.Backoff{},
		logger:                  l.Named("ca"),
	}

	l.Debugf("[NEW]: Certificate rotation rate: %v", tr.CertRefreshDurationRate)

	l.Debug("roots Initialization")
	store, err := roots.New(cai.CFIdentity.Roots)
	if err != nil {
		return nil, err
	}
	tr.TrustStore = store

	l.Debug("client roots Initialization")
	if len(cai.CFIdentity.ClientRoots) > 0 {
		if !reflect.DeepEqual(cai.CFIdentity.Roots, cai.CFIdentity.ClientRoots) {
			store, err = roots.New(cai.CFIdentity.ClientRoots)
			if err != nil {
				return nil, err
			}
		}

		tr.ClientTrustStore = store
	}

	l.Debug("xkeyProvider Initialization")
	xkey, err := keyprovider.NewXKeyProvider(id)
	if err != nil {
		return nil, err
	}

	xkey.CSRConf = cai.CSRConf
	if keyPEM != nil && certPEM != nil {
		l.Debug("xkeyProvider set up keyPEM")
		if err := xkey.SetPrivateKeyPEM(keyPEM); err != nil {
			return nil, err
		}
		l.Debug("xkeyProvider set up certPEM")
		if err := xkey.SetCertificatePEM(certPEM); err != nil {
			return nil, err
		}
	}
	tr.Provider = xkey

	l.Debug("CA Initialization")
	tr.CA, err = transport.NewCA(cai.CFIdentity)
	if err != nil {
		return nil, err
	}

	return tr, nil
}

// RotateController ...
func (ex *Exchanger) RotateController() *RotateController {
	return &RotateController{
		transport: ex.Transport,
		logger:    ex.logger.Named("rotator"),
	}
}
