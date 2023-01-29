package contract

import (
	"context"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Config struct {
	Address string
	RpcUrl  string
}

type EthClient struct {
	Client   *ethclient.Client
	Instance *Certificate
}

func NewEthClient(ctx context.Context, cfg *Config) (*EthClient, error) {
	client, err := InitGethClient(ctx, cfg)
	if err != nil {
		return nil, err
	}
	contractAdd := common.HexToAddress(cfg.Address)
	instance, err := NewCertificate(contractAdd, client)
	if err != nil {
		return nil, err
	}
	result := &EthClient{
		Client:   client,
		Instance: instance,
	}
	return result, err
}

func InitGethClient(ctx context.Context, cfg *Config) (*ethclient.Client, error) {
	client, err := ethclient.DialContext(ctx, cfg.RpcUrl)
	if err != nil {
		return nil, err
	}
	return client, nil
}
