package storage

import (
	"fmt"
	etcd "github.com/coreos/etcd/client"
	"golang.org/x/net/context"
	"time"
)

type Client2 struct {
	client         *etcd.Client
	kapi           etcd.KeysAPI
	requestTimeout time.Duration
}

func NewClientV2(endpoints []string, requestTimeout time.Duration) (ClientEngine, error) {
	cfg := etcd.Config{
		Endpoints: endpoints,
	}

	client, err := etcd.New(cfg)
	if err != nil {
		return nil, err
	}

	return &Client2{
		client:         &client,
		kapi:           etcd.NewKeysAPI(client),
		requestTimeout: requestTimeout,
	}, nil
}

func (c *Client2) Close() {
}

func (c *Client2) Put(key string, value string) error {

	fmt.Println(c.requestTimeout)
	fmt.Println("Putting " + key + " value " + value)
	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	res, err := c.kapi.Set(ctx, key, value, nil)
	fmt.Println(res)
	fmt.Println(err)
	cancel()

	return err
}

func (c *Client2) Get(key string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	resp, err := c.kapi.Get(ctx, key, nil)
	cancel()

	data := resp.Node.Value

	return data, err
}

func (c *Client2) Del(key string) error {

	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	_, err := c.kapi.Delete(ctx, key, nil)
	cancel()

	return err
}
