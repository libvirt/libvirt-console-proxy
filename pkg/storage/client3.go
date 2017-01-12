package storage

import (
	"fmt"
	etcd3 "github.com/coreos/etcd/clientv3"
	"golang.org/x/net/context"
	"time"
)

type Client3 struct {
	client         *etcd3.Client
	kapi           etcd3.KV
	requestTimeout time.Duration
}

func NewClientV3(endpoints []string, requestTimeout time.Duration) (ClientEngine, error) {
	cfg := etcd3.Config{
		Endpoints: endpoints,
	}

	client, err := etcd3.New(cfg)
	if err != nil {
		return nil, err
	}

	return &Client3{
		client:         client,
		kapi:           etcd3.NewKV(client),
		requestTimeout: requestTimeout,
	}, nil
}

func (c *Client3) Close() {
	c.client.Close()
}

func (c *Client3) Put(key string, value string) error {

	fmt.Println(c.requestTimeout)
	fmt.Println("Putting " + key + " value " + value)
	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	res, err := c.kapi.Put(ctx, key, value)
	fmt.Println(res)
	fmt.Println(err)
	cancel()

	return err
}

func (c *Client3) Get(key string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	resp, err := c.kapi.Get(ctx, key)
	cancel()

	data := string(resp.Kvs[0].Value)

	return data, err
}

func (c *Client3) Del(key string) error {

	ctx, cancel := context.WithTimeout(context.Background(), c.requestTimeout)
	_, err := c.kapi.Delete(ctx, key)
	cancel()

	return err
}
