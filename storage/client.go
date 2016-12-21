package storage

import (
	"time"
)

type ClientEngine interface {
	Close()
	Put(key string, value string) error
	Get(key string) (string, error)
	Del(key string) error
}

type Client struct {
	engine ClientEngine
}

func NewClient(endpoints []string, requestTimeout time.Duration, v3 bool) (*Client, error) {
	if v3 {
		engine, err := NewClientV3(endpoints, requestTimeout)
		if err != nil {
			return nil, err
		}
		return &Client{
			engine: engine,
		}, nil
	} else {
		engine, err := NewClientV2(endpoints, requestTimeout)
		if err != nil {
			return nil, err
		}
		return &Client{
			engine: engine,
		}, nil
	}
}

func (c *Client) PutObj(key string, obj Object) error {
	value, err := obj.Serialize()
	if err != nil {
		return err
	}

	return c.Put(key, string(value))
}

func (c *Client) GetObj(key string, obj Object) error {
	value, err := c.Get(key)
	if err != nil {
		return err
	}

	return obj.Deserialize(value)
}

func (c *Client) Put(key string, value string) error {
	return c.engine.Put(key, value)
}

func (c *Client) Get(key string) (string, error) {
	return c.engine.Get(key)
}

func (c *Client) Del(key string) error {
	return c.engine.Del(key)
}
func (c *Client) Close() {
	c.engine.Close()
}
