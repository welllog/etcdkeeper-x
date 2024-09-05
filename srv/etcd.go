package srv

import (
	"crypto/tls"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	"go.etcd.io/etcd/client/v3"
)

type etcdManager struct {
	rootClients map[string]*clientv3.Client
	clients    map[string]*clientv3.Client
	mu sync.RWMutex
}

func newEtcdManager() *etcdManager {
	return &etcdManager{
		rootClients: make(map[string]*clientv3.Client, 1),
		clients:    make(map[string]*clientv3.Client, 1),
	}
}

func (m *etcdManager) GetClient(host string, root bool) (*clientv3.Client, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if root {
		c, ok := m.rootClients[host]
		return c, ok
	}

	c, ok := m.clients[host]
	return c, ok
}

func (m *etcdManager) SetClient(host string, root bool, c *clientv3.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()

	store := m.clients
	if root {
		store = m.rootClients
	}

	oc, ok := store[host]
	if ok {
		oc.Close()
	}
	store[host] = c
}

func (m *etcdManager) close() {
	m.mu.Lock()
	for k, c := range m.clients {
		delete(m.clients, k)
		c.Close()
	}

	for k, c := range m.rootClients {
		delete(m.rootClients, k)
		c.Close()
	}
	m.mu.Unlock()
}

func newEtcdClient(cf Etcd) (*clientv3.Client, error) {
	// use tls if usetls is true
	var tlsConfig *tls.Config
	if cf.Tls.Enable {
		tlsInfo := transport.TLSInfo{
			CertFile:      cf.Tls.CertFile,
			KeyFile:       cf.Tls.KeyFile,
			TrustedCAFile: cf.Tls.TrustedCAFile,
		}
		var err error
		tlsConfig, err = tlsInfo.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("tls config failed: %w", err)
		}
	}

	conf := clientv3.Config{
		Endpoints:          []string{cf.Endpoints},
		DialTimeout:        10 * time.Second,
		TLS:                tlsConfig,
		DialKeepAliveTime: time.Minute,
		DialKeepAliveTimeout: time.Minute,
	}

	if cf.Auth {
		conf.Username = cf.User
		conf.Password = cf.Passwd
	}

	c, err := clientv3.New(conf)
	if err != nil {
		return nil, fmt.Errorf("new etcd client failed: %w", err)
	}

	return c, nil
}
