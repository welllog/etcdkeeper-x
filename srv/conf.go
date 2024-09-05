package srv

import "fmt"

type Etcd struct {
	Endpoints string `yaml:"endpoints"`
	Separator string `yaml:"separator"`
    Auth bool `yaml:"auth"`
	User string `yaml:"-"`
	Passwd string `yaml:"passwd"`
    Tls struct {
		Enable bool `yaml:"enable"`
		CertFile string `yaml:"certFile"`
		KeyFile string `yaml:"keyFile"`
		TrustedCAFile string `yaml:"trustedCAFile"`
	} `yaml:"tls"`
}

type Conf struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	Etcds []Etcd `yaml:"etcds"`
	etcds map[string]Etcd
}

func (c *Conf) Validate() error {
	for _, v := range c.Etcds {
		if v.Auth && v.Passwd == "" {
			return fmt.Errorf("%s auth is enabled but password is empty", v.Endpoints)
		}
	}
	return nil
}

func (c *Conf) Init() {
	c.Default()
	c.etcds = make(map[string]Etcd, len(c.Etcds))
	for _, v := range c.Etcds {
		c.etcds[v.Endpoints] = v
	}
}

func (c *Conf) GetEtcdConfig(endpoints string) (Etcd, bool) {
	cf, ok := c.etcds[endpoints]
	return cf, ok
}

func (c *Conf) Default() {
	if c.Host == "" {
		c.Host = "0.0.0.0"
	}

	if c.Port <= 0 {
		c.Port = 8010
	}

	if len(c.Etcds) == 0 {
		c.Etcds = []Etcd{{}}
		for i := range c.Etcds {
			c.Etcds[i].Default()
		}
	}
}

func (e *Etcd) Default() {
	if e.Endpoints == "" {
		e.Endpoints = "127.0.0.1:2379"
	}

	if e.Separator == "" {
		e.Separator = "/"
	}
}
