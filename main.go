package main

import (
	"embed"
	"os"

	"github.com/welllog/etcdkeeper-x/srv"
	"github.com/welllog/olog"
	"gopkg.in/yaml.v3"
)

//go:embed assets
var assets embed.FS

func main() {
	olog.SetLoggerOptions(
		olog.WithLoggerEncode(olog.PLAIN),
		olog.WithLoggerTimeFormat("2006/01/02 15:04:05"),
		olog.WithLoggerCaller(false),
	)

	var cf srv.Conf
	b, err := os.ReadFile("./config.yaml")
	if err == nil {
		olog.Infof("load ./config.yaml content: %s", string(b))
		err = yaml.Unmarshal(b, &cf)
		if err != nil {
			olog.Fatalf("unmarshal config.yaml failed: %v", err)
		}
	}

	cf.Init()
	srv.NewServer(cf, assets).Start()
}
