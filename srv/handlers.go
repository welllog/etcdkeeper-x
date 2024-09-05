package srv

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/welllog/etcdkeeper-x/srv/session"
	"github.com/welllog/olog"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
)

type v3Handlers struct {
	cf      Conf
	sessmgr *session.Manager
	climgr  *etcdManager
	rootUsers *UserStore
}

func newV3Handlers(cf Conf) (*v3Handlers, error) {
	sessmgr, err := session.NewManager("memory", "_etcdkeeper_session", 86400)
	if err != nil {
		return nil, err
	}

	time.AfterFunc(86400*time.Second, func() {
		sessmgr.GC()
	})

	rootUsers := newUserStore()
	if err := rootUsers.Load(); err != nil {
		return nil, err
	}

	return &v3Handlers{
		cf:      cf,
		sessmgr: sessmgr,
		climgr: newEtcdManager(),
		rootUsers:   newUserStore(),
	}, nil
}

func (h *v3Handlers) Separator(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte(h.cf.Etcds[0].Separator))
}

func (h *v3Handlers) Connect(w http.ResponseWriter, r *http.Request) {
	sess := h.sessmgr.SessionStart(w, r)
	cuinfo := userInfo{
		Host:  r.FormValue("host"),
		Name: r.FormValue("uname"),
		Passwd: r.FormValue("passwd"),
	}

	logger := olog.WithEntries(olog.GetLogger(), map[string]any{
		"method": r.Method,
		"host":  cuinfo.Host,
		"uname": cuinfo.Name,
	})

	ctx := r.Context()
	userHostLoginKey := fmt.Sprintf("%s:%s", cuinfo.Host, cuinfo.Name)
	loginInfo := sess.Get(userHostLoginKey)
	if loginInfo != nil {
		// user login current etcd host
	}

	// start login
	cf, ok := h.cf.GetEtcdConfig(cuinfo.Host)
	if !ok {
		// not found etcd config of host, use default
		cf.Default()
		cf.Endpoints = cuinfo.Host
	}

	if cf.Auth {
		rootCli, ok := h.climgr.GetClient(cuinfo.Host, true)
		if !ok {
			// root client not exists, check root user exists in config
			if cf.Passwd != "" {
				cf.User = "root"
				cli, err := newEtcdClient(cf)
				if err != nil {
					
				}
			}

			if cuinfo.Name != "root" || cuinfo.Passwd == "" {
				Rsp{"status": "root"}.WriteTo(w)
				return
			}

			// as root user login
			cf.User = cuinfo.Name
			cf.Passwd = cuinfo.Passwd
		} else {

		}

		// need username and password
		if cuinfo.Name == "" || cuinfo.Passwd == "" {
			Rsp{"status": "login"}.WriteTo(w)
			return
		}

		if cf.Passwd == "" {
			if cuinfo.Name != "root" {
				Rsp{"status": "root"}.WriteTo(w)
				return
			}

			if cuinfo.Passwd == "" {
				Rsp{"status": "root"}.WriteTo(w)
				return
			}


			cf.User = cuinfo.Name
			cf.Passwd = cuinfo.Passwd
			cli, err := newEtcdClient(cf)
			if err != nil {
				logger.Warnf("new etcd client: %v", err)
				Rsp{"status": "error", "message": err.Error()}.WriteTo(w)
				return
			}

			stResp, err := cli.Status(ctx, cuinfo.Host)
			if err != nil {
				logger.Warnf("etcd status: %v", err)
				Rsp{"status": "error", "message": err.Error()}.WriteTo(w)
				cli.Close()
				return
			}


		}
	}

	// copy config
	ucf := cf
	ucf.User = cuinfo.Name
	ucf.Passwd = cuinfo.Passwd
	ucli, err := newEtcdClient(ucf)
	if err != nil {
		logger.Warnf("new etcd client: %v", err)
		Rsp{"status": "error", "message": err.Error()}.WriteTo(w)
		return
	}

	authRsp, err := ucli.AuthStatus(ctx)
	if err != nil {
		logger.Warnf("auth status: %v", err)
		Rsp{"status": "error", "message": err.Error()}.WriteTo(w)
		return
	}

	if !authRsp.Enabled {
		// reuse this client globally
		h.climgr.SetClient(cuinfo.Host, true, ucli)
	}

	if cuinfo.Name != "root" {
		// check root client is exists
	}


	if cf.Auth {
		// need auth
		if cf.Passwd == "" {
			// config not root user
			if cuinfo.Name != "root" {
				Rsp{"status": "root"}.WriteTo(w)
			}

			// as root user login
			cf.Passwd = cuinfo.Passwd
			cli, err := newEtcdClient(cf)
			if err != nil {

			}
		}
	}
	// need auth
	if h.cf.Auth {
		// first check root user
		_, ok := h.rootUsers.Get(cuinfo.Host)
		if !ok {
			// check current user whether is root
			uinfo := sess.Get(cuinfo.Host)
			if uinfo == nil { // need login
				Rsp{"status": "root"}.WriteTo(w)
			}
		}
		if !ok && cuinfo.Name != "root" { // no root user
			Rsp{"status": "root"}.WriteTo(w)
			return
		}

		if uname == "" || passwd == "" {
			Rsp{"status": "login"}.WriteTo(w)
			return
		}
	}

	if uinfo, ok := sess.Get("uinfo").(*userInfo); ok {
		if host == uinfo.host && uname == uinfo.uname && passwd == uinfo.passwd {
			info := h.getInfo(host)
			Rsp{"status": "running", "info": info}.WriteTo(w)
			return
		}
	}

	uinfo := &userInfo{host: host, uname: uname, passwd: passwd}
	c, err := h.newClient(uinfo)
	if err != nil {
		olog.Warnf("method: %s, connect fail: %v", r.Method, err)
		Rsp{"status": "error", "message": err.Error()}.WriteTo(w)
		return
	}

	defer c.Close()
	_ = sess.Set("uinfo", uinfo)

	if h.cf.Auth {
		if uname == "root" {
			h.setUser(host, uinfo)
		}
	} else {
		h.setUser(host, uinfo)
	}

	olog.Debugf("%s v3 connect success.", r.Method)
	info := h.getInfo(host)
	Rsp{"status": "running", "info": info}.WriteTo(w)
}

func (h *v3Handlers) Put(w http.ResponseWriter, r *http.Request) {
	cli := h.getClient(w, r)
	defer cli.Close()

	key := r.FormValue("key")
	value := r.FormValue("value")
	ttl := r.FormValue("ttl")
	olog.Debugf("PUT v3 %s", key)

	var err error
	data := make(map[string]interface{})
	if ttl != "" {
		var sec int64
		sec, err = strconv.ParseInt(ttl, 10, 64)
		if err != nil {
			olog.Warnf("parse ttl: %v", err)
		}

		var leaseResp *clientv3.LeaseGrantResponse
		leaseResp, err = cli.Grant(context.TODO(), sec)
		if err == nil && leaseResp != nil {
			_, err = cli.Put(context.Background(), key, value, clientv3.WithLease(leaseResp.ID))
		}
	} else {
		_, err = cli.Put(context.Background(), key, value)
	}

	if err != nil {
		data["errorCode"] = 500
		data["message"] = err.Error()
	} else {
		if resp, err := cli.Get(context.Background(), key); err != nil {
			data["errorCode"] = 500
			data["errorCode"] = err.Error()
		} else {
			if resp.Count > 0 {
				kv := resp.Kvs[0]
				node := make(map[string]interface{})
				node["key"] = string(kv.Key)
				node["value"] = string(kv.Value)
				node["dir"] = false
				node["ttl"] = getTTL(cli, kv.Lease)
				node["createdIndex"] = kv.CreateRevision
				node["modifiedIndex"] = kv.ModRevision
				data["node"] = node
			}
		}
	}

	Rsp(data).WriteTo(w)
}

func (h *v3Handlers) Get(w http.ResponseWriter, r *http.Request) {
	data := make(map[string]interface{})
	key := r.FormValue("key")
	olog.Debugf("GET v3 %s", key)

	var cli *clientv3.Client
	sess := h.sessmgr.SessionStart(w, r)
	v := sess.Get("uinfo")
	var uinfo *userInfo
	if v != nil {
		uinfo = v.(*userInfo)
		cli, _ = h.newClient(uinfo)
		defer cli.Close()

		permissions, e := h.getPermissionPrefix(uinfo.host, uinfo.uname, key)
		if e != nil {
			io.WriteString(w, e.Error())
			return
		}

		if r.FormValue("prefix") == "true" {
			pnode := make(map[string]interface{})
			pnode["key"] = key
			pnode["nodes"] = make([]map[string]interface{}, 0)
			for _, p := range permissions {
				var (
					resp *clientv3.GetResponse
					err  error
				)
				if p[1] != "" {
					prefixKey := p[0]
					resp, err = cli.Get(context.Background(), prefixKey, clientv3.WithPrefix())
				} else {
					resp, err = cli.Get(context.Background(), p[0])
				}
				if err != nil {
					data["errorCode"] = 500
					data["message"] = err.Error()
				} else {
					for _, kv := range resp.Kvs {
						node := make(map[string]interface{})
						node["key"] = string(kv.Key)
						node["value"] = string(kv.Value)
						node["dir"] = false
						if key == string(kv.Key) {
							node["ttl"] = getTTL(cli, kv.Lease)
						} else {
							node["ttl"] = 0
						}
						node["createdIndex"] = kv.CreateRevision
						node["modifiedIndex"] = kv.ModRevision
						nodes := pnode["nodes"].([]map[string]interface{})
						pnode["nodes"] = append(nodes, node)
					}
				}
			}
			data["node"] = pnode
		} else {
			if resp, err := cli.Get(context.Background(), key); err != nil {
				data["errorCode"] = 500
				data["message"] = err.Error()
			} else {
				if resp.Count > 0 {
					kv := resp.Kvs[0]
					node := make(map[string]interface{})
					node["key"] = string(kv.Key)
					node["value"] = string(kv.Value)
					node["dir"] = false
					node["ttl"] = getTTL(cli, kv.Lease)
					node["createdIndex"] = kv.CreateRevision
					node["modifiedIndex"] = kv.ModRevision
					data["node"] = node
				} else {
					data["errorCode"] = 500
					data["message"] = "The node does not exist."
				}
			}
		}
	}

	Rsp(data).WriteTo(w)
}

func (h *v3Handlers) Del(w http.ResponseWriter, r *http.Request) {
	cli := h.getClient(w, r)
	defer cli.Close()

	key := r.FormValue("key")
	dir := r.FormValue("dir")
	olog.Debugf("DELETE v3 %s", key)

	if _, err := cli.Delete(context.Background(), key); err != nil {
		io.WriteString(w, err.Error())
		return
	}

	if dir == "true" {
		if _, err := cli.Delete(context.Background(), key+separator, clientv3.WithPrefix()); err != nil {
			io.WriteString(w, err.Error())
			return
		}
	}

	io.WriteString(w, "ok")
}

func (h *v3Handlers) GetPath(w http.ResponseWriter, r *http.Request) {
	originKey := r.FormValue("key")
	olog.Debugf("GET v3 %s", originKey)

	var (
		data = make(map[string]interface{})
		/*
			{1:["/"], 2:["/foo", "/foo2"], 3:["/foo/bar", "/foo2/bar"], 4:["/foo/bar/test"]}
		*/
		all = make(map[int][]map[string]interface{})
		min int
		max int
		// prefixKey string
	)

	var cli *clientv3.Client
	sess := h.sessmgr.SessionStart(w, r)
	v := sess.Get("uinfo")
	var uinfo *userInfo
	if v != nil {
		uinfo = v.(*userInfo)
		cli, _ = h.newClient(uinfo)
		defer cli.Close()

		permissions, e := h.getPermissionPrefix(uinfo.host, uinfo.uname, originKey)
		if e != nil {
			io.WriteString(w, e.Error())
			return
		}

		// parent
		var (
			presp *clientv3.GetResponse
			err   error
		)
		if originKey != separator {
			presp, err = cli.Get(context.Background(), originKey)
			if err != nil {
				data["errorCode"] = 500
				data["message"] = err.Error()
				Rsp(data).WriteTo(w)
				return
			}
		}
		if originKey == separator {
			min = 1
			// prefixKey = separator
		} else {
			min = len(strings.Split(originKey, separator))
			// prefixKey = originKey
		}
		max = min
		all[min] = []map[string]interface{}{{"key": originKey}}
		if presp != nil && presp.Count != 0 {
			all[min][0]["value"] = string(presp.Kvs[0].Value)
			all[min][0]["ttl"] = getTTL(cli, presp.Kvs[0].Lease)
			all[min][0]["createdIndex"] = presp.Kvs[0].CreateRevision
			all[min][0]["modifiedIndex"] = presp.Kvs[0].ModRevision
		}
		all[min][0]["nodes"] = make([]map[string]interface{}, 0)

		for _, p := range permissions {
			key, rangeEnd := p[0], p[1]
			// child
			var resp *clientv3.GetResponse
			if rangeEnd != "" {
				resp, err = cli.Get(context.Background(), key, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend))
			} else {
				resp, err = cli.Get(context.Background(), key, clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend))
			}
			if err != nil {
				data["errorCode"] = 500
				data["message"] = err.Error()
				Rsp(data).WriteTo(w)
				return
			}

			for _, kv := range resp.Kvs {
				if string(kv.Key) == separator {
					continue
				}
				keys := strings.Split(string(kv.Key), separator) // /foo/bar
				for i := range keys {                            // ["", "foo", "bar"]
					k := strings.Join(keys[0:i+1], separator)
					if k == "" {
						continue
					}
					node := map[string]interface{}{"key": k}
					if node["key"].(string) == string(kv.Key) {
						node["value"] = string(kv.Value)
						if key == string(kv.Key) {
							node["ttl"] = getTTL(cli, kv.Lease)
						} else {
							node["ttl"] = 0
						}
						node["createdIndex"] = kv.CreateRevision
						node["modifiedIndex"] = kv.ModRevision
					}
					level := len(strings.Split(k, separator))
					if level > max {
						max = level
					}

					if _, ok := all[level]; !ok {
						all[level] = make([]map[string]interface{}, 0)
					}
					levelNodes := all[level]
					var isExist bool
					for _, n := range levelNodes {
						if n["key"].(string) == k {
							isExist = true
						}
					}
					if !isExist {
						node["nodes"] = make([]map[string]interface{}, 0)
						all[level] = append(all[level], node)
					}
				}
			}
		}

		// parent-child mapping
		for i := max; i > min; i-- {
			for _, a := range all[i] {
				for _, pa := range all[i-1] {
					if i == 2 {
						pa["nodes"] = append(pa["nodes"].([]map[string]interface{}), a)
						pa["dir"] = true
					} else {
						if strings.HasPrefix(a["key"].(string), pa["key"].(string)+separator) {
							pa["nodes"] = append(pa["nodes"].([]map[string]interface{}), a)
							pa["dir"] = true
						}
					}
				}
			}
		}
	}
	data = all[min][0]

	Rsp{"node": data}.WriteTo(w)
}

func (h *v3Handlers) getUser(host string) (*userInfo, bool) {
	h.mu.RLock()
	u, ok := h.users[host]
	h.mu.RUnlock()

	return u, ok
}

func (h *v3Handlers) setUser(host string, u *userInfo) {
	h.mu.Lock()
	h.users[host] = u
	h.mu.Unlock()
}

func (h *v3Handlers) getInfo(host string) map[string]string {
	info := make(map[string]string)
	uinfo, _ := h.getUser(host)

	rootClient, err := h.newClient(uinfo)
	if err != nil {
		olog.Errorf("new client: %v", err)
		return info
	}
	defer rootClient.Close()

	status, err := rootClient.Status(context.Background(), host)
	if err != nil {
		olog.Fatalf("etcd status: %v", err)
	}

	mems, err := rootClient.MemberList(context.Background())
	if err != nil {
		olog.Fatalf("etcd member list: %v", err)
	}

	kb := 1024
	mb := kb * 1024
	gb := mb * 1024
	for _, m := range mems.Members {
		if m.ID == status.Leader {
			info["version"] = status.Version
			gn, rem1 := size(int(status.DbSize), gb)
			mn, rem2 := size(rem1, mb)
			kn, bn := size(rem2, kb)

			if gn > 0 {
				info["size"] = fmt.Sprintf("%dG", gn)
			} else {
				if mn > 0 {
					info["size"] = fmt.Sprintf("%dM", mn)
				} else {
					if kn > 0 {
						info["size"] = fmt.Sprintf("%dK", kn)
					} else {
						info["size"] = fmt.Sprintf("%dByte", bn)
					}
				}
			}
			info["name"] = m.GetName()
			break
		}
	}
	return info
}

func (h *v3Handlers) newClient(uinfo *userInfo) (*clientv3.Client, error) {
	endpoints := []string{uinfo.host}
	var err error

	// use tls if usetls is true
	var tlsConfig *tls.Config
	if h.cf.Tls.Enable {
		tlsInfo := transport.TLSInfo{
			CertFile:      h.cf.Tls.CertFile,
			KeyFile:       h.cf.Tls.KeyFile,
			TrustedCAFile: h.cf.Tls.TrustedCAFile,
		}
		tlsConfig, err = tlsInfo.ClientConfig()
		if err != nil {
			olog.Errorf("tls config: %v", err)
		}
	}

	conf := clientv3.Config{
		Endpoints:          endpoints,
		DialTimeout:        time.Second * time.Duration(h.cf.ConnectTimeout),
		TLS:                tlsConfig,
		DialOptions:        []grpc.DialOption{grpc.WithBlock()},
		MaxCallSendMsgSize: h.cf.SendMsgSize,
	}

	if h.cf.Auth {
		conf.Username = uinfo.uname
		conf.Password = uinfo.passwd
	}

	var c *clientv3.Client
	c, err = clientv3.New(conf)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (h *v3Handlers) getClient(w http.ResponseWriter, r *http.Request) *clientv3.Client {
	sess := h.sessmgr.SessionStart(w, r)
	v := sess.Get("uinfo")
	if v != nil {
		uinfo := v.(*userInfo)
		c, _ := h.newClient(uinfo)
		return c
	}
	return nil
}

func (h *v3Handlers) getPermissionPrefix(host, uname, key string) ([][]string, error) {
	if !h.cf.Auth {
		return [][]string{{key, "p"}}, nil // No auth return all
	} else {
		if uname == "root" {
			return [][]string{{key, "p"}}, nil
		}

		rootUser, _ := h.getUser(host)
		rootCli, err := h.newClient(rootUser)
		if err != nil {
			return nil, err
		}
		defer rootCli.Close()

		if resp, err := rootCli.UserList(context.Background()); err != nil {
			return nil, err
		} else {
			// Find user permissions
			set := make(map[string]string)
			for _, u := range resp.Users {
				if u == uname {
					ur, err := rootCli.UserGet(context.Background(), u)
					if err != nil {
						return nil, err
					}

					for _, r := range ur.Roles {
						rr, err := rootCli.RoleGet(context.Background(), r)
						if err != nil {
							return nil, err
						}

						for _, p := range rr.Perm {
							set[string(p.Key)] = string(p.RangeEnd)
						}
					}
					break
				}
			}

			var pers [][]string
			for k, v := range set {
				pers = append(pers, []string{k, v})
			}
			return pers, nil
		}
	}
}
