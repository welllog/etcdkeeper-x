package srv

import (
	"encoding/json"
	"net/http"
)

type userInfo struct {
	Host   string
	Name  string
	Passwd string
}

type Rsp map[string]any

func (r Rsp) WriteTo(w http.ResponseWriter) {
	JsonRsp(w, r)
}

func JsonRsp(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

type Node struct {
	Key           string `json:"key"`
	Dir           bool   `json:"dir,omitempty"`
	CreatedIndex  int    `json:"createdIndex,omitempty"`
	ModifiedIndex int    `json:"modifiedIndex,omitempty"`
	Ttl           int    `json:"ttl"`
	Nodes         []Node `json:"nodes"`
}
