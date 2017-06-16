package http_authproxy

import (
	"github.com/linuzilla/ipacl"
)

type Config struct {
	Host         string `json:"host" binding:"required"`
	Scheme       string `json:"scheme" binding:"required"`
	LogDir       string `json:"logDir" binding:"required"`
	TrustyProxy  string `json:"trustyProxy" binding:"required"`
	TrustyHeader string `json:"trustyHeader" binding:"required"`
	ProxyAccount struct {
		Username   string `json:"username" binding:"required"`
		Password   string `json:"-"`
		Base64pass string `json:"base64pass" binding:"required"`
	} `json:"proxyAccount" binding:"required"`
	AcceptableFrom map[string]*struct {
		Password   string           `json:"-"`
		Base64pass string           `json:"base64pass" binding:"required"`
		AccessList []string         `json:"accessList" binding:"required"`
		acl        ipacl.IPListMgmt `json:"-"`
	} `json:"acceptableFrom" binding:"required"`
}
