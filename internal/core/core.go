package core

import(
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type AppServer struct {
	InfoPod 		*InfoPod 		`json:"info_pod"`
	Server     		*Server     	`json:"server"`
	ConfigOTEL		*ConfigOTEL		`json:"otel_config"`
}

type InfoPod struct {
	PodName				string `json:"pod_name"`
	ApiVersion			string `json:"version"`
	OSPID				string `json:"os_pid"`
	IPAddress			string `json:"ip_address"`
	AvailabilityZone 	string `json:"availabilityZone"`
	IsAZ				bool	`json:"is_az"`
	Env					string `json:"enviroment,omitempty"`
	AccountID			string `json:"account_id,omitempty"`
}

type Server struct {
	Port 			int `json:"port"`
	ReadTimeout		int `json:"readTimeout"`
	WriteTimeout	int `json:"writeTimeout"`
	IdleTimeout		int `json:"idleTimeout"`
	CtxTimeout		int `json:"ctxTimeout"`
}

type ConfigOTEL struct {
	OtelExportEndpoint		string
	TimeInterval            int64    `mapstructure:"TimeInterval"`
	TimeAliveIncrementer    int64    `mapstructure:"RandomTimeAliveIncrementer"`
	TotalHeapSizeUpperBound int64    `mapstructure:"RandomTotalHeapSizeUpperBound"`
	ThreadsActiveUpperBound int64    `mapstructure:"RandomThreadsActiveUpperBound"`
	CpuUsageUpperBound      int64    `mapstructure:"RandomCpuUsageUpperBound"`
	SampleAppPorts          []string `mapstructure:"SampleAppPorts"`
}

type Authentication struct {
	Token			string	`json:"token,omitempty"`
	TokenEncrypted	string	`json:"token_encrypted,omitempty"`
	ExpirationTime	time.Time `json:"expiration_time,omitempty"`
	ApiKey			string	`json:"api_key,omitempty"`
}

type Credential struct {
	ID				string	`json:"ID"`
	SK				string	`json:"SK"`
	User			string	`json:"user,omitempty"`
	Password		string	`json:"password,omitempty"`
	Token			string 	`json:"token,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
}

type CredentialScope struct {
	ID				string		`json:"ID"`
	SK				string		`json:"SK"`
	User			string		`json:"user,omitempty"`
	Scope			[]string	`json:"scope,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
}

type JwtData struct {
	Username	string 	`json:"username"`
	Scope	  []string 	`json:"scope"`
	jwt.RegisteredClaims
}