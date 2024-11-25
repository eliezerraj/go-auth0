package core

import(
	"time"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v4"
)

type AppServer struct {
	InfoPod 		*InfoPod 		`json:"info_pod"`
	Server     		*Server     	`json:"server"`
	ConfigOTEL		*ConfigOTEL		`json:"otel_config"`
	DynamoConfig	*DatabaseDynamo	`json:"dynamo_config"`
	RSA_Key			*RSA_Key		`json:"rsa_key"`
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
	ID				string	`json:"ID,omitempty"`
	SK				string	`json:"SK,omitempty"`
	User			string	`json:"user,omitempty"`
	Password		string	`json:"password,omitempty"`
	BasicAuth		string	`json:"basic_auth,omitempty"`
	Token			string 	`json:"token,omitempty"`
}

type CredentialScope struct {
	ID				string		`json:"ID"`
	SK				string		`json:"SK"`
	User			string		`json:"user,omitempty"`
	Scope			[]string	`json:"scope,omitempty"`
	Updated_at  	time.Time 	`json:"updated_at,omitempty"`
}

type JwtData struct {
	TokenUse	string 	`json:"token_use"`
	ISS			string 	`json:"iss"`
	Version		string 	`json:"version"`
	JwtId		string 	`json:"jwt_id"`
	Username	string 	`json:"username"`
	Scope	  	[]string `json:"scope"`
	jwt.RegisteredClaims
}

type DatabaseDynamo struct {
	UserTableName		string `json:"order_table"`
	AwsRegion			string	`json:"aws_region"`
}

type RSA_Key struct{
	RSAPublicKey		string 	`json:"rsa_public_key"`
	RSAPublicKeyByte 	[]byte 	`json:"rsa_public_key_byte"`
	RSAPrivateKey		string 	`json:"rsa_private_key"`
	RSAPrivateKeyByte 	[]byte 	`json:"rsa_private_key_byte"`
	PrivateKeyPem		*rsa.PrivateKey
	HS256				[]byte 	`json:"h256_key_byte"`		
}

type Jwks struct{
	Keys		[]JKey 	`json:"keys"`
}

type JKey struct{
	Type		string 	`json:"kty"`
	Algorithm	string 	`json:"alg"`
	JwtId		string 	`json:"kid"`
	NBase64		string 	`json:"n"`
}

type JwksData struct {
	Token			string 	`json:"token,omitempty"`
	JwtId			string 	`json:"kid,omitempty"`
	RSAPublicKeyB64	string 	`json:"rsa_public_key_b64"`
}