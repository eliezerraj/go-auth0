package secret_manager_aws

import (
	"context"
	
	"github.com/rs/zerolog/log"

	"github.com/go-auth0/internal/lib"
	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/config/config_aws"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var childLogger = log.With().Str("repository", "AwsClientSecretManager").Logger()

type AwsClientSecretManager struct {
	Client *secretsmanager.Client
}

func NewClientSecretManager(ctx context.Context, databaseDynamo core.DatabaseDynamo) (*AwsClientSecretManager, error) {
	childLogger.Debug().Msg("NewClientSecretManager")

	span := lib.Span(ctx, "repository.NewClientParameterStore")	
    defer span.End()
	
	sdkConfig, err := config_aws.GetAWSConfig(ctx, databaseDynamo.AwsRegion)
	if err != nil{
		return nil, err
	}
	
	client := secretsmanager.NewFromConfig(*sdkConfig)
	return &AwsClientSecretManager{
		Client: client,
	}, nil
}

func (p *AwsClientSecretManager) GetSecret(ctx context.Context, secretName string) (*string, error) {
	result, err := p.Client.GetSecretValue(ctx, 
										&secretsmanager.GetSecretValueInput{
											SecretId:		aws.String(secretName),
											VersionStage:	aws.String("AWSCURRENT"),
										})
	if err != nil {
		return nil, err
	}
	return result.SecretString, nil
}