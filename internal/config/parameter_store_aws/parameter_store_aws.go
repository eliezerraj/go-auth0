package parameter_store_aws

import (
	"context"

	"github.com/rs/zerolog/log"

	"github.com/go-auth0/internal/lib"
	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/config/config_aws"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

var childLogger = log.With().Str("repository", "AwsClientParameterStore").Logger()

type AwsClientParameterStore struct {
	Client *ssm.Client
}

func NewClientParameterStore(ctx context.Context, databaseDynamo core.DatabaseDynamo) (*AwsClientParameterStore, error) {
	childLogger.Debug().Msg("NewClientParameterStore")

	span := lib.Span(ctx, "repository.NewClientParameterStore")	
    defer span.End()

	sdkConfig, err := config_aws.GetAWSConfig(ctx, databaseDynamo.AwsRegion)
	if err != nil{
		return nil, err
	}

	client := ssm.NewFromConfig(*sdkConfig)
	return &AwsClientParameterStore{
		Client: client,
	}, nil
}

func (p *AwsClientParameterStore) GetParameter(ctx context.Context, parameterName string) (*string, error) {
	result, err := p.Client.GetParameter(ctx, 
										&ssm.GetParameterInput{
											Name:	aws.String(parameterName),
											WithDecryption:	aws.Bool(false),
										})
	if err != nil {
		return nil, err
	}
	return result.Parameter.Value, nil
}