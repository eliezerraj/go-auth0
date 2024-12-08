package aws_parameter_store

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/go-auth0/pkg/observability"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

var childLogger = log.With().Str("pkg", "aws_parameter_store").Logger()

type AwsClientParameterStore struct {
	Client *ssm.Client
}

func NewClientParameterStore(configAWS *aws.Config) (*AwsClientParameterStore, error) {
	childLogger.Debug().Msg("NewClientParameterStore")

	client := ssm.NewFromConfig(*configAWS)
	return &AwsClientParameterStore{
		Client: client,
	}, nil
}

func (p *AwsClientParameterStore) GetParameter(ctx context.Context, parameterName string) (*string, error) {
	childLogger.Debug().Msg("GetSecret")

	span := observability.Span(ctx, "aws_secret_manager.GetSecret")	
    defer span.End()

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