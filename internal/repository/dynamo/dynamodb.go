package dynamo

import(
	"context"
	"fmt"

	"github.com/go-auth0/internal/lib"
	"github.com/go-auth0/internal/erro"
	"github.com/go-auth0/internal/core"
	"github.com/go-auth0/internal/config/config_aws"

	"github.com/rs/zerolog/log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
)

var childLogger = log.With().Str("repository", "DynamoRepository").Logger()

type DynamoRepository struct {
	client 		*dynamodb.Client
	tableName   *string
}

func NewDynamoRepository(ctx context.Context, databaseDynamo core.DatabaseDynamo) (*DynamoRepository, error){
	childLogger.Debug().Msg("NewDynamoRepository")

	span := lib.Span(ctx, "repository.NewDynamoRepository")	
    defer span.End()

	sdkConfig, err :=config_aws.GetAWSConfig(ctx, databaseDynamo.AwsRegion)
	if err != nil{
		return nil, err
	}

	client := dynamodb.NewFromConfig(*sdkConfig)

	return &DynamoRepository {
		client: client,
		tableName: aws.String(databaseDynamo.UserTableName),
	}, nil
}

func (r *DynamoRepository) Login(ctx context.Context, user_credential core.Credential) (*core.Credential, error){
	childLogger.Debug().Msg("Login")

	span := lib.Span(ctx, "repo.Login")	
    defer span.End()

	var keyCond expression.KeyConditionBuilder
	id := "USER-" + user_credential.User

	keyCond = expression.KeyAnd(
		expression.Key("ID").Equal(expression.Value(id)),
		expression.Key("SK").BeginsWith(id),
	)

	expr, err := expression.NewBuilder().
							WithKeyCondition(keyCond).
							Build()
	if err != nil {
		childLogger.Error().Err(err).Msg("error NewBuilder")
		return nil, erro.ErrPreparedQuery
	}

	key := &dynamodb.QueryInput{	TableName:                 r.tableName,
									ExpressionAttributeNames:  expr.Names(),
									ExpressionAttributeValues: expr.Values(),
									KeyConditionExpression:    expr.KeyCondition(),
	}

	result, err := r.client.Query(ctx, key)
	if err != nil {
		childLogger.Error().Err(err).Msg("error Query")
		return nil, erro.ErrQuery
	}

	credential := []core.Credential{}
	err = attributevalue.UnmarshalListOfMaps(result.Items, &credential)
    if err != nil {
		childLogger.Error().Err(err).Msg("error UnmarshalListOfMaps")
		return nil, erro.ErrUnmarshal
    }

	if len(credential) == 0 {
		return nil, erro.ErrNotFound
	} else {
		return &credential[0], nil
	}
}

func (r *DynamoRepository) QueryCredentialScope(ctx context.Context, user_credential core.Credential) (*core.CredentialScope, error){
	childLogger.Debug().Msg("QueryCredentialScope")

	span := lib.Span(ctx, "repo.QueryCredentialScope")	
    defer span.End()

	var keyCond expression.KeyConditionBuilder

	id := fmt.Sprintf("USER-%s", user_credential.User)
	sk := "SCOPE-001"

	keyCond = expression.KeyAnd(
		expression.Key("ID").Equal(expression.Value(id)),
		expression.Key("SK").BeginsWith(sk),
	)

	expr, err := expression.NewBuilder().
							WithKeyCondition(keyCond).
							Build()
	if err != nil {
		return nil, err
	}

	key := &dynamodb.QueryInput{TableName:                 r.tableName,
								ExpressionAttributeNames:  expr.Names(),
								ExpressionAttributeValues: expr.Values(),
								KeyConditionExpression:    expr.KeyCondition(),
							}

	result, err := r.client.Query(ctx, key)
	if err != nil {
		childLogger.Error().Err(err).Msg("error Query")
		return nil, erro.ErrList
	}

	credential_scope_temp := []core.CredentialScope{}
	err = attributevalue.UnmarshalListOfMaps(result.Items, &credential_scope_temp)
    if err != nil {
		childLogger.Error().Err(err).Msg("error UnmarshalListOfMaps")
		return nil, erro.ErrUnmarshal
    }

	credential_scope_result := core.CredentialScope{}
	for _, item := range credential_scope_temp{
		credential_scope_result.ID = item.ID
		credential_scope_result.SK = item.SK
		credential_scope_result.Updated_at = item.Updated_at
		credential_scope_result.Scope = item.Scope
	}

	return &credential_scope_result, nil
}