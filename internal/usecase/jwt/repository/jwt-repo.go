package repository

import(
	"context"
	"fmt"
	"github.com/rs/zerolog/log"

	database "github.com/go-auth0/pkg/database/dynamo"
	"github.com/go-auth0/pkg/observability"
	"github.com/go-auth0/internal/erro"
	"github.com/go-auth0/internal/model"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
)

var childLogger = log.With().Str("repository", "DynamoRepository").Logger()

type RepoWorker struct{
	TableName   *string
	Repository	*database.Database
}

func NewRepoWorker(	repository *database.Database,
					tableName   *string) *RepoWorker{
	childLogger.Debug().Msg("NewRepoCredential")

	return &RepoWorker{
		Repository: repository,
		TableName: tableName,
	}
}

func (r *RepoWorker) Login(ctx context.Context, user_credential model.Credential) (*model.Credential, error){
	childLogger.Debug().Msg("Login")

	span := observability.Span(ctx, "repo.Login")	
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

	key := &dynamodb.QueryInput{	TableName:                 r.TableName,
									ExpressionAttributeNames:  expr.Names(),
									ExpressionAttributeValues: expr.Values(),
									KeyConditionExpression:    expr.KeyCondition(),
	}

	result, err := r.Repository.Client.Query(ctx, key)
	if err != nil {
		childLogger.Error().Err(err).Msg("error Query")
		return nil, erro.ErrQuery
	}

	credential := []model.Credential{}
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

func (r *RepoWorker) QueryCredentialScope(ctx context.Context, user_credential model.Credential) (*model.CredentialScope, error){
	childLogger.Debug().Msg("QueryCredentialScope")

	span := observability.Span(ctx, "repo.QueryCredentialScope")	
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

	key := &dynamodb.QueryInput{TableName:                 r.TableName,
								ExpressionAttributeNames:  expr.Names(),
								ExpressionAttributeValues: expr.Values(),
								KeyConditionExpression:    expr.KeyCondition(),
							}

	result, err := r.Repository.Client.Query(ctx, key)
	if err != nil {
		childLogger.Error().Err(err).Msg("error Query")
		return nil, erro.ErrList
	}

	credential_scope_temp := []model.CredentialScope{}
	err = attributevalue.UnmarshalListOfMaps(result.Items, &credential_scope_temp)
    if err != nil {
		childLogger.Error().Err(err).Msg("error UnmarshalListOfMaps")
		return nil, erro.ErrUnmarshal
    }

	credential_scope_result := model.CredentialScope{}
	for _, item := range credential_scope_temp{
		credential_scope_result.ID = item.ID
		credential_scope_result.SK = item.SK
		credential_scope_result.Updated_at = item.Updated_at
		credential_scope_result.Scope = item.Scope
	}

	return &credential_scope_result, nil
}