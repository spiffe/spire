package dynamostore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"

	"github.com/spiffe/spire/proto/spire/common"
)

type TableBasics struct {
	DynamoDbClient *dynamodb.Client
	TableName      *string
}

type LocalMetadata struct {
	CreatedAt time.Time `json:"CreatedAt"`
	UpdatedAt time.Time `json:"UpdatedAt"`
	Revision  int64     `json:"Revision"`
}

type LocalRecord struct {
	LocalMetadata `json:"Metadata"`
	Kind          string      `json:"Kind"`
	Key           string      `json:"Key"`
	Value         interface{} `json:"Value"`
}

type Config struct {
	Now             func() time.Time
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	Endpoint        string
	TableName       string
}

type Store struct {
	now      func() time.Time
	awsTable *TableBasics
}

func newAWSConfig(ctx context.Context, c *Config) (aws.Config, error) {
	cfg, err := awsConfig.LoadDefaultConfig(ctx,
		awsConfig.WithRegion(c.Region),
	)
	if err != nil {
		return aws.Config{}, err
	}

	if c.SecretAccessKey != "" && c.AccessKeyID != "" {
		cfg.Credentials = credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, "")
	}

	return cfg, nil
}

func createClient(ctx context.Context, config Config) (*dynamodb.Client, error) {
	cfg, err := newAWSConfig(ctx, &config)

	if err != nil {
		return nil, err
	}

	return dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if config.Endpoint != "" {
			o.BaseEndpoint = aws.String(config.Endpoint)
		}
	}), nil
}

func buildCreateTableInput(tableName string) *dynamodb.CreateTableInput {
	return &dynamodb.CreateTableInput{
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("Key"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("Kind"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("Kind"),
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String("Key"),
				KeyType:       types.KeyTypeRange,
			},
		},
		TableName:   aws.String(tableName),
		BillingMode: types.BillingModePayPerRequest,
	}
}

func tableExists(ctx context.Context, client *dynamodb.Client, name string) bool {
	tables, err := client.ListTables(ctx, &dynamodb.ListTablesInput{})
	if err != nil {
		//fmt.Printf("Dynamo list tables error %+v\n", err)
		return false
	}
	for _, n := range tables.TableNames {
		if n == name {
			return true
		}
	}
	return false
}

func checkTable(ctx context.Context, client *dynamodb.Client, name string) error {
	for i := 1; i <= 6; i++ {
		describeTableOutput, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(name),
		})
		if err != nil {
			return fmt.Errorf("failed to describe table: %w", err)
		}

		if describeTableOutput.Table.TableStatus == types.TableStatusActive {
			//fmt.Printf("DynamoDB table %s is now ready.\n", name)
			return nil
		}

		//fmt.Printf("Waiting for table %s to be created...\n", name)
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("table %s is not active after waiting", name)
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if config.Now == nil {
		config.Now = time.Now
	}

	if config.TableName == "" {
		config.TableName = "Spire"
	}

	dynamoClient, err := createClient(ctx, config)

	if err != nil {
		return nil, err
	}

	if tableExists(ctx, dynamoClient, config.TableName) {
		//fmt.Printf("Dynamo table Spire exist\n")
	} else {
		//fmt.Printf("Dynamo table Spire not exist, creating...\n")
		_, err := dynamoClient.CreateTable(ctx, buildCreateTableInput(config.TableName))
		if err != nil {
			//fmt.Printf("CreateTable failed", err)
			return nil, err
		}
	}

	err = checkTable(ctx, dynamoClient, config.TableName)
	if err != nil {
		//fmt.Printf("Error checking table: %v\n", err)
		return nil, err
	} else {
		//fmt.Printf("Table check completed successfully.\n")
	}

	return &Store{
		now: config.Now,
		awsTable: &TableBasics{
			DynamoDbClient: dynamoClient,
			TableName:      aws.String(config.TableName),
		},
	}, nil
}

func (s *Store) Close() error {
	return nil
}

// Get retrieves a record from the store based on kind and key.
func (s *Store) Get(ctx context.Context, kind string, key string) (keyvalue.Record, error) {
	tableKey := map[string]types.AttributeValue{
		"Key":  &types.AttributeValueMemberS{Value: key},
		"Kind": &types.AttributeValueMemberS{Value: kind},
	}

	input := &dynamodb.GetItemInput{
		TableName: s.awsTable.TableName,
		Key:       tableKey,
	}

	result, err := s.awsTable.DynamoDbClient.GetItem(ctx, input)
	if err != nil {
		//fmt.Printf("Dynamo Failed to read item: %v\n", err)
		return keyvalue.Record{}, err // Return an empty record
	}

	if len(result.Item) == 0 {
		return keyvalue.Record{}, keyvalue.ErrNotFound
	}

	var record keyvalue.Record
	if err := attributevalue.UnmarshalMap(result.Item, &record); err != nil {
		return keyvalue.Record{}, err
	}

	return record, nil
}

// Create inserts a new record into the store with the given kind, key, and object data.
func (s *Store) Create(ctx context.Context, kind string, key string, object interface{}, byteValue []byte) error {
	now := s.now().UTC()

	record := keyvalue.Record{
		Metadata: keyvalue.Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Revision:  1,
		},
		Object:    object,
		ByteValue: byteValue,
	}
	record.Key = key
	record.Kind = kind

	attribs, err := attributevalue.MarshalMap(record)
	if err != nil {
		return err
	}

	condition, err := notExist().Build()
	if err != nil {
		return err
	}

	input := &dynamodb.PutItemInput{
		ExpressionAttributeNames: condition.Names(),
		ConditionExpression:      condition.Condition(),
		TableName:                s.awsTable.TableName,
		Item:                     attribs,
	}

	_, err = s.awsTable.DynamoDbClient.PutItem(ctx, input)

	if err != nil {
		//fmt.Printf("Dynamo Failed to write item: %v\n", err)

		var conditionalCheckErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckErr) {
			//fmt.Printf("Create failed because entry exists, %v",
			//	conditionalCheckErr.ErrorMessage())
			return keyvalue.ErrExists
		}

		return err
	}

	return nil
}

// Update modifies an existing record in the store based on kind and key,
// with the value if the specified revision matches the one in the store.
func (s *Store) Update(ctx context.Context, kind string, key string, value interface{}, byteValue []byte, revision int64) error {
	tableKey := map[string]types.AttributeValue{
		"Key":  &types.AttributeValueMemberS{Value: key},
		"Kind": &types.AttributeValueMemberS{Value: kind},
	}

	updateExpr := expression.Set(expression.Name("Object"), expression.Value(value)).
		Set(expression.Name("ByteValue"), expression.Value(byteValue)).
		Set(expression.Name("UpdatedAt"), expression.Value(s.now().UTC())).
		Add(expression.Name("Revision"), expression.Value(1))

	expr, err := atModRevision(revision).WithUpdate(updateExpr).Build()

	if err != nil {
		//fmt.Printf("Couldn't build expression for update. Here's why: %v\n", err)
		return err
	}

	_, err = s.awsTable.DynamoDbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 s.awsTable.TableName,
		Key:                       tableKey,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
		ConditionExpression:       expr.Condition(),
		//ReturnValues:              types.ReturnValueUpdatedNew,
	})

	if err != nil {
		//fmt.Printf("Couldn't update %s %s. Here's why: %v\n", key, kind, err)
		var conditionalCheckErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckErr) {
			//fmt.Printf("update failed because condition failed, %v",
			//	conditionalCheckErr.ErrorMessage())
			return keyvalue.ErrConflict
		}
	}

	return nil

}

// Replace restar an existing record in the store based on kind and key,
// with the value if the specified revision matches the one in the store.
func (s *Store) Replace(ctx context.Context, kind string, key string, value interface{}, byteValue []byte) error {
	tableKey := map[string]types.AttributeValue{
		"Key":  &types.AttributeValueMemberS{Value: key},
		"Kind": &types.AttributeValueMemberS{Value: kind},
	}

	updateExpr := expression.Set(expression.Name("Object"), expression.Value(value)).
		Set(expression.Name("ByteValue"), expression.Value(byteValue)).
		Set(expression.Name("UpdatedAt"), expression.Value(s.now().UTC())).
		Add(expression.Name("Revision"), expression.Value(1))

	expr, err := expression.NewBuilder().WithUpdate(updateExpr).Build()

	if err != nil {
		//fmt.Printf("Couldn't build expression for update. Here's why: %v\n", err)
		return err
	}

	_, err = s.awsTable.DynamoDbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 s.awsTable.TableName,
		Key:                       tableKey,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
		//ReturnValues:              types.ReturnValueUpdatedNew,
	})

	if err != nil {
		//fmt.Printf("Couldn't replace %s %s. Here's why: %v\n", key, kind, err)
		var conditionalCheckErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckErr) {
			//fmt.Printf("replace failed because condition failed, %v",
			//	conditionalCheckErr.ErrorMessage())
			return keyvalue.ErrConflict
		}
	}

	return err
}

// Delete removes a record from the store based on kind and key.
func (s *Store) Delete(ctx context.Context, kind string, key string) error {
	tableKey := map[string]types.AttributeValue{
		"Key":  &types.AttributeValueMemberS{Value: key},
		"Kind": &types.AttributeValueMemberS{Value: kind},
	}

	condition, err := exist().Build()
	if err != nil {
		return err
	}

	_, err = s.awsTable.DynamoDbClient.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:                s.awsTable.TableName,
		Key:                      tableKey,
		ExpressionAttributeNames: condition.Names(),
		ConditionExpression:      condition.Condition(),
	})
	if err != nil {
		//fmt.Printf("Couldn't delete %v from the table. Here's why: %v\n", key, err)
		var conditionalCheckErr *types.ConditionalCheckFailedException
		if errors.As(err, &conditionalCheckErr) {
			//fmt.Printf("update failed because condition failed, %v",
			//	conditionalCheckErr.ErrorMessage())
			return keyvalue.ErrNotFound
		}
	}

	return nil
}

func (s *Store) Batch(ctx context.Context, ops []keyvalue.Op) error {
	return errors.New("unimplemented")
}

// AtomicCounter increments and retrieves the current value of the atomic counter
// for the given kind.
func (s *Store) AtomicCounter(ctx context.Context, kind string) (uint, error) {
	// The "kind" will be used as key to the counter
	tableKey := map[string]types.AttributeValue{
		"Key":  &types.AttributeValueMemberS{Value: kind},
		"Kind": &types.AttributeValueMemberS{Value: "atomicCounter"},
	}

	updateExpr := expression.Add(expression.Name("Count"), expression.Value(1))

	expr, err := expression.NewBuilder().WithUpdate(updateExpr).Build()

	if err != nil {
		//fmt.Printf("Couldn't build expression for update. Here's why: %v\n", err)
		return 0, err
	}

	response, err := s.awsTable.DynamoDbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                 s.awsTable.TableName,
		Key:                       tableKey,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		UpdateExpression:          expr.Update(),
		ReturnValues:              types.ReturnValueUpdatedNew,
	})

	if err != nil {
		//fmt.Printf("Couldn't update AtomicCounter %s. Here's why: %v\n", kind, err)
		return 0, err
	}

	var newValue uint
	err = attributevalue.Unmarshal(response.Attributes["Count"], &newValue)
	if err != nil {
		//fmt.Printf("Couldn't unmarshal AtomicCounter. Here's why: %v\n", err)
		return 0, err
	}

	return newValue, nil

}

// List retrieves records from the store based on kind,
// filters, and pagination parameters from the ListObject.
func (s *Store) List(ctx context.Context, kind string, listObject *keyvalue.ListObject) ([]keyvalue.Record, string, error) {
	var results []keyvalue.Record
	var projection []string //TODO
	var nextCursor string

	keyCondition := expression.Key("Kind").Equal(expression.Value(kind))
	filterExpression := expression.ConditionBuilder{}

	for idx, filter := range listObject.Filters {
		field := expression.Name(filter.Name)
		var exp expression.ConditionBuilder

		switch filter.Op {
		case keyvalue.EqualTo:
			exp = field.Equal(expression.Value(filter.Value))
		case keyvalue.LessThan:
			exp = field.LessThan(expression.Value(filter.Value))
		case keyvalue.GreaterThan:
			exp = field.GreaterThan(expression.Value(filter.Value))

		case keyvalue.MatchAny:
			switch values := filter.Value.(type) {
			case []*common.Selector:
				exp = listMatchAny[*common.Selector](field, values)
			case []string:
				exp = listMatchAny[string](field, values)
			default:
				return nil, "", fmt.Errorf("unknown value type for filter")
			}
		case keyvalue.MatchExact:
			switch values := filter.Value.(type) {
			case []*common.Selector:
				exp = listMatchExact[*common.Selector](field, values)
			case []string:
				exp = listMatchExact[string](field, values)
			default:
				return nil, "", fmt.Errorf("unknown value type for filter")
			}
		case keyvalue.MatchSuperset:
			switch values := filter.Value.(type) {
			case []*common.Selector:
				exp = listMatchSuperset[*common.Selector](field, values)
			case []string:
				exp = listMatchSuperset[string](field, values)
			default:
				return nil, "", fmt.Errorf("unknown value type for filter")
			}
		case keyvalue.MatchSubset:
			switch values := filter.Value.(type) {
			case []*common.Selector:
				exp = listMatchSubset[*common.Selector](field, values)
			case []string:
				exp = listMatchSubset[string](field, values)
			default:
				return nil, "", fmt.Errorf("unknown value type for filter")
			}
		default:
			return nil, "", fmt.Errorf("unknown value type for filter")
		}

		if idx == 0 {
			filterExpression = exp
		} else {
			filterExpression = filterExpression.And(exp)
		}
	}

	builder := expression.NewBuilder().WithKeyCondition(keyCondition)

	if len(projection) > 0 {
		projBuilder := expression.NamesList(expression.Name(projection[0]))
		for _, attr := range projection[1:] {
			projBuilder = projBuilder.AddNames(expression.Name(attr))
		}
		builder = builder.WithProjection(projBuilder)
	}

	if len(listObject.Filters) != 0 {
		builder = builder.WithFilter(filterExpression)
	}

	expr, err := builder.Build()
	if err != nil {
		return nil, "", fmt.Errorf("error when building expression: %w", err)
	}

	input := &dynamodb.QueryInput{
		TableName:                 s.awsTable.TableName,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		ProjectionExpression:      expr.Projection(),
	}

	if len(listObject.Filters) != 0 {
		input.FilterExpression = expr.Filter()
	}

	if listObject != nil && listObject.Cursor != "" {
		input.ExclusiveStartKey = map[string]types.AttributeValue{
			"Kind": &types.AttributeValueMemberS{Value: kind},
			"Key":  &types.AttributeValueMemberS{Value: listObject.Cursor},
		}
	}

	var limit int
	if listObject != nil && listObject.Limit > 0 {
		limit = listObject.Limit

		input.Limit = new(int32)
		*input.Limit = int32(listObject.Limit)
	}

	queryPaginator := dynamodb.NewQueryPaginator(s.awsTable.DynamoDbClient, input)

	for queryPaginator.HasMorePages() && (limit <= 0 || len(results) < limit) {
		page, err := queryPaginator.NextPage(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to fetch records: %w", err)
		}

		var pageResults []keyvalue.Record
		if err := attributevalue.UnmarshalListOfMaps(page.Items, &pageResults); err != nil {
			return nil, "", fmt.Errorf("failure to deserialize records: %w", err)
		}

		results = append(results, pageResults...)

		if page.LastEvaluatedKey != nil {
			nextCursor = page.LastEvaluatedKey["Key"].(*types.AttributeValueMemberS).Value
		} else {
			nextCursor = ""
		}
	}

	if listObject.Limit > 0 && len(results) != 0 {
		if len(results) > listObject.Limit {
			results = results[:listObject.Limit]
		}
		nextCursor = results[len(results)-1].Key
	}

	return results, nextCursor, nil
}

func listMatchAny[T any](field expression.NameBuilder, values []T) expression.ConditionBuilder {
	exp := expression.Contains(field, values[0])

	for _, selector := range values[1:] {
		exp = exp.Or(expression.Contains(field, selector))
	}

	return exp
}

func listMatchExact[T any](field expression.NameBuilder, values []T) expression.ConditionBuilder {
	exp := expression.Equal(expression.Size(field), expression.Value(len(values)))

	return exp.And(expression.In(field, expression.Value(values)))
}

func listMatchSuperset[T any](field expression.NameBuilder, values []T) expression.ConditionBuilder {
	exp := expression.Contains(field, values[0])

	for _, selector := range values[1:] {
		exp = exp.And(expression.Contains(field, selector))
	}

	return exp
}

/*
MORE TESTS NEED TO BE PERFORMED
*/
func listMatchSubset[T any](field expression.NameBuilder, values []T) expression.ConditionBuilder {
	exp := expression.LessThanEqual(expression.Size(field), expression.Value(len(values)))

	var subExp expression.ConditionBuilder

	var currentSubset []T
	var backtrack func(int)
	backtrack = func(start int) {
		if len(currentSubset) > 0 {
			destination := make([]T, len(currentSubset))

			copy(destination, currentSubset)
			if start == 1 {
				subExp = listMatchExact[T](field, destination)
			} else {
				subExp = subExp.Or(listMatchExact[T](field, destination))
			}
		}

		// Generate the next subsets by including new elements
		for i := start; i < len(values); i++ {
			currentSubset = append(currentSubset, values[i])     // Include the new element
			backtrack(i + 1)                                     // Recurse with the new subset
			currentSubset = currentSubset[:len(currentSubset)-1] // Backtrack to explore other combinations
		}
	}

	backtrack(0)

	return exp.And(subExp)
}

func notExist() expression.Builder {
	return expression.NewBuilder().
		WithCondition(expression.And(expression.AttributeNotExists(expression.Name("Key")), expression.AttributeNotExists(expression.Name("Kind"))))
}
func exist() expression.Builder {
	return expression.NewBuilder().
		WithCondition(expression.And(expression.AttributeExists(expression.Name("Key")), expression.AttributeExists(expression.Name("Kind"))))
}

func atModRevision(revision int64) expression.Builder {
	return expression.NewBuilder().
		WithCondition(expression.Equal(expression.Name("Revision"), expression.Value(revision)))
}
