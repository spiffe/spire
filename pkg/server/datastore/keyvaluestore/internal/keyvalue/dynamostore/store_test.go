package dynamostore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore/keyvaluestore/internal/keyvalue"
	"github.com/stretchr/testify/require"

	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamoTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"strconv"
)

type MyObject struct {
	Data         string
	Data_float64 float64
	Tags         []string
}

var (
	kind = "kind"
	key  = "key"
)

func TestStoreOperations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	config := Config{
		AccessKeyID:     "dummy",
		SecretAccessKey: "dummy",
		Region:          "us-west-1",
		Endpoint:        "http://localhost:8000",
		TableName:       "Spire",
	}

	wipeDynamo(ctx, t, config)

	s, err := Open(ctx, config)
	require.NoError(t, err, "failed to open store")
	require.NotNil(t, s, "store should not be nil")

	now := time.Now()
	r1, err := s.Get(ctx, kind, key)
	require.True(t, errors.Is(err, keyvalue.ErrNotFound), "unexpected error %q", err)

	objData1 := new(MyObject)
	objData1.Data = "data1"
	objData1.Data_float64 = 1
	data1, _ := json.Marshal(objData1)

	err = s.Create(ctx, kind, key, objData1, data1)
	require.NoError(t, err)

	r1, err = s.Get(ctx, kind, key)
	require.NoError(t, err)

	err = s.Create(ctx, kind, key, objData1, data1)
	require.True(t, errors.Is(err, keyvalue.ErrExists), "unexpected error %q", err)

	objData2 := new(MyObject)
	objData2.Data = "data2"
	objData2.Data_float64 = 2
	data2, _ := json.Marshal(objData2)

	err = s.Update(ctx, kind, key, objData2, data2, r1.Revision+1)
	require.True(t, errors.Is(err, keyvalue.ErrConflict), "unexpected error %q", err)

	now = now.Add(time.Second)
	err = s.Update(ctx, kind, key, objData2, data2, r1.Revision)
	require.NoError(t, err)

	r2, err := s.Get(ctx, kind, key)
	require.NoError(t, err)
	require.Equal(t, r1.CreatedAt, r2.CreatedAt)
	require.NotEqual(t, r1.UpdatedAt, r2.UpdatedAt)

	objData3 := new(MyObject)
	objData3.Data = "data3"
	objData3.Data_float64 = 3
	data3, _ := json.Marshal(objData3)

	now = now.Add(time.Second)
	err = s.Replace(ctx, kind, key, objData3, data3)
	require.NoError(t, err)

	r3, err := s.Get(ctx, kind, key)
	require.NoError(t, err)
	require.Equal(t, r1.CreatedAt, r3.CreatedAt)
	require.NotEqual(t, r1.UpdatedAt, r3.UpdatedAt)
	require.Equal(t, r2.CreatedAt, r3.CreatedAt)
	require.NotEqual(t, r2.UpdatedAt, r3.UpdatedAt)

	err = s.Delete(ctx, kind, key)
	require.NoError(t, err)

	_, err = s.Get(ctx, kind, key)
	require.True(t, errors.Is(err, keyvalue.ErrNotFound), "unexpected error %q", err)

	err = s.Delete(ctx, kind, key)
	require.True(t, errors.Is(err, keyvalue.ErrNotFound), "unexpected error %q", err)
}

func TestAtomicCounter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	config := Config{
		AccessKeyID:     "dummy",
		SecretAccessKey: "dummy",
		Region:          "us-west-1",
		Endpoint:        "http://localhost:8000",
		TableName:       "Spire",
	}

	wipeDynamo(ctx, t, config)

	s, err := Open(ctx, config)
	require.NoError(t, err, "failed to open store")
	require.NotNil(t, s, "store should not be nil")

	for i := 0; i < 1; i++ {
		r1, err := s.AtomicCounter(ctx, kind+strconv.Itoa(1))
		require.NoError(t, err, "Failed to initialize the AtomicCounter")
		require.Equal(t, r1, uint(i+1))
		r2, err := s.AtomicCounter(ctx, kind+strconv.Itoa(2))
		require.NoError(t, err, "Failed to initialize the AtomicCounter")
		require.Equal(t, r2, uint(i+1))
		r3, err := s.AtomicCounter(ctx, kind+strconv.Itoa(3))
		require.NoError(t, err, "Failed to initialize the AtomicCounter")
		require.Equal(t, r3, uint(i+1))
		r4, err := s.AtomicCounter(ctx, kind+strconv.Itoa(1))
		require.NoError(t, err, "Failed to initialize the AtomicCounter")
		require.Equal(t, r4, uint(i+2))
	}
}

func TestList(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	config := Config{
		AccessKeyID:     "dummy",
		SecretAccessKey: "dummy",
		Region:          "us-west-1",
		Endpoint:        "http://localhost:8000",
		TableName:       "Spire",
	}

	s, err := Open(ctx, config)
	require.NoError(t, err, "failed to open store")
	require.NotNil(t, s, "store should not be nil")

	tagLists := [][]string{
		{"TestA", "TestB"},
		{"TestC", "TestD"},
		{"TestA", "TestC"},
		{"TestB", "TestC"},
		{"TestA", "TestB", "TestC"},
		{"TestB", "TestC", "TestD"},
		{"TestA", "TestC", "TestD"},
		{"TestA", "TestB", "TestD"},
		{"TestA", "TestB", "TestC"},
		{"TestA", "TestB", "TestC", "TestD"},
	}

	for i := 0; i < 10; i += 2 {

		tags1 := tagLists[i%len(tagLists)]
		tags2 := tagLists[(i+1)%len(tagLists)]

		objData, data, err := createMyObject("data"+strconv.Itoa(i), float64(i), tags1...)
		require.NoError(t, err, "Failed to create and marshal MyObject")

		err = s.Create(ctx, kind, key+strconv.Itoa(i), objData, data)
		require.NoError(t, err, "Failed to create object with key "+strconv.Itoa(i))

		objData, data, err = createMyObject("data"+strconv.Itoa(i), float64(i+1), tags2...)
		require.NoError(t, err, "Failed to create and marshal MyObject")

		err = s.Create(ctx, kind, key+strconv.Itoa(i+1), objData, data)
		require.NoError(t, err, "Failed to create object with key "+strconv.Itoa(i+1))
	}

	//Testing without any operator
	listObject := CreateListObject("", 5)

	records, nextCursor, err := s.List(ctx, kind, listObject)
	require.Equal(t, "key4", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 5, "Invalid size")

	var records_test []keyvalue.Record

	record, err := makeRecord("kind", "key0", "data0", 0, "TestA", "TestB")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key1", "data0", 1, "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key2", "data2", 2, "TestA", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key3", "data2", 3, "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key4", "data4", 4, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the EqualTo operator
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Data", keyvalue.EqualTo, "data0")

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key1", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 2, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key0", "data0", 0, "TestA", "TestB")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key1", "data0", 1, "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the EqualTo operator for two attributes
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Data", keyvalue.EqualTo, "data2")
	AddFilter(listObject, "Object.Data_float64", keyvalue.EqualTo, 2)

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key2", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 1, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key2", "data2", 2, "TestA", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	require.Equal(t, records_test[0].ByteValue, records[0].ByteValue)

	//Testing the GreaterThan operator
	listObject = CreateListObject("", 5)
	AddFilter(listObject, "Object.Data_float64", keyvalue.GreaterThan, 5)

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key9", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 4, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key6", "data6", 6, "TestA", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key7", "data6", 7, "TestA", "TestB", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key8", "data8", 8, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key9", "data8", 9, "TestA", "TestB", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the LessThan operator
	listObject = CreateListObject("", 5)
	AddFilter(listObject, "Object.Data_float64", keyvalue.LessThan, 5)

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.NoError(t, err, "failed to list records")
	require.Equal(t, "key4", nextCursor, "The strings are not equal")
	require.Len(t, records, 5, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key0", "data0", 0, "TestA", "TestB")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key1", "data0", 1, "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key2", "data2", 2, "TestA", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key3", "data2", 3, "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key4", "data4", 4, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the GreaterThan and LessThan operators
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Data_float64", keyvalue.LessThan, 6)
	AddFilter(listObject, "Object.Data_float64", keyvalue.GreaterThan, 2)

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key5", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 3, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key3", "data2", 3, "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key4", "data4", 4, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	record, err = makeRecord("kind", "key5", "data4", 5, "TestB", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the MatchAny operator returning a non-zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchAny, []string{"TestD"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key9", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 5, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key1", "data0", 1, "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key5", "data4", 5, "TestB", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key6", "data6", 6, "TestA", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key7", "data6", 7, "TestA", "TestB", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key9", "data8", 9, "TestA", "TestB", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the MatchAny operator returning zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchAny, []string{"TestE"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 0, "Invalid size")

	//Testing the MatchExact operator returning a non-zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchExact, []string{"TestA", "TestB", "TestC"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key8", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 2, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key4", "data4", 4, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key8", "data8", 8, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the MatchExact operator returning zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchExact, []string{"TestA", "TestD"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 0, "Invalid size")

	//Testing the MatchSuperset operator returning a non-zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchSuperset, []string{"TestC", "TestB"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key9", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 5, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key3", "data2", 3, "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key4", "data4", 4, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key5", "data4", 5, "TestB", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key8", "data8", 8, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key9", "data8", 9, "TestA", "TestB", "TestC", "TestD")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the MatchSuperset operator returning zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchSuperset, []string{"TestA", "TestB", "TestC", "TestD", "TestE"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 0, "Invalid size")

	//Testing the MatchSubset operator returning a non-zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchSubset, []string{"TestA", "TestB", "TestC"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "key8", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 5, "Invalid size")

	records_test = []keyvalue.Record{}
	record, err = makeRecord("kind", "key0", "data0", 0, "TestA", "TestB")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key2", "data2", 2, "TestA", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key3", "data2", 3, "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key4", "data4", 4, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)
	record, err = makeRecord("kind", "key8", "data8", 8, "TestA", "TestB", "TestC")
	require.NoError(t, err, "Falha ao criar o registro")
	records_test = append(records_test, record)

	for i, test := range records_test {
		require.Equal(t, test.ByteValue, records[i].ByteValue)
	}

	//Testing the MatchSubset operator returning zero result.
	listObject = CreateListObject("", 10)
	AddFilter(listObject, "Object.Tags", keyvalue.MatchSubset, []string{"TestA"})

	records, nextCursor, err = s.List(ctx, kind, listObject)
	require.Equal(t, "", nextCursor, "The strings are not equal")
	require.NoError(t, err, "failed to list records")
	require.Len(t, records, 0, "Invalid size")

}

func wipeDynamo(ctx context.Context, t *testing.T, c Config) {

	cfg, err := newAWSConfig(ctx, &c)
	require.NoError(t, err)

	dynamoClient := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint) // usa o endpoint fornecido
		}
	})

	_, err = dynamoClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(c.TableName),
	})

	if err == nil {
		_, err = dynamoClient.DeleteTable(ctx, &dynamodb.DeleteTableInput{
			TableName: aws.String(c.TableName),
		})
		require.NoError(t, err)

		maxRetries := 5
		for i := 0; i < maxRetries; i++ {
			_, err = dynamoClient.DescribeTable(ctx, &dynamodb.DescribeTableInput{
				TableName: aws.String(c.TableName),
			})

			if err != nil {
				if temp := new(dynamoTypes.ResourceNotFoundException); errors.As(err, &temp) {
					fmt.Println("Table deleted successfully.")
					break
				}
			}

			time.Sleep(5 * time.Second)
		}
	}
}

func makeTags(vs ...string) []string {
	return vs
}

func makeRecord(kind, key, data string, dataFloat64 float64, tags ...string) (keyvalue.Record, error) {

	Object := MyObject{
		Data:         data,
		Data_float64: dataFloat64,
	}

	if len(tags) > 0 {
		Object.Tags = makeTags(tags...)
	}

	record := keyvalue.Record{
		Kind:   kind,
		Key:    key,
		Object: Object,
	}

	byteValue, err := json.Marshal(record.Object)
	if err != nil {
		return keyvalue.Record{}, fmt.Errorf("Failed to marshal Object to ByteValue: %v", err)
	}

	record.ByteValue = byteValue

	return record, nil
}

func createMyObject(data string, dataFloat64 float64, tags ...string) (*MyObject, []byte, error) {
	objData := &MyObject{
		Data:         data,
		Data_float64: dataFloat64,
	}

	if len(tags) > 0 {
		objData.Tags = makeTags(tags...)
	}

	dataBytes, err := json.Marshal(objData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal MyObject: %v", err)
	}

	return objData, dataBytes, nil
}

func CreateListObject(cursor string, limit int) *keyvalue.ListObject {
	return &keyvalue.ListObject{
		Cursor:  cursor,
		Limit:   limit,
		Filters: []keyvalue.ListOp{},
	}
}

func AddFilter(listObject *keyvalue.ListObject, name string, op keyvalue.MatchBehavior, value interface{}) {
	listObject.Filters = append(listObject.Filters, keyvalue.ListOp{
		Name:  name,
		Op:    op,
		Value: value,
	})
}
