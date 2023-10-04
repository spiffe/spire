package authorizedentries

import "sync"

var (
	// Stores pointers to record slices. See https://staticcheck.io/docs/checks#SA6002.
	recordPool = sync.Pool{
		New: func() interface{} {
			p := []entryRecord(nil)
			return &p
		},
	}
)

func allocRecordSlice() []entryRecord {
	return *recordPool.Get().(*[]entryRecord)
}

func freeRecordSlice(records []entryRecord) {
	records = records[:0]
	recordPool.Put(&records)
}
