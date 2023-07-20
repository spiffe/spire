package authorizedentries

import "sync"

var (
	recordPool = sync.Pool{
		New: func() interface{} {
			return []entryRecord(nil)
		},
	}
)

func allocRecordSlice() []entryRecord {
	return recordPool.Get().([]entryRecord)
}

func freeRecordSlice(records []entryRecord) {
	recordPool.Put(records[:0])
}
