package keymanager

import "time"

// rpcTimeout is used to provide a consistent timeout for all key manager
// operations. It is not unusual to have a key manager implemented by a
// remote API. The timeout prevents network failures or other similar failure
// conditions from stalling critical SPIRE operations.
const rpcTimeout = 30 * time.Second
