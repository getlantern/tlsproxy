package tlsproxy

import (
	"github.com/oxtoacart/bpool"
)

const (
	maxBufferBytes = 100 * 1024 * 1024

	// Taken from getlantern/lampshade.
	maxFrameSize = 1448 // basically this is the practical TCP MSS for anything traversing Ethernet and using TCP timestamps
)

var (
	pool = bpool.NewBytePool(maxBufferBytes/maxFrameSize, maxFrameSize)
)

func getBuffer() []byte {
	return pool.Get()
}

func putBuffer(b []byte) {
	pool.Put(b)
}
