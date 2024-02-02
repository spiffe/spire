package logger

import (
	"strings"
	"sync"

	"github.com/google/btree"
)

type loggerRecord struct {
	name string
}

// True if a is first, false otherwise
func sortByName(lesser, greater loggerRecord) bool {
	lesserSegments := strings.Split(lesser.name, ".")
	greaterSegments := strings.Split(greater.name, ".")

	var index int // declaration for post loop processing
	for index = 0; index < len(lesserSegments); index++ {
		//  lesser is "... (index) segment", greater is "... (index)"
		//  fewer segments in greater, so lesser is not lesser
		if index >= len(greaterSegments) {
			return false
		}
		//  lesser is "... (index) aaa", greater is "... (index) b"
		//  lexographic ordering of segments, so lesser is lesser
		if lesserSegments[index] < greaterSegments[index] {
			return true
		}
		//  lesser is "... (index) b", greater is "... (index) aaa"
		//  lexographic ordering of segments, so lesser is not lesser
		if lesserSegments[index] > greaterSegments[index] {
			return false
		}
		// lesser is "... (index) aaa", greater is "... (index) aaa"
		// continue comparison advancing to next segment
	} 
	// lesser is "... (index)", greater is "... (index) aaa"
	// fewer segements in greater, so lesser is lesser
	return len(lesserSegments) < len(greaterSegments)
}

type Registry struct {
	mu sync.RWMutex

	loggersByName  *btree.BTreeG[loggerRecord]
}

