package pemutil

func FuzzBlocks(data []byte) int {
	_, err := ParseBlocks(data)
	if err != nil {
		return 0
	}
	return 1
}
