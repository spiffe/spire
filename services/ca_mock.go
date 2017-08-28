package services

//CAMock
type CAMock struct {
}

func (mock *CAMock) SignCsr(csr []byte) (cert []byte, err error) {
	return nil, nil
}
