package clevis

func expandBuffer(buffer []byte, finalLength int) []byte {
	if len(buffer) < finalLength {
		newBuffer := make([]byte, finalLength-len(buffer), finalLength)
		newBuffer = append(newBuffer, buffer...)
		return newBuffer
	}
	return buffer
}
