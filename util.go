package clevis

func expandBuffer(buffer []byte, finalLength int) []byte {
	if len(buffer) < finalLength {
		newBuffer := make([]byte, finalLength-len(buffer), finalLength)
		newBuffer = append(newBuffer, buffer...)
		return newBuffer
	}
	return buffer
}

// divRoundUp divides num to divisor with rounding up the result to the next integer value
func divRoundUp(num, divisor int) int {
	return (num + divisor - 1) / divisor
}
