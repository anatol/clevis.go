package clevis

import (
	"crypto/elliptic"
	"math/big"
)

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

// ecSubtract subtracts point (x2,y2) from (x1,y1) over curve ecCurve
func ecSubtract(ecCurve elliptic.Curve, x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	yy := new(big.Int).Neg(y2)
	yy.Mod(yy, ecCurve.Params().P)
	return ecCurve.Add(x1, y1, x2, yy)
}
