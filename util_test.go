package clevis

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDivRoundUp(t *testing.T) {
	require.Equal(t, 1, divRoundUp(6, 8))
	require.Equal(t, 0, divRoundUp(0, 5))
	require.Equal(t, 5, divRoundUp(22, 5))
	require.Equal(t, 6, divRoundUp(48, 8))
	require.Equal(t, 1, divRoundUp(1, 1))
	require.Equal(t, 1, divRoundUp(8, 8))
}

func TestExpandBuffer(t *testing.T) {
	// Shorter buffer gets zero-padded at the front
	result := expandBuffer([]byte{0x01, 0x02}, 4)
	require.Equal(t, []byte{0x00, 0x00, 0x01, 0x02}, result)

	// Equal length returns same content
	result = expandBuffer([]byte{0x01, 0x02, 0x03}, 3)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, result)

	// Longer buffer returned as-is
	result = expandBuffer([]byte{0x01, 0x02, 0x03, 0x04}, 2)
	require.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, result)

	// Empty buffer
	result = expandBuffer([]byte{}, 3)
	require.Equal(t, []byte{0x00, 0x00, 0x00}, result)

	// Zero target length
	result = expandBuffer([]byte{0x01}, 0)
	require.Equal(t, []byte{0x01}, result)
}

func TestEcSubtract(t *testing.T) {
	curve := elliptic.P256()
	gx, gy := curve.Params().Gx, curve.Params().Gy

	// Subtracting a point from itself gives the point at infinity
	rx, ry := ecSubtract(curve, gx, gy, gx, gy)
	require.Equal(t, int64(0), rx.Int64())
	require.Equal(t, int64(0), ry.Int64())

	// (G + G) - G should equal G
	x2, y2 := curve.Double(gx, gy) // 2G
	rx, ry = ecSubtract(curve, x2, y2, gx, gy)
	require.Equal(t, gx, rx)
	require.Equal(t, gy, ry)

	// G - (2G) should equal -G (i.e. (Gx, P-Gy))
	rx, ry = ecSubtract(curve, gx, gy, x2, y2)
	// Verify the result is on the curve
	require.True(t, curve.IsOnCurve(rx, ry))
	// Adding the result back to 2G should give G
	checkX, checkY := curve.Add(rx, ry, x2, y2)
	require.Equal(t, gx, checkX)
	require.Equal(t, gy, checkY)
}

func TestLagrangeInterpolation(t *testing.T) {
	// Test with a known polynomial: f(x) = 5 (constant), prime = 97
	// Any set of points from f(x)=5 should interpolate back to f(0)=5
	prime := big.NewInt(97)
	points := []point{
		{big.NewInt(1), big.NewInt(5)},
		{big.NewInt(2), big.NewInt(5)},
	}
	result := lagrangeInterpolation(prime, points)
	require.Equal(t, int64(5), result.Int64())

	// Test with f(x) = 3x + 7 mod 97
	// f(1) = 10, f(2) = 13, f(0) should be 7
	points = []point{
		{big.NewInt(1), big.NewInt(10)},
		{big.NewInt(2), big.NewInt(13)},
	}
	result = lagrangeInterpolation(prime, points)
	require.Equal(t, int64(7), result.Int64())

	// Test with f(x) = 2x^2 + x + 3 mod 97
	// f(1) = 6, f(2) = 13, f(3) = 24, f(0) should be 3
	points = []point{
		{big.NewInt(1), big.NewInt(6)},
		{big.NewInt(2), big.NewInt(13)},
		{big.NewInt(3), big.NewInt(24)},
	}
	result = lagrangeInterpolation(prime, points)
	require.Equal(t, int64(3), result.Int64())

	// Single point: f(x) = 42, f(5) = 42, f(0) should be 42
	points = []point{
		{big.NewInt(5), big.NewInt(42)},
	}
	result = lagrangeInterpolation(prime, points)
	require.Equal(t, int64(42), result.Int64())
}
