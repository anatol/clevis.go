package clevis

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDivRoundUp(t *testing.T) {
	require.Equal(t, divRoundUp(6, 8), 1)
	require.Equal(t, divRoundUp(0, 5), 0)
	require.Equal(t, divRoundUp(22, 5), 5)
	require.Equal(t, divRoundUp(48, 8), 6)
}
