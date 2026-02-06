package crf

import "math"

// ForwardBackwardResult holds the results of the forward-backward algorithm.
type ForwardBackwardResult struct {
	LogZ      float64     // log partition function
	Marginals [][]float64 // [T][L] marginal probabilities P(y_t=j|x)
	Alpha     [][]float64 // [T][L] scaled forward variables
	Beta      [][]float64 // [T][L] scaled backward variables
	Scale     []float64   // [T] scaling factors
}

// ForwardBackward computes scaled forward-backward algorithm.
// stateScores: [T][L] state feature scores
// transScores: [L][L] transition feature scores
func ForwardBackward(stateScores, transScores [][]float64) ForwardBackwardResult {
	T := len(stateScores)
	if T == 0 {
		return ForwardBackwardResult{}
	}
	L := len(stateScores[0])

	// Precompute exp of scores
	expState := make([][]float64, T)
	for t := range T {
		expState[t] = make([]float64, L)
		for y := range L {
			expState[t][y] = math.Exp(stateScores[t][y])
		}
	}

	expTrans := make([][]float64, L)
	for i := range L {
		expTrans[i] = make([]float64, L)
		for j := range L {
			expTrans[i][j] = math.Exp(transScores[i][j])
		}
	}

	// Forward pass with scaling
	alpha := make([][]float64, T)
	scale := make([]float64, T)

	// t = 0
	alpha[0] = make([]float64, L)
	var sum float64
	for y := range L {
		alpha[0][y] = expState[0][y]
		sum += alpha[0][y]
	}
	scale[0] = 1.0 / sum
	for y := range L {
		alpha[0][y] *= scale[0]
	}

	// t = 1..T-1
	for t := 1; t < T; t++ {
		alpha[t] = make([]float64, L)
		sum = 0
		for y := range L {
			var s float64
			for yp := range L {
				s += alpha[t-1][yp] * expTrans[yp][y]
			}
			alpha[t][y] = s * expState[t][y]
			sum += alpha[t][y]
		}
		if sum == 0 {
			scale[t] = 1.0
		} else {
			scale[t] = 1.0 / sum
		}
		for y := range L {
			alpha[t][y] *= scale[t]
		}
	}

	// Backward pass with same scale factors
	beta := make([][]float64, T)

	// t = T-1
	beta[T-1] = make([]float64, L)
	for y := range L {
		beta[T-1][y] = scale[T-1]
	}

	// t = T-2..0
	for t := T - 2; t >= 0; t-- {
		beta[t] = make([]float64, L)
		for y := range L {
			var s float64
			for yn := range L {
				s += expTrans[y][yn] * expState[t+1][yn] * beta[t+1][yn]
			}
			beta[t][y] = s * scale[t]
		}
	}

	// LogZ = -sum(log(scale_factors))
	logZ := 0.0
	for t := range T {
		logZ -= math.Log(scale[t])
	}

	// Marginals: P(y_t=j|x) = alpha[t][j] * beta[t][j] / scale[t]
	marginals := make([][]float64, T)
	for t := range T {
		marginals[t] = make([]float64, L)
		for y := range L {
			marginals[t][y] = alpha[t][y] * beta[t][y] / scale[t]
		}
	}

	return ForwardBackwardResult{
		LogZ:      logZ,
		Marginals: marginals,
		Alpha:     alpha,
		Beta:      beta,
		Scale:     scale,
	}
}

// TransitionMarginals computes P(y_{t-1}=i, y_t=j | x) for all t, i, j.
// Returns [T-1][L][L] tensor.
func TransitionMarginals(fb ForwardBackwardResult, stateScores, transScores [][]float64) [][][]float64 {
	T := len(stateScores)
	if T <= 1 {
		return nil
	}
	L := len(stateScores[0])

	expState := make([][]float64, T)
	for t := range T {
		expState[t] = make([]float64, L)
		for y := range L {
			expState[t][y] = math.Exp(stateScores[t][y])
		}
	}
	expTrans := make([][]float64, L)
	for i := range L {
		expTrans[i] = make([]float64, L)
		for j := range L {
			expTrans[i][j] = math.Exp(transScores[i][j])
		}
	}

	result := make([][][]float64, T-1)
	for t := range T - 1 {
		result[t] = make([][]float64, L)
		for i := range L {
			result[t][i] = make([]float64, L)
			for j := range L {
				result[t][i][j] = fb.Alpha[t][i] * expTrans[i][j] * expState[t+1][j] * fb.Beta[t+1][j]
			}
		}
	}
	return result
}
