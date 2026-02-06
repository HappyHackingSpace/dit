package crf

import "math"

// Viterbi finds the best label sequence using the Viterbi algorithm (log-domain).
func Viterbi(stateScores, transScores [][]float64) ([]int, float64) {
	T := len(stateScores)
	if T == 0 {
		return nil, math.Inf(-1)
	}
	L := len(stateScores[0])

	// delta[t][y] = best score ending at time t with label y
	delta := make([][]float64, T)
	// psi[t][y] = best previous label for backtracking
	psi := make([][]int, T)

	// t = 0
	delta[0] = make([]float64, L)
	psi[0] = make([]int, L)
	for y := range L {
		delta[0][y] = stateScores[0][y]
		psi[0][y] = 0
	}

	// t = 1..T-1
	for t := 1; t < T; t++ {
		delta[t] = make([]float64, L)
		psi[t] = make([]int, L)
		for y := range L {
			bestScore := math.Inf(-1)
			bestPrev := 0
			for yp := range L {
				score := delta[t-1][yp] + transScores[yp][y]
				if score > bestScore {
					bestScore = score
					bestPrev = yp
				}
			}
			delta[t][y] = bestScore + stateScores[t][y]
			psi[t][y] = bestPrev
		}
	}

	// Find best final label
	bestScore := math.Inf(-1)
	bestLabel := 0
	for y := range L {
		if delta[T-1][y] > bestScore {
			bestScore = delta[T-1][y]
			bestLabel = y
		}
	}

	// Backtrack
	path := make([]int, T)
	path[T-1] = bestLabel
	for t := T - 2; t >= 0; t-- {
		path[t] = psi[t+1][path[t+1]]
	}

	return path, bestScore
}

// Predict returns the best label sequence as strings.
func (m *Model) Predict(features []map[string]float64) []string {
	stateScores := m.ComputeStateScores(features)
	transScores := m.ComputeTransScores()
	path, _ := Viterbi(stateScores, transScores)

	labels := make([]string, len(path))
	for i, id := range path {
		if id < len(m.Labels.ToStr) {
			labels[i] = m.Labels.ToStr[id]
		}
	}
	return labels
}

// PredictMarginals returns marginal probabilities for each position.
func (m *Model) PredictMarginals(features []map[string]float64) []map[string]float64 {
	stateScores := m.ComputeStateScores(features)
	transScores := m.ComputeTransScores()
	fb := ForwardBackward(stateScores, transScores)

	result := make([]map[string]float64, len(features))
	for t := range features {
		result[t] = make(map[string]float64)
		for y := range m.NumLabels {
			if y < len(m.Labels.ToStr) {
				result[t][m.Labels.ToStr[y]] = fb.Marginals[t][y]
			}
		}
	}
	return result
}
