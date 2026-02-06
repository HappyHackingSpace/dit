package crf

import (
	"log/slog"
	"math"
)

// TrainerConfig holds CRF training hyperparameters.
type TrainerConfig struct {
	C1                     float64 // L1 regularization
	C2                     float64 // L2 regularization
	MaxIterations          int
	AllPossibleTransitions bool
	Epsilon                float64 // convergence threshold
	Verbose                bool
}

// DefaultTrainerConfig returns default training config matching Formasaurus.
func DefaultTrainerConfig() TrainerConfig {
	return TrainerConfig{
		C1:                     0.1655,
		C2:                     0.0236,
		MaxIterations:          100,
		AllPossibleTransitions: true,
		Epsilon:                1e-5,
	}
}

// Train trains a CRF model on the given sequences using OWL-QN.
func Train(sequences []TrainingSequence, config TrainerConfig) *Model {
	model := NewModel()

	// Build alphabets
	model.Labels = BuildLabelAlphabet(sequences)
	model.Attributes = BuildAttributeAlphabet(sequences)
	model.NumLabels = model.Labels.Size()

	numWeights := model.NumWeights()
	model.Weights = make([]float64, numWeights)

	// Convert training data to internal representation
	type internalSeq struct {
		features [][]featureEntry // [T][...] sorted (attrID, value)
		labels   []int            // [T] label IDs
	}

	internals := make([]internalSeq, len(sequences))
	for i, seq := range sequences {
		T := len(seq.Features)
		is := internalSeq{
			features: make([][]featureEntry, T),
			labels:   make([]int, T),
		}
		for t := range T {
			for attr, val := range seq.Features[t] {
				attrID := model.Attributes.Get(attr)
				if attrID >= 0 {
					is.features[t] = append(is.features[t], featureEntry{attrID, val})
				}
			}
			is.labels[t] = model.Labels.Get(seq.Labels[t])
		}
		internals[i] = is
	}

	L := model.NumLabels
	transOffset := model.TransOffset()

	// OWL-QN optimization
	m := 10 // L-BFGS memory size
	lbfgs := newLBFGS(numWeights, m)

	w := model.Weights
	grad := make([]float64, numWeights)

	for iter := range config.MaxIterations {
		// Compute objective and gradient
		for i := range grad {
			grad[i] = 0
		}
		nll := 0.0

		for _, is := range internals {
			T := len(is.features)
			if T == 0 {
				continue
			}

			// Compute state scores
			stateScores := make([][]float64, T)
			for t := range T {
				stateScores[t] = make([]float64, L)
				for _, fe := range is.features[t] {
					for y := range L {
						idx := fe.attrID*L + y
						stateScores[t][y] += w[idx] * fe.value
					}
				}
			}

			// Compute transition scores
			transScores := make([][]float64, L)
			for i := range L {
				transScores[i] = make([]float64, L)
				for j := range L {
					transScores[i][j] = w[transOffset+i*L+j]
				}
			}

			// Forward-backward
			fb := ForwardBackward(stateScores, transScores)

			// NLL contribution: -score(y*) + logZ
			goldScore := 0.0
			for t := range T {
				y := is.labels[t]
				goldScore += stateScores[t][y]
				if t > 0 {
					yp := is.labels[t-1]
					goldScore += transScores[yp][y]
				}
			}
			nll += -goldScore + fb.LogZ

			// Gradient: E_model[f_k|x] - E_empirical[f_k]
			// State features
			for t := range T {
				goldY := is.labels[t]
				for _, fe := range is.features[t] {
					// Subtract empirical
					grad[fe.attrID*L+goldY] -= fe.value
					// Add model expectation
					for y := range L {
						grad[fe.attrID*L+y] += fb.Marginals[t][y] * fe.value
					}
				}
			}

			// Transition features
			if T > 1 {
				transMarg := TransitionMarginals(fb, stateScores, transScores)
				for t := range T - 1 {
					// Subtract empirical
					yp, y := is.labels[t], is.labels[t+1]
					grad[transOffset+yp*L+y] -= 1.0
					// Add model expectation
					for i := range L {
						for j := range L {
							grad[transOffset+i*L+j] += transMarg[t][i][j]
						}
					}
				}
			}
		}

		// Add L2 regularization
		l2Reg := 0.0
		if config.C2 > 0 {
			for i := range numWeights {
				l2Reg += w[i] * w[i]
				grad[i] += config.C2 * w[i]
			}
			nll += 0.5 * config.C2 * l2Reg
		}

		// L1 regularization contributes to objective but not gradient (handled by OWL-QN)
		if config.C1 > 0 {
			for i := range numWeights {
				nll += config.C1 * math.Abs(w[i])
			}
		}

		slog.Debug("CRF training iteration", "iteration", iter+1, "nll", nll)

		// OWL-QN step
		// Compute pseudo-gradient for L1
		pg := make([]float64, numWeights)
		for i := range numWeights {
			switch {
			case w[i] > 0:
				pg[i] = grad[i] + config.C1
			case w[i] < 0:
				pg[i] = grad[i] - config.C1
			default:
				switch {
				case grad[i]+config.C1 < 0:
					pg[i] = grad[i] + config.C1
				case grad[i]-config.C1 > 0:
					pg[i] = grad[i] - config.C1
				default:
					pg[i] = 0
				}
			}
		}

		// Get search direction from L-BFGS
		dir := lbfgs.computeDirection(pg)

		// Constrain direction to same orthant as pseudo-gradient
		for i := range numWeights {
			if dir[i]*pg[i] > 0 {
				dir[i] = 0
			}
		}

		// Line search with orthant projection
		step := owlqnLineSearch(w, dir, nll, pg, func(wNew []float64) float64 {
			obj := 0.0
			for _, is := range internals {
				T := len(is.features)
				if T == 0 {
					continue
				}
				stateScores := make([][]float64, T)
				for t := range T {
					stateScores[t] = make([]float64, L)
					for _, fe := range is.features[t] {
						for y := range L {
							stateScores[t][y] += wNew[fe.attrID*L+y] * fe.value
						}
					}
				}
				transScores := make([][]float64, L)
				for i := range L {
					transScores[i] = make([]float64, L)
					for j := range L {
						transScores[i][j] = wNew[transOffset+i*L+j]
					}
				}
				fb := ForwardBackward(stateScores, transScores)
				goldScore := 0.0
				for t := range T {
					y := is.labels[t]
					goldScore += stateScores[t][y]
					if t > 0 {
						goldScore += transScores[is.labels[t-1]][y]
					}
				}
				obj += -goldScore + fb.LogZ
			}
			if config.C2 > 0 {
				l2 := 0.0
				for _, v := range wNew {
					l2 += v * v
				}
				obj += 0.5 * config.C2 * l2
			}
			if config.C1 > 0 {
				for _, v := range wNew {
					obj += config.C1 * math.Abs(v)
				}
			}
			return obj
		}, numWeights, config.C1)

		if step == 0 {
			slog.Warn("CRF line search failed, stopping")
			break
		}

		// Update weights
		prevW := make([]float64, numWeights)
		copy(prevW, w)
		for i := range numWeights {
			w[i] += step * dir[i]
		}

		// Project onto orthant (OWL-QN constraint)
		if config.C1 > 0 {
			for i := range numWeights {
				if w[i]*prevW[i] < 0 {
					w[i] = 0
				}
			}
		}

		// Update L-BFGS memory
		s := make([]float64, numWeights)
		for i := range numWeights {
			s[i] = w[i] - prevW[i]
		}

		// Recompute gradient at new point for y
		newGrad := make([]float64, numWeights)
		for _, is := range internals {
			T := len(is.features)
			if T == 0 {
				continue
			}
			stateScores := make([][]float64, T)
			for t := range T {
				stateScores[t] = make([]float64, L)
				for _, fe := range is.features[t] {
					for y := range L {
						stateScores[t][y] += w[fe.attrID*L+y] * fe.value
					}
				}
			}
			transScores := make([][]float64, L)
			for i := range L {
				transScores[i] = make([]float64, L)
				for j := range L {
					transScores[i][j] = w[transOffset+i*L+j]
				}
			}
			fb := ForwardBackward(stateScores, transScores)
			for t := range T {
				goldY := is.labels[t]
				for _, fe := range is.features[t] {
					newGrad[fe.attrID*L+goldY] -= fe.value
					for y := range L {
						newGrad[fe.attrID*L+y] += fb.Marginals[t][y] * fe.value
					}
				}
			}
			if T > 1 {
				transMarg := TransitionMarginals(fb, stateScores, transScores)
				for t := range T - 1 {
					yp, y := is.labels[t], is.labels[t+1]
					newGrad[transOffset+yp*L+y] -= 1.0
					for i := range L {
						for j := range L {
							newGrad[transOffset+i*L+j] += transMarg[t][i][j]
						}
					}
				}
			}
		}
		if config.C2 > 0 {
			for i := range numWeights {
				newGrad[i] += config.C2 * w[i]
			}
		}

		// Pseudo-gradient at new point
		newPG := make([]float64, numWeights)
		for i := range numWeights {
			switch {
			case w[i] > 0:
				newPG[i] = newGrad[i] + config.C1
			case w[i] < 0:
				newPG[i] = newGrad[i] - config.C1
			default:
				switch {
				case newGrad[i]+config.C1 < 0:
					newPG[i] = newGrad[i] + config.C1
				case newGrad[i]-config.C1 > 0:
					newPG[i] = newGrad[i] - config.C1
				default:
					newPG[i] = 0
				}
			}
		}

		y := make([]float64, numWeights)
		for i := range numWeights {
			y[i] = newPG[i] - pg[i]
		}
		lbfgs.update(s, y)

		// Check convergence
		maxGrad := 0.0
		for _, g := range newPG {
			if math.Abs(g) > maxGrad {
				maxGrad = math.Abs(g)
			}
		}
		if maxGrad < config.Epsilon {
			slog.Debug("CRF converged", "iteration", iter+1, "max_gradient", maxGrad)
			break
		}
	}

	model.Weights = w
	return model
}

type featureEntry struct {
	attrID int
	value  float64
}

// lbfgs implements the L-BFGS two-loop recursion.
type lbfgs struct {
	n    int // number of variables
	m    int // memory size
	s    [][]float64
	y    [][]float64
	rho  []float64
	k    int
	size int
}

func newLBFGS(n, m int) *lbfgs {
	return &lbfgs{
		n:   n,
		m:   m,
		s:   make([][]float64, m),
		y:   make([][]float64, m),
		rho: make([]float64, m),
	}
}

func (l *lbfgs) update(s, y []float64) {
	sy := dot(s, y)
	if sy <= 0 {
		return
	}
	idx := l.k % l.m
	l.s[idx] = make([]float64, l.n)
	l.y[idx] = make([]float64, l.n)
	copy(l.s[idx], s)
	copy(l.y[idx], y)
	l.rho[idx] = 1.0 / sy
	l.k++
	if l.size < l.m {
		l.size++
	}
}

func (l *lbfgs) computeDirection(pg []float64) []float64 {
	q := make([]float64, l.n)
	copy(q, pg)

	if l.size == 0 {
		// Simple gradient descent direction
		for i := range q {
			q[i] = -q[i]
		}
		return q
	}

	alpha := make([]float64, l.size)

	// First loop
	for i := l.size - 1; i >= 0; i-- {
		idx := (l.k - 1 - (l.size - 1 - i)) % l.m
		if idx < 0 {
			idx += l.m
		}
		alpha[i] = l.rho[idx] * dot(l.s[idx], q)
		for j := range l.n {
			q[j] -= alpha[i] * l.y[idx][j]
		}
	}

	// Scale by H_0 = (s_k^T y_k) / (y_k^T y_k)
	latestIdx := (l.k - 1) % l.m
	if latestIdx < 0 {
		latestIdx += l.m
	}
	yy := dot(l.y[latestIdx], l.y[latestIdx])
	if yy > 0 {
		sy := dot(l.s[latestIdx], l.y[latestIdx])
		gamma := sy / yy
		for i := range q {
			q[i] *= gamma
		}
	}

	// Second loop
	for i := range l.size {
		idx := (l.k - l.size + i) % l.m
		if idx < 0 {
			idx += l.m
		}
		beta := l.rho[idx] * dot(l.y[idx], q)
		for j := range l.n {
			q[j] += (alpha[i] - beta) * l.s[idx][j]
		}
	}

	// Negate for descent direction
	for i := range q {
		q[i] = -q[i]
	}
	return q
}

func dot(a, b []float64) float64 {
	var s float64
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

// owlqnLineSearch performs a backtracking line search for OWL-QN.
func owlqnLineSearch(w, dir []float64, fVal float64, pg []float64, objFunc func([]float64) float64, n int, c1 float64) float64 {
	dirDeriv := dot(dir, pg)
	if dirDeriv >= 0 {
		return 0
	}

	step := 1.0
	c := 1e-4 // Armijo constant
	wNew := make([]float64, n)

	for trial := 0; trial < 20; trial++ {
		for i := range n {
			wNew[i] = w[i] + step*dir[i]
		}
		// Project onto orthant
		if c1 > 0 {
			for i := range n {
				if wNew[i]*w[i] < 0 {
					wNew[i] = 0
				}
			}
		}

		fNew := objFunc(wNew)
		if fNew <= fVal+c*step*dirDeriv {
			return step
		}
		step *= 0.5
	}
	return step // return last tried step even if not sufficient decrease
}
