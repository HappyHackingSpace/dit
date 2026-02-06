// Package vectorizer provides text vectorization utilities matching sklearn behavior.
package vectorizer

import "math"

// SparseVector represents a sparse float64 vector.
type SparseVector struct {
	Indices []int
	Values  []float64
	Dim     int
}

// NewSparseVector creates a sparse vector with given dimension.
func NewSparseVector(dim int) SparseVector {
	return SparseVector{Dim: dim}
}

// Set adds or updates a value at the given index.
func (sv *SparseVector) Set(idx int, val float64) {
	for i, existingIdx := range sv.Indices {
		if existingIdx == idx {
			sv.Values[i] = val
			return
		}
	}
	sv.Indices = append(sv.Indices, idx)
	sv.Values = append(sv.Values, val)
}

// Dot computes the dot product with a dense vector.
func (sv SparseVector) Dot(dense []float64) float64 {
	var sum float64
	for i, idx := range sv.Indices {
		if idx < len(dense) {
			sum += sv.Values[i] * dense[idx]
		}
	}
	return sum
}

// ToDense converts to a dense float64 slice.
func (sv SparseVector) ToDense() []float64 {
	dense := make([]float64, sv.Dim)
	for i, idx := range sv.Indices {
		if idx < sv.Dim {
			dense[idx] = sv.Values[i]
		}
	}
	return dense
}

// Nnz returns the number of non-zero entries.
func (sv SparseVector) Nnz() int {
	return len(sv.Indices)
}

// ConcatSparse concatenates multiple sparse vectors with offsets into a single vector.
func ConcatSparse(vectors []SparseVector) SparseVector {
	totalDim := 0
	totalNnz := 0
	for _, v := range vectors {
		totalDim += v.Dim
		totalNnz += v.Nnz()
	}
	result := SparseVector{
		Indices: make([]int, 0, totalNnz),
		Values:  make([]float64, 0, totalNnz),
		Dim:     totalDim,
	}
	offset := 0
	for _, v := range vectors {
		for i, idx := range v.Indices {
			result.Indices = append(result.Indices, idx+offset)
			result.Values = append(result.Values, v.Values[i])
		}
		offset += v.Dim
	}
	return result
}

// L2Norm returns the L2 norm of the sparse vector.
func (sv SparseVector) L2Norm() float64 {
	var sum float64
	for _, v := range sv.Values {
		sum += v * v
	}
	return math.Sqrt(sum)
}
