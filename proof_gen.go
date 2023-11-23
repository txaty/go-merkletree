package merkletree

import (
	"sync"

	"golang.org/x/sync/errgroup"
)

// generateProofs constructs the Merkle Tree and generates the Merkle proofs for each leaf.
// It returns an error if there is an issue during the generation process.
func (m *MerkleTree) generateProofs() (err error) {
	m.initProofs()
	buffer, bufferSize := m.initBuffer()
	for step := 0; step < m.Depth; step++ {
		bufferSize = fixOddNumOfNodes(buffer, bufferSize, step)
		m.updateProofs(buffer, bufferSize, step)
		for idx := 0; idx < bufferSize; idx += 2 {
			leftIdx := idx << step
			rightIdx := min(leftIdx+(1<<step), len(buffer)-1)
			buffer[leftIdx], err = m.HashFunc(m.concatHashFunc(buffer[leftIdx], buffer[rightIdx]))
			if err != nil {
				return
			}
		}
		bufferSize >>= 1
	}
	m.Root = buffer[0]
	return
}

// generateProofsParallel generates proofs concurrently for the MerkleTree.
func (m *MerkleTree) generateProofsParallel() (err error) {
	m.initProofs()
	buffer, bufferSize := m.initBuffer()
	numRoutines := m.NumRoutines
	for step := 0; step < m.Depth; step++ {
		// Limit the number of workers to the previous level length.
		if numRoutines > bufferSize {
			numRoutines = bufferSize
		}
		bufferSize = fixOddNumOfNodes(buffer, bufferSize, step)
		m.updateProofsParallel(buffer, bufferSize, step)
		eg := new(errgroup.Group)
		hashFunc := m.HashFunc
		concatHashFunc := m.concatHashFunc
		for startIdx := 0; startIdx < numRoutines; startIdx++ {
			startIdx := startIdx << 1
			eg.Go(func() error {
				return workerProofGen(
					hashFunc, concatHashFunc,
					buffer, bufferSize, numRoutines, startIdx, step,
				)
			})
		}
		if err = eg.Wait(); err != nil {
			return
		}
		bufferSize >>= 1
	}
	m.Root = buffer[0]
	return
}

func workerProofGen(
	hashFunc TypeHashFunc, concatHashFunc typeConcatHashFunc,
	buffer [][]byte, bufferSize, numRoutine, startIdx, step int,
) error {
	var err error
	for i := startIdx; i < bufferSize; i += numRoutine << 1 {
		leftIdx := i << step
		rightIdx := min(leftIdx+(1<<step), len(buffer)-1)
		buffer[leftIdx], err = hashFunc(concatHashFunc(buffer[leftIdx], buffer[rightIdx]))
		if err != nil {
			return err
		}
	}
	return nil
}

// initProofs initializes the MerkleTree's Proofs with the appropriate size and depth.
// This is to reduce overhead of slice resizing during the generation process.
func (m *MerkleTree) initProofs() {
	m.Proofs = make([]*Proof, m.NumLeaves)
	for i := 0; i < m.NumLeaves; i++ {
		m.Proofs[i] = new(Proof)
		m.Proofs[i].Siblings = make([][]byte, 0, m.Depth)
	}
}

// initBuffer initializes the buffer with the leaves and returns the buffer size.
// If the number of leaves is odd, the buffer size is increased by 1.
func (m *MerkleTree) initBuffer() ([][]byte, int) {
	var buffer [][]byte
	// If the number of leaves is odd, make initial buffer size even by adding 1.
	if m.NumLeaves&1 == 1 {
		buffer = make([][]byte, m.NumLeaves+1)
	} else {
		buffer = make([][]byte, m.NumLeaves)
	}
	copy(buffer, m.Leaves)
	return buffer, m.NumLeaves
}

// fixOddNumOfNodes adjusts the buffer size if it has an odd number of nodes.
// It appends the last node to the buffer if the buffer length is odd.
func fixOddNumOfNodes(buffer [][]byte, bufferSize, step int) int {
	// If the buffer length is even, no adjustment is needed.
	if bufferSize&1 == 0 {
		return bufferSize
	}
	// Determine the node to append.
	appendNodeIndex := (bufferSize - 1) << step
	// The appended node will be put at the end of the buffer.
	buffer[len(buffer)-1] = buffer[appendNodeIndex]
	bufferSize++
	return bufferSize
}

// updateProofs updates the proofs for all the leaves while constructing the Merkle Tree.
func (m *MerkleTree) updateProofs(buffer [][]byte, bufferSize, step int) {
	batch := 1 << step
	for i := 0; i < bufferSize; i += 2 {
		m.updateProofPairs(buffer, i, batch, step)
	}
}

// updateProofsParallel updates the proofs for all the leaves while constructing the Merkle Tree in parallel.
func (m *MerkleTree) updateProofsParallel(buffer [][]byte, bufferLength, step int) {
	batch := 1 << step
	numRoutines := m.NumRoutines
	if numRoutines > bufferLength {
		numRoutines = bufferLength
	}
	var wg sync.WaitGroup
	wg.Add(numRoutines)
	for startIdx := 0; startIdx < numRoutines; startIdx++ {
		go func(startIdx int) {
			defer wg.Done()
			for i := startIdx; i < bufferLength; i += numRoutines << 1 {
				m.updateProofPairs(buffer, i, batch, step)
			}
		}(startIdx << 1)
	}
	wg.Wait()
}

// updateProofPairs updates the proofs in the Merkle Tree in pairs.
func (m *MerkleTree) updateProofPairs(buffer [][]byte, idx, batch, step int) {
	start := idx * batch
	end := min(start+batch, len(m.Proofs))
	siblingNodeIdx := min((idx+1)<<step, len(buffer)-1)
	for i := start; i < end; i++ {
		m.Proofs[i].Path += 1 << step
		m.Proofs[i].Siblings = append(m.Proofs[i].Siblings, buffer[siblingNodeIdx])
	}
	start += batch
	end = min(start+batch, len(m.Proofs))
	siblingNodeIdx = min(idx<<step, len(buffer)-1)
	for i := start; i < end; i++ {
		m.Proofs[i].Siblings = append(m.Proofs[i].Siblings, buffer[siblingNodeIdx])
	}
}
