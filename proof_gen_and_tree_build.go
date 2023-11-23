// MIT License
//
// Copyright (c) 2023 Tommy TIAN
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package merkletree implements a high-performance Merkle Tree in Go.
// It supports parallel execution for enhanced performance and
// offers compatibility with OpenZeppelin through sorted sibling pairs.
package merkletree

import "sync"

func (m *MerkleTree) proofGenAndTreeBuild() error {
	if err := m.treeBuild(); err != nil {
		return err
	}
	m.initProofs()
	for i := 0; i < len(m.nodes); i++ {
		m.computeAllProofsFromTree(m.nodes[i], len(m.nodes[i]), i)
	}
	return nil
}

func (m *MerkleTree) proofGenAndTreeBuildParallel() error {
	if err := m.treeBuildParallel(); err != nil {
		return err
	}
	m.initProofs()
	for i := 0; i < len(m.nodes); i++ {
		m.computeAllProofsFromTreeParallel(m.nodes[i], len(m.nodes[i]), i)
	}
	return nil
}

func (m *MerkleTree) computeAllProofsFromTree(buffer [][]byte, bufferLength, step int) {
	batch := 1 << step
	for i := 0; i < bufferLength; i += 2 {
		buildProofPairsFromNodes(m.Proofs, buffer, i, batch, step)
	}
}

func (m *MerkleTree) computeAllProofsFromTreeParallel(buffer [][]byte, bufferLength, step int) {
	var (
		batch       = 1 << step
		numRoutines = min(m.NumRoutines, bufferLength)
		wg          = new(sync.WaitGroup)
	)
	wg.Add(numRoutines)
	for startIdx := 0; startIdx < numRoutines; startIdx++ {
		go func(startIdx int) {
			defer wg.Done()
			for i := startIdx; i < bufferLength; i += numRoutines << 1 {
				buildProofPairsFromNodes(m.Proofs, buffer, i, batch, step)
			}
		}(startIdx << 1)
	}
	wg.Wait()
}

func buildProofPairsFromNodes(proofs []*Proof, buffer [][]byte, idx, batch, step int) {
	start := idx * batch
	end := min(start+batch, len(proofs))
	for i := start; i < end; i++ {
		proofs[i].Path += 1 << step
		proofs[i].Siblings = append(proofs[i].Siblings, buffer[idx+1])
	}
	start += batch
	end = min(start+batch, len(proofs))
	for i := start; i < end; i++ {
		proofs[i].Siblings = append(proofs[i].Siblings, buffer[idx])
	}
}
