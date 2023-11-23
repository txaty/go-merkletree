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

import (
	"bytes"
	"math/bits"
	"runtime"
	"sync"

	"golang.org/x/sync/errgroup"
)

const (
	// ModeProofGen is the proof generation configuration mode.
	ModeProofGen TypeConfigMode = iota
	// ModeTreeBuild is the tree building configuration mode.
	ModeTreeBuild
	// ModeProofGenAndTreeBuild is the proof generation and tree building configuration mode.
	ModeProofGenAndTreeBuild
)

// TypeConfigMode is the type in the Merkle Tree configuration indicating what operations are performed.
type TypeConfigMode int

// TypeHashFunc is the signature of the hash functions used for Merkle Tree generation.
type TypeHashFunc func([]byte) ([]byte, error)

type typeConcatHashFunc func([]byte, []byte) []byte

// Config is the configuration of Merkle Tree.
type Config struct {
	// Customizable hash function used for tree generation.
	HashFunc TypeHashFunc
	// Number of goroutines run in parallel.
	// If RunInParallel is true and NumRoutine is set to 0, use number of CPU as the number of goroutines.
	NumRoutines int
	// Mode of the Merkle Tree generation.
	Mode TypeConfigMode
	// If RunInParallel is true, the generation runs in parallel, otherwise runs without parallelization.
	// This increase the performance for the calculation of large number of data blocks, e.g. over 10,000 blocks.
	RunInParallel bool
	// SortSiblingPairs is the parameter for OpenZeppelin compatibility.
	// If set to `true`, the hashing sibling pairs are sorted.
	SortSiblingPairs bool
	// If true, the leaf nodes are NOT hashed before being added to the Merkle Tree.
	DisableLeafHashing bool
}

// MerkleTree implements the Merkle Tree data structure.
type MerkleTree struct {
	*Config
	// leafMap maps the data (converted to string) of each leaf node to its index in the Tree slice.
	// It is only available when the configuration mode is set to ModeTreeBuild or ModeProofGenAndTreeBuild.
	leafMap map[string]int
	// leafMapMu is a mutex that protects concurrent access to the leafMap.
	leafMapMu sync.Mutex
	// concatHashFunc is the function for concatenating two hashes.
	// If SortSiblingPairs in Config is true, then the sibling pairs are first sorted and then concatenated,
	// supporting the OpenZeppelin Merkle Tree protocol.
	// Otherwise, the sibling pairs are concatenated directly.
	concatHashFunc typeConcatHashFunc
	// nodes contains the Merkle Tree's internal node structure.
	// It is only available when the configuration mode is set to ModeTreeBuild or ModeProofGenAndTreeBuild.
	nodes [][][]byte
	// Root is the hash of the Merkle root node.
	Root []byte
	// Leaves are the hashes of the data blocks that form the Merkle Tree's leaves.
	// These hashes are used to generate the tree structure.
	// If the DisableLeafHashing configuration is set to true, the original data blocks are used as the leaves.
	Leaves [][]byte
	// Proofs are the proofs to the data blocks generated during the tree building process.
	Proofs []*Proof
	// Depth is the depth of the Merkle Tree.
	Depth int
	// NumLeaves is the number of leaves in the Merkle Tree.
	// This value is fixed once the tree is built.
	NumLeaves int
}

// Proof represents a Merkle Tree proof.
type Proof struct {
	Siblings [][]byte // Sibling nodes to the Merkle Tree path of the data block.
	Path     uint32   // Path variable indicating whether the neighbor is on the left or right.
}

// New generates a new Merkle Tree with the specified configuration and data blocks.
func New(config *Config, blocks []DataBlock) (m *MerkleTree, err error) {
	// Check if there are enough data blocks to build the tree.
	if len(blocks) <= 1 {
		return nil, ErrInvalidNumOfDataBlocks
	}

	// Initialize the configuration if it is not provided.
	if config == nil {
		config = new(Config)
	}

	// Create a MerkleTree with the provided configuration.
	m = &MerkleTree{
		Config:    config,
		NumLeaves: len(blocks),
		Depth:     bits.Len(uint(len(blocks) - 1)),
	}

	// Initialize the hash function.
	if m.HashFunc == nil {
		if m.RunInParallel {
			// Use a concurrent safe hash function for parallel execution.
			m.HashFunc = DefaultHashFuncParallel
		} else {
			m.HashFunc = DefaultHashFunc
		}
	}

	// Hash concatenation function initialization.
	if m.concatHashFunc == nil {
		if m.SortSiblingPairs {
			m.concatHashFunc = concatSortHash
		} else {
			m.concatHashFunc = concatHash
		}
	}

	// Configure parallelization settings.
	if m.RunInParallel {
		// Set NumRoutines to the number of CPU cores if not specified or invalid.
		if m.NumRoutines <= 0 {
			m.NumRoutines = runtime.NumCPU()
		}
		if m.Leaves, err = m.computeLeafNodesParallel(blocks); err != nil {
			return nil, err
		}
	} else {
		// Generate leaves without parallelization.
		if m.Leaves, err = m.computeLeafNodes(blocks); err != nil {
			return nil, err
		}
	}

	// Perform actions based on the configured mode.
	// Set the mode to ModeProofGen by default if not specified.
	if m.Mode == 0 {
		m.Mode = ModeProofGen
	}

	// Generate proofs in ModeProofGen.
	if m.Mode == ModeProofGen {
		if m.RunInParallel {
			err = m.generateProofsParallel()
			return
		}
		err = m.generateProofs()
		return
	}
	// Initialize the leafMap for ModeTreeBuild and ModeProofGenAndTreeBuild.
	m.leafMap = make(map[string]int)

	// Build the tree in ModeTreeBuild.
	if m.Mode == ModeTreeBuild {
		if m.RunInParallel {
			err = m.buildTreeParallel()
			return
		}
		err = m.buildTree()
		return
	}

	// Build the tree and generate proofs in ModeProofGenAndTreeBuild.
	if m.Mode == ModeProofGenAndTreeBuild {
		if m.RunInParallel {
			if err = m.buildTreeParallel(); err != nil {
				return
			}
			m.initProofs()
			for i := 0; i < len(m.nodes); i++ {
				m.buildProofsFromNodesParallel(m.nodes[i], len(m.nodes[i]), i)
			}
			return
		}
		if err = m.buildTree(); err != nil {
			return
		}
		m.initProofs()
		for i := 0; i < len(m.nodes); i++ {
			m.buildProofsFromNodes(m.nodes[i], len(m.nodes[i]), i)
		}
		return
	}

	// Return an error if the configuration mode is invalid.
	return nil, ErrInvalidConfigMode
}

// concatHash concatenates two byte slices, b1 and b2.
func concatHash(b1 []byte, b2 []byte) []byte {
	result := make([]byte, len(b1)+len(b2))
	copy(result, b1)
	copy(result[len(b1):], b2)
	return result
}

// concatSortHash concatenates two byte slices, b1 and b2, in a sorted order.
// The function ensures that the smaller byte slice (in terms of lexicographic order)
// is placed before the larger one. This is used for compatibility with OpenZeppelin's
// Merkle Proof verification implementation.
func concatSortHash(b1 []byte, b2 []byte) []byte {
	if bytes.Compare(b1, b2) < 0 {
		return concatHash(b1, b2)
	}
	return concatHash(b2, b1)
}

// buildTree builds the Merkle Tree and stores all the nodes.
func (m *MerkleTree) buildTree() (err error) {
	finishMap := make(chan struct{})
	go m.routineBuildLeafMap(finishMap)
	m.initNodes()
	for i := 0; i < m.Depth-1; i++ {
		m.nodes[i] = appendNodeIfOdd(m.nodes[i])
		numNodes := len(m.nodes[i])
		m.nodes[i+1] = make([][]byte, numNodes>>1)
		for j := 0; j < numNodes; j += 2 {
			if m.nodes[i+1][j>>1], err = m.HashFunc(
				m.concatHashFunc(m.nodes[i][j], m.nodes[i][j+1]),
			); err != nil {
				return
			}
		}
	}
	if m.Root, err = m.HashFunc(m.concatHashFunc(
		m.nodes[m.Depth-1][0], m.nodes[m.Depth-1][1],
	)); err != nil {
		return
	}
	<-finishMap
	return
}

func (m *MerkleTree) routineBuildLeafMap(finishChan chan struct{}) {
	m.leafMapMu.Lock()
	defer m.leafMapMu.Unlock()
	for i := 0; i < m.NumLeaves; i++ {
		m.leafMap[string(m.Leaves[i])] = i
	}
	finishChan <- struct{}{} // empty channel to serve as a wait group for map generation
}

func appendNodeIfOdd(buffer [][]byte) [][]byte {
	if len(buffer)&1 == 0 {
		return buffer
	}
	appendNode := buffer[len(buffer)-1]
	buffer = append(buffer, appendNode)
	return buffer
}

func (m *MerkleTree) initNodes() {
	m.nodes = make([][][]byte, m.Depth)
	m.nodes[0] = make([][]byte, m.NumLeaves)
	copy(m.nodes[0], m.Leaves)
}

// buildTreeParallel builds the Merkle Tree and stores all the nodes in parallel.
func (m *MerkleTree) buildTreeParallel() (err error) {
	finishMap := make(chan struct{})
	go m.routineBuildLeafMap(finishMap)
	m.initNodes()
	for i := 0; i < m.Depth-1; i++ {
		m.nodes[i] = appendNodeIfOdd(m.nodes[i])
		numNodes := len(m.nodes[i])
		m.nodes[i+1] = make([][]byte, numNodes>>1)
		numRoutines := m.NumRoutines
		if numRoutines > numNodes {
			numRoutines = numNodes
		}
		eg := new(errgroup.Group)
		for startIdx := 0; startIdx < numRoutines; startIdx++ {
			startIdx := startIdx
			eg.Go(func() error {
				for j := startIdx << 1; j < numNodes; j += numRoutines << 1 {
					newHash, err := m.HashFunc(m.concatHashFunc(
						m.nodes[i][j], m.nodes[i][j+1],
					))
					if err != nil {
						return err
					}
					m.nodes[i+1][j>>1] = newHash
				}
				return nil
			})
		}
		if err = eg.Wait(); err != nil {
			return
		}
	}
	if m.Root, err = m.HashFunc(m.concatHashFunc(
		m.nodes[m.Depth-1][0], m.nodes[m.Depth-1][1],
	)); err != nil {
		return
	}
	<-finishMap
	return
}

func (m *MerkleTree) buildProofsFromNodes(buffer [][]byte, bufferLength, step int) {
	batch := 1 << step
	for i := 0; i < bufferLength; i += 2 {
		m.buildProofPairsFromNodes(buffer, i, batch, step)
	}
}

func (m *MerkleTree) buildProofsFromNodesParallel(buffer [][]byte, bufferLength, step int) {
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
				m.buildProofPairsFromNodes(buffer, i, batch, step)
			}
		}(startIdx << 1)
	}
	wg.Wait()
}

func (m *MerkleTree) buildProofPairsFromNodes(buffer [][]byte, idx, batch, step int) {
	start := idx * batch
	end := min(start+batch, len(m.Proofs))
	for i := start; i < end; i++ {
		m.Proofs[i].Path += 1 << step
		m.Proofs[i].Siblings = append(m.Proofs[i].Siblings, buffer[idx+1])
	}
	start += batch
	end = min(start+batch, len(m.Proofs))
	for i := start; i < end; i++ {
		m.Proofs[i].Siblings = append(m.Proofs[i].Siblings, buffer[idx])
	}
}

// Verify checks if the data block is valid using the Merkle Tree proof and the cached Merkle root hash.
func (m *MerkleTree) Verify(dataBlock DataBlock, proof *Proof) (bool, error) {
	return Verify(dataBlock, proof, m.Root, m.Config)
}

// Verify checks if the data block is valid using the Merkle Tree proof and the provided Merkle root hash.
// It returns true if the data block is valid, false otherwise. An error is returned in case of any issues
// during the verification process.
func Verify(dataBlock DataBlock, proof *Proof, root []byte, config *Config) (bool, error) {
	// Validate input parameters.
	if dataBlock == nil {
		return false, ErrDataBlockIsNil
	}
	if proof == nil {
		return false, ErrProofIsNil
	}
	if config == nil {
		config = new(Config)
	}
	if config.HashFunc == nil {
		config.HashFunc = DefaultHashFunc
	}

	// Determine the concatenation function based on the configuration.
	concatFunc := concatHash
	if config.SortSiblingPairs {
		concatFunc = concatSortHash
	}

	// Convert the data block to a leaf.
	leaf, err := dataBlockToLeaf(dataBlock, config.HashFunc, config.DisableLeafHashing)
	if err != nil {
		return false, err
	}

	// Traverse the Merkle proof and compute the resulting hash.
	// Copy the slice so that the original leaf won't be modified.
	result := make([]byte, len(leaf))
	copy(result, leaf)
	path := proof.Path
	for _, sib := range proof.Siblings {
		if path&1 == 1 {
			result, err = config.HashFunc(concatFunc(result, sib))
		} else {
			result, err = config.HashFunc(concatFunc(sib, result))
		}
		if err != nil {
			return false, err
		}
		path >>= 1
	}
	return bytes.Equal(result, root), nil
}

// Proof generates the Merkle proof for a data block using the previously generated Merkle Tree structure.
// This method is only available when the configuration mode is ModeTreeBuild or ModeProofGenAndTreeBuild.
// In ModeProofGen, proofs for all the data blocks are already generated, and the Merkle Tree structure
// is not cached.
func (m *MerkleTree) Proof(dataBlock DataBlock) (*Proof, error) {
	if m.Mode != ModeTreeBuild && m.Mode != ModeProofGenAndTreeBuild {
		return nil, ErrProofInvalidModeTreeNotBuilt
	}

	// Convert the data block to a leaf.
	leaf, err := dataBlockToLeaf(dataBlock, m.HashFunc, m.DisableLeafHashing)
	if err != nil {
		return nil, err
	}

	// Retrieve the index of the leaf in the Merkle Tree.
	m.leafMapMu.Lock()
	idx, ok := m.leafMap[string(leaf)]
	m.leafMapMu.Unlock()
	if !ok {
		return nil, ErrProofInvalidDataBlock
	}

	// Compute the path and siblings for the proof.
	var (
		path     uint32
		siblings = make([][]byte, m.Depth)
	)
	for i := 0; i < m.Depth; i++ {
		if idx&1 == 1 {
			siblings[i] = m.nodes[i][idx-1]
		} else {
			path += 1 << i
			siblings[i] = m.nodes[i][idx+1]
		}
		idx >>= 1
	}
	return &Proof{
		Path:     path,
		Siblings: siblings,
	}, nil
}
