package transform

// Cache memoizes chain outputs for one request. Rules share chains (most
// use "urldecode, lower"), so without this every rule would re-decode
// every value. Outputs live in one arena as offsets, which keeps the hot
// GET path at zero allocations once the arena is warm.
type Cache struct {
	arena []byte
	idx   map[uint64][2]int32
	a, b  []byte
}

func NewCache() *Cache {
	return &Cache{
		arena: make([]byte, 0, 8192),
		idx:   make(map[uint64][2]int32, 64),
		a:     make([]byte, 0, 1024),
		b:     make([]byte, 0, 1024),
	}
}

// Reset keeps the buffers, forgets the entries.
func (c *Cache) Reset() {
	c.arena = c.arena[:0]
	for k := range c.idx {
		delete(c.idx, k)
	}
}

// Grown reports whether the arena got big, callers drop such caches
// instead of pooling them so one huge body does not pin memory forever.
func (c *Cache) Grown(limit int) bool { return cap(c.arena) > limit }

// Get returns the chain output for value valueIdx, computing it once.
// maxOut caps the result size; a chain that grows past it is truncated.
func (c *Cache) Get(valueIdx int, chainID int, chain []ID, src []byte, maxOut int) []byte {
	if len(chain) == 0 {
		return src
	}
	key := uint64(valueIdx)<<16 | uint64(chainID)
	if off, ok := c.idx[key]; ok {
		return c.arena[off[0]:off[1]]
	}
	var out []byte
	out, c.a, c.b = Run(chain, src, c.a, c.b)
	if maxOut > 0 && len(out) > maxOut {
		out = out[:maxOut]
	}
	start := len(c.arena)
	c.arena = append(c.arena, out...)
	c.idx[key] = [2]int32{int32(start), int32(len(c.arena))}
	return c.arena[start:]
}
