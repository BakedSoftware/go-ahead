// Package goahead provides ACL inspired permissions
package goahead

import (
	"encoding/json"
	"strconv"

	"github.com/willf/bitset"
)

// PermissionSet represents a group of permissions where each set bit grants
// permission
type PermissionSet struct {
	ID       uint64
	bits     bitset.BitSet
	children map[uint]*PermissionSet
}

// Has returns if bit at index is 1
func (p *PermissionSet) Has(index uint) bool {
	return p.bits.Test(index)
}

// HasMultiple checks the sets of permissions and upto 1 child group
func (p *PermissionSet) HasMultiple(sets ...map[uint][]uint) map[uint][]bool {
	results := make(map[uint][]bool, len(sets))

	for set_key := range sets {
		for k, v := range sets[set_key] {
			length := 1
			if count := len(v); count > length {
				length = count
			}
			values := make([]bool, length)
			if p.Has(uint(k)) {
				values[0] = true
				set := p.Child(uint(k))
				if set.Len() > 0 {
					for i, idx := range v {
						values[i] = set.Has(idx)
					}
				}
			}
			results[uint(k)] = values
		}
	}

	return results
}

// Set sets the underlying bits to 1 for the specified indices
func (p *PermissionSet) Set(indices ...uint) *PermissionSet {
	for _, i := range indices {
		p.bits.Set(i)
	}
	return p
}

func (p *PermissionSet) Clear(indices ...uint) *PermissionSet {
	for _, i := range indices {
		p.bits.Clear(i)
	}
	return p
}

// Child eturns the child set for that index. If the Child does not exists a new
// set will be created of length 0
func (p *PermissionSet) Child(index uint) *PermissionSet {
	if p.children == nil {
		p.children = make(map[uint]*PermissionSet, 1)
	}
	if child, exists := p.children[index]; exists {
		return child
	}
	child := new(PermissionSet)
	p.children[index] = child
	return child
}

// Walk checks that the all permissions at the indices are 1 where each index is
// for a level. If the level does not exist and the parent was 1 the result is
// true
func (p *PermissionSet) Walk(indices ...uint) bool {
	var set = p
	for _, i := range indices {
		if set.bits.Test(i) {
			if p.children == nil {
				return true
			}
			if next, exists := set.children[i]; exists {
				set = next
			} else {
				return true
			}
		} else {
			return false
		}
	}
	return false
}

// All returns true iff all bits are set
func (p *PermissionSet) All(indices ...uint) bool {
	other := bitset.New(p.bits.Len())
	for _, i := range indices {
		other.Set(i)
	}
	return p.bits.IsSuperSet(other)
}

// Any returns true if any index is set
func (p *PermissionSet) Any(indices ...uint) bool {
	other := bitset.New(p.bits.Len())
	for _, i := range indices {
		other.Set(i)
	}
	return p.bits.Intersection(other).Any()
}

func (p *PermissionSet) Len() uint {
	return p.bits.Len()
}

func (p *PermissionSet) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	data["ID"] = p.ID
	str, _ := p.bits.MarshalJSON()
	data["bits"] = string(str)

	if p.children != nil {
		children := make(map[string]string)
		for k, v := range p.children {
			if b, err := v.MarshalJSON(); err != nil {
				return nil, err
			} else {
				children[strconv.Itoa(int(k))] = string(b)
			}
		}
		data["children"] = children
	}

	return json.Marshal(data)
}

func UnmarshalJSON(data []byte) (*PermissionSet, error) {
	intermediate := make(map[string]interface{})
	err := json.Unmarshal(data, &intermediate)
	if err != nil {
		return nil, err
	}

	set := new(PermissionSet)
	set.ID = uint64(intermediate["ID"].(float64))
	str := intermediate["bits"].(string)
	if err = set.bits.UnmarshalJSON([]byte(str)); err != nil {
		return nil, err
	}

	return set, nil
}