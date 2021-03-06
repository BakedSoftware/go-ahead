// Package goahead provides ACL inspired permissions
package goahead

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/willf/bitset"
)

var (
	ErrBufTooSmall = errors.New("Binary buffer is too small")
	ErrBufOveflow  = errors.New("64 bit overflow detected")
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

// Union is the equivalent of the |= other
func (p *PermissionSet) Union(other *PermissionSet) *PermissionSet {
	for i, e := other.bits.NextSet(0); e; i, e = other.bits.NextSet(i + 1) {
		p.Set(i)
		if child, exists := other.children[i]; exists {
			p.Child(i).Union(child)
		}
	}
	p.bits.InPlaceUnion(&other.bits)
	return p
}

func (p *PermissionSet) InPlaceIntersection(other *PermissionSet) *PermissionSet {
	for i, e := other.bits.NextSet(0); e; i, e = other.bits.NextSet(i + 1) {
		if p.Has(i) {
			if child, exists := other.children[i]; exists {
				p.Child(i).InPlaceIntersection(child)
			}
		}
	}
	p.bits.InPlaceIntersection(&other.bits)
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
	return true
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
	if childData, exists := intermediate["children"]; exists {
		set.children = make(map[uint]*PermissionSet)
		for k, v := range childData.(map[string]interface{}) {
			key, _ := strconv.ParseUint(k, 10, 64)
			set.children[uint(key)], _ = UnmarshalJSON([]byte(v.(string)))
		}
	}

	return set, nil
}

func (p *PermissionSet) MarshalBinary() ([]byte, error) {
	bytes, err := p.bits.MarshalBinary()
	if err != nil {
		return nil, err
	}
	//[ID][SIZE][TOTAL_SIZE][DATA]{[CHILD_INDEX][CHILD_DATA]}
	size := uint64(len(bytes))
	data := make([]byte, 24+size)
	binary.PutUvarint(data, p.ID)
	binary.PutUvarint(data[8:], size)
	copy(data[24:], bytes)

	if p.children != nil {
		for i, v := range p.children {
			if b, err := v.MarshalBinary(); err != nil {
				return nil, err
			} else {
				header := make([]byte, 8)
				binary.PutUvarint(header, uint64(i))
				size += 8 + uint64(len(b))
				data = append(data, append(header, b...)...)
			}
		}
	}
	binary.PutUvarint(data[16:], size+24)

	return data, nil
}

func (p *PermissionSet) UnmarshalBinary(data []byte) error {
	maxLen := uint64(len(data))
	if maxLen == 0 {
		return nil
	}

	//[ID][SIZE][TOTAL_SIZE][DATA]{[CHILD_INDEX][CHILD_DATA]}
	var read int
	p.ID, read = binary.Uvarint(data[:7])
	if read == 0 {
		return ErrBufTooSmall
	} else if read < 0 {
		return ErrBufOveflow
	}
	size, read := binary.Uvarint(data[8:15])
	if read == 0 {
		return ErrBufTooSmall
	} else if read < 0 {
		return ErrBufOveflow
	}
	err := p.bits.UnmarshalBinary(data[24 : 24+size])
	if err != nil {
		return err
	}

	// Look for children
	offset := 24 + size
	if maxLen > offset {
		p.children = make(map[uint]*PermissionSet)
		for maxLen > offset {
			//[IDX][ID][SIZE][TOTAL_SIZE]
			//[0-7][8-15][16-23][24-31]
			child := new(PermissionSet)
			idx, read := binary.Uvarint(data[offset : offset+7])
			if read == 0 {
				return ErrBufTooSmall
			} else if read < 0 {
				return ErrBufOveflow
			}
			childSize, read := binary.Uvarint(data[offset+24 : offset+31])
			if read == 0 {
				return ErrBufTooSmall
			} else if read < 0 {
				return ErrBufOveflow
			}
			if err := child.UnmarshalBinary(data[offset+8 : offset+8+childSize]); err != nil {
				return err
			}
			p.children[uint(idx)] = child
			offset += 8 + childSize
		}
	}
	return nil
}

// Bytes returns the underling storage. The indices correspond to walking through
// the children.
func (p *PermissionSet) Bytes(indices ...uint) []uint64 {
	var set *PermissionSet
	set = p
	for _, idx := range indices {
		set = set.Child(idx)
	}
	return set.bits.Bytes()
}

// IsEmpty returns true if no bits are set
func (p *PermissionSet) IsEmpty() bool {
	return p.bits.None()
}
func (p *PermissionSet) BitString() string {
	return p.bits.DumpAsBits()
}
