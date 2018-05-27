package sipparser

import (
	"encoding/binary"
	//"fmt"
	"reflect"
	"strconv"
	"unsafe"

	"github.com/lioneagle/goutil/src/chars"
)

type AbnfPtr uint16

const (
	ABNF_PTR_BITS = unsafe.Sizeof(AbnfPtr(0)) * 8
	ABNF_PTR_BIT  = AbnfPtr(1 << (ABNF_PTR_BITS - 1))
	ABNF_PTR_MASK = AbnfPtr(^ABNF_PTR_BIT)
)

const ABNF_PTR_NIL = AbnfPtr(0)

func (this AbnfPtr) IsAbnfPtr() bool {
	return (this & ABNF_PTR_BIT) == 0
}

func (this AbnfPtr) GetValue() uint {
	return uint(this & ABNF_PTR_MASK)
}

func AbnfPtrSetValue(value AbnfPtr) AbnfPtr {
	return value | ABNF_PTR_BIT
}
func (this AbnfPtr) SetValue() uint {
	return uint(this | ABNF_PTR_BIT)
}

func (this AbnfPtr) GetMemAddr(context *Context) *byte {
	return (*byte)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetMemPointer(context *Context) unsafe.Pointer {
	return unsafe.Pointer(&context.allocator.mem[this])
}

func (this AbnfPtr) GetUintptr(context *Context) uintptr {
	return (uintptr)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) String() string {
	if this == ABNF_PTR_NIL {
		return "nil"
	}
	return strconv.FormatUint(uint64(this), 10)
}

func (this AbnfPtr) CString(context *Context) string {
	if this == ABNF_PTR_NIL {
		return ""
	}

	header := reflect.StringHeader{Data: this.GetUintptr(context), Len: this.Strlen(context)}
	return *(*string)(unsafe.Pointer(&header))
}

func (this AbnfPtr) HasPrefixNoCase(context *Context, prefix string) bool {
	len1 := this.Strlen(context)
	len2 := len(prefix)
	if len1 < len2 {
		return false
	}

	prefix1 := StringToByteSlice(prefix)
	return chars.EqualNoCase(context.allocator.mem[this:this+AbnfPtr(len2)], prefix1)
}

func (this AbnfPtr) RemoveTelUriVisualSeperator(context *Context) {
	len1 := AbnfPtr(this.Strlen(context))
	read := this
	write := this
	end := read + len1
	data := context.allocator.mem
	for read < end {
		if !IsTelVisualSperator(data[read]) {
			data[write] = data[read]
			write++
		}
		read++
	}
	binary.LittleEndian.PutUint16(data[this-2:], uint16(write-this))
}

func (this AbnfPtr) CStringEqualNoCase(context *Context, name []byte) bool {
	if this == ABNF_PTR_NIL {
		return false
	}
	len1 := len(name)
	len2 := this.Strlen(context)

	if len1 != len2 {
		return false
	}

	p1 := this.GetUintptr(context)
	p2 := uintptr(unsafe.Pointer(&name[0]))
	end := p1 + uintptr(len1)
	end1 := p1 + uintptr((len1>>3)<<3)

	for p1 < end1 {
		if *((*int64)(unsafe.Pointer(p1))) != *((*int64)(unsafe.Pointer(p2))) {
			break
		}
		p1 += 8
		p2 += 8
	}

	for p1 < end {
		if *((*byte)(unsafe.Pointer(p1))) != *((*byte)(unsafe.Pointer(p2))) {
			break
		}
		p1++
		p2++
	}
	for p1 < end {
		if chars.ToLower(*((*byte)(unsafe.Pointer(p1)))) != chars.ToLower(*((*byte)(unsafe.Pointer(p2)))) {
			return false
		}
		p1++
		p2++
	}
	return true

	/*p1 := this.GetUintptr(context)
	p2 := uintptr(unsafe.Pointer(&name[0]))
	end2 := uintptr(unsafe.Pointer(&name[0])) + uintptr(len1)

	//*
	for {
		v1 := *((*byte)(unsafe.Pointer(p1)))
		if v1 == 0 {
			return p2 == end2
		}

		if p2 >= end2 {
			return false
		}

		v2 := *((*byte)(unsafe.Pointer(p2)))

		if v1 != v2 {
			if chars.ToLower(v1) != chars.ToLower(v2) {
				return false
			}
		}

		p1++
		p2++
	} //*/

	/*
		for {
			v1 := chars.ToLower(*((*byte)(unsafe.Pointer(p1))))
			v2 := chars.ToLower(*((*byte)(unsafe.Pointer(p2))))
			if v1 == 0 {
				return p2 == (end2 - 1)
			}

			if p2 >= end2 {
				return false
			}

			if v1 != v2 {
				return false
			}

			p1++
			p2++
		} //*/
	//return false
}

func (this AbnfPtr) WriteCString(context *Context, buf *AbnfByteBuffer) {
	if this == ABNF_PTR_NIL {
		return
	}
	data := this.GetCStringAsByteSlice(context)
	buf.Write(data)
}

func (this AbnfPtr) WriteCStringEscape(context *Context, buf *AbnfByteBuffer, charsetIndex int, mask uint32) {
	if this == ABNF_PTR_NIL {
		return
	}

	charset := &g_charsets[charsetIndex]
	p := this.GetUintptr(context)
	end := p + uintptr(this.Strlen(context))

	for ; p < end; p++ {
		v := *((*byte)(unsafe.Pointer(p)))

		if (charset[v] & mask) != 0 {
			buf.WriteByte(v)
		} else {
			buf.WriteByte('%')
			buf.WriteByte(chars.ToUpperHex(v >> 4))
			buf.WriteByte(chars.ToUpperHex(v))
		}
	}
}

func (this AbnfPtr) GetCStringAsByteSlice(context *Context) []byte {
	if this == ABNF_PTR_NIL {
		return nil
	}
	size := this.Strlen(context)
	header := reflect.SliceHeader{Data: this.GetUintptr(context), Len: size, Cap: size}
	return *(*[]byte)(unsafe.Pointer(&header))
}

func (this AbnfPtr) GetAsByteSlice(context *Context, size int) []byte {
	if this == ABNF_PTR_NIL {
		return nil
	}
	//*
	header := reflect.SliceHeader{Data: this.GetUintptr(context), Len: size, Cap: size}
	return *(*[]byte)(unsafe.Pointer(&header))
	//*/
	//return context.allocator.mem[int(this) : int(this)+size]
}

func (this AbnfPtr) CopyFrom(context *Context, src AbnfPtr, size int) {
	if this == ABNF_PTR_NIL || src == ABNF_PTR_NIL {
		return
	}
	/*
		    header1 := reflect.SliceHeader{Data: this.GetUintptr(context), Len: size, Cap: size}
			header2 := reflect.SliceHeader{Data: src.GetUintptr(context), Len: size, Cap: size}
			copy(*(*[]byte)(unsafe.Pointer(&header1)), *(*[]byte)(unsafe.Pointer(&header2)))
		    //*/
	copy(context.allocator.mem[int(this):int(this)+size], context.allocator.mem[int(src):int(src)+size])
}

func (this AbnfPtr) Strlen2(context *Context) int {
	if this == ABNF_PTR_NIL {
		return 0
	}

	p := this.GetUintptr(context)
	begin := p
	for *((*byte)(unsafe.Pointer(p))) != 0 {
		p++
	}
	return int(p - begin)
}

const (
	himagic uint64 = 0x8080808080808080
	lomagic uint64 = 0x0101010101010101
)

func (this AbnfPtr) Strlen(context *Context) int {
	if this == ABNF_PTR_NIL {
		return 0
	}

	return int(binary.LittleEndian.Uint16(context.allocator.mem[this-2:]))

	/*

		p := this.GetUintptr(context)
		end1 := (this.GetUintptr(context) + 7) & uintptr(0xfffffffffffffff8)
		//end1 := ((this.GetUintptr(context) + 7) >> 3) << 3
		start := this.GetUintptr(context)
		for p < end1 {
			if *((*byte)(unsafe.Pointer(p))) == 0 {
				break
			}
			p++
		}

		for {
			v := *((*uint64)(unsafe.Pointer(p)))
			if ((v - lomagic) & ^v & himagic) != 0 {
				if *((*byte)(unsafe.Pointer(p))) == 0 {
					return int(p - start)
				}

				if *((*byte)(unsafe.Pointer(p + 1))) == 0 {
					return int(p - start + 1)
				}

				if *((*byte)(unsafe.Pointer(p + 2))) == 0 {
					return int(p - start + 2)
				}

				if *((*byte)(unsafe.Pointer(p + 3))) == 0 {
					return int(p - start + 3)
				}

				if *((*byte)(unsafe.Pointer(p + 4))) == 0 {
					return int(p - start + 4)
				}

				if *((*byte)(unsafe.Pointer(p + 5))) == 0 {
					return int(p - start + 5)
				}

				if *((*byte)(unsafe.Pointer(p + 6))) == 0 {
					return int(p - start + 6)
				}

				if *((*byte)(unsafe.Pointer(p + 7))) == 0 {
					return int(p - start + 7)
				}
			}

			p += 8
		}

		return int(p - start)*/
}
