package sipparser

import (
	"encoding/binary"
	//"fmt"
	"reflect"
	"strconv"
	"unsafe"

	"github.com/lioneagle/goutil/src/chars"
)

type AbnfPtr uint32

const ABNF_PTR_NIL = AbnfPtr(0)

func (this AbnfPtr) GetMemAddr(context *ParseContext) *byte {
	return (*byte)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetMemPointer(context *ParseContext) unsafe.Pointer {
	return unsafe.Pointer(&context.allocator.mem[this])
}

func (this AbnfPtr) GetUintptr(context *ParseContext) uintptr {
	return (uintptr)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) String() string {
	if this == ABNF_PTR_NIL {
		return "nil"
	}
	return strconv.FormatUint(uint64(this), 10)
}

func (this AbnfPtr) CString(context *ParseContext) string {
	if this == ABNF_PTR_NIL {
		return ""
	}

	header := reflect.StringHeader{Data: this.GetUintptr(context), Len: this.Strlen(context)}
	return *(*string)(unsafe.Pointer(&header))
}

func (this AbnfPtr) CStringEqualNoCase(context *ParseContext, name []byte) bool {
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

func (this AbnfPtr) WriteCString(context *ParseContext, buf *AbnfByteBuffer) {
	data := this.GetCStringAsByteSlice(context)
	buf.Write(data[:len(data)-1])
}

func (this AbnfPtr) WriteCStringEscape(context *ParseContext, buf *AbnfByteBuffer, charsetIndex int, mask uint32) {
	if this == ABNF_PTR_NIL {
		return
	}

	charset := &g_charsets[charsetIndex]
	p := this.GetUintptr(context)

	for {
		v := *((*byte)(unsafe.Pointer(p)))
		if v == 0 {
			return
		}

		if (charset[v] & mask) != 0 {
			buf.WriteByte(v)
		} else {
			buf.WriteByte('%')
			buf.WriteByte(chars.ToUpperHex(v >> 4))
			buf.WriteByte(chars.ToUpperHex(v))
		}

		p++
	}
}

func (this AbnfPtr) GetCStringAsByteSlice(context *ParseContext) []byte {
	if this == ABNF_PTR_NIL {
		return nil
	}
	size := this.Strlen(context) + 1
	header := reflect.SliceHeader{Data: this.GetUintptr(context), Len: size, Cap: size}
	return *(*[]byte)(unsafe.Pointer(&header))
}

func (this AbnfPtr) GetAsByteSlice(context *ParseContext, size int) []byte {
	if this == ABNF_PTR_NIL {
		return nil
	}
	header := reflect.SliceHeader{Data: this.GetUintptr(context), Len: size, Cap: size}
	return *(*[]byte)(unsafe.Pointer(&header))
}

func (this AbnfPtr) CopyFrom(context *ParseContext, src AbnfPtr, size int) {
	if this == ABNF_PTR_NIL || src == ABNF_PTR_NIL {
		return
	}
	header1 := reflect.SliceHeader{Data: this.GetUintptr(context), Len: size, Cap: size}
	header2 := reflect.SliceHeader{Data: src.GetUintptr(context), Len: size, Cap: size}
	copy(*(*[]byte)(unsafe.Pointer(&header1)), *(*[]byte)(unsafe.Pointer(&header2)))
}

func (this AbnfPtr) Strlen2(context *ParseContext) int {
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

func (this AbnfPtr) Strlen(context *ParseContext) int {
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
