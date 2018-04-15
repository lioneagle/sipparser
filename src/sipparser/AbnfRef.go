package sipparser

import (
	//"bytes"
	_ "fmt"
	//"reflect"
	"unsafe"
)

type AbnfRef struct {
	Begin int32
	End   int32
}

func (this *AbnfRef) Len() int32 {
	return this.End - this.Begin
}

func (this *AbnfRef) Parse(src []byte, pos AbnfPos, charsetIndex int, mask uint32) (end AbnfPos) {
	this.Begin = int32(pos)
	len1 := AbnfPos(len(src))

	charset := &g_charsets[charsetIndex]

	if pos >= len1 || (((charset[src[pos]]) & mask) == 0) {
		this.End = int32(pos)
		return pos
	}

	for end = pos + 1; end < len1; end++ {
		if ((charset[src[end]]) & mask) == 0 {
			break
		}
	}

	this.End = int32(end)
	return end
}

func (this *AbnfRef) ParseEscapable(src []byte, pos AbnfPos, charsetIndex int, mask uint32) (escapeNum int, newPos AbnfPos, ok bool) {
	this.Begin = int32(pos)
	len1 := AbnfPos(len(src))

	charset := &g_charsets[charsetIndex]
	newPos = pos

	for {
		for ; newPos < len1; newPos++ {
			if ((charset[src[newPos]]) & mask) == 0 {
				if src[newPos] == '%' {
					break
				}
				this.End = int32(newPos)
				return escapeNum, newPos, true
			}
		}

		if newPos >= len1 {
			this.End = int32(newPos)
			return escapeNum, newPos, true
		}

		if (newPos + 2) >= len1 {
			return escapeNum, newPos, false
		}

		if !IsHex(src[newPos+1]) || !IsHex(src[newPos+2]) {
			return escapeNum, newPos, false
		}

		escapeNum++
		newPos += 3
	}

	this.End = int32(newPos)
	return escapeNum, newPos, true
}

func (this *AbnfRef) ParseEscapable3(src []byte, pos AbnfPos, charsetIndex int, mask uint32) (escapeNum int, newPos AbnfPos, ok bool) {
	this.Begin = int32(pos)
	//len1 := AbnfPos(len(src))

	p := uintptr(unsafe.Pointer(&src[pos]))
	begin := uintptr(unsafe.Pointer(&src[0]))
	end := begin + uintptr(len(src))

	charset := &g_charsets[charsetIndex]

	for {
		for ; p < end; p++ {
			if ((charset[*((*byte)(unsafe.Pointer(p)))]) & mask) == 0 {
				if *((*byte)(unsafe.Pointer(p))) == '%' {
					break
				}
				newPos = AbnfPos(p - begin)
				this.End = int32(newPos)
				return escapeNum, newPos, true
			}
		}

		if p >= end {
			newPos = AbnfPos(p - begin)
			this.End = int32(newPos)
			return escapeNum, newPos, true
		}

		if (p + 2) >= end {
			return escapeNum, AbnfPos(p - begin), false
		}

		if !IsHex(*((*byte)(unsafe.Pointer(p + 1)))) || !IsHex(*((*byte)(unsafe.Pointer(p + 2)))) {
			return escapeNum, AbnfPos(p - begin), false
		}

		escapeNum++
		p += 3
	}

	/*
		for ; p < end; p++ {
			//v := *((*byte)(unsafe.Pointer(p)))
			if ((charset[*((*byte)(unsafe.Pointer(p)))]) & mask) == 0 {
				if *((*byte)(unsafe.Pointer(p))) == '%' {
					break
				}

				newPos = AbnfPos(p - begin)
				this.End = int32(newPos)
				return escapeNum, newPos, true
			}
		}

		for ; p < end; p++ {
			//v := *((*byte)(unsafe.Pointer(p)))
			if *((*byte)(unsafe.Pointer(p))) == '%' {
				if (p + 2) >= end {
					return escapeNum, AbnfPos(p - begin), false
				}
				if !IsHex(*((*byte)(unsafe.Pointer(p + 1)))) || !IsHex(*((*byte)(unsafe.Pointer(p + 2)))) {
					return escapeNum, AbnfPos(p - begin), false
				}
				escapeNum++
				p += 2
			} else if (charset[*((*byte)(unsafe.Pointer(p)))] & mask) == 0 {
				newPos = AbnfPos(p - begin)
				this.End = int32(newPos)
				return escapeNum, newPos, true
			}
		}*/
	newPos = AbnfPos(p - begin)
	this.End = int32(newPos)
	return escapeNum, newPos, true
}

func (this *AbnfRef) ParseEscapable2(src []byte, pos AbnfPos, charset *[256]uint32, mask uint32) (escapeNum uint, newPos AbnfPos, ok bool) {
	this.Begin = int32(pos)
	len1 := AbnfPos(len(src))

	for newPos = pos; newPos < len1; newPos++ {
		if ((charset[src[newPos]]) & mask) == 0 {
			if src[newPos] == '%' {
				break
			}
			this.End = int32(newPos)
			return escapeNum, newPos, true
		}
	}

	for ; newPos < len1; newPos++ {
		if src[newPos] == '%' {
			if (newPos + 2) >= len1 {
				return escapeNum, newPos, false
			}
			if !IsHex(src[newPos+1]) || !IsHex(src[newPos+2]) {
				return escapeNum, newPos, false
			}
			escapeNum++
			newPos += 2
		} else if ((charset[src[newPos]]) & mask) == 0 {
			this.End = int32(newPos)
			return escapeNum, newPos, true
		}
	}
	this.End = int32(newPos)
	return escapeNum, newPos, true
}

func ParseAndAllocSipToken(context *ParseContext, src []byte, pos AbnfPos) (addr AbnfPtr, ok bool) {
	ref := AbnfRef{}
	newPos := ref.Parse(src, pos, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)

	context.SetParsePos(newPos)

	if ref.Begin >= ref.End {
		return ABNF_PTR_NIL, false
	}

	addr = AllocCString(context, src[ref.Begin:ref.End])
	return addr, true
}

func ParseAndAllocSipToken2(context *ParseContext) (addr AbnfPtr, ok bool) {
	return context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_USER, ABNF_CHARSET_MASK_SIP_USER)
}
