package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderContentLength struct {
	size      uint32
	encodeEnd uint32 // record end position when encoding for modify length of sip msg
}

func SizeofSipHeaderContentLength() int {
	return int(unsafe.Sizeof(SipHeaderContentLength{}))
}

func NewSipHeaderContentLength(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderContentLength()))
}

func (this *SipHeaderContentLength) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderContentLength) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderContentLength())
}

func (this *SipHeaderContentLength) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderContentLength) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("Content-Length: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderContentLength) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	//EncodeUInt(buf, uint64(this.size))
	EncodeUIntWithWidth(buf, uint64(this.size), 10)
	this.encodeEnd = uint32(len(buf.Bytes()))
}

/* RFC3261
 *
 * Content-Length  =  ( "Content-Length" / "l" ) HCOLON 1*DIGIT
 */
func (this *SipHeaderContentLength) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderContentLength) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for CSeq header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for CSeq header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContentLength) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContentLength) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	digit, _, newPos, ok := ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.parsePos = newPos
		context.AddError(newPos, "parse num failed for CSeq header")
		return false
	}

	this.size = uint32(digit)
	context.parsePos = newPos
	return true
}

func (this *SipHeaderContentLength) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'c' {
		pos++

		if (pos + 13) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'o') &&
			((src[pos+1] | 0x20) == 'n') &&
			((src[pos+2] | 0x20) == 't') &&
			((src[pos+3] | 0x20) == 'e') &&
			((src[pos+4] | 0x20) == 'n') &&
			((src[pos+5] | 0x20) == 't') &&
			(src[pos+6] == '-') &&
			((src[pos+7] | 0x20) == 'l') &&
			((src[pos+8] | 0x20) == 'e') &&
			((src[pos+9] | 0x20) == 'n') &&
			((src[pos+10] | 0x20) == 'g') &&
			((src[pos+11] | 0x20) == 't') &&
			((src[pos+12] | 0x20) == 'h') {
			if src[pos+13] == ':' || IsWspChar(src[pos+13]) {
				context.parsePos = pos + 13
				return true
			}
		}
	} else if src[pos]|0x20 == 'l' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}
	}

	return false
}

func ParseSipContentLength(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderContentLength(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Content-Length header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderContentLength(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipContentLengthValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderContentLength(context).EncodeValue(context, buf)
}
