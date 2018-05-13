package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderCSeq struct {
	id     uint32
	method SipMethod
}

func SizeofSipHeaderCSeq() int {
	return int(unsafe.Sizeof(SipHeaderCSeq{}))
}

func NewSipHeaderCSeq(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderCSeq()))
}

func (this *SipHeaderCSeq) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderCSeq) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderCSeq())
}

func (this *SipHeaderCSeq) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderCSeq) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("CSeq: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderCSeq) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	EncodeUInt(buf, uint64(this.id))
	buf.WriteByte(' ')
	this.method.Encode(context, buf)
}

/* RFC3261
 *
 * CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method
 *
 */
func (this *SipHeaderCSeq) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderCSeq) ParseWithoutInit(context *ParseContext) (ok bool) {
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

func (this *SipHeaderCSeq) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderCSeq) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	digit, _, newPos, ok := ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.parsePos = newPos
		context.AddError(newPos, "parse num failed for CSeq header")
		return false
	}

	this.id = uint32(digit)
	context.parsePos = newPos

	ok = ParseLWS(context)
	if !ok {
		context.AddError(context.parsePos, "parse LWS failed for CSeq header")
		return false
	}

	ok = this.method.Parse(context)
	if !ok {
		context.AddError(context.parsePos, "parse Method failed for CSeq header")
		return false
	}

	return true
}

func (this *SipHeaderCSeq) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 4) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'c') &&
		((src[pos+1] | 0x20) == 's') &&
		((src[pos+2] | 0x20) == 'e') &&
		((src[pos+3] | 0x20) == 'q') {
		if src[pos+4] == ':' || IsWspChar(src[pos+4]) {
			context.parsePos = pos + 4
			return true
		}
	}

	return false
}

func ParseSipCSeq(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderCSeq(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for CSeq header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderCSeq(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipCSeqValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderCSeq(context).EncodeValue(context, buf)
}
