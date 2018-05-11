package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderCseq struct {
	id     uint32
	method SipMethod
}

func SizeofSipHeaderCseq() int {
	return int(unsafe.Sizeof(SipHeaderCseq{}))
}

func NewSipHeaderCseq(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderCseq()))
}

func (this *SipHeaderCseq) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderCseq) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderCseq())
}

func (this *SipHeaderCseq) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderCseq) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("CSeq: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderCseq) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	EncodeUInt(buf, uint64(this.id))
	buf.WriteByte(' ')
	this.method.Encode(context, buf)
}

/* RFC3261
 *
 * CSeq  =  "CSeq" HCOLON 1*DIGIT LWS Method
 *
 */
func (this *SipHeaderCseq) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderCseq) ParseWithoutInit(context *ParseContext) (ok bool) {
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

func (this *SipHeaderCseq) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderCseq) ParseValueWithoutInit(context *ParseContext) (ok bool) {
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

func (this *SipHeaderCseq) parseHeaderName(context *ParseContext) (ok bool) {
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

func ParseSipCseq(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderCseq(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for CSeq header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderCseq(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipCseqValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderCseq(context).EncodeValue(context, buf)
}
