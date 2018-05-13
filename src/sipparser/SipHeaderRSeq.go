package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderRSeq struct {
	size uint32
}

func SizeofSipHeaderRSeq() int {
	return int(unsafe.Sizeof(SipHeaderRSeq{}))
}

func NewSipHeaderRSeq(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderRSeq()))
}

func (this *SipHeaderRSeq) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderRSeq) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderRSeq())
}

func (this *SipHeaderRSeq) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderRSeq) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("RSeq: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderRSeq) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	EncodeUInt(buf, uint64(this.size))
}

/* RFC3262
 *
 * RSeq          =  "RSeq" HCOLON response-num
 * response-num  =  1*DIGIT
 */
func (this *SipHeaderRSeq) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderRSeq) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for RSeq header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for RSeq header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRSeq) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRSeq) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	digit, _, newPos, ok := ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.parsePos = newPos
		context.AddError(newPos, "parse num failed for RSeq header")
		return false
	}

	this.size = uint32(digit)
	context.parsePos = newPos
	return true
}

func (this *SipHeaderRSeq) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 4) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'r') &&
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

func ParseSipRSeq(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderRSeq(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for RSeq header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderRSeq(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipRSeqValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderRSeq(context).EncodeValue(context, buf)
}
