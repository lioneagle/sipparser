package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderRseq struct {
	size uint32
}

func SizeofSipHeaderRseq() int {
	return int(unsafe.Sizeof(SipHeaderRseq{}))
}

func NewSipHeaderRseq(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderRseq()))
}

func (this *SipHeaderRseq) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderRseq) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderRseq())
}

func (this *SipHeaderRseq) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderRseq) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("RSeq: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderRseq) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	EncodeUInt(buf, uint64(this.size))
}

/* RFC3262
 *
 * RSeq          =  "RSeq" HCOLON response-num
 * response-num  =  1*DIGIT
 */
func (this *SipHeaderRseq) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderRseq) ParseWithoutInit(context *ParseContext) (ok bool) {
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

func (this *SipHeaderRseq) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRseq) ParseValueWithoutInit(context *ParseContext) (ok bool) {
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

func (this *SipHeaderRseq) parseHeaderName(context *ParseContext) (ok bool) {
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

func ParseSipRseq(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderRseq(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for RSeq header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderRseq(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipRseqValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderRseq(context).EncodeValue(context, buf)
}
