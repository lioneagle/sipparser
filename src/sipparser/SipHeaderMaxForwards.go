package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderMaxForwards struct {
	size byte
}

func SizeofSipHeaderMaxForwards() int {
	return int(unsafe.Sizeof(SipHeaderMaxForwards{}))
}

func NewSipHeaderMaxForwards(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderMaxForwards()))
}

func (this *SipHeaderMaxForwards) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderMaxForwards) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderMaxForwards())
}

func (this *SipHeaderMaxForwards) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderMaxForwards) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("Max-Forwards: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderMaxForwards) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	EncodeUInt(buf, uint64(this.size))
}

/* RFC3261
 *
 * Max-Forwards  =  "Max-Forwards" HCOLON 1*DIGIT
 *
 */
func (this *SipHeaderMaxForwards) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderMaxForwards) ParseWithoutInit(context *ParseContext) (ok bool) {
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

func (this *SipHeaderMaxForwards) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderMaxForwards) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	digit, _, newPos, ok := ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.parsePos = newPos
		context.AddError(newPos, "parse num failed for CSeq header")
		return false
	}

	this.size = byte(digit)
	context.parsePos = newPos
	return true
}

func (this *SipHeaderMaxForwards) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 12) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'm') &&
		((src[pos+1] | 0x20) == 'a') &&
		((src[pos+2] | 0x20) == 'x') &&
		(src[pos+3] == '-') &&
		((src[pos+4] | 0x20) == 'f') &&
		((src[pos+5] | 0x20) == 'o') &&
		((src[pos+6] | 0x20) == 'r') &&
		((src[pos+7] | 0x20) == 'w') &&
		((src[pos+8] | 0x20) == 'a') &&
		((src[pos+9] | 0x20) == 'r') &&
		((src[pos+10] | 0x20) == 'd') &&
		((src[pos+11] | 0x20) == 's') {
		if src[pos+12] == ':' || IsWspChar(src[pos+12]) {
			context.parsePos = pos + 12
			return true
		}
	}

	return false
}

func ParseSipMaxForwards(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderMaxForwards(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Max-Forwards header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderMaxForwards(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipMaxForwardsValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderMaxForwards(context).EncodeValue(context, buf)
}
