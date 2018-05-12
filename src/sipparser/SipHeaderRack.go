package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderRack struct {
	rseq   uint32
	cseq   uint32
	method SipMethod
}

func SizeofSipHeaderRack() int {
	return int(unsafe.Sizeof(SipHeaderRack{}))
}

func NewSipHeaderRack(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderRack()))
}

func (this *SipHeaderRack) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderRack) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderRack())
}

func (this *SipHeaderRack) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderRack) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("RAck: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderRack) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	EncodeUInt(buf, uint64(this.rseq))
	buf.WriteByte(' ')
	EncodeUInt(buf, uint64(this.cseq))
	buf.WriteByte(' ')
	this.method.Encode(context, buf)
}

/* RFC3261
 *
 * RAck          =  "RAck" HCOLON response-num LWS CSeq-num LWS Method
 * response-num  =  1*DIGIT
 * CSeq-num      =  1*DIGIT
 *
 */
func (this *SipHeaderRack) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderRack) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for RAck header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for RAck header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRack) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRack) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	digit, _, newPos, ok := ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.parsePos = newPos
		context.AddError(newPos, "parse rseq failed for RAck header")
		return false
	}

	this.rseq = uint32(digit)
	context.parsePos = newPos

	ok = ParseLWS(context)
	if !ok {
		context.AddError(context.parsePos, "parse LWS failed after rseq for RAck header")
		return false
	}

	digit, _, newPos, ok = ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.parsePos = newPos
		context.AddError(newPos, "parse cseq failed for RAck header")
		return false
	}

	this.cseq = uint32(digit)
	context.parsePos = newPos

	ok = ParseLWS(context)
	if !ok {
		context.AddError(context.parsePos, "parse LWS failed after cseq for RAck header")
		return false
	}

	ok = this.method.Parse(context)
	if !ok {
		context.AddError(context.parsePos, "parse Method failed for RAck header")
		return false
	}

	return true
}

func (this *SipHeaderRack) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 4) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'r') &&
		((src[pos+1] | 0x20) == 'a') &&
		((src[pos+2] | 0x20) == 'c') &&
		((src[pos+3] | 0x20) == 'k') {
		if src[pos+4] == ':' || IsWspChar(src[pos+4]) {
			context.parsePos = pos + 4
			return true
		}
	}

	return false
}

func ParseSipRack(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderRack(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for RAck header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderRack(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipRackValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderRack(context).EncodeValue(context, buf)
}
