package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderRAck struct {
	rseq   uint32
	cseq   uint32
	method SipMethod
}

func SizeofSipHeaderRAck() int {
	return int(unsafe.Sizeof(SipHeaderRAck{}))
}

func NewSipHeaderRAck(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderRAck()))
}

func (this *SipHeaderRAck) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderRAck) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderRAck())
}

func (this *SipHeaderRAck) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderRAck) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("RAck: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderRAck) EncodeValue(context *Context, buf *AbnfByteBuffer) {
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
func (this *SipHeaderRAck) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderRAck) ParseWithoutInit(context *Context) (ok bool) {
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

func (this *SipHeaderRAck) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRAck) ParseValueWithoutInit(context *Context) (ok bool) {
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

func (this *SipHeaderRAck) parseHeaderName(context *Context) (ok bool) {
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

func ParseSipRAck(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderRAck(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for RAck header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderRAck(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipRAckValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderRAck(context).EncodeValue(context, buf)
}
