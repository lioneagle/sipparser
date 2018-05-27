package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderExpires struct {
	size uint32
}

func SizeofSipHeaderExpires() int {
	return int(unsafe.Sizeof(SipHeaderExpires{}))
}

func NewSipHeaderExpires(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderExpires()))
}

func (this *SipHeaderExpires) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderExpires) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderExpires())
}

func (this *SipHeaderExpires) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderExpires) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("Expires: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderExpires) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	EncodeUInt(buf, uint64(this.size))
}

/* RFC3261
 *
 * Expires        =  "Expires" HCOLON delta-seconds
 * delta-seconds  =  1*DIGIT
 */
func (this *SipHeaderExpires) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderExpires) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Expires header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Expires header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderExpires) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderExpires) ParseValueWithoutInit(context *Context) (ok bool) {
	digit, _, newPos, ok := ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.parsePos = newPos
		context.AddError(newPos, "parse num failed for Expires header")
		return false
	}

	this.size = uint32(digit)
	context.parsePos = newPos
	return true
}

func (this *SipHeaderExpires) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 7) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'e') &&
		((src[pos+1] | 0x20) == 'x') &&
		((src[pos+2] | 0x20) == 'p') &&
		((src[pos+3] | 0x20) == 'i') &&
		((src[pos+4] | 0x20) == 'r') &&
		((src[pos+5] | 0x20) == 'e') &&
		((src[pos+6] | 0x20) == 's') {
		if src[pos+7] == ':' || IsWspChar(src[pos+7]) {
			context.parsePos = pos + 7
			return true
		}
	}

	return false
}

func ParseSipExpires(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderExpires(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Expires header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderExpires(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipExpiresValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderExpires(context).EncodeValue(context, buf)
}
