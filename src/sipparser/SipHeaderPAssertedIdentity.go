package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderPAssertedIdentity struct {
	addr SipAddr
	next AbnfPtr
}

func SizeofSipHeaderPAssertedIdentity() int {
	return int(unsafe.Sizeof(SipHeaderPAssertedIdentity{}))
}

func NewSipHeaderPAssertedIdentity(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderPAssertedIdentity()))
}

func (this *SipHeaderPAssertedIdentity) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderPAssertedIdentity) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderPAssertedIdentity())
}

func (this *SipHeaderPAssertedIdentity) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderPAssertedIdentity) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("P-Asserted-Identity: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderPAssertedIdentity) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	this.addr.Encode(context, buf)
}

/* RFC3327
 *
 * Path       = "Path" HCOLON path-value *( COMMA path-value )
 * path-value = name-addr *( SEMI rr-param )
 * rr-param   =  generic-param
 */
func (this *SipHeaderPAssertedIdentity) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderPAssertedIdentity) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for P-Asserted-Identity header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for P-Asserted-Identity header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderPAssertedIdentity) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderPAssertedIdentity) ParseValueWithoutInit(context *Context) (ok bool) {
	ok = this.addr.ParseWithoutInit(context, false)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for P-Asserted-Identity header")
		return false
	}

	return true
}

func (this *SipHeaderPAssertedIdentity) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 19) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'p') &&
		((src[pos+1] | 0x20) == '-') &&
		((src[pos+2] | 0x20) == 'a') &&
		((src[pos+3] | 0x20) == 's') &&
		((src[pos+4] | 0x20) == 's') &&
		((src[pos+5] | 0x20) == 'e') &&
		((src[pos+6] | 0x20) == 'r') &&
		((src[pos+7] | 0x20) == 't') &&
		((src[pos+8] | 0x20) == 'e') &&
		((src[pos+9] | 0x20) == 'd') &&
		((src[pos+10] | 0x20) == '-') &&
		((src[pos+11] | 0x20) == 'i') &&
		((src[pos+12] | 0x20) == 'd') &&
		((src[pos+13] | 0x20) == 'e') &&
		((src[pos+14] | 0x20) == 'n') &&
		((src[pos+15] | 0x20) == 't') &&
		((src[pos+16] | 0x20) == 'i') &&
		((src[pos+17] | 0x20) == 't') &&
		((src[pos+18] | 0x20) == 'y') {
		if src[pos+19] == ':' || IsWspChar(src[pos+19]) {
			context.parsePos = pos + 19
			return true
		}
	}

	return false
}

func ParseSipPAssertedIdentity(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderPAssertedIdentity(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for P-Asserted-Identity header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderPAssertedIdentity(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipPAssertedIdentityValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderPAssertedIdentity(context).EncodeValue(context, buf)
}

func AppendSipPAssertedIdentityValue(context *Context, parsed AbnfPtr, header AbnfPtr) {
	for addr := parsed; addr != ABNF_PTR_NIL; {
		h := addr.GetSipHeaderPAssertedIdentity(context)
		if h.next == ABNF_PTR_NIL {
			h.next = header
			return
		}
		addr = h.next
	}
}

func GetNextPAssertedIdentityValue(context *Context, parsed AbnfPtr) AbnfPtr {
	return parsed.GetSipHeaderPAssertedIdentity(context).next
}
