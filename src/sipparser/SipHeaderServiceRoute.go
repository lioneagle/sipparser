package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderServiceRoute struct {
	addr        SipAddr
	params      AbnfPtr
	knownParams AbnfPtr
	next        AbnfPtr
}

func SizeofSipHeaderServiceRoute() int {
	return int(unsafe.Sizeof(SipHeaderServiceRoute{}))
}

func NewSipHeaderServiceRoute(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderServiceRoute()))
}

func (this *SipHeaderServiceRoute) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderServiceRoute) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderServiceRoute())
}

func (this *SipHeaderServiceRoute) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderServiceRoute) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("Service-Route: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderServiceRoute) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	this.addr.Encode(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * Service-Route = "Service-Route" HCOLON sr-value *( COMMA sr-value)
 * sr-value      = name-addr *( SEMI rr-param )
 * rr-param      =  generic-param
 */
func (this *SipHeaderServiceRoute) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderServiceRoute) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Service-Route header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Service-Route header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderServiceRoute) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderServiceRoute) ParseValueWithoutInit(context *Context) (ok bool) {
	ok = this.addr.ParseNameAddrWithoutInit(context)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for Service-Route header")
		return false
	}

	if context.ParseSetSipServiceRouteKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Service-Route header")
		return false
	}

	return true
}

func (this *SipHeaderServiceRoute) EncodeKnownParams(context *Context, buf *AbnfByteBuffer) {
	return
}

func (this *SipHeaderServiceRoute) SetKnownParams(context *Context, name AbnfPtr, param AbnfPtr) bool {
	return false
}

func (this *SipHeaderServiceRoute) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if (pos + 13) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 's') &&
		((src[pos+1] | 0x20) == 'e') &&
		((src[pos+2] | 0x20) == 'r') &&
		((src[pos+3] | 0x20) == 'v') &&
		((src[pos+4] | 0x20) == 'i') &&
		((src[pos+5] | 0x20) == 'c') &&
		((src[pos+6] | 0x20) == 'e') &&
		((src[pos+7] | 0x20) == '-') &&
		((src[pos+8] | 0x20) == 'r') &&
		((src[pos+9] | 0x20) == 'o') &&
		((src[pos+10] | 0x20) == 'u') &&
		((src[pos+11] | 0x20) == 't') &&
		((src[pos+12] | 0x20) == 'e') {
		if src[pos+13] == ':' || IsWspChar(src[pos+13]) {
			context.parsePos = pos + 13
			return true
		}
	}

	return false
}

func ParseSipServiceRoute(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderRecordRoute(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Service-Route header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderServiceRoute(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipServiceRouteValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderServiceRoute(context).EncodeValue(context, buf)
}

func AppendSipServiceRouteValue(context *Context, parsed AbnfPtr, header AbnfPtr) {
	for addr := parsed; addr != ABNF_PTR_NIL; {
		h := addr.GetSipHeaderServiceRoute(context)
		if h.next == ABNF_PTR_NIL {
			h.next = header
			return
		}
		addr = h.next
	}
}

func GetNextServiceRouteValue(context *Context, parsed AbnfPtr) AbnfPtr {
	return parsed.GetSipHeaderServiceRoute(context).next
}
