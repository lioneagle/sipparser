package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderRecordRoute struct {
	addr        SipAddr
	params      AbnfPtr
	knownParams AbnfPtr
	next        AbnfPtr
}

func SizeofSipHeaderRecordRoute() int {
	return int(unsafe.Sizeof(SipHeaderRecordRoute{}))
}

func NewSipHeaderRecordRoute(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderRecordRoute()))
}

func (this *SipHeaderRecordRoute) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderRecordRoute) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderRecordRoute())
}

func (this *SipHeaderRecordRoute) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderRecordRoute) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("Record-Route: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderRecordRoute) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	this.addr.Encode(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * Record-Route  =  "Record-Route" HCOLON rec-route *(COMMA rec-route)
 * rec-route     =  name-addr *( SEMI rr-param )
 * rr-param      =  generic-param
 */
func (this *SipHeaderRecordRoute) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderRecordRoute) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Record-Route header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Record-Route header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRecordRoute) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRecordRoute) ParseValueWithoutInit(context *Context) (ok bool) {
	ok = this.addr.ParseNameAddrWithoutInit(context)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for Record-Route header")
		return false
	}

	if context.ParseSetSipRecordRouteKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Record-Route header")
		return false
	}

	return true
}

func (this *SipHeaderRecordRoute) EncodeKnownParams(context *Context, buf *AbnfByteBuffer) {
	return
}

func (this *SipHeaderRecordRoute) SetKnownParams(context *Context, name AbnfPtr, param AbnfPtr) bool {
	return false
}

func (this *SipHeaderRecordRoute) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 12) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'r') &&
		((src[pos+1] | 0x20) == 'e') &&
		((src[pos+2] | 0x20) == 'c') &&
		((src[pos+3] | 0x20) == 'o') &&
		((src[pos+4] | 0x20) == 'r') &&
		((src[pos+5] | 0x20) == 'd') &&
		((src[pos+6] | 0x20) == '-') &&
		((src[pos+7] | 0x20) == 'r') &&
		((src[pos+8] | 0x20) == 'o') &&
		((src[pos+9] | 0x20) == 'u') &&
		((src[pos+10] | 0x20) == 't') &&
		((src[pos+11] | 0x20) == 'e') {
		if src[pos+12] == ':' || IsWspChar(src[pos+12]) {
			context.parsePos = pos + 12
			return true
		}

	}

	return false
}

func ParseSipRecordRoute(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderRecordRoute(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Record-Route header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderRecordRoute(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipRecordRouteValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderRecordRoute(context).EncodeValue(context, buf)
}

func AppendSipRecordRouteValue(context *Context, parsed AbnfPtr, header AbnfPtr) {
	for addr := parsed; addr != ABNF_PTR_NIL; {
		h := addr.GetSipHeaderRecordRoute(context)
		if h.next == ABNF_PTR_NIL {
			h.next = header
			return
		}
		addr = h.next
	}
}

func GetNextRecordRouteValue(context *Context, parsed AbnfPtr) AbnfPtr {
	return parsed.GetSipHeaderRecordRoute(context).next
}
