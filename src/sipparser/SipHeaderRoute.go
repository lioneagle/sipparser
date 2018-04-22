package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderRoute struct {
	addr        SipAddr
	params      AbnfPtr
	knownParams AbnfPtr
	next        AbnfPtr
}

func SizeofSipHeaderRoute() int {
	return int(unsafe.Sizeof(SipHeaderRoute{}))
}

func NewSipHeaderRoute(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderRoute()))
}

func (this *SipHeaderRoute) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderRoute) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderRoute())
}

func (this *SipHeaderRoute) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderRoute) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("Route: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderRoute) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	this.addr.Encode(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3261
 *
 * Route        =  "Route" HCOLON route-param *(COMMA route-param)
 * route-param  =  name-addr *( SEMI rr-param )
 * rr-param     =  generic-param
 */
func (this *SipHeaderRoute) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderRoute) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Route header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Route header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRoute) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderRoute) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	ok = this.addr.ParseNameAddrWithoutInit(context)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for Route header")
		return false
	}

	if context.ParseSetSipRouteKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Route header")
		return false
	}

	return true
}

func (this *SipHeaderRoute) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	return
}

func (this *SipHeaderRoute) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool {
	return false
}

func (this *SipHeaderRoute) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'r' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}

		if (pos + 4) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'o') &&
			((src[pos+1] | 0x20) == 'u') &&
			((src[pos+2] | 0x20) == 't') &&
			((src[pos+3] | 0x20) == 'e') {
			if src[pos+4] == ':' || IsWspChar(src[pos+4]) {
				context.parsePos = pos + 4
				return true
			}
		}
	}

	return false
}

func ParseSipRoute(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderRoute(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for From header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderRoute(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipRouteValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderRoute(context).EncodeValue(context, buf)
}