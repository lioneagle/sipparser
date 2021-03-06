package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipHeaderPath struct {
	addr        SipAddr
	params      AbnfPtr
	knownParams AbnfPtr
	next        AbnfPtr
}

func SizeofSipHeaderPath() int {
	return int(unsafe.Sizeof(SipHeaderPath{}))
}

func NewSipHeaderPath(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderPath()))
}

func (this *SipHeaderPath) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderPath) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderPath())
}

func (this *SipHeaderPath) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderPath) Encode(context *Context, buf *AbnfByteBuffer) {
	buf.WriteString("Path: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderPath) EncodeValue(context *Context, buf *AbnfByteBuffer) {
	this.addr.Encode(context, buf)
	EncodeSipGenericParams(context, buf, this.params, ';', this)
}

/* RFC3327
 *
 * Path       = "Path" HCOLON path-value *( COMMA path-value )
 * path-value = name-addr *( SEMI rr-param )
 * rr-param   =  generic-param
 */
func (this *SipHeaderPath) Parse(context *Context) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderPath) ParseWithoutInit(context *Context) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Path header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Path header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderPath) ParseValue(context *Context) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderPath) ParseValueWithoutInit(context *Context) (ok bool) {
	ok = this.addr.ParseNameAddrWithoutInit(context)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for Path header")
		return false
	}

	if context.ParseSetSipPathKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Path header")
		return false
	}

	return true
}

func (this *SipHeaderPath) EncodeKnownParams(context *Context, buf *AbnfByteBuffer) {
	return
}

func (this *SipHeaderPath) SetKnownParams(context *Context, name AbnfPtr, param AbnfPtr) bool {
	return false
}

func (this *SipHeaderPath) parseHeaderName(context *Context) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if (pos + 4) >= len1 {
		return false
	}

	if ((src[pos] | 0x20) == 'p') &&
		((src[pos+1] | 0x20) == 'a') &&
		((src[pos+2] | 0x20) == 't') &&
		((src[pos+3] | 0x20) == 'h') {
		if src[pos+4] == ':' || IsWspChar(src[pos+4]) {
			context.parsePos = pos + 4
			return true
		}
	}

	return false
}

func ParseSipPath(context *Context) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderPath(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Path header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderPath(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipPathValue(parsed AbnfPtr, context *Context, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderPath(context).EncodeValue(context, buf)
}

func AppendSipPathValue(context *Context, parsed AbnfPtr, header AbnfPtr) {
	for addr := parsed; addr != ABNF_PTR_NIL; {
		h := addr.GetSipHeaderPath(context)
		if h.next == ABNF_PTR_NIL {
			h.next = header
			return
		}
		addr = h.next
	}
}

func GetNextPathValue(context *Context, parsed AbnfPtr) AbnfPtr {
	return parsed.GetSipHeaderPath(context).next
}
