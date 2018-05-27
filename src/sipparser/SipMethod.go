package sipparser

import (
	//"fmt"
	"unsafe"
)

var g_sipMethodName = []string{
	SIP_METHOD_UNKNOWN:   "UKNOWN",
	SIP_METHOD_INVITE:    "INVITE",
	SIP_METHOD_PRACK:     "PRACK",
	SIP_METHOD_UPDATE:    "UPDATE",
	SIP_METHOD_INFO:      "INFO",
	SIP_METHOD_ACK:       "ACK",
	SIP_METHOD_BYE:       "BYE",
	SIP_METHOD_REGISTER:  "REGISTER",
	SIP_METHOD_SUBSCRIBE: "SUBSCRIBE",
	SIP_METHOD_NOTIFY:    "NOTIFY",
	SIP_METHOD_REFER:     "REFER",
	SIP_METHOD_OPTIONS:   "OPTIONS",
	SIP_METHOD_MESSAGE:   "MESSAGE",
	SIP_METHOD_PUBLISH:   "PUBLISH",
}

type SipMethod struct {
	//method        byte
	//unknownMethod AbnfPtr
	method AbnfPtr
}

func SizeofSipMethod() int {
	return int(unsafe.Sizeof(SipMethod{}))
}

func NewSipMethod(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipMethod()))
}

func (this *SipMethod) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipMethod) Init() {
	ZeroMem(this.memAddr(), SizeofSipMethod())
}

func (this *SipMethod) String(context *Context) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipMethod) Encode(context *Context, buf *AbnfByteBuffer) {
	if !this.method.IsAbnfPtr() {
		buf.WriteString(g_sipMethodName[this.method.GetValue()])
	} else {
		this.method.WriteCString(context, buf)
	}
}

/*
 * Method            =  INVITEm / ACKm / OPTIONSm / BYEm
 *                     / CANCELm / REGISTERm
 *                     / extension-method
 * extension-method  =  token
 */
func (this *SipMethod) Parse(context *Context) (ok bool) {
	method, newPos := GetSipMethodIndex(context.parseSrc, context.parsePos)

	if method == SIP_METHOD_UNKNOWN {
		//this.unknownMethod, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
		this.method, ok = context.allocator.ParseAndAllocCStringFromPos(context, newPos, ABNF_CHARSET_SIP_TOKEN, ABNF_CHARSET_MASK_SIP_TOKEN)
		return ok
	} else {
		context.parsePos = newPos
		//this.method = AbnfPtr(method)
		//this.method = AbnfPtr(this.method.SetValue())
		this.method = AbnfPtrSetValue(AbnfPtr(method))
	}
	return true
}
