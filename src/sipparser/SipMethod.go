package sipparser

import (
	//"fmt"
	"unsafe"
)

var g_sipMethodName = []string{
	ABNF_SIP_METHOD_UNKNOWN:   "UKNOWN",
	ABNF_SIP_METHOD_INVITE:    "INVITE",
	ABNF_SIP_METHOD_PRACK:     "PRACK",
	ABNF_SIP_METHOD_UPDATE:    "UPDATE",
	ABNF_SIP_METHOD_INFO:      "INFO",
	ABNF_SIP_METHOD_ACK:       "ACK",
	ABNF_SIP_METHOD_BYE:       "BYE",
	ABNF_SIP_METHOD_REGISTER:  "REGISTER",
	ABNF_SIP_METHOD_SUBSCRIBE: "SUBSCRIBE",
	ABNF_SIP_METHOD_NOTIFY:    "NOTIFY",
	ABNF_SIP_METHOD_REFER:     "REFER",
	ABNF_SIP_METHOD_OPTIONS:   "OPTIONS",
	ABNF_SIP_METHOD_MESSAGE:   "MESSAGE",
	ABNF_SIP_METHOD_PUBLISH:   "PUBLISH",
}

type SipMethod struct {
	//method        byte
	//unknownMethod AbnfPtr
	method AbnfPtr
}

func SizeofSipMethod() int {
	return int(unsafe.Sizeof(SipMethod{}))
}

func NewSipMethod(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipMethod()))
}

func (this *SipMethod) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipMethod) Init() {
	ZeroMem(this.memAddr(), SizeofSipMethod())
}

func (this *SipMethod) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipMethod) Encode(context *ParseContext, buf *AbnfByteBuffer) {
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
func (this *SipMethod) Parse(context *ParseContext) (ok bool) {
	var newPos AbnfPos
	method, newPos := GetSipMethodIndex(context.parseSrc, context.parsePos)

	if method == ABNF_SIP_METHOD_UNKNOWN {
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
