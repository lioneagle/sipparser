package sipparser

import (
	//"fmt"
	"unsafe"
)

const ABNF_SIP_CONTENT_LENGTH_SPACE = 10
const ABNF_SIP_CONTENT_LENGTH_PRINT_FMT = "%10d"
const ABNF_SIP_DEFAULT_BOUNDARY = "sip-unique-boundary-aasdasdewfd"

func (this AbnfPtr) GetSipHostPort(context *Context) *SipHostPort {
	return (*SipHostPort)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipUri(context *Context) *SipUri {
	return (*SipUri)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipUriKnownParams(context *Context) *SipUriKnownParams {
	return (*SipUriKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipAddr(context *Context) *SipAddr {
	return (*SipAddr)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetUriParam(context *Context) *UriParam {
	return (*UriParam)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetUriHeader(context *Context) *UriHeader {
	return (*UriHeader)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipGenericParam(context *Context) *SipGenericParam {
	return (*SipGenericParam)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderFrom(context *Context) *SipHeaderFrom {
	return (*SipHeaderFrom)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipFromKnownParams(context *Context) *SipFromKnownParams {
	return (*SipFromKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderTo(context *Context) *SipHeaderTo {
	return (*SipHeaderTo)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipToKnownParams(context *Context) *SipToKnownParams {
	return (*SipToKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderCallID(context *Context) *SipHeaderCallID {
	return (*SipHeaderCallID)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderCSeq(context *Context) *SipHeaderCSeq {
	return (*SipHeaderCSeq)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMethod(context *Context) *SipMethod {
	return (*SipMethod)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderMaxForwards(context *Context) *SipHeaderMaxForwards {
	return (*SipHeaderMaxForwards)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipStartLine(context *Context) *SipStartLine {
	return (*SipStartLine)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipVersion(context *Context) *SipVersion {
	return (*SipVersion)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderRoute(context *Context) *SipHeaderRoute {
	return (*SipHeaderRoute)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderRecordRoute(context *Context) *SipHeaderRecordRoute {
	return (*SipHeaderRecordRoute)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipContactKnownParams(context *Context) *SipContactKnownParams {
	return (*SipContactKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContact(context *Context) *SipHeaderContact {
	return (*SipHeaderContact)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContentLength(context *Context) *SipHeaderContentLength {
	return (*SipHeaderContentLength)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipViaKnownParams(context *Context) *SipViaKnownParams {
	return (*SipViaKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderVia(context *Context) *SipHeaderVia {
	return (*SipHeaderVia)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipContentTypeKnownParams(context *Context) *SipContentTypeKnownParams {
	return (*SipContentTypeKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContentType(context *Context) *SipHeaderContentType {
	return (*SipHeaderContentType)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipContentDispositionKnownParams(context *Context) *SipContentDispositionKnownParams {
	return (*SipContentDispositionKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContentDisposition(context *Context) *SipHeaderContentDisposition {
	return (*SipHeaderContentDisposition)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeader(context *Context) *SipHeader {
	return (*SipHeader)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipSentProtocol(context *Context) *SipSentProtocol {
	return (*SipSentProtocol)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMsg(context *Context) *SipMsg {
	return (*SipMsg)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMsgBody(context *Context) *SipMsgBody {
	return (*SipMsgBody)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetTelUriKnownParams(context *Context) *TelUriKnownParams {
	return (*TelUriKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetTelUri(context *Context) *TelUri {
	return (*TelUri)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderExpires(context *Context) *SipHeaderExpires {
	return (*SipHeaderExpires)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderPath(context *Context) *SipHeaderPath {
	return (*SipHeaderPath)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderServiceRoute(context *Context) *SipHeaderServiceRoute {
	return (*SipHeaderServiceRoute)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderRSeq(context *Context) *SipHeaderRSeq {
	return (*SipHeaderRSeq)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderRAck(context *Context) *SipHeaderRAck {
	return (*SipHeaderRAck)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderPAssertedIdentity(context *Context) *SipHeaderPAssertedIdentity {
	return (*SipHeaderPAssertedIdentity)(unsafe.Pointer(&context.allocator.mem[this]))
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*func (this AbnfPtr) GetSipMsg(context *ParseContext) *SipMsg {
	return (*SipMsg)(unsafe.Pointer(&context.allocator.mem[this]))
}*/
