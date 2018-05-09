package sipparser

import (
	//"fmt"
	"unsafe"
)

const ABNF_SIP_CONTENT_LENGTH_SPACE = 10
const ABNF_SIP_CONTENT_LENGTH_PRINT_FMT = "%10d"
const ABNF_SIP_DEFAULT_BOUNDARY = "sip-unique-boundary-aasdasdewfd"

func (this AbnfPtr) GetSipHostPort(context *ParseContext) *SipHostPort {
	return (*SipHostPort)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipUri(context *ParseContext) *SipUri {
	return (*SipUri)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipUriKnownParams(context *ParseContext) *SipUriKnownParams {
	return (*SipUriKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipAddr(context *ParseContext) *SipAddr {
	return (*SipAddr)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetUriParam(context *ParseContext) *UriParam {
	return (*UriParam)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetUriHeader(context *ParseContext) *UriHeader {
	return (*UriHeader)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipGenericParam(context *ParseContext) *SipGenericParam {
	return (*SipGenericParam)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderFrom(context *ParseContext) *SipHeaderFrom {
	return (*SipHeaderFrom)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipFromKnownParams(context *ParseContext) *SipFromKnownParams {
	return (*SipFromKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderTo(context *ParseContext) *SipHeaderTo {
	return (*SipHeaderTo)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipToKnownParams(context *ParseContext) *SipToKnownParams {
	return (*SipToKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderCallId(context *ParseContext) *SipHeaderCallId {
	return (*SipHeaderCallId)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderCseq(context *ParseContext) *SipHeaderCseq {
	return (*SipHeaderCseq)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMethod(context *ParseContext) *SipMethod {
	return (*SipMethod)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderMaxForwards(context *ParseContext) *SipHeaderMaxForwards {
	return (*SipHeaderMaxForwards)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipStartLine(context *ParseContext) *SipStartLine {
	return (*SipStartLine)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipVersion(context *ParseContext) *SipVersion {
	return (*SipVersion)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderRoute(context *ParseContext) *SipHeaderRoute {
	return (*SipHeaderRoute)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderRecordRoute(context *ParseContext) *SipHeaderRecordRoute {
	return (*SipHeaderRecordRoute)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipContactKnownParams(context *ParseContext) *SipContactKnownParams {
	return (*SipContactKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContact(context *ParseContext) *SipHeaderContact {
	return (*SipHeaderContact)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContentLength(context *ParseContext) *SipHeaderContentLength {
	return (*SipHeaderContentLength)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipViaKnownParams(context *ParseContext) *SipViaKnownParams {
	return (*SipViaKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderVia(context *ParseContext) *SipHeaderVia {
	return (*SipHeaderVia)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipContentTypeKnownParams(context *ParseContext) *SipContentTypeKnownParams {
	return (*SipContentTypeKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContentType(context *ParseContext) *SipHeaderContentType {
	return (*SipHeaderContentType)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipContentDispositionKnownParams(context *ParseContext) *SipContentDispositionKnownParams {
	return (*SipContentDispositionKnownParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeaderContentDisposition(context *ParseContext) *SipHeaderContentDisposition {
	return (*SipHeaderContentDisposition)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipHeader(context *ParseContext) *SipHeader {
	return (*SipHeader)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipSentProtocol(context *ParseContext) *SipSentProtocol {
	return (*SipSentProtocol)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMsg(context *ParseContext) *SipMsg {
	return (*SipMsg)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMsgBody(context *ParseContext) *SipMsgBody {
	return (*SipMsgBody)(unsafe.Pointer(&context.allocator.mem[this]))
}

/*func (this AbnfPtr) GetSipSingleHeader(context *ParseContext) *SipSingleHeader {
	return (*SipSingleHeader)(unsafe.Pointer(&context.allocator.mem[this]))
}
func (this AbnfPtr) GetSipSingleHeaders(context *ParseContext) *SipSingleHeaders {
	return (*SipSingleHeaders)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMultiHeader(context *ParseContext) *SipMultiHeader {
	return (*SipMultiHeader)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMultiHeaders(context *ParseContext) *SipMultiHeaders {
	return (*SipMultiHeaders)(unsafe.Pointer(&context.allocator.mem[this]))
}



func (this AbnfPtr) GetTelUriContext(context *ParseContext) *TelUriContext {
	return (*TelUriContext)(unsafe.Pointer(&context.allocator.mem[this]))
}


func (this AbnfPtr) GetTelUri(context *ParseContext) *TelUri {
	return (*TelUri)(unsafe.Pointer(&context.allocator.mem[this]))
}


func (this AbnfPtr) GetSipMsgBody(context *ParseContext) *SipMsgBody {
	return (*SipMsgBody)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipMsgBodies(context *ParseContext) *SipMsgBodies {
	return (*SipMsgBodies)(unsafe.Pointer(&context.allocator.mem[this]))
}*/

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*func (this AbnfPtr) GetSipMsg(context *ParseContext) *SipMsg {
	return (*SipMsg)(unsafe.Pointer(&context.allocator.mem[this]))
}*/
