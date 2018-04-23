package sipparser

import (
	//"fmt"
	"unsafe"
)

const ABNF_SIP_CONTENT_LENGTH_SPACE = 10
const ABNF_SIP_CONTENT_LENGTH_PRINT_FMT = "%10d"
const ABNF_SIP_DEFAULT_BOUNDARY = "sip-unique-boundary-aasdasdewfd"

type SipHeaderIndexType uint32

const (
	ABNF_SIP_HDR_UNKNOWN             SipHeaderIndexType = 0
	ABNF_SIP_HDR_FROM                SipHeaderIndexType = 1
	ABNF_SIP_HDR_TO                  SipHeaderIndexType = 2
	ABNF_SIP_HDR_VIA                 SipHeaderIndexType = 3
	ABNF_SIP_HDR_CALL_ID             SipHeaderIndexType = 4
	ABNF_SIP_HDR_CSEQ                SipHeaderIndexType = 5
	ABNF_SIP_HDR_CONTENT_LENGTH      SipHeaderIndexType = 6
	ABNF_SIP_HDR_CONTENT_TYPE        SipHeaderIndexType = 7
	ABNF_SIP_HDR_CONTACT             SipHeaderIndexType = 8
	ABNF_SIP_HDR_MAX_FORWARDS        SipHeaderIndexType = 9
	ABNF_SIP_HDR_ROUTE               SipHeaderIndexType = 10
	ABNF_SIP_HDR_RECORD_ROUTE        SipHeaderIndexType = 11
	ABNF_SIP_HDR_CONTENT_DISPOSITION SipHeaderIndexType = 12
	ABNF_SIP_HDR_ALLOW               SipHeaderIndexType = 13
	ABNF_SIP_HDR_CONTENT_ENCODING    SipHeaderIndexType = 14
	ABNF_SIP_HDR_DATE                SipHeaderIndexType = 15
	ABNF_SIP_HDR_SUBJECT             SipHeaderIndexType = 16
	ABNF_SIP_HDR_SUPPORTED           SipHeaderIndexType = 17
	ABNF_SIP_HDR_ALLOW_EVENTS        SipHeaderIndexType = 18
	ABNF_SIP_HDR_EVENT               SipHeaderIndexType = 19
	ABNF_SIP_HDR_REFER_TO            SipHeaderIndexType = 20
	ABNF_SIP_HDR_ACCEPT_CONTACT      SipHeaderIndexType = 21
	ABNF_SIP_HDR_REJECT_CONTACT      SipHeaderIndexType = 22
	ABNF_SIP_HDR_REQUEST_DISPOSITION SipHeaderIndexType = 23
	ABNF_SIP_HDR_REFERRED_BY         SipHeaderIndexType = 24
	ABNF_SIP_HDR_SESSION_EXPIRES     SipHeaderIndexType = 25
	ABNF_SIP_HDR_MIME_VERSION        SipHeaderIndexType = 26
	ABNF_SIP_HDR_TOTAL_NUM           SipHeaderIndexType = iota
)

type SipPaseOneHeaderValue func(context *ParseContext, src []byte, pos AbnfPos) (newPos AbnfPos, parsed AbnfPtr, err error)
type SipEncodeOneHeaderValue func(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer)

type SipHeaderInfo struct {
	index        SipHeaderIndexType
	name         []byte
	shortName    []byte
	parseFunc    SipPaseOneHeaderValue
	encodeFunc   SipEncodeOneHeaderValue
	hasShortName bool
	isKeyheader  bool
	allowMulti   bool
	needParse    bool
}

/*
var g_SipHeaderInfos = []*SipHeaderInfo{
	&SipHeaderInfo{name: []byte("unknown"), hasShortName: false, needParse: false},
	&SipHeaderInfo{name: []byte("From"), isKeyheader: true, hasShortName: true, shortName: []byte("f"), needParse: true, parseFunc: ParseSipFrom, encodeFunc: EncodeSipFromValue},
	&SipHeaderInfo{name: []byte("To"), isKeyheader: true, hasShortName: true, shortName: []byte("t"), needParse: true, parseFunc: ParseSipTo, encodeFunc: EncodeSipToValue},
	&SipHeaderInfo{name: []byte("Via"), isKeyheader: true, hasShortName: true, shortName: []byte("v"), allowMulti: true, needParse: true, parseFunc: ParseSipVia, encodeFunc: EncodeSipViaValue},
	&SipHeaderInfo{name: []byte("Call-ID"), isKeyheader: true, hasShortName: true, shortName: []byte("i"), needParse: true, parseFunc: ParseSipCallId, encodeFunc: EncodeSipCallIdValue},
	&SipHeaderInfo{name: []byte("CSeq"), isKeyheader: true, needParse: true, parseFunc: ParseSipCseq, encodeFunc: EncodeSipCseqValue},
	&SipHeaderInfo{name: []byte("Content-Length"), isKeyheader: true, hasShortName: true, shortName: []byte("l"), needParse: true, parseFunc: ParseSipContentLength, encodeFunc: EncodeSipContentLengthValue},
	&SipHeaderInfo{name: []byte("Content-Type"), hasShortName: true, shortName: []byte("c"), needParse: true, parseFunc: ParseSipContentType, encodeFunc: EncodeSipContentTypeValue},
	&SipHeaderInfo{name: []byte("Contact"), hasShortName: true, shortName: []byte("m"), allowMulti: true, needParse: true, parseFunc: ParseSipContact, encodeFunc: EncodeSipContactValue},
	&SipHeaderInfo{name: []byte("Max-Forwards"), needParse: true, parseFunc: ParseSipMaxForwards, encodeFunc: EncodeSipMaxForwardsValue},
	&SipHeaderInfo{name: []byte("Route"), allowMulti: true, needParse: true, parseFunc: ParseSipRoute, encodeFunc: EncodeSipRouteValue},
	&SipHeaderInfo{name: []byte("Record-Route"), allowMulti: true, needParse: true, parseFunc: ParseSipRecordRoute, encodeFunc: EncodeSipRecordRouteValue},
	&SipHeaderInfo{name: []byte("Content-Disposition"), needParse: true, parseFunc: ParseSipContentDisposition, encodeFunc: EncodeSipContentDispositionValue},
	&SipHeaderInfo{name: []byte("Allow"), allowMulti: true},
	&SipHeaderInfo{name: []byte("Content-Encoding"), hasShortName: true, shortName: []byte("e"), allowMulti: true},
	&SipHeaderInfo{name: []byte("Date")},
	&SipHeaderInfo{name: []byte("Subject"), hasShortName: true, shortName: []byte("s")},
	&SipHeaderInfo{name: []byte("Supported"), hasShortName: true, shortName: []byte("k"), allowMulti: true},
	&SipHeaderInfo{name: []byte("Allow-Events"), hasShortName: true, shortName: []byte("u")},
	&SipHeaderInfo{name: []byte("Event"), hasShortName: true, shortName: []byte("o")},
	&SipHeaderInfo{name: []byte("Refer-To"), hasShortName: true, shortName: []byte("r")},
	&SipHeaderInfo{name: []byte("Accept-Contact"), hasShortName: true, shortName: []byte("a"), allowMulti: true},
	&SipHeaderInfo{name: []byte("Reject-Contact"), hasShortName: true, shortName: []byte("j"), allowMulti: true},
	&SipHeaderInfo{name: []byte("Request-Disposition"), hasShortName: true, shortName: []byte("d"), allowMulti: true},
	&SipHeaderInfo{name: []byte("Referred-By"), hasShortName: true, shortName: []byte("b")},
	&SipHeaderInfo{name: []byte("Session-Expires"), hasShortName: true, shortName: []byte("x")},
	&SipHeaderInfo{name: []byte("MIME-Version")},
}

func GetSipHeaderIndex2(name []byte) SipHeaderIndexType {
	len1 := len(name)
	for i := SipHeaderIndexType(1); i < ABNF_SIP_HDR_TOTAL_NUM; i++ {
		info := g_SipHeaderInfos[i]
		if len1 == len(info.name) && EqualNoCase(name, info.name) {
			//if EqualNoCase(name, info.name) {
			return i
		}
		if info.hasShortName && len1 == len(info.shortName) && EqualNoCase(name, info.shortName) {
			return i
		}
	}
	return ABNF_SIP_HDR_UNKNOWN
}

func GetSipHeaderInfo(name []byte) (info *SipHeaderInfo, ok bool) {
	index := GetSipHeaderIndex(name)

	if index == ABNF_SIP_HDR_UNKNOWN {
		return nil, false
	}
	return g_SipHeaderInfos[index], true
}
*/

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

/*
func (this AbnfPtr) GetSipUriParam(context *ParseContext) *SipUriParam {
	return (*SipUriParam)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipUriHeader(context *ParseContext) *SipUriHeader {
	return (*SipUriHeader)(unsafe.Pointer(&context.allocator.mem[this]))
}
*/

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



func (this AbnfPtr) GetSipUriParams(context *ParseContext) *SipUriParams {
	return (*SipUriParams)(unsafe.Pointer(&context.allocator.mem[this]))
}



func (this AbnfPtr) GetSipUriHeaders(context *ParseContext) *SipUriHeaders {
	return (*SipUriHeaders)(unsafe.Pointer(&context.allocator.mem[this]))
}



func (this AbnfPtr) GetTelUriContext(context *ParseContext) *TelUriContext {
	return (*TelUriContext)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetTelUriParam(context *ParseContext) *TelUriParam {
	return (*TelUriParam)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetTelUriParams(context *ParseContext) *TelUriParams {
	return (*TelUriParams)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetTelUri(context *ParseContext) *TelUri {
	return (*TelUri)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipAddrSpec(context *ParseContext) *SipAddrSpec {
	return (*SipAddrSpec)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipDisplayName(context *ParseContext) *SipDisplayName {
	return (*SipDisplayName)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipQuotedString(context *ParseContext) *SipQuotedString {
	return (*SipQuotedString)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipNameAddr(context *ParseContext) *SipNameAddr {
	return (*SipNameAddr)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipAddr(context *ParseContext) *SipAddr {
	return (*SipAddr)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipGenericParam(context *ParseContext) *SipGenericParam {
	return (*SipGenericParam)(unsafe.Pointer(&context.allocator.mem[this]))
}

func (this AbnfPtr) GetSipGenericParams(context *ParseContext) *SipGenericParams {
	return (*SipGenericParams)(unsafe.Pointer(&context.allocator.mem[this]))
}




func (this AbnfPtr) GetSipHeaderContentDisposition(context *ParseContext) *SipHeaderContentDisposition {
	return (*SipHeaderContentDisposition)(unsafe.Pointer(&context.allocator.mem[this]))
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
