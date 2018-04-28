package sipparser

type SipPaseOneHeaderValue func(context *ParseContext) (parsed AbnfPtr, ok bool)
type SipEncodeOneHeaderValue func(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer)

type SipHeaderIndexType uint16

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

func (this *SipHeaderInfo) AllowMulti() bool   { return this.allowMulti }
func (this *SipHeaderInfo) HasShortName() bool { return this.hasShortName }
func (this *SipHeaderInfo) ShortName() []byte  { return this.shortName }

var g_SipHeaderInfos = []*SipHeaderInfo{
	ABNF_SIP_HDR_UNKNOWN:             &SipHeaderInfo{name: []byte("unknown"), hasShortName: false, needParse: false},
	ABNF_SIP_HDR_FROM:                &SipHeaderInfo{name: []byte("From"), isKeyheader: true, hasShortName: true, shortName: []byte("f"), needParse: true, parseFunc: ParseSipFrom, encodeFunc: EncodeSipFromValue},
	ABNF_SIP_HDR_TO:                  &SipHeaderInfo{name: []byte("To"), isKeyheader: true, hasShortName: true, shortName: []byte("t"), needParse: true, parseFunc: ParseSipTo, encodeFunc: EncodeSipToValue},
	ABNF_SIP_HDR_VIA:                 &SipHeaderInfo{name: []byte("Via"), isKeyheader: true, hasShortName: true, shortName: []byte("v"), allowMulti: true, needParse: true, parseFunc: ParseSipVia, encodeFunc: EncodeSipViaValue},
	ABNF_SIP_HDR_CALL_ID:             &SipHeaderInfo{name: []byte("Call-ID"), isKeyheader: true, hasShortName: true, shortName: []byte("i"), needParse: true, parseFunc: ParseSipCallId, encodeFunc: EncodeSipCallIdValue},
	ABNF_SIP_HDR_CSEQ:                &SipHeaderInfo{name: []byte("CSeq"), isKeyheader: true, needParse: true, parseFunc: ParseSipCseq, encodeFunc: EncodeSipCseqValue},
	ABNF_SIP_HDR_CONTENT_LENGTH:      &SipHeaderInfo{name: []byte("Content-Length"), isKeyheader: true, hasShortName: true, shortName: []byte("l"), needParse: true, parseFunc: ParseSipContentLength, encodeFunc: EncodeSipContentLengthValue},
	ABNF_SIP_HDR_CONTENT_TYPE:        &SipHeaderInfo{name: []byte("Content-Type"), hasShortName: true, shortName: []byte("c"), needParse: true, parseFunc: ParseSipContentType, encodeFunc: EncodeSipContentTypeValue},
	ABNF_SIP_HDR_CONTACT:             &SipHeaderInfo{name: []byte("Contact"), hasShortName: true, shortName: []byte("m"), allowMulti: true, needParse: true, parseFunc: ParseSipContact, encodeFunc: EncodeSipContactValue},
	ABNF_SIP_HDR_MAX_FORWARDS:        &SipHeaderInfo{name: []byte("Max-Forwards"), needParse: true, parseFunc: ParseSipMaxForwards, encodeFunc: EncodeSipMaxForwardsValue},
	ABNF_SIP_HDR_ROUTE:               &SipHeaderInfo{name: []byte("Route"), allowMulti: true, needParse: true, parseFunc: ParseSipRoute, encodeFunc: EncodeSipRouteValue},
	ABNF_SIP_HDR_RECORD_ROUTE:        &SipHeaderInfo{name: []byte("Record-Route"), allowMulti: true, needParse: true, parseFunc: ParseSipRecordRoute, encodeFunc: EncodeSipRecordRouteValue},
	ABNF_SIP_HDR_CONTENT_DISPOSITION: &SipHeaderInfo{name: []byte("Content-Disposition"), needParse: true, parseFunc: ParseSipContentDisposition, encodeFunc: EncodeSipContentDispositionValue},
	ABNF_SIP_HDR_ALLOW:               &SipHeaderInfo{name: []byte("Allow"), allowMulti: true},
	ABNF_SIP_HDR_CONTENT_ENCODING:    &SipHeaderInfo{name: []byte("Content-Encoding"), hasShortName: true, shortName: []byte("e"), allowMulti: true},
	ABNF_SIP_HDR_DATE:                &SipHeaderInfo{name: []byte("Date")},
	ABNF_SIP_HDR_SUBJECT:             &SipHeaderInfo{name: []byte("Subject"), hasShortName: true, shortName: []byte("s")},
	ABNF_SIP_HDR_SUPPORTED:           &SipHeaderInfo{name: []byte("Supported"), hasShortName: true, shortName: []byte("k"), allowMulti: true},
	ABNF_SIP_HDR_ALLOW_EVENTS:        &SipHeaderInfo{name: []byte("Allow-Events"), hasShortName: true, shortName: []byte("u")},
	ABNF_SIP_HDR_EVENT:               &SipHeaderInfo{name: []byte("Event"), hasShortName: true, shortName: []byte("o")},
	ABNF_SIP_HDR_REFER_TO:            &SipHeaderInfo{name: []byte("Refer-To"), hasShortName: true, shortName: []byte("r")},
	ABNF_SIP_HDR_ACCEPT_CONTACT:      &SipHeaderInfo{name: []byte("Accept-Contact"), hasShortName: true, shortName: []byte("a"), allowMulti: true},
	ABNF_SIP_HDR_REJECT_CONTACT:      &SipHeaderInfo{name: []byte("Reject-Contact"), hasShortName: true, shortName: []byte("j"), allowMulti: true},
	ABNF_SIP_HDR_REQUEST_DISPOSITION: &SipHeaderInfo{name: []byte("Request-Disposition"), hasShortName: true, shortName: []byte("d"), allowMulti: true},
	ABNF_SIP_HDR_REFERRED_BY:         &SipHeaderInfo{name: []byte("Referred-By"), hasShortName: true, shortName: []byte("b")},
	ABNF_SIP_HDR_SESSION_EXPIRES:     &SipHeaderInfo{name: []byte("Session-Expires"), hasShortName: true, shortName: []byte("x")},
	ABNF_SIP_HDR_MIME_VERSION:        &SipHeaderInfo{name: []byte("MIME-Version")},
}
