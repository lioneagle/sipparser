package sipparser

type SipPaseOneHeaderValue func(context *ParseContext) (parsed AbnfPtr, ok bool)
type SipEncodeOneHeaderValue func(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer)
type SipAppendOneHeaderValue func(context *ParseContext, parsed AbnfPtr, header AbnfPtr)
type SipGetNextHeaderValue func(context *ParseContext, parsed AbnfPtr) AbnfPtr

type SipHeaderIndexType uint16

type SipHeaderInfo struct {
	Index        SipHeaderIndexType
	Name         []byte
	ShortName    []byte
	ParseFunc    SipPaseOneHeaderValue
	EncodeFunc   SipEncodeOneHeaderValue
	AppendFunc   SipAppendOneHeaderValue
	GetNextFunc  SipGetNextHeaderValue
	HasShortName bool
	IsKeyheader  bool
	AllowMulti   bool
	NeedParse    bool
}

func (this *SipHeaderInfo) Clone() (ret *SipHeaderInfo) {
	ret = &SipHeaderInfo{}
	*ret = *this
	if this.Name != nil {
		ret.Name = make([]byte, len(this.Name))
		copy(ret.Name, this.Name)
	}
	if this.ShortName != nil {
		ret.ShortName = make([]byte, len(this.ShortName))
		copy(ret.ShortName, this.ShortName)
	}
	return ret
}

type SipHeaderInfos [SIP_HDR_MAX_NUM]*SipHeaderInfo

func (this *SipHeaderInfos) Clone() (ret SipHeaderInfos) {
	for i, v := range this {
		if v != nil {
			ret[i] = v.Clone()
		}
	}
	return ret
}

var g_SipHeaderInfos = SipHeaderInfos{
	SIP_HDR_UNKNOWN:             &SipHeaderInfo{Name: []byte("unknown"), HasShortName: false, NeedParse: false},
	SIP_HDR_FROM:                &SipHeaderInfo{Name: []byte("From"), IsKeyheader: true, HasShortName: true, ShortName: []byte("f"), NeedParse: true, ParseFunc: ParseSipFrom, EncodeFunc: EncodeSipFromValue},
	SIP_HDR_TO:                  &SipHeaderInfo{Name: []byte("To"), IsKeyheader: true, HasShortName: true, ShortName: []byte("t"), NeedParse: true, ParseFunc: ParseSipTo, EncodeFunc: EncodeSipToValue},
	SIP_HDR_VIA:                 &SipHeaderInfo{Name: []byte("Via"), IsKeyheader: true, HasShortName: true, ShortName: []byte("v"), AllowMulti: true, NeedParse: true, ParseFunc: ParseSipVia, EncodeFunc: EncodeSipViaValue, AppendFunc: AppendSipViaValue, GetNextFunc: GetNextViaValue},
	SIP_HDR_CALL_ID:             &SipHeaderInfo{Name: []byte("Call-ID"), IsKeyheader: true, HasShortName: true, ShortName: []byte("i"), NeedParse: true, ParseFunc: ParseSipCallID, EncodeFunc: EncodeSipCallIDValue},
	SIP_HDR_CSEQ:                &SipHeaderInfo{Name: []byte("CSeq"), IsKeyheader: true, NeedParse: true, ParseFunc: ParseSipCSeq, EncodeFunc: EncodeSipCSeqValue},
	SIP_HDR_CONTENT_LENGTH:      &SipHeaderInfo{Name: []byte("Content-Length"), IsKeyheader: true, HasShortName: true, ShortName: []byte("l"), NeedParse: true, ParseFunc: ParseSipContentLength, EncodeFunc: EncodeSipContentLengthValue},
	SIP_HDR_CONTENT_TYPE:        &SipHeaderInfo{Name: []byte("Content-Type"), HasShortName: true, ShortName: []byte("c"), NeedParse: true, ParseFunc: ParseSipContentType, EncodeFunc: EncodeSipContentTypeValue},
	SIP_HDR_CONTACT:             &SipHeaderInfo{Name: []byte("Contact"), HasShortName: true, ShortName: []byte("m"), AllowMulti: true, NeedParse: true, ParseFunc: ParseSipContact, EncodeFunc: EncodeSipContactValue, AppendFunc: AppendSipContactValue, GetNextFunc: GetNextContactValue},
	SIP_HDR_MAX_FORWARDS:        &SipHeaderInfo{Name: []byte("Max-Forwards"), NeedParse: true, ParseFunc: ParseSipMaxForwards, EncodeFunc: EncodeSipMaxForwardsValue},
	SIP_HDR_ROUTE:               &SipHeaderInfo{Name: []byte("Route"), AllowMulti: true, NeedParse: true, ParseFunc: ParseSipRoute, EncodeFunc: EncodeSipRouteValue, AppendFunc: AppendSipRouteValue, GetNextFunc: GetNextRouteValue},
	SIP_HDR_RECORD_ROUTE:        &SipHeaderInfo{Name: []byte("Record-Route"), AllowMulti: true, NeedParse: true, ParseFunc: ParseSipRecordRoute, EncodeFunc: EncodeSipRecordRouteValue, AppendFunc: AppendSipRecordRouteValue, GetNextFunc: GetNextRecordRouteValue},
	SIP_HDR_CONTENT_DISPOSITION: &SipHeaderInfo{Name: []byte("Content-Disposition"), NeedParse: true, ParseFunc: ParseSipContentDisposition, EncodeFunc: EncodeSipContentDispositionValue},
	SIP_HDR_ALLOW:               &SipHeaderInfo{Name: []byte("Allow"), AllowMulti: true},
	SIP_HDR_CONTENT_ENCODING:    &SipHeaderInfo{Name: []byte("Content-Encoding"), HasShortName: true, ShortName: []byte("e"), AllowMulti: true},
	SIP_HDR_DATE:                &SipHeaderInfo{Name: []byte("Date")},
	SIP_HDR_SUBJECT:             &SipHeaderInfo{Name: []byte("Subject"), HasShortName: true, ShortName: []byte("s")},
	SIP_HDR_SUPPORTED:           &SipHeaderInfo{Name: []byte("Supported"), HasShortName: true, ShortName: []byte("k"), AllowMulti: true},
	SIP_HDR_ALLOW_EVENTS:        &SipHeaderInfo{Name: []byte("Allow-Events"), HasShortName: true, ShortName: []byte("u")},
	SIP_HDR_EVENT:               &SipHeaderInfo{Name: []byte("Event"), HasShortName: true, ShortName: []byte("o")},
	SIP_HDR_REFER_TO:            &SipHeaderInfo{Name: []byte("Refer-To"), HasShortName: true, ShortName: []byte("r")},
	SIP_HDR_ACCEPT_CONTACT:      &SipHeaderInfo{Name: []byte("Accept-Contact"), HasShortName: true, ShortName: []byte("a"), AllowMulti: true},
	SIP_HDR_REJECT_CONTACT:      &SipHeaderInfo{Name: []byte("Reject-Contact"), HasShortName: true, ShortName: []byte("j"), AllowMulti: true},
	SIP_HDR_REQUEST_DISPOSITION: &SipHeaderInfo{Name: []byte("Request-Disposition"), HasShortName: true, ShortName: []byte("d"), AllowMulti: true},
	SIP_HDR_REFERRED_BY:         &SipHeaderInfo{Name: []byte("Referred-By"), HasShortName: true, ShortName: []byte("b")},
	SIP_HDR_SESSION_EXPIRES:     &SipHeaderInfo{Name: []byte("Session-Expires"), HasShortName: true, ShortName: []byte("x")},
	SIP_HDR_MIME_VERSION:        &SipHeaderInfo{Name: []byte("MIME-Version")},
	SIP_HDR_EXPIRES:             &SipHeaderInfo{Name: []byte("Expires"), NeedParse: true, ParseFunc: ParseSipExpires, EncodeFunc: EncodeSipExpiresValue},
	SIP_HDR_USER_AGENT:          &SipHeaderInfo{Name: []byte("User-Agent")},
	SIP_HDR_PATH:                &SipHeaderInfo{Name: []byte("Path"), AllowMulti: true, NeedParse: true, ParseFunc: ParseSipPath, EncodeFunc: EncodeSipPathValue, AppendFunc: AppendSipPathValue, GetNextFunc: GetNextPathValue},
	SIP_HDR_SERVICE_ROUTE:       &SipHeaderInfo{Name: []byte("Service-Route"), AllowMulti: true, NeedParse: true, ParseFunc: ParseSipServiceRoute, EncodeFunc: EncodeSipServiceRouteValue, AppendFunc: AppendSipServiceRouteValue, GetNextFunc: GetNextServiceRouteValue},
	SIP_HDR_RSEQ:                &SipHeaderInfo{Name: []byte("RSeq"), NeedParse: true, ParseFunc: ParseSipRSeq, EncodeFunc: EncodeSipRSeqValue},
	SIP_HDR_RACK:                &SipHeaderInfo{Name: []byte("RAck"), NeedParse: true, ParseFunc: ParseSipRAck, EncodeFunc: EncodeSipRAckValue},
	SIP_HDR_P_ASSERTED_IDENTITY: &SipHeaderInfo{Name: []byte("P-Asserted-Identity"), AllowMulti: true, NeedParse: true, ParseFunc: ParseSipPAssertedIdentity, EncodeFunc: EncodeSipPAssertedIdentityValue, AppendFunc: AppendSipPAssertedIdentityValue, GetNextFunc: GetNextPAssertedIdentityValue},
}
