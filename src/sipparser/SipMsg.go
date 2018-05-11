package sipparser

import (
	"bytes"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/lioneagle/goutil/src/chars"
)

const (
	SIP_MSG_COMMON_HDR_START_LINE     = 0
	SIP_MSG_COMMON_HDR_VIA            = 1
	SIP_MSG_COMMON_HDR_ROUTE          = 2
	SIP_MSG_COMMON_HDR_CONTACT        = 3
	SIP_MSG_COMMON_HDR_FROM           = 4
	SIP_MSG_COMMON_HDR_TO             = 5
	SIP_MSG_COMMON_HDR_CALL_ID        = 6
	SIP_MSG_COMMON_HDR_CONTENT_LENGTH = 7
	SIP_MSG_COMMON_HDR_CSEQ           = 8
	SIP_MSG_COMMON_HDR_RECORD_ROUTE   = 9
	SIP_MSG_COMMON_HDR_CONTENT_TYPE   = 10
	SIP_MSG_COMMON_HDR_MAX_FORWARDS   = 11
	//SIP_MSG_COMMON_HDR_SUPPORTED           = 12
	//SIP_MSG_COMMON_HDR_ALLOW               = 13
	//SIP_MSG_COMMON_HDR_EVENT               = 14
	SIP_MSG_COMMON_HDR_CONTENT_DISPOSITION = 12
	SIP_MSG_COMMON_HDR_EXPIRES             = 13
	SIP_MSG_COMMON_HDR_PATH                = 14
	SIP_MSG_COMMON_HDR_SERVICE_ROUTE       = 15
	//SIP_MSG_COMMON_HDR_SESSION_EXPIRES     = 17
	//SIP_MSG_COMMON_HDR_MIME_VERSION        = 18
	//SIP_MSG_COMMON_HDR_REFER_TO            = 19
	//SIP_MSG_COMMON_HDR_REFERRED_BY         = 20
	SIP_MSG_COMMON_HDR_MAX_NUM = iota
)

var g_SipMsgHeaderIndexToCommonIndex = [SIP_HDR_MAX_NUM]int{
	SIP_HDR_VIA:            SIP_MSG_COMMON_HDR_VIA,
	SIP_HDR_ROUTE:          SIP_MSG_COMMON_HDR_ROUTE,
	SIP_HDR_CONTACT:        SIP_MSG_COMMON_HDR_CONTACT,
	SIP_HDR_FROM:           SIP_MSG_COMMON_HDR_FROM,
	SIP_HDR_TO:             SIP_MSG_COMMON_HDR_TO,
	SIP_HDR_CALL_ID:        SIP_MSG_COMMON_HDR_CALL_ID,
	SIP_HDR_CONTENT_LENGTH: SIP_MSG_COMMON_HDR_CONTENT_LENGTH,
	SIP_HDR_CSEQ:           SIP_MSG_COMMON_HDR_CSEQ,
	SIP_HDR_RECORD_ROUTE:   SIP_MSG_COMMON_HDR_RECORD_ROUTE,
	SIP_HDR_CONTENT_TYPE:   SIP_MSG_COMMON_HDR_CONTENT_TYPE,
	SIP_HDR_MAX_FORWARDS:   SIP_MSG_COMMON_HDR_MAX_FORWARDS,
	//SIP_HDR_SUPPORTED:           12,
	//SIP_HDR_ALLOW:               13,
	//SIP_HDR_EVENT:               14,
	SIP_HDR_CONTENT_DISPOSITION: SIP_MSG_COMMON_HDR_CONTENT_DISPOSITION,
	SIP_HDR_EXPIRES:             SIP_MSG_COMMON_HDR_EXPIRES,
	SIP_HDR_PATH:                SIP_MSG_COMMON_HDR_PATH,
	SIP_HDR_SERVICE_ROUTE:       SIP_MSG_COMMON_HDR_SERVICE_ROUTE,
}

var g_SipMsgCommonIndexToHeaderIndex = [SIP_MSG_COMMON_HDR_MAX_NUM]SipHeaderIndexType{
	SIP_MSG_COMMON_HDR_VIA:            SIP_HDR_VIA,
	SIP_MSG_COMMON_HDR_ROUTE:          SIP_HDR_ROUTE,
	SIP_MSG_COMMON_HDR_CONTACT:        SIP_HDR_CONTACT,
	SIP_MSG_COMMON_HDR_FROM:           SIP_HDR_FROM,
	SIP_MSG_COMMON_HDR_TO:             SIP_HDR_TO,
	SIP_MSG_COMMON_HDR_CALL_ID:        SIP_HDR_CALL_ID,
	SIP_MSG_COMMON_HDR_CONTENT_LENGTH: SIP_HDR_CONTENT_LENGTH,
	SIP_MSG_COMMON_HDR_CSEQ:           SIP_HDR_CSEQ,
	SIP_MSG_COMMON_HDR_RECORD_ROUTE:   SIP_HDR_RECORD_ROUTE,
	SIP_MSG_COMMON_HDR_CONTENT_TYPE:   SIP_HDR_CONTENT_TYPE,
	SIP_MSG_COMMON_HDR_MAX_FORWARDS:   SIP_HDR_MAX_FORWARDS,
	//SIP_MSG_COMMON_HDR_SUPPORTED:           SIP_HDR_SUPPORTED,
	//SIP_MSG_COMMON_HDR_ALLOW:               SIP_HDR_ALLOW,
	//SIP_MSG_COMMON_HDR_EVENT:               SIP_HDR_EVENT,
	SIP_MSG_COMMON_HDR_CONTENT_DISPOSITION: SIP_HDR_CONTENT_DISPOSITION,
	SIP_MSG_COMMON_HDR_EXPIRES:             SIP_HDR_EXPIRES,
	SIP_MSG_COMMON_HDR_PATH:                SIP_HDR_PATH,
	SIP_MSG_COMMON_HDR_SERVICE_ROUTE:       SIP_HDR_SERVICE_ROUTE,
}

const (
	SIP_MSG_COMMON_BODY_SESSION       = 0
	SIP_MSG_COMMON_BODY_EARLY_SESSION = 1
	SIP_MSG_COMMON_BODY_REG_INFO      = 2
	SIP_MSG_COMMON_BODY_MAX_NUM       = iota
)

type SipMsg struct {
	startLine     SipStartLine
	commonHeaders [SIP_MSG_COMMON_HDR_MAX_NUM]AbnfPtr
	commonBodies  [SIP_MSG_COMMON_BODY_MAX_NUM]AbnfPtr
	headers       AbnfPtr // uncommon headers
	bodies        AbnfPtr // uncommon bodies
}

func SizeofSipMsg() int {
	return int(unsafe.Sizeof(SipMsg{}))
}

func NewSipMsg(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipMsg()))
}

func (this *SipMsg) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipMsg) Init() {
	ZeroMem(this.memAddr(), SizeofSipMsg())
}

func (this *SipMsg) NeedParse(context *ParseContext, headerIndex SipHeaderIndexType) bool {
	if context.ParseSipHeaderAsRaw {
		return headerIndex == SIP_HDR_CONTENT_TYPE || headerIndex == SIP_HDR_CONTENT_LENGTH ||
			headerIndex == SIP_HDR_CONTENT_DISPOSITION
	}
	return g_SipMsgHeaderIndexToCommonIndex[headerIndex] != 0
}

func (this *SipMsg) SetHeaders(context *ParseContext, headerIndex SipHeaderIndexType, header AbnfPtr) bool {
	commomHeaderIndex := g_SipMsgHeaderIndexToCommonIndex[headerIndex]
	if this.NeedParse(context, headerIndex) {
		if g_SipHeaderInfos[headerIndex].allowMulti {
			if this.commonHeaders[commomHeaderIndex] == ABNF_PTR_NIL {
				this.commonHeaders[commomHeaderIndex] = header
			} else {
				g_SipHeaderInfos[headerIndex].appendFunc(context, this.commonHeaders[commomHeaderIndex], header)
			}
		} else {
			this.commonHeaders[commomHeaderIndex] = header
		}
	} else {
		if this.headers == ABNF_PTR_NIL {
			if headerIndex != SIP_HDR_UNKNOWN {
			}
			this.headers = header
		} else {
			if !appendUnknownSipHeader(context, this.headers, header) {
				context.AddError(context.parsePos, "append uncommon header failed for sip msg")
				return false
			}
		}
	}

	return true
}

func (this *SipMsg) EncodeHeaders(context *ParseContext, buf *AbnfByteBuffer) {
	len1 := len(this.commonHeaders)
	for i := 1; i < len1; i++ {
		v := this.commonHeaders[i]
		if v == ABNF_PTR_NIL {
			continue
		}
		info := g_SipHeaderInfos[g_SipMsgCommonIndexToHeaderIndex[i]]
		buf.Write(info.name)
		buf.WriteString(": ")
		info.encodeFunc(v, context, buf)
		if info.allowMulti {
			header := info.getNextFunc(context, v)
			for header != ABNF_PTR_NIL {
				buf.WriteString(", ")
				info.encodeFunc(header, context, buf)
				header = info.getNextFunc(context, header)
			}
		}
		buf.WriteString("\r\n")
	}

	if this.headers != ABNF_PTR_NIL {
		EncodeRawHeaders(context, this.headers, buf)
	}
}

func (this *SipMsg) String(context *ParseContext) string {
	var buf AbnfByteBuffer
	this.Encode(context, &buf)
	return buf.String()
}

func (this *SipMsg) Encode(context *ParseContext, buf *AbnfByteBuffer) (ok bool) {

	hasMultiBody := this.HasMultiBody(context)

	// create Content-Length header if not exist
	if this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_LENGTH] == ABNF_PTR_NIL {
		addr := NewSipHeaderContentLength(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for creating Content-Length for sip msg encode")
			return false
		}
		this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_LENGTH] = addr
	}

	this.startLine.Encode(context, buf)

	var boundary []byte

	if hasMultiBody {
		// remove Content-* headers from sip message except Content-Length and Content-Type
		//this.RemoveContentHeaders(context)
		boundary = this.FindOrCreateBoundary(context)

		if boundary == nil {
			context.AddError(context.parsePos, "find or create boundary failed for sip msg encode")
			return false
		}
	}

	this.EncodeHeaders(context, buf)

	if hasMultiBody {
		header, _ := this.GetHeaderByIndex(context, SIP_HDR_MIME_VERSION)
		if header == ABNF_PTR_NIL {
			buf.WriteString("MIME-Version: 1.0\r\n")
		}
	}

	buf.WriteString("\r\n")

	if this.bodies == ABNF_PTR_NIL {
		return true
	}

	bodyStart := len(buf.Bytes())

	if !hasMultiBody {
		this.EncodeSingleMsgBody(context, buf)
	} else {
		this.EncodeMultiMsgBody(context, buf, boundary)
	}

	bodySize := StringToByteSlice(strconv.FormatUint(uint64(len(buf.Bytes())-bodyStart), 10))

	// modify Content-Length size
	contentLength := this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_LENGTH].GetSipHeaderContentLength(context)
	encodeEnd := int(contentLength.encodeEnd)
	copy(buf.Bytes()[encodeEnd-len(bodySize):encodeEnd], bodySize)

	return true
}

func (this *SipMsg) FindOrCreateBoundary(context *ParseContext) (boundary []byte) {
	var contentType *SipHeaderContentType

	if this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_TYPE] == ABNF_PTR_NIL {
		addr := NewSipHeaderContentType(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for creating Content-Type")
			return nil
		}
		this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_TYPE] = addr
		contentType = this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_TYPE].GetSipHeaderContentType(context)
		contentType.mainType = AllocCString(context, StringToByteSlice("multipart"))
		if contentType.mainType == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for main-type when creating Content-Type")
			return nil
		}
		contentType.subType = AllocCString(context, StringToByteSlice("mixed"))
		if contentType.subType == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for sub-type when creating Content-Type")
			return nil
		}
	} else {
		contentType = this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_TYPE].GetSipHeaderContentType(context)
	}

	addr := contentType.GetKnownParam(context, SIP_CONTENT_TYPE_KNOWN_PARAM_BOUNDARY)
	if addr == ABNF_PTR_NIL {
		addr = contentType.SetBoundary(context, StringToByteSlice(ABNF_SIP_DEFAULT_BOUNDARY))
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "set boundary failed when creating Content-Type")
			return nil
		}
	}

	return addr.GetSipGenericParam(context).value.GetCStringAsByteSlice(context)
}

func (this *SipMsg) GetHeaderByIndex(context *ParseContext, headerIndex SipHeaderIndexType) (header AbnfPtr, isCommonHeader bool) {
	for i, v := range this.commonHeaders {
		if (v != ABNF_PTR_NIL) && (g_SipMsgCommonIndexToHeaderIndex[i] == headerIndex) {
			return v, true
		}
	}

	addr := this.headers
	for addr != ABNF_PTR_NIL {
		header := addr.GetSipHeader(context)
		if header.id == headerIndex {
			return addr, false
		}
		addr = header.next
	}
	return ABNF_PTR_NIL, false
}

// remove Content-* headers from sip msg except Content-Length and Content-Type
func (this *SipMsg) RemoveContentHeaders(context *ParseContext) (ok bool) {
	// Content-Length, Content-Type and Content-Disposition are common headers
	// now there is no other Content-* headers for sip msg common headers
	var prevHeader *SipHeader = nil

	this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_DISPOSITION] = ABNF_PTR_NIL

	addr := this.headers
	for addr != ABNF_PTR_NIL {
		header := addr.GetSipHeader(context)

		if header.id == SIP_HDR_CONTENT_ENCODING ||
			header.id == SIP_HDR_CONTENT_TRANSFER_ENCODING ||
			header.id == SIP_HDR_CONTENT_ID ||
			header.id == SIP_HDR_CONTENT_DESCRIPTION ||
			header.id == SIP_HDR_CONTENT_LANGUAGE ||
			(header.id == SIP_HDR_UNKNOWN && header.hname.HasPrefixNoCase(context, "Content-")) {
			if prevHeader == nil {
				this.headers = header.next
			} else {
				prevHeader.next = header.next
			}
		} else {
			if prevHeader == nil {
				prevHeader = header
			}
		}
		addr = header.next
	}

	return true
}

func (this *SipMsg) EncodeSingleMsgBody(context *ParseContext, buf *AbnfByteBuffer) {
	for _, v := range this.commonBodies {
		if v != ABNF_PTR_NIL {
			v.GetSipMsgBody(context).body.WriteCString(context, buf)
			return
		}
	}

	if this.bodies != ABNF_PTR_NIL {
		this.bodies.GetSipMsgBody(context).body.WriteCString(context, buf)
	}
}

func (this *SipMsg) EncodeMultiMsgBody(context *ParseContext, buf *AbnfByteBuffer, boundary []byte) {
	for _, v := range this.commonBodies {
		if v != ABNF_PTR_NIL {
			// dash-boundary
			buf.WriteString("--")
			buf.Write(boundary)
			buf.WriteString("\r\n")

			v.GetSipMsgBody(context).Encode(context, buf)
			buf.WriteString("\r\n")
		}
	}

	addr := this.bodies
	for addr != ABNF_PTR_NIL {
		// dash-boundary
		buf.WriteString("--")
		buf.Write(boundary)
		buf.WriteString("\r\n")

		addr.GetSipMsgBody(context).Encode(context, buf)
		buf.WriteString("\r\n")

		addr = addr.GetSipMsgBody(context).next
	}

	buf.WriteString("--")
	buf.Write(boundary)
	buf.WriteString("--")
}

func (this *SipMsg) HasMultiBody(context *ParseContext) bool {
	count := 0
	for _, v := range this.commonBodies {
		if v != ABNF_PTR_NIL {
			count++
		}
		if count > 1 {
			return true
		}
	}

	addr := this.bodies
	for addr != ABNF_PTR_NIL {
		count++
		if count > 1 {
			return true
		}
		addr = addr.GetSipMsgBody(context).next
	}
	return false
}

func (this *SipMsg) Parse(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))

	this.Init()
	ok = this.startLine.Parse(context)
	if !ok {
		context.AddError(context.parsePos, "parse start-line failed for sip msg")
		return false
	}

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "no headers for sip msg failed")
		return false
	}

	ok = ParseHeaders(context, this)
	if !ok {
		context.AddError(context.parsePos, "parse headers failed for sip msg")
		return false
	}

	ok = this.ParseMsgBody(context)
	if !ok {
		context.AddError(context.parsePos, "parse msg body failed for sip msg")
		return false
	}

	return true
}

func (this *SipMsg) ParseMsgBody(context *ParseContext) (ok bool) {
	ptr := this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_TYPE]
	if ptr == ABNF_PTR_NIL {
		// no Content-Type means no msg-body
		return true
	}

	contentType := ptr.GetSipHeaderContentType(context)
	if contentType.mainType.CStringEqualNoCase(context, StringToByteSlice("multipart")) {
		// mime bodies
		boundaryParam := contentType.GetKnownParam(context, SIP_CONTENT_TYPE_KNOWN_PARAM_BOUNDARY)
		if boundaryParam == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no boundary for multipart body")
			return false
		}

		boundary := boundaryParam.GetSipGenericParam(context)

		return this.ParseMultiBody(context, boundary.value)
	}

	return this.ParseSingleBody(context)
}

func (this *SipMsg) ParseSingleBody(context *ParseContext) (ok bool) {
	var bodySize int

	left := len(context.parseSrc) - int(context.parsePos)

	ptr := this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_LENGTH]
	if ptr != ABNF_PTR_NIL {
		bodySize = int(ptr.GetSipHeaderContentLength(context).size)
		if bodySize > left {
			bodySize = left
		}
	}

	if bodySize == 0 {
		return true
	}

	addr := NewSipMsgBody(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for sip single msg-body")
		return false
	}

	bodyAddr := AllocCString(context, context.parseSrc[context.parsePos:context.parsePos+AbnfPos(bodySize)])
	if bodyAddr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for sip single msg-body value")
		return false
	}

	body := addr.GetSipMsgBody(context)
	body.body = bodyAddr
	this.bodies = addr

	return true
}

/*
func (this *SipMsg) CopyContentToSipMsgBody(context *ParseContext, body *SipMsgBody) (ok bool) {
	// Content-Length, Content-Type and Content-Disposition are common headers
	// now there is no other Content-* headers for sip msg common headers
	var lastBodyHeader *SipHeader = nil

	body.commonHeaders[SIP_BODY_COMMON_HDR_CONTENT_LENGTH] = this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_LENGTH]
	body.commonHeaders[SIP_BODY_COMMON_HDR_CONTENT_TYPE] = this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_TYPE]
	body.commonHeaders[SIP_BODY_COMMON_HDR_CONTENT_DISPOSITION] = this.commonHeaders[SIP_MSG_COMMON_HDR_CONTENT_DISPOSITION]

	for addr := body.headers; addr != ABNF_PTR_NIL; {
		lastBodyHeader = addr.GetSipHeader(context)
		if lastBodyHeader.next == ABNF_PTR_NIL {
			break
		}
		addr = lastBodyHeader.next
	}

	for addr := this.headers; addr != ABNF_PTR_NIL; {
		header := addr.GetSipHeader(context)

		if header.id == SIP_HDR_CONTENT_ENCODING ||
			header.id == SIP_HDR_CONTENT_TRANSFER_ENCODING ||
			header.id == SIP_HDR_CONTENT_ID ||
			header.id == SIP_HDR_CONTENT_DESCRIPTION ||
			header.id == SIP_HDR_CONTENT_LANGUAGE ||
			(header.id == SIP_HDR_UNKNOWN && header.hname.HasPrefixNoCase(context, "Content-")) {
			if lastBodyHeader == nil {
				body.headers = addr
				lastBodyHeader = header
			} else {
				lastBodyHeader.next = addr
				lastBodyHeader = header
			}
		} else {
			if prevHeader == nil {
				prevHeader = header
			}
		}
		addr = header.next
	}

	return true
}
*/

/* RFC2046
 * boundary := 0*69<bchars> bcharsnospace
 *
 * bchars := bcharsnospace / " "
 *
 * bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" /
 *                  "+" / "_" / "," / "-" / "." /
 *                  "/" / ":" / "=" / "?"
 *
 * body-part := <"message" as defined in RFC 822, with all
 *               header fields optional, not starting with the
 *               specified dash-boundary, and with the
 *               delimiter not occurring anywhere in the
 *               body part.  Note that the semantics of a
 *               part differ from the semantics of a message,
 *               as described in the text.>
 *
 * close-delimiter := delimiter "--"
 *
 * dash-boundary := "--" boundary
 *                  ; boundary taken from the value of
 *                  ; boundary parameter of the
 *                  ; Content-Type field.
 *
 * delimiter := CRLF dash-boundary
 *
 * discard-text := *(*text CRLF)
 *                 ; May be ignored or discarded.
 *
 * encapsulation := delimiter transport-padding
 *                  CRLF body-part
 *
 * epilogue := discard-text
 *
 * multipart-body := [preamble CRLF]
 *                   dash-boundary transport-padding CRLF
 *                   body-part *encapsulation
 *                   close-delimiter transport-padding
 *                   [CRLF epilogue]
 *
 * preamble := discard-text
 *
 * transport-padding := *LWSP-char
 *                      ; Composers MUST NOT generate
 *                      ; non-zero length transport
 *                      ; padding, but receivers MUST
 *                      ; be able to handle padding
 *                      ; added by message transports.
 *
 * RFC822
 *
 * message     =  fields *( CRLF *text )       ; Everything after
 *                                             ;  first null line
 *                                             ;  is message body
 *
 * field       =  field-name ":" [ field-body ] CRLF
 * fields      =    dates                      ; Creation time,
 *                  source                     ;  author id & one
 *                  1*destination              ;  address required
 *                  optional-field             ;  others optional
 *
 * optional-field =
 *            /  "Message-ID"        ":"   msg-id
 *            /  "Resent-Message-ID" ":"   msg-id
 *            /  "In-Reply-To"       ":"  *(phrase / msg-id)
 *            /  "References"        ":"  *(phrase / msg-id)
 *            /  "Keywords"          ":"  #phrase
 *            /  "Subject"           ":"  *text
 *            /  "Comments"          ":"  *text
 *            /  "Encrypted"         ":" 1#2word
 *            /  extension-field              ; To be defined
 *            /  user-defined-field           ; May be pre-empted
 *
 * extension-field =
 *            <Any field which is defined in a document
 *             published as a formal extension to this
 *             specification; none will have names beginning
 *             with the string "X-">
 *
 * user-defined-field =
 *            <Any field which has not been defined
 *             in this specification or published as an
 *             extension to this specification; names for
 *             such fields must be unique and may be
 *             pre-empted by published extensions>
 *
 * field-body  =  field-body-contents
 *                [CRLF LWSP-char field-body]
 *
 * field-body-contents =
 *                <the ASCII characters making up the field-body, as
 *                 defined in the following sections, and consisting
 *                 of combinations of atom, quoted-string, and
 *                 specials tokens, or else consisting of texts>
 *
 * field-name      =  1*<any CHAR, excluding CTLs, SPACE, and ":">
 *
 * field-body      =   *text [CRLF LWSP-char field-body]
 *
 * text        =  <any CHAR, including bare    ; => atoms, specials,
 *                 CR & bare LF, but NOT       ;  comments and
 *                 including CRLF>             ;  quoted-strings are
 *                                             ;  NOT recognized.
 * LWSP-char   =  SPACE / HTAB                 ; semantics = SPACE
 */
func (this *SipMsg) ParseMultiBody(context *ParseContext, boundary AbnfPtr) (ok bool) {
	b := boundary.GetCStringAsByteSlice(context)

	dash_boundary := append([]byte{'-', '-'}, b...)
	delimiter := append([]byte{'\r', '\n'}, dash_boundary...)

	src := context.parseSrc
	pos1 := bytes.Index(src[context.parsePos:], dash_boundary)
	if pos1 != 0 {
		context.AddError(context.parsePos, "no first dash-bounday for sip multi msg-body")
		return false
	}

	context.parsePos += AbnfPos(len(dash_boundary))

	var prevBody *SipMsgBody = nil

	len1 := AbnfPos(len(src))

	for context.parsePos < len1 {
		if context.parsePos+1 >= len1 {
			context.AddError(context.parsePos, "reach end without close-delimiter for sip multi msg-body")
			return false
		}

		if src[context.parsePos] == '-' || src[context.parsePos+1] == '-' {
			// reach close-delimiter
			context.parsePos += 2
			return true
		}

		// skip transport-padding CRLF
		_, ok = FindCrlfByRFC3261(context)
		if !ok {
			context.AddError(context.parsePos, "no CRLF after dash-bounday for sip multi msg-body")
			return false
		}

		addr := NewSipMsgBody(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for sip msg body when parsing sip multi msg-body")
			return false
		}

		body := addr.GetSipMsgBody(context)

		if !ParseHeaders(context, body) {
			context.AddError(context.parsePos, "parsed headers failed for sip multi msg-body")
			return false
		}

		begin := int(context.parsePos)
		end := bytes.Index(src[begin:], delimiter)
		if end == -1 {
			context.AddError(context.parsePos, "no delimiter after body for sip multi msg-body")
			return false
		}

		end += begin
		body.body = AllocCString(context, src[begin:end])
		if prevBody == nil {
			this.bodies = addr
		} else {
			prevBody.next = addr
		}

		prevBody = body
		context.parsePos = AbnfPos(end + len(delimiter))

	}

	return false
}

func SipMsgRawScan(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))

	for context.parsePos < len1 {
		if IsCRLF(src, AbnfPos(context.parsePos)) {
			/* reach message-body */
			context.parsePos += 2
			return true
		}

		_, ok = FindCrlfByRFC3261(context)
		if !ok {
			return false
		}

		//fmt.Println("pos =", context.parsePos)
	}
	return true
}

func ByteSliceIndexNoCase(src []byte, pos AbnfPos, find []byte) (newPos AbnfPos, ok bool) {
	len1 := AbnfPos(len(src))
	len2 := AbnfPos(len(find))

	if len2 <= 0 {
		return 0, false
	}

	newPos = pos
	findPos := 0

	c := chars.ToLower(find[findPos])
	findPos++
	len2--

	for {
		for {
			if newPos >= len1 {
				return 0, false
			}
			sc := chars.ToLower(src[newPos])
			newPos++
			if sc == c {
				break
			}
		}
		if (newPos + len2) >= len1 {
			return 0, false
		}

		if chars.EqualNoCase(src[newPos:newPos+len2], find[findPos:]) {
			break
		}
	}

	return newPos - 1, true
}

func FindSipHeader1(context *ParseContext, name []byte, buf *AbnfByteBuffer) (ok bool) {
	src := context.parseSrc
	newPos := context.parsePos
	firstTime := true
	len1 := AbnfPos(len(src))
	len2 := AbnfPos(len(name))
	num := 0
	short_form := false
	header_with_newline := chars.StringToByteSlice(fmt.Sprintf("\n%s", chars.ByteSliceToString(name)))

	for {
		newPos = context.parsePos
		for {
			newPos, ok = ByteSliceIndexNoCase(src, newPos, header_with_newline)
			if !ok {
				break
			}

			if !firstTime {
				newPos += len2 + 1
				for ; newPos < len1 && IsWspChar(src[newPos]); newPos++ {
				}
			} else {
				newPos++
			}
			begin := newPos

			firstTime = false
			for {
				pos := bytes.IndexByte(src[newPos:], '\n')
				if pos == -1 {
					break
				}

				newPos += AbnfPos(pos)
				if newPos+1 >= len1 {
					break
				}
				if !IsWspChar(src[newPos]) {
					break
				}
			}

			if num > 0 {
				buf.WriteString(", ")
			}
			num++
			buf.Write(src[begin : newPos-1])

			newPos++
		}

		if num > 0 {
			break
		}

		if short_form {
			return num > 0
		}

		short_form = true

		if chars.EqualNoCase(name, chars.StringToByteSlice("Call-ID:")) {
			name = chars.StringToByteSlice("i:")
			header_with_newline = chars.StringToByteSlice("\ni:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Contact:")) {
			name = chars.StringToByteSlice("m:")
			header_with_newline = chars.StringToByteSlice("\nm:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Content-Encoding:")) {
			name = chars.StringToByteSlice("e:")
			header_with_newline = chars.StringToByteSlice("\ne:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Content-Length:")) {
			name = chars.StringToByteSlice("l:")
			header_with_newline = chars.StringToByteSlice("\nl:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Content-Type:")) {
			name = chars.StringToByteSlice("c:")
			header_with_newline = chars.StringToByteSlice("\nc:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("From:")) {
			name = chars.StringToByteSlice("f:")
			header_with_newline = chars.StringToByteSlice("\nf:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("To:")) {
			name = chars.StringToByteSlice("t:")
			header_with_newline = chars.StringToByteSlice("\nt:")
		} else if chars.EqualNoCase(name, chars.StringToByteSlice("Via:")) {
			name = chars.StringToByteSlice("v:")
			header_with_newline = chars.StringToByteSlice("\nv:")
		} else {
			return num > 0
		}
	}

	return num > 0
}

func FindSipHeader2(context *ParseContext, name []byte, shortname []byte) (newPos AbnfPos, ok bool) {
	src := context.parseSrc
	newPos = context.parsePos
	len1 := AbnfPos(len(src))
	len2 := AbnfPos(len(name))
	len3 := AbnfPos(len(shortname))

	for newPos < len1 {
		find := false
		if chars.EqualNoCase(name, src[newPos:newPos+len2]) {
			find = true
			newPos += len2
		} else if chars.EqualNoCase(shortname, src[newPos:newPos+len3]) {
			find = true
			newPos += len3
		}

		if find {
			for ; newPos < len1; newPos++ {
				if !IsWspChar(src[newPos]) {
					break
				}
			}
			if newPos >= len1 {
				return newPos, false
			}

			if src[newPos] == ':' {
				newPos, ok = ParseLWS_2(src, newPos)
				if !ok {
					return newPos, false
				}
				return newPos, true
			}
		}

		p1 := bytes.IndexByte(src[newPos:], '\n')
		if p1 == -1 {
			return newPos, false
		}

		newPos += AbnfPos(p1) + 1
	}

	return newPos, false
}
