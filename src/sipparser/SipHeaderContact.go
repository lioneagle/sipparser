package sipparser

import (
	//"fmt"
	"unsafe"
)

type SipContactKnownParamInfo struct {
	name  []byte
	index int
}

const (
	SIP_CONTACT_KNOWN_PARAM_EXPIRES = 0
	SIP_CONTACT_KNOWN_PARAM_Q       = 1
	SIP_CONTACT_KNOWN_PARAM_MAX_NUM = iota
)

var g_SipContactKnownParamInfo = []SipContactKnownParamInfo{
	{[]byte("expires\000"), SIP_CONTACT_KNOWN_PARAM_EXPIRES},
	{[]byte("q\000"), SIP_CONTACT_KNOWN_PARAM_Q},
}

type SipContactKnownParams struct {
	params [SIP_CONTACT_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofSipContactKnownParams() int {
	return int(unsafe.Sizeof(SipContactKnownParams{}))
}

func NewSipContactKnownParams(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipContactKnownParams()))
}

type SipHeaderContact struct {
	isStar      bool
	addr        SipAddr
	params      AbnfPtr
	knownParams AbnfPtr
	next        AbnfPtr
}

func SizeofSipHeaderContact() int {
	return int(unsafe.Sizeof(SipHeaderContact{}))
}

func NewSipHeaderContact(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHeaderContact()))
}

func (this *SipHeaderContact) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHeaderContact) Init() {
	ZeroMem(this.memAddr(), SizeofSipHeaderContact())
}

func (this *SipHeaderContact) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHeaderContact) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("Contact: ")
	this.EncodeValue(context, buf)
}

func (this *SipHeaderContact) EncodeValue(context *ParseContext, buf *AbnfByteBuffer) {
	if this.isStar {
		buf.WriteByte('*')
	} else {
		this.addr.Encode(context, buf)
		EncodeSipGenericParams(context, buf, this.params, ';', this)
	}
}

/* RFC3261
 *
 * Contact        =  ("Contact" / "m" ) HCOLON
 *                   ( STAR / (contact-param *(COMMA contact-param)))
 * contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
 * name-addr      =  [ display-name ] LAQUOT addr-spec RAQUOT
 * addr-spec      =  SIP-URI / SIPS-URI / absoluteURI
 * display-name   =  *(token LWS)/ quoted-string

 * contact-params     =  c-p-q / c-p-expires
 *                      / contact-extension
 * c-p-q              =  "q" EQUAL qvalue
 * c-p-expires        =  "expires" EQUAL delta-seconds
 * contact-extension  =  generic-param
 * delta-seconds      =  1*DIGIT
 *
 * RFC3840, page 13
 *
 * feature-param    =  enc-feature-tag [EQUAL LDQUOT (tag-value-list
 *                     / string-value ) RDQUOT]
 * enc-feature-tag  =  base-tags / other-tags
 * base-tags        =  "audio" / "automata" /
 *                     "class" / "duplex" / "data" /
 *                     "control" / "mobility" / "description" /
 *                     "events" / "priority" / "methods" /
 *                     "schemes" / "application" / "video" /
 *                     "language" / "type" / "isfocus" /
 *                     "actor" / "text" / "extensions"
 * other-tags      =  "+" ftag-name
 * ftag-name       =  ALPHA *( ALPHA / DIGIT / "!" / "'" /
 *                    "." / "-" / "%" )
 * tag-value-list  =  tag-value *("," tag-value)
 * tag-value       =  ["!"] (token-nobang / boolean / numeric)
 * token-nobang    =  1*(alphanum / "-" / "." / "%" / "*"
 *                    / "_" / "+" / "`" / "'" / "~" )
 * boolean         =  "TRUE" / "FALSE"
 * numeric         =  "#" numeric-relation number
 * numeric-relation  =  ">=" / "<=" / "=" / (number ":")
 * number          =  [ "+" / "-" ] 1*DIGIT ["." 0*DIGIT]
 * string-value    =  "<" *(qdtext-no-abkt / quoted-pair ) ">"
 * qdtext-no-abkt  =  LWS / %x21 / %x23-3B / %x3D
 *                    / %x3F-5B / %x5D-7E / UTF8-NONASCII
 *
 * draft-ietf-sip-gruu-15.txt, page 22
 *
 * contact-params  =/ temp-gruu / pub-gruu
 * temp-gruu       =  "temp-gruu" EQUAL LDQUOT *(qdtext / quoted-pair )
 *                    RDQUOT
 * pub-gruu        =  "pub-gruu" EQUAL LDQUOT *(qdtext / quoted-pair )
 *                    RDQUOT
 *
 * uri-parameter   =/ gr-param
 * gr-param        = "gr" ["=" pvalue]   ; defined in RFC3261
 *
 * draft-ietf-sip-outbound-10.txt
 *
 * c-p-reg        = "reg-id" EQUAL 1*DIGIT ; 1 to 2**31
 * c-p-instance   =  "+sip.instance" EQUAL
 *                   LDQUOT "<" instance-val ">" RDQUOT
 * instance-val   = *uric ; defined in RFC 2396
 *
 */
func (this *SipHeaderContact) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHeaderContact) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseHeaderName(context)
	if !ok {
		context.AddError(context.parsePos, "parse header-name failed for Contact header")
		return false
	}

	ok = ParseHcolon(context)
	if !ok {
		context.AddError(context.parsePos, "parse HCOLON failed for Contact header")
		return false
	}

	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContact) ParseValue(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseValueWithoutInit(context)
}

func (this *SipHeaderContact) ParseValueWithoutInit(context *ParseContext) (ok bool) {
	ok = ParseSWS_2(context)
	if !ok {
		return false
	}

	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		context.AddError(context.parsePos, "empty hvalue for Contact header")
		return false
	}

	if context.parseSrc[context.parsePos] == '*' {
		context.parsePos++
		this.isStar = true
		return ParseSWS_2(context)
	}

	ok = this.addr.ParseWithoutInit(context, false)
	if !ok {
		context.AddError(context.parsePos, "parse sip-addr failed for Contact header")
		return false
	}

	if context.ParseSetSipContactKnownParam {
		this.params, ok = ParseSipGenericParams(context, ';', this)
	} else {
		this.params, ok = ParseSipGenericParams(context, ';', nil)
	}
	if !ok {
		context.AddError(context.parsePos, "parse generic-params failed for Contact header")
		return false
	}

	return true
}

func (this *SipHeaderContact) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetSipContactKnownParams(context)

	for i := 0; i < SIP_CONTACT_KNOWN_PARAM_MAX_NUM; i++ {
		param := knownParams.params[i]
		if param != ABNF_PTR_NIL {
			buf.WriteByte(';')
			buf.Write(g_SipContactKnownParamInfo[i].name)
			param.GetSipGenericParam(context).EncodeValue(context, buf)
		}
	}
}

func (this *SipHeaderContact) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) bool {
	if !context.ParseSetSipContactKnownParam {
		return false
	}

	var knownParams *SipContactKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.params.GetSipContactKnownParams(context)
	}

	len1 := len(g_SipContactKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_SipContactKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewSipContactKnownParams(context)
				knownParams = this.knownParams.GetSipContactKnownParams(context)
			}

			knownParams.params[g_SipContactKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *SipHeaderContact) parseHeaderName(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if src[pos]|0x20 == 'c' {
		pos++

		if (pos + 6) >= len1 {
			return false
		}

		if ((src[pos] | 0x20) == 'o') &&
			((src[pos+1] | 0x20) == 'n') &&
			((src[pos+2] | 0x20) == 't') &&
			((src[pos+3] | 0x20) == 'a') &&
			((src[pos+4] | 0x20) == 'c') &&
			((src[pos+5] | 0x20) == 't') {
			if src[pos+6] == ':' || IsWspChar(src[pos+6]) {
				context.parsePos = pos + 6
				return true
			}
		}
	} else if src[pos]|0x20 == 'm' {
		pos++
		if pos >= len1 {
			return false
		}
		if src[pos] == ':' || IsWspChar(src[pos]) {
			context.parsePos = pos
			return true
		}
	}

	return false
}

func ParseSipContact(context *ParseContext) (parsed AbnfPtr, ok bool) {
	addr := NewSipHeaderContact(context)
	if addr == ABNF_PTR_NIL {
		context.AddError(context.parsePos, "no mem for Contact header")
		return ABNF_PTR_NIL, false
	}
	ok = addr.GetSipHeaderContact(context).ParseValueWithoutInit(context)
	return addr, ok
}

func EncodeSipContactValue(parsed AbnfPtr, context *ParseContext, buf *AbnfByteBuffer) {
	if parsed == ABNF_PTR_NIL {
		return
	}
	parsed.GetSipHeaderContact(context).EncodeValue(context, buf)
}
