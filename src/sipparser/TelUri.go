package sipparser

import (
	//"fmt"
	"unsafe"
)

var g_TelUriParamCharsetInfo = CharsetInfo{
	nameCharsetIndex:  ABNF_CHARSET_TEL_PNAME,
	valueCharsetIndex: ABNF_CHARSET_TEL_PVALUE,
	nameMask:          ABNF_CHARSET_MASK_TEL_PNAME,
	valueMask:         ABNF_CHARSET_MASK_TEL_PVALUE,
}

type TelUriKnownParamInfo struct {
	name  []byte
	index int
}

const (
	TEL_URI_KNOWN_PARAM_ISUB      = 0
	TEL_URI_KNOWN_PARAM_EXTENSION = 1

	TEL_URI_KNOWN_PARAM_MAX_NUM = iota
)

var g_TelUriKnownParamInfo = []TelUriKnownParamInfo{
	{[]byte("isub"), TEL_URI_KNOWN_PARAM_ISUB},
	{[]byte("ext"), TEL_URI_KNOWN_PARAM_EXTENSION},
}

type TelUriKnownParams struct {
	params [TEL_URI_KNOWN_PARAM_MAX_NUM]AbnfPtr
}

func SizeofTelUriKnownParams() int {
	return int(unsafe.Sizeof(TelUriKnownParams{}))
}

func NewTelUriKnownParams(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofTelUriKnownParams()))
}

type TelUri struct {
	IsGlobalNumber  bool
	ContextIsDomain bool
	number          AbnfPtr
	context         AbnfPtr
	params          AbnfPtr
	knownParams     AbnfPtr
}

func SizeofTelUri() int {
	return int(unsafe.Sizeof(TelUri{}))
}

func NewTelUri(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofTelUri()))
}

func (this *TelUri) Init() {
	ZeroMem(this.memAddr(), SizeofTelUri())
}

func (this *TelUri) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *TelUri) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *TelUri) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	buf.WriteString("tel:")
	this.number.WriteCString(context, buf)

	if !this.IsGlobalNumber {
		if this.context != ABNF_PTR_NIL {
			buf.WriteString(";phone-context")
			this.context.GetUriParam(context).EncodeValue(context, buf, &g_TelUriParamCharsetInfo)
		}
	}

	if this.knownParams != ABNF_PTR_NIL {
		EncodeUriParamsEx(context, buf, this.params, &g_TelUriParamCharsetInfo, this)
	} else {
		EncodeUriParams(context, buf, this.params, &g_TelUriParamCharsetInfo)
	}
}

func (this *TelUri) EncodeKnownParams(context *ParseContext, buf *AbnfByteBuffer) {
	if this.knownParams == ABNF_PTR_NIL {
		return
	}

	knownParams := this.knownParams.GetTelUriKnownParams(context)

	for i := 0; i < TEL_URI_KNOWN_PARAM_MAX_NUM; i++ {
		param := knownParams.params[i]
		if param != ABNF_PTR_NIL {
			buf.WriteByte(';')
			buf.Write(g_TelUriKnownParamInfo[i].name)
			param.GetUriParam(context).EncodeValue(context, buf, &g_TelUriParamCharsetInfo)
		}
	}
}

func (this *TelUri) SetKnownParams(context *ParseContext, name AbnfPtr, param AbnfPtr) (ok bool) {
	if name.CStringEqualNoCase(context, StringToByteSlice("phone-context")) {
		this.context = param
		this.ContextIsDomain = (param.GetUriParam(context).value.GetCStringAsByteSlice(context)[0] != '+')
		if !this.ContextIsDomain {
			param.GetUriParam(context).value.RemoveTelUriVisualSeperator(context)
		}
		return true
	}

	if !context.ParseSetSipUriKnownParam {
		return false
	}

	var knownParams *TelUriKnownParams

	if this.knownParams != ABNF_PTR_NIL {
		knownParams = this.knownParams.GetTelUriKnownParams(context)
	}

	len1 := len(g_TelUriKnownParamInfo)
	for i := 0; i < len1; i++ {
		if name.CStringEqualNoCase(context, g_TelUriKnownParamInfo[i].name) {
			if this.knownParams == ABNF_PTR_NIL {
				this.knownParams = NewTelUriKnownParams(context)
				knownParams = this.knownParams.GetTelUriKnownParams(context)
			}

			knownParams.params[g_TelUriKnownParamInfo[i].index] = param
			return true
		}
	}
	return false
}

func (this *TelUri) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *TelUri) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.parseScheme(context)
	if !ok {
		return false
	}

	return this.ParseAfterSchemeWithoutInit(context)
}

func (this *TelUri) ParseAfterScheme(context *ParseContext) (ok bool) {
	return this.ParseAfterSchemeWithoutInit(context)
}

func (this *TelUri) ParseAfterSchemeWithoutInit(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	ok = this.parseNumber(context)
	if !ok {
		context.AddError(context.parsePos, "parse number failed")
		return false
	}

	if context.parsePos >= len1 {
		return true
	}

	if context.parseSrc[context.parsePos] == ';' {
		context.parsePos++
		this.params, ok = ParseUriParamsEx(context, &g_SipUriParamCharsetInfo, this)
		if !ok {
			context.AddError(context.parsePos, "parse tel uri params failed")
			return false
		}
	}

	return true
}

func (this *TelUri) ParseAfterSchemeWithoutParam(context *ParseContext) (ok bool) {
	return this.parseNumber(context)
}

func (this *TelUri) parseNumber(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "no number after \"tel:\"")
		return false
	}

	if context.parseSrc[context.parsePos] == '+' {
		if !this.parseGlobalNumber(context) {
			return false
		}
		this.IsGlobalNumber = true
		return true
	}

	if !this.parseLocalNumber(context) {
		return false
	}

	this.IsGlobalNumber = false
	return true
}

func (this *TelUri) parseGlobalNumber(context *ParseContext) (ok bool) {
	this.number, ok = context.allocator.ParseAndAllocTelNumberRemoveVisualSeperator(context, ABNF_CHARSET_TEL_PHONE_DIGIT, ABNF_CHARSET_MASK_TEL_PHONE_DIGIT)
	if !ok {
		context.AddError(context.parsePos, "parse global-number failed for tel uri")
		return false
	}
	return true
}

func (this *TelUri) parseLocalNumber(context *ParseContext) (ok bool) {
	this.number, ok = context.allocator.ParseAndAllocTelNumberRemoveVisualSeperator(context, ABNF_CHARSET_TEL_PHONE_DIGIT_HEX, ABNF_CHARSET_MASK_TEL_PHONE_DIGIT_HEX)
	if !ok {
		context.AddError(context.parsePos, "parse local-number failed for tel uri")
		return false
	}
	return true
}

func (this *TelUri) parseScheme(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(context.parseSrc))
	pos := context.parsePos

	if pos >= len1 {
		return false
	}

	if (pos + 3) >= len1 {
		return false
	}

	if (src[pos]|0x20 == 't') &&
		((src[pos+1] | 0x20) == 'e') &&
		((src[pos+2] | 0x20) == 'l') &&
		((src[pos+3] | 0x20) == ':') {
		context.parsePos = pos + 4
		return true
	}

	return false
}
