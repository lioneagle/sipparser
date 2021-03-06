package sipparser

import (
	//"fmt"
	"unsafe"
)

type KnownUriParams interface {
	SetKnownParams(context *Context, name AbnfPtr, param AbnfPtr) bool
	EncodeKnownParams(context *Context, buf *AbnfByteBuffer)
}

type UriParam struct {
	name  AbnfPtr
	value AbnfPtr
	next  AbnfPtr
}

type CharsetInfo struct {
	nameCharsetIndex  int
	valueCharsetIndex int
	nameMask          uint32
	valueMask         uint32
}

func SizeofUriParam() int {
	return int(unsafe.Sizeof(UriParam{}))
}

func NewUriParam(context *Context) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofUriParam()))
}

func (this *UriParam) Encode(context *Context, buf *AbnfByteBuffer, charsets *CharsetInfo) {
	if this.name != ABNF_PTR_NIL {
		if !context.EncodeUriNoEscape {
			this.name.WriteCStringEscape(context, buf, charsets.nameCharsetIndex, charsets.nameMask)
		} else {
			this.name.WriteCString(context, buf)
		}

		this.EncodeValue(context, buf, charsets)
	}
}

func (this *UriParam) EncodeValue(context *Context, buf *AbnfByteBuffer, charsets *CharsetInfo) {
	if this.value != ABNF_PTR_NIL {
		buf.WriteByte('=')
		if !context.EncodeUriNoEscape {
			this.value.WriteCStringEscape(context, buf, charsets.valueCharsetIndex, charsets.valueMask)
		} else {
			this.value.WriteCString(context, buf)
		}
	}

}

/* uri-parameters    =  *( ";" uri-parameter)
 * uri-parameter     =  transport-param / user-param / method-param
 *                      / ttl-param / maddr-param / lr-param / other-param
 * transport-param   =  "transport="
 *                      ( "udp" / "tcp" / "sctp" / "tls"
 *                      / other-transport)
 * other-transport   =  token
 * user-param        =  "user=" ( "phone" / "ip" / other-user)
 * other-user        =  token
 * method-param      =  "method=" Method
 * ttl-param         =  "ttl=" ttl
 * maddr-param       =  "maddr=" host
 * lr-param          =  "lr"
 * other-param       =  pname [ "=" pvalue ]
 * pname             =  1*paramchar
 * pvalue            =  1*paramchar
 * paramchar         =  param-unreserved / unreserved / escaped
 * param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
 */
func (this *UriParam) Parse(context *Context, charsets *CharsetInfo) (ok bool) {
	var name AbnfPtr
	var value AbnfPtr

	src := context.parseSrc
	len1 := AbnfPos(len(src))
	name, ok = context.allocator.ParseAndAllocCStringEscapable(context, charsets.nameCharsetIndex, charsets.nameMask)
	if !ok {
		context.AddError(context.parsePos, "parse uri pname failed")
		return false
	}

	this.name = name

	if context.parsePos >= len1 {
		return true
	}

	if src[context.parsePos] == '=' {
		context.parsePos++
		value, ok = context.allocator.ParseAndAllocCStringEscapable(context, charsets.valueCharsetIndex, charsets.valueMask)
		if !ok {
			context.AddError(context.parsePos, "parse uri pvalue failed")
			return false
		}
		this.value = value
	}

	return true
}

func ParseUriParams(context *Context, charsets *CharsetInfo) (params AbnfPtr, ok bool) {
	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after ';' for uri params")
		return ABNF_PTR_NIL, false
	}

	var prev *UriParam = nil

	for context.parsePos < len1 {
		addr := NewUriParam(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for uri param")
			return ABNF_PTR_NIL, false
		}
		param := addr.GetUriParam(context)
		ok = param.Parse(context, charsets)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		if prev != nil {
			prev.next = addr
		} else {
			params = addr
		}
		prev = param

		if context.parsePos >= len1 {
			break
		}

		if context.parseSrc[context.parsePos] != ';' {
			break
		}
		context.parsePos++
	}

	return params, true
}

func ParseUriParamsEx(context *Context, charsets *CharsetInfo, knownParams KnownUriParams) (params AbnfPtr, ok bool) {

	len1 := AbnfPos(len(context.parseSrc))
	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end after ';' for uri params")
		return ABNF_PTR_NIL, false
	}

	var prev *UriParam = nil

	for context.parsePos < len1 {
		addr := NewUriParam(context)
		if addr == ABNF_PTR_NIL {
			context.AddError(context.parsePos, "no mem for uri param")
			return ABNF_PTR_NIL, false
		}
		param := addr.GetUriParam(context)
		ok = param.Parse(context, charsets)
		if !ok {
			return ABNF_PTR_NIL, false
		}

		if (knownParams == nil) || !knownParams.SetKnownParams(context, param.name, addr) {
			if prev != nil {
				prev.next = addr
			} else {
				params = addr
			}
			prev = param
		}

		if context.parsePos >= len1 {
			return params, true
		}

		if context.parseSrc[context.parsePos] != ';' {
			return params, true
		}
		context.parsePos++
	}

	return params, true
}

func EncodeUriParams(context *Context, buf *AbnfByteBuffer, params AbnfPtr, charsets *CharsetInfo) {
	if params != ABNF_PTR_NIL {
		param := params.GetUriParam(context)

		for {
			buf.WriteByte(';')
			param.Encode(context, buf, charsets)
			if param.next == ABNF_PTR_NIL {
				return
			}
			param = param.next.GetUriParam(context)
		}
	}
}

func EncodeUriParamsEx(context *Context, buf *AbnfByteBuffer, params AbnfPtr, charsets *CharsetInfo, knownParams KnownUriParams) {
	if knownParams != nil {
		knownParams.EncodeKnownParams(context, buf)
	}

	if params != ABNF_PTR_NIL {
		param := params.GetUriParam(context)
		for {
			buf.WriteByte(';')
			param.Encode(context, buf, charsets)
			if param.next == ABNF_PTR_NIL {
				return
			}
			param = param.next.GetUriParam(context)
		}
	}
}

func GetUriParamByName(context *Context, params AbnfPtr, name []byte) *UriParam {
	for params != ABNF_PTR_NIL {
		param := params.GetUriParam(context)
		if param.name.CStringEqualNoCase(context, name) {
			return param
		}
		params = param.next
	}

	return nil
}
