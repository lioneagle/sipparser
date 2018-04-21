package sipparser

import (
	"bytes"
	//"fmt"
	"unsafe"

	"github.com/lioneagle/goutil/src/chars"
)

func ParseEscapable2(context *ParseContext, src []byte, pos AbnfPos, charsetIndex int, mask uint32) (addr AbnfPtr, newPos AbnfPos, ok bool) {
	ref := &AbnfRef{}
	escapeNum, newPos, ok := ref.ParseEscapable(src, pos, charsetIndex, mask)
	if !ok {
		context.AddError(newPos, "ParseEscapable: parse escapable failed")
		return ABNF_PTR_NIL, newPos, false
	}

	if ref.End <= ref.Begin {
		context.AddError(newPos, "ParseEscapable: empty string")
		return ABNF_PTR_NIL, newPos, false
	}

	addr = AllocCStringWithUnescapeNum(context, src[ref.Begin:ref.End], escapeNum)
	if addr == ABNF_PTR_NIL {
		context.AddError(newPos, "ParseEscapable: no mem")
		return ABNF_PTR_NIL, newPos, false
	}
	return addr, newPos, true
}

func ParseEscapable(context *ParseContext, src []byte, pos AbnfPos, charsetIndex int, mask uint32) (addr AbnfPtr, newPos AbnfPos, ok bool) {
	context.SetParsePos(pos)
	addr, ok = context.allocator.ParseAndAllocCStringEscapable(context, charsetIndex, mask)
	newPos = context.parsePos
	/*if newPos <= pos {
		context.AddError(newPos, "ParseEscapable: empty string")
		return ABNF_PTR_NIL, newPos, false
	}*/
	return addr, newPos, ok
}

func ParseEscapableEnableEmpty2(context *ParseContext, src []byte, pos AbnfPos, charsetIndex int, mask uint32) (addr AbnfPtr, newPos AbnfPos, ok bool) {
	ref := &AbnfRef{}
	escapeNum, newPos, ok := ref.ParseEscapable(src, pos, charsetIndex, mask)
	if !ok {
		context.AddError(newPos, "ParseEscapable: parse escapable failed")
		return ABNF_PTR_NIL, newPos, false
	}

	addr = AllocCStringWithUnescapeNum(context, src[ref.Begin:ref.End], escapeNum)
	if addr == ABNF_PTR_NIL {
		context.AddError(newPos, "ParseEscapable: no mem")
		return ABNF_PTR_NIL, newPos, false
	}
	return addr, newPos, true
}

func ParseEscapableEnableEmpty(context *ParseContext, src []byte, pos AbnfPos, charsetIndex int, mask uint32) (addr AbnfPtr, newPos AbnfPos, ok bool) {
	context.SetParsePos(pos)
	addr, ok = context.allocator.ParseAndAllocCStringEscapableEnableEmpty(context, charsetIndex, mask)
	newPos = context.parsePos
	/*if newPos <= pos {
		context.AddError(newPos, "ParseEscapable: empty string")
		return ABNF_PTR_NIL, newPos, false
	}*/
	return addr, newPos, ok
}

func AllocCString(context *ParseContext, buf []byte) AbnfPtr {
	len1 := uint32(len(buf))

	addr := context.allocator.Alloc(len1 + 1)
	if addr == ABNF_PTR_NIL {
		return ABNF_PTR_NIL
	}

	dest := addr.GetAsByteSlice(context, int(len1+1))

	if buf != nil {
		copy(dest, buf)
	}
	dest[len1] = 0
	return addr
}

func AllocCString2(context *ParseContext, buf []byte) AbnfPtr {
	len1 := uint32(len(buf))

	addr := context.allocator.Alloc(len1 + 1)
	if addr == ABNF_PTR_NIL {
		return ABNF_PTR_NIL
	}

	p := addr.GetUintptr(context)
	if len1 > 0 {
		Memcpy(p, (uintptr)(unsafe.Pointer(&buf[0])), int(len1))
	}

	*((*byte)(unsafe.Pointer(p + uintptr(len1)))) = 0

	return addr
}

func AllocCStringWithUnescapeNum(context *ParseContext, buf []byte, escapeNum int) AbnfPtr {
	if escapeNum <= 0 {
		return AllocCString(context, buf)
	}

	len1 := len(buf)

	addr := context.allocator.Alloc(uint32(len1 - 2*escapeNum + 1))
	if addr == ABNF_PTR_NIL {
		return ABNF_PTR_NIL
	}

	dest := addr.GetAsByteSlice(context, len1-2*escapeNum+1)
	j := 0
	i := 0

	for ; i < len1; i++ {
		if buf[i] != '%' {
			dest[j] = buf[i]
		} else {
			break
		}
		j++
	}

	for i < len1 {
		if buf[i] != '%' {
			dest[j] = buf[i]
			i++
		} else if ((i + 2) < len1) && IsHex(buf[i+1]) && IsHex(buf[i+2]) {
			dest[j] = chars.UnescapeToByteEx(buf[i+1], buf[i+2])
			i += 3
		} else {
			dest[j] = buf[i]
			i++
		}
		j++
	}

	dest[j] = 0
	return addr
}

func AllocCStringWithUnescapeNum2(context *ParseContext, buf []byte, escapeNum int) AbnfPtr {
	if escapeNum <= 0 {
		return AllocCString(context, buf)
	}

	len1 := len(buf)

	addr := context.allocator.Alloc(uint32(len1 - 2*escapeNum + 1))
	if addr == ABNF_PTR_NIL {
		return ABNF_PTR_NIL
	}
	src := uintptr(unsafe.Pointer(&buf[0]))
	end := uintptr(unsafe.Pointer(&buf[0])) + uintptr(len(buf))
	dst := addr.GetUintptr(context)

	/*for ; src < end; src++ {
		v := *((*byte)(unsafe.Pointer(src)))
		if v != '%' {
			*((*byte)(unsafe.Pointer(dst))) = v
			dst++
		} else {
			break
		}
	}*/

	for src < end {
		v := *((*byte)(unsafe.Pointer(src)))
		if v != '%' {
			*((*byte)(unsafe.Pointer(dst))) = v
			src++
		} else if ((src + 2) < end) && IsHex(*((*byte)(unsafe.Pointer(src + 1)))) &&
			IsHex(*((*byte)(unsafe.Pointer(src + 2)))) {
			*((*byte)(unsafe.Pointer(dst))) = chars.UnescapeToByteEx(*((*byte)(unsafe.Pointer(src + 1))), *((*byte)(unsafe.Pointer(src + 2))))
			src += 3
		} else {
			*((*byte)(unsafe.Pointer(dst))) = v
			src++
		}
		dst++
	}

	*((*byte)(unsafe.Pointer(dst))) = 0
	return addr
}

func AllocCStringWithUnescape(context *ParseContext, buf []byte) AbnfPtr {
	if bytes.IndexByte(buf, '%') == -1 {
		return AllocCString(context, buf)
	}

	return AllocCStringWithUnescapeNum(context, buf, len(buf))
}

func ParseUInt(src []byte, pos AbnfPos) (digit uint, num uint32, newPos AbnfPos, ok bool) {
	len1 := AbnfPos(len(src))
	charset := &g_charsets[ABNF_CHARSET_DIGIT]
	if pos >= len1 || ((charset[src[pos]] & ABNF_CHARSET_MASK_DIGIT) == 0) {
		return 0, 0, pos, false
	}

	digit = uint(0)

	for newPos = pos; newPos < len1 && ((charset[src[newPos]] & ABNF_CHARSET_MASK_DIGIT) != 0); {
		digit = digit*10 + uint(src[newPos]) - '0'
		newPos++
	}

	/*if (newPos-pos) > 20 || (digit > 0xffffffffffffffff) {
		return 0, 0, newPos, false
	}*/
	return digit, uint32(newPos - pos), newPos, true
}

func ParseUInt_2(context *ParseContext) (digit uint, p uintptr, ok bool) {
	p = context.parseBegin + uintptr(context.parsePos)
	end := context.parseEnd

	charset := &g_charsets[ABNF_CHARSET_DIGIT]
	if p >= end || ((charset[*((*byte)(unsafe.Pointer(p)))] & ABNF_CHARSET_MASK_DIGIT) == 0) {
		return 0, p, false
	}

	digit = uint(0)

	for p < end {
		v := *((*byte)(unsafe.Pointer(p)))
		if (charset[v] & ABNF_CHARSET_MASK_DIGIT) == 0 {
			break
		}

		digit = digit*10 + uint(v) - '0'
		p++
	}

	/*if (p-uintptr(context.parsePos)) > 20 || (digit > 0xffffffffffffffff) {
		return 0, 0, newPos, false
	}*/
	context.parsePos = AbnfPos(p - context.parseBegin)
	return digit, p, true
}

func ParseUInt32(src []byte, pos AbnfPos) (digit uint32, num uint32, newPos AbnfPos, ok bool) {
	len1 := AbnfPos(len(src))
	charset := &g_charsets[ABNF_CHARSET_DIGIT]
	if pos >= len1 || ((charset[src[pos]] & ABNF_CHARSET_MASK_DIGIT) == 0) {
		return 0, 0, pos, false
	}

	digit1 := uint(0)

	for newPos = pos; newPos < len1 && ((charset[src[newPos]] & ABNF_CHARSET_MASK_DIGIT) != 0); {
		digit1 = digit1*10 + uint(src[newPos]) - '0'
		newPos++
	}

	/*if (newPos-pos) > 10 || (digit1 > 0xffffffff) {
		return 0, 0, newPos, false
	}*/
	return uint32(digit1), uint32(newPos - pos), newPos, true
}

func ParseUInt16(src []byte, pos AbnfPos) (digit uint16, num uint32, newPos AbnfPos, ok bool) {
	len1 := AbnfPos(len(src))
	charset := &g_charsets[ABNF_CHARSET_DIGIT]
	if pos >= len1 || ((charset[src[pos]] & ABNF_CHARSET_MASK_DIGIT) == 0) {
		return 0, 0, pos, false
	}

	digit1 := uint(0)

	for newPos = pos; newPos < len1 && ((charset[src[newPos]] & ABNF_CHARSET_MASK_DIGIT) != 0); {
		digit1 = digit1*10 + uint(src[newPos]) - '0'
		newPos++
	}

	/*if (digit1 > 0xffff) || (newPos-pos) > 5 {
		return 0, 0, newPos, false
	}*/
	return uint16(digit1), uint32(newPos - pos), newPos, true
}

func ParseUInt8(src []byte, pos AbnfPos) (digit uint8, num uint32, newPos AbnfPos, ok bool) {
	len1 := AbnfPos(len(src))
	charset := &g_charsets[ABNF_CHARSET_DIGIT]
	if pos >= len1 || ((charset[src[pos]] & ABNF_CHARSET_MASK_DIGIT) == 0) {
		return 0, 0, pos, false
	}

	digit1 := uint(0)

	for newPos = pos; newPos < len1 && ((charset[src[newPos]] & ABNF_CHARSET_MASK_DIGIT) != 0); {
		digit1 = digit1*10 + uint(src[newPos]) - '0'
		newPos++
	}

	/*if (digit1 > 0xffff) || (newPos-pos) > 5 {
		return 0, 0, newPos, false
	}*/
	return uint8(digit1), uint32(newPos - pos), newPos, true
}

/* RFC3261 Section 25.1, page 220
 *
 * HCOLON  =  *( SP / HTAB ) ":" SWS
 */
func ParseHcolon(context *ParseContext) (ok bool) {
	src := context.parseSrc
	len1 := AbnfPos(len(src))
	newPos := context.parsePos

	for ; newPos < len1; newPos++ {
		if !IsWspChar(src[newPos]) {
			break
		}
	}

	if newPos >= len1 {
		context.parsePos = newPos
		context.AddError(newPos, "HCOLON parse: reach end before ':'")
		return false
	}

	if src[newPos] != ':' {
		context.parsePos = newPos
		context.AddError(newPos, "HCOLON parse: no ':' after *( SP / HTAB )")
		return false
	}

	context.parsePos = newPos + 1

	return ParseSWS_2(context)
}

func ParseHcolon2(context *ParseContext, src []byte, pos AbnfPos) (newPos AbnfPos, ok bool) {

	//ref := AbnfRef{}
	//newPos = ref.ParseWspChar(src, pos)
	//newPos = (&AbnfRef{}).ParseWspChar(src, pos)

	len1 := AbnfPos(len(src))

	for newPos = pos; newPos < len1; newPos++ {
		if !IsWspChar(src[newPos]) {
			break
		}
	}

	if newPos >= len1 {
		context.AddError(newPos, "HCOLON parse: reach end before ':'")
		return newPos, false
	}

	if src[newPos] != ':' {
		context.AddError(newPos, "HCOLON parse: no ':' after *( SP / HTAB )")
		return newPos, false
	}

	return ParseSWS(src, newPos+1)
}

func ParseSWSMarkCanOmmit(context *ParseContext, mark byte) (matchMark bool, ok bool) {
	src := context.parseSrc
	ok = ParseSWS_2(context)
	if !ok {
		return false, true
	}

	if context.parsePos >= AbnfPos(len(src)) {
		context.AddError(context.parsePos, "reach end before mark for SWSMark")
		return false, false
	}

	if src[context.parsePos] != mark {
		return false, true
	}

	context.parsePos++

	ok = ParseSWS_2(context)
	return true, ok
}

func ParseSWSMarkCanOmmit_2(context *ParseContext, src []byte, pos AbnfPos, mark byte) (newPos AbnfPos, matchMark bool, ok bool) {
	newPos = pos
	newPos, ok = ParseSWS(src, newPos)
	if !ok {
		return newPos, false, true
	}

	if newPos >= AbnfPos(len(src)) {
		context.AddError(newPos, "SWSMark parse: reach end before mark")
		return newPos, false, false
	}

	if src[newPos] != mark {
		return pos, false, true
	}

	newPos, ok = ParseSWS(src, newPos+1)
	return newPos, true, ok
}

/* RFC3261 Section 25.1, page 220
 *
 * STAR    =  SWS "*" SWS ; asterisk
 * SLASH   =  SWS "/" SWS ; slash
 * EQUAL   =  SWS "=" SWS ; equal
 * LPAREN  =  SWS "(" SWS ; left parenthesis
 * RPAREN  =  SWS ")" SWS ; right parenthesis
 * COMMA   =  SWS "," SWS ; comma
 * SEMI    =  SWS ";" SWS ; semicolon
 * COLON   =  SWS ":" SWS ; colon
 */
func ParseSWSMark(context *ParseContext, mark byte) (ok bool) {
	src := context.parseSrc

	ok = ParseSWS_2(context)
	if !ok {
		return false
	}

	if context.parsePos >= AbnfPos(len(src)) {
		context.AddError(context.parsePos, "reach end before mark for SWSMark")
		return false
	}

	if src[context.parsePos] != mark {
		context.AddError(context.parsePos, "not expected mark after SWS for SWSMark")
		return false
	}

	context.parsePos++

	return ParseSWS_2(context)
}

func ParseSWSMark_2(context *ParseContext, src []byte, pos AbnfPos, mark byte) (newPos AbnfPos, ok bool) {

	newPos = pos
	newPos, ok = ParseSWS(src, newPos)
	if !ok {
		return newPos, true
	}

	if newPos >= AbnfPos(len(src)) {
		context.AddError(newPos, "SWSMark parse: reach end before mark")
		return newPos, false
	}

	if src[newPos] != mark {
		context.AddError(newPos, "SWSMark parse: not expected mark after SWS")
		return newPos, false
	}

	return ParseSWS(src, newPos+1)
}

/* Parse SWS
 *
 * RFC3261 Section 25.1, page 220
 *
 * SWS  =  [LWS] ; sep whitespace
 */
func ParseSWS_2(context *ParseContext) (ok bool) {
	src := context.parseSrc

	if context.parsePos >= AbnfPos(len(src)) {
		return true
	}

	if !IsLwsChar(src[context.parsePos]) {
		/*if (src[context.parsePos] != ' ') && (src[context.parsePos] != '\t') &&
		(src[context.parsePos] != '\r') && (src[context.parsePos] != '\n') {*/
		return true
	}

	pos := context.parsePos
	ok = ParseLWS(context)
	if !ok {
		context.parsePos = pos
	}
	return true
}

func ParseSWS(src []byte, pos AbnfPos) (newPos AbnfPos, ok bool) {
	/* RFC3261 Section 25.1, page 220
	 *
	 * SWS  =  [LWS] ; sep whitespace
	 */
	newPos = pos
	if newPos >= AbnfPos(len(src)) {
		return newPos, true
	}

	if !IsLwsChar(src[newPos]) {
		return newPos, true
	}

	newPos1, ok := ParseLWS_2(src, newPos)
	if ok {
		newPos = newPos1
	}
	return newPos, true
}

/* Parse LWS
 *
 * RFC3261 Section 25.1, page 220
 *
 * LWS  =  [*WSP CRLF] 1*WSP ; linear whitespace
 * WSP  =  ( SP | HTAB )
 *
 * NOTE:
 *
 * 1. this defination of LWS is different from that in RFC2616 (HTTP/1.1)
 *    RFC2616 Section 2.2, page 16:
 *
 *    LWS  = [CRLF] 1*( SP | HTAB )
 *
 * 2. WSP's defination is from RFC2234 Section 6.1, page 12
 *
 */
func ParseLWS(context *ParseContext) (ok bool) {
	src := context.parseSrc
	newPos := context.parsePos
	len1 := AbnfPos(len(src))

	for ; newPos < len1; newPos++ {
		if (src[newPos] != ' ') && (src[newPos] != '\t') {
			break
		}
	}

	if (newPos + 1) >= len1 {
		context.parsePos = newPos
		return true
	}

	if (src[newPos] == '\r') && (src[newPos+1] == '\n') {
		newPos += 2

		if newPos >= len1 {
			context.parsePos = newPos
			return false
		}

		if (src[newPos] != ' ') && (src[newPos] != '\t') {
			context.parsePos = newPos
			return false
		}

		for ; newPos < len1; newPos++ {
			if (src[newPos] != ' ') && (src[newPos] != '\t') {
				context.parsePos = newPos
				return true
			}
		}
	}
	context.parsePos = newPos
	return true
}

func ParseLWS_2(src []byte, pos AbnfPos) (newPos AbnfPos, ok bool) {
	//newPos = eatWsp(src, pos)
	len1 := AbnfPos(len(src))
	for newPos = pos; newPos < len1; newPos++ {
		//if !IsWspChar(src[newPos]) {
		if (src[newPos] != ' ') && (src[newPos] != '\t') {
			break
		}
	}

	if (newPos + 1) >= len1 {
		return newPos, true
	}

	//if IsCRLF2(src, newPos) {
	if (src[newPos] == '\r') && (src[newPos+1] == '\n') {
		newPos += 2

		if newPos >= len1 {
			//return newPos, &AbnfError{"LWS parse: no char after CRLF in LWS", src, newPos}
			return newPos, false
		}

		//if !IsWspChar(src[newPos]) {
		if (src[newPos] != ' ') && (src[newPos] != '\t') {
			//return newPos, &AbnfError{"LWS parse: no WSP after CRLF in LWS", src, newPos}
			return newPos, false
		}

		//newPos = eatWsp(src, newPos)
		for ; newPos < len1; newPos++ {
			//if !IsWspChar(src[newPos]) {
			if (src[newPos] != ' ') && (src[newPos] != '\t') {
				return newPos, true
			}
		}
	}

	return newPos, true
}

func eatWsp(src []byte, pos AbnfPos) (newPos AbnfPos) {
	len1 := AbnfPos(len(src))
	for newPos = pos; newPos < len1; newPos++ {
		if !IsWspChar(src[newPos]) {
			break
		}
	}
	return newPos
}

/* RFC3261 Section 25.1, page 221
 *
 * LAQUOT  =  SWS "<"; left angle quote
 *
 */
func ParseLeftAngleQuote(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "LAQUOT parse: reach end at begining")
		return false
	}

	ok = ParseSWS_2(context)
	if !ok {
		return false
	}

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "LAQUOT parse: reach end before '<'")
		return false
	}

	if context.parseSrc[context.parsePos] != '<' {
		context.AddError(context.parsePos, "LAQUOT parse: no '<'")
		return false
	}

	context.parsePos++

	return true
}

/* RFC3261 Section 25.1, page 221
 *
 * LAQUOT  =  SWS "<"; left angle quote
 *
 */
func ParseLeftAngleQuote2(context *ParseContext, src []byte, pos AbnfPos) (newPos AbnfPos, ok bool) {

	newPos = pos
	len1 := AbnfPos(len(src))

	if newPos >= len1 {
		context.AddError(newPos, "LAQUOT parse: reach end at begining")
		return newPos, false
	}

	newPos, ok = ParseSWS(src, newPos)
	if !ok {
		return newPos, false
	}

	if newPos >= len1 {
		context.AddError(newPos, "reach end before '<' for LAQUOT")
		return newPos, false
	}

	if src[newPos] != '<' {
		context.AddError(newPos, "no '<' for LAQUOT")
		return newPos, false
	}

	return newPos + 1, true
}

/* RFC3261 Section 25.1, page 221
 *
 * RAQUOT  =  ">" SWS ; right angle quote
 *
 */
func ParseRightAngleQuote(context *ParseContext) (ok bool) {
	len1 := AbnfPos(len(context.parseSrc))

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "reach end at begining for RAQUOT")
		return false
	}

	if context.parseSrc[context.parsePos] != '>' {
		context.AddError(context.parsePos, "no '>' for RAQUOT")
		return false
	}

	context.parsePos++

	return ParseSWS_2(context)
}

/* RFC3261 Section 25.1, page 221
 *
 * RAQUOT  =  ">" SWS ; right angle quote
 *
 */
func ParseRightAngleQuote2(context *ParseContext, src []byte, pos AbnfPos) (newPos AbnfPos, ok bool) {

	newPos = pos
	if newPos >= AbnfPos(len(src)) {
		context.AddError(newPos, "RAQUOT parse: reach end at begining")
		return newPos, false
	}

	if src[newPos] != '>' {
		context.AddError(newPos, "RAQUOT parse: no '>'")
		return newPos, false
	}

	return ParseSWS(src, newPos+1)
}

func IsCRLF(src []byte, pos AbnfPos) bool {
	return ((pos + 1) < AbnfPos(len(src))) && (src[pos] == '\r') && (src[pos+1] == '\n')
}

func IsCRLF2(src []byte, pos AbnfPos) bool {
	return (src[pos] == '\r') && (src[pos+1] == '\n')
}

func IsOnlyCRLF(src []byte, pos AbnfPos) bool {
	len1 := AbnfPos(len(src))
	if (pos + 2) < len1 {
		return (src[pos] == '\r') && (src[pos+1] == '\n') && !IsWspChar(src[pos+2])
	}
	return (pos+2) == len1 && (src[pos] == '\r') && (src[pos+1] == '\n')
}

func ParseCRLF(src []byte, pos AbnfPos) (newPos AbnfPos, ok bool) {
	if !IsCRLF(src, pos) {
		//return pos, &AbnfError{"CRLF parse: wrong CRLF", src, pos}
		return pos, false
	}
	return pos + 2, true
}

func EncodeUInt2(buf *AbnfByteBuffer, digit uint64) {
	//buf.WriteString(strconv.FormatUint(uint64(digit), 10))
	if digit == 0 {
		buf.WriteByte('0')
		return
	}
	var val [32]byte
	num := 0
	for digit > 0 {
		mod := digit
		digit /= 10
		val[num] = '0' + byte(mod-digit*10)
		num++
	}

	for i := num - 1; i >= 0; i-- {
		buf.WriteByte(val[i])
	}
}

func EncodeUInt(buf *AbnfByteBuffer, digit uint64) {
	//buf.WriteString(strconv.FormatUint(uint64(digit), 10))
	if digit == 0 {
		buf.WriteByte('0')
		return
	}
	var val [32]byte
	num := 31
	for digit > 0 {
		mod := digit
		digit /= 10
		val[num] = '0' + byte(mod-digit*10)
		num--
	}

	buf.Write(val[num+1:])
}

func EncodeUIntWithWidth(buf *AbnfByteBuffer, digit uint64, width int) {
	//buf.WriteString(strconv.FormatUint(uint64(digit), 10))
	if digit == 0 {
		width--
		for i := 0; i < width; i++ {
			buf.WriteByte(' ')
		}
		buf.WriteByte('0')
		return
	}

	var val [32]byte
	num := 31
	for digit > 0 {
		mod := digit
		digit /= 10
		val[num] = '0' + byte(mod-digit*10)
		num--
	}

	for i := width - 32 + num + 1; i > 0; i-- {
		buf.WriteByte(' ')
	}

	buf.Write(val[num+1:])
}

func EncodeUInt32(buf *AbnfByteBuffer, digit uint32) {
	if digit == 0 {
		buf.WriteByte('0')
		return
	}
	var val [16]byte
	num := 15
	for digit > 0 {
		mod := digit
		digit /= 10
		val[num] = '0' + byte(mod-digit*10)
		num--
	}

	buf.Write(val[num+1:])
}

func EncodeUInt32WithWidth(buf *AbnfByteBuffer, digit uint32, width int) {
	if digit == 0 {
		width--
		for i := 0; i < width; i++ {
			buf.WriteByte(' ')
		}
		buf.WriteByte('0')
		return
	}

	var val [16]byte
	num := 15
	for digit > 0 {
		mod := digit
		digit /= 10
		val[num] = '0' + byte(mod-digit*10)
		num--
	}

	for i := width - 16 + num + 1; i > 0; i-- {
		buf.WriteByte(' ')
	}

	buf.Write(val[num+1:])
}

func ZeroByteSlice(src []byte) {
	len1 := len(src)
	if len1 == 0 {
		return
	}

	p := uintptr(unsafe.Pointer(&src[0]))
	end := p + uintptr(len1)
	end1 := p + uintptr((len1>>3)<<3)

	for p < end1 {
		*((*uint64)(unsafe.Pointer(p))) = 0
		p += 8
	}

	for p < end {
		*((*byte)(unsafe.Pointer(p))) = 0
		p++
	}
}

func ZeroMem(addr uintptr, size int) {
	if size == 0 {
		return
	}
	p := addr
	end := p + uintptr(size)
	//end1 := ((p + 7) >> 3) << 3
	end2 := p + uintptr(((size)>>3)<<3)

	/*for p < end1 {
		*((*byte)(unsafe.Pointer(p))) = 0
		p++
	}*/

	for p < end2 {
		*((*uint64)(unsafe.Pointer(p))) = 0
		p += 8
	}

	for p < end {
		*((*byte)(unsafe.Pointer(p))) = 0
		p++
	}
}

func Memcpy(addr1, addr2 uintptr, size int) {
	p1 := addr1
	p2 := addr2
	end := p2 + uintptr(size)
	//end1 := ((p2 + 7) >> 3) << 3
	end2 := p2 + uintptr((size>>3)<<3)

	/*for p2 < end1 {
		*((*byte)(unsafe.Pointer(p1))) = *((*byte)(unsafe.Pointer(p2)))
		p2++
		p1++
	}*/

	for p2 < end2 {
		*((*int64)(unsafe.Pointer(p1))) = *((*int64)(unsafe.Pointer(p2)))
		p2 += 8
		p1 += 8
	}

	for p2 < end {
		*((*byte)(unsafe.Pointer(p1))) = *((*byte)(unsafe.Pointer(p2)))
		p2++
		p1++
	}
}
