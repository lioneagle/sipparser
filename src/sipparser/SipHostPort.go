package sipparser

import (
	//"fmt"
	"net"
	"unsafe"
)

const (
	HOST_TYPE_UNKNOWN = 0
	HOST_TYPE_IPV4    = 1
	HOST_TYPE_IPV6    = 2
	HOST_TYPE_NAME    = 3
)

type SipHostPort struct {
	id      byte
	hasPort bool
	port    uint16
	data    AbnfPtr
}

func SizeofSipHostPort() int {
	return int(unsafe.Sizeof(SipHostPort{}))
}

func NewSipHostPort(context *ParseContext) AbnfPtr {
	return context.allocator.AllocWithClear(uint32(SizeofSipHostPort()))
}

func (this *SipHostPort) Init() {
	ZeroMem(this.memAddr(), SizeofSipHostPort())
}

func (this *SipHostPort) IsIpv4() bool     { return this.id == HOST_TYPE_IPV4 }
func (this *SipHostPort) IsIpv6() bool     { return this.id == HOST_TYPE_IPV6 }
func (this *SipHostPort) IsHostname() bool { return this.id == HOST_TYPE_NAME }

func (this *SipHostPort) HasPort() bool   { return this.hasPort }
func (this *SipHostPort) GetPort() uint16 { return this.port }

func (this *SipHostPort) SetPort(port uint16) {
	this.hasPort = true
	this.port = port
}

func (this *SipHostPort) memAddr() uintptr {
	return uintptr(unsafe.Pointer(this))
}

func (this *SipHostPort) String(context *ParseContext) string {
	return AbnfEncoderToString(context, this)
}

func (this *SipHostPort) Encode(context *ParseContext, buf *AbnfByteBuffer) {
	this.EncodeHost(context, buf)
	if this.hasPort {
		buf.WriteByte(':')
		EncodeUInt(buf, uint64(this.port))
	}
}

func (this *SipHostPort) EncodeHost(context *ParseContext, buf *AbnfByteBuffer) {
	/*
		if this.id == HOST_TYPE_IPV4 {
			this.WriteIpv4AsString(context, buf)
		} else if this.id == HOST_TYPE_IPV6 {
			buf.WriteByte('[')
			buf.WriteString(net.IP(this.data.GetAsByteSlice(context, 16)).String())
			buf.WriteByte(']')
		} else if this.id == HOST_TYPE_NAME {
			this.data.WriteCString(context, buf)
		} else {
			buf.WriteString("unknown host")
		}
		//*/
	//*
	switch this.id {
	case HOST_TYPE_IPV4:
		this.WriteIpv4AsString(context, buf)
	case HOST_TYPE_IPV6:
		buf.WriteByte('[')
		buf.WriteString(net.IP(this.data.GetAsByteSlice(context, 16)).String())
		buf.WriteByte(']')
	case HOST_TYPE_NAME:
		this.data.WriteCString(context, buf)
	default:
		buf.WriteString("unknown host")
	} //*/
}

func (this *SipHostPort) WriteIpv4AsString(context *ParseContext, buf *AbnfByteBuffer) {
	ip := this.data.GetAsByteSlice(context, 4)

	WriteByteAsString(buf, ip[0])
	buf.WriteByte('.')
	WriteByteAsString(buf, ip[1])
	buf.WriteByte('.')
	WriteByteAsString(buf, ip[2])
	buf.WriteByte('.')
	WriteByteAsString(buf, ip[3])
}

func WriteByteAsString(buf *AbnfByteBuffer, v byte) {
	//buf.WriteString(g_byteAsString_table[v])
	//*
	if v == 0 {
		buf.WriteByte('0')
		return
	}

	x2 := v / 10
	x1 := v - x2*10
	x3 := x2 / 10
	x2 -= x3 * 10

	if x3 != 0 {
		buf.WriteByte('0' + x3)
		buf.WriteByte('0' + x2)
	} else if x2 != 0 {
		buf.WriteByte('0' + x2)
	}

	buf.WriteByte('0' + x1) //*/

}

func (this *SipHostPort) Parse(context *ParseContext) (ok bool) {
	this.Init()
	return this.ParseWithoutInit(context)
}

func (this *SipHostPort) ParseWithoutInit(context *ParseContext) (ok bool) {
	ok = this.ParseHost(context)
	if !ok {
		context.AddError(context.parsePos, "sip-hostport parse: parse host failed")
		return false
	}

	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		return true
	}

	if context.parseSrc[context.parsePos] != ':' {
		return true
	}

	context.parsePos++

	var digit uint

	digit, _, context.parsePos, ok = ParseUInt(context.parseSrc, context.parsePos)
	if !ok {
		context.AddError(context.parsePos, "sip-hostport parse: parse port failed after \":\"")
		return false
	}

	if digit < 0 || digit > 0xffff {
		context.AddError(context.parsePos, "sip-hostport parse: port wrong range \":\"")
		return false
	}

	this.SetPort(uint16(digit))

	return true
}

func (this *SipHostPort) ParseHost(context *ParseContext) (ok bool) {
	if context.parsePos >= AbnfPos(len(context.parseSrc)) {
		context.AddError(context.parsePos, "sip-hostport parse: reach end at beginning")
		return false
	}

	if context.parseSrc[context.parsePos] == '[' {
		context.parsePos++
		return this.parseIpv6(context)
	}

	if IsAlpha(context.parseSrc[context.parsePos]) {
		return this.parseHostname(context)
	}

	var ipv4 [4]byte

	pos := context.parsePos
	ipv4, ok = this.parseIpv4(context)
	if !ok {
		context.parsePos = pos
		return this.parseHostname(context)
	}

	ok = this.SetIpv4(context, ipv4[0:])
	if !ok {
		context.AddError(context.parsePos, "sip-host parse: no mem for ipv4")
		return false
	}
	return true
}

func (this *SipHostPort) parseIpv6(context *ParseContext) (ok bool) {
	pos := context.parsePos
	len1 := AbnfPos(len(context.parseSrc))
	for ; context.parsePos < len1; context.parsePos++ {
		if context.parseSrc[context.parsePos] == ']' {
			break
		}
	}

	if context.parsePos >= len1 {
		context.AddError(context.parsePos, "sip-host parse: no \"]\" for ipv6-reference")
		return false
	}

	ipv6 := net.ParseIP(ByteSliceToString(context.parseSrc[pos:context.parsePos]))
	if ipv6 == nil {
		context.AddError(context.parsePos, "sip-host parse: parse ipv6 failed")
		return false
	}

	ok = this.SetIpv6(context, ipv6)
	if !ok {
		context.AddError(context.parsePos, "sip-host parse: no mem for ipv6")
		return false
	}
	context.parsePos++
	return true
}

func (this *SipHostPort) parseIpv4(context *ParseContext) (ip [4]byte, ok bool) {
	src := context.parseSrc
	newPos := context.parsePos
	len1 := AbnfPos(len(src))

	if newPos >= len1 {
		return ip, false
	}

	var digit uint

	digit, _, newPos, ok = ParseUInt(src, newPos)
	if !ok || digit > 0xff {
		context.parsePos = newPos
		return ip, false
	}

	ip[0] = byte(digit)

	for num := 1; num < net.IPv4len; num++ {
		if newPos >= len1 {
			context.parsePos = newPos
			return ip, false
		}

		if src[newPos] != '.' {
			context.parsePos = newPos
			return ip, false
		}
		newPos++

		digit, _, newPos, ok = ParseUInt(src, newPos)

		if !ok || digit > 0xff {
			context.parsePos = newPos
			return ip, false
		}

		ip[num] = byte(digit)
	}

	if newPos < len1 && IsHostname(src[newPos]) {
		context.parsePos = newPos
		return ip, false
	}

	context.parsePos = newPos
	return ip, true
}

func (this *SipHostPort) parseHostname(context *ParseContext) (ok bool) {
	//*
	this.data, ok = context.allocator.ParseAndAllocCString(context, ABNF_CHARSET_HOSTNAME, ABNF_CHARSET_MASK_HOSTNAME)
	if ok {
		this.id = HOST_TYPE_NAME
	}
	return ok //*/

	/*

		src := context.parseSrc
		newPos := context.parsePos
		pos := newPos
		len1 := AbnfPos(len(src))

		for ; newPos < len1 && IsHostname(src[newPos]); newPos++ {
		}

		if newPos <= pos {
			context.parsePos = newPos
			context.AddError(newPos, "sip-host parse: null hostname")
			return false
		}

		ok = this.SetHostname(context, src[pos:newPos])
		if !ok {
			context.parsePos = newPos
			context.AddError(newPos, "sip-host parse: no mem for hostname")
			return false
		}
		context.parsePos = newPos
		return true
		//*/

}

func (this *SipHostPort) SetIpv4(context *ParseContext, ip []byte) bool {
	addr := context.allocator.Alloc(4)
	if addr == ABNF_PTR_NIL {
		return false
	}

	copy(addr.GetAsByteSlice(context, 4), ip)

	/*
		    ipv4 := addr.GetAsByteSlice(context, 4)

			ipv4[0] = ip[0]
			ipv4[1] = ip[1]
			ipv4[2] = ip[2]
			ipv4[3] = ip[3]
			//*/

	/*
		p := context.allocator.GetMem(addr)

		*((*byte)(unsafe.Pointer(p))) = ip[0]
		*((*byte)(unsafe.Pointer(p + 1))) = ip[1]
		*((*byte)(unsafe.Pointer(p + 2))) = ip[2]
		*((*byte)(unsafe.Pointer(p + 3))) = ip[3]
	    //*/

	this.id = HOST_TYPE_IPV4
	this.data = addr
	return true
}

func (this *SipHostPort) SetIpv6(context *ParseContext, ip net.IP) bool {
	addr := context.allocator.Alloc(16)
	if addr == ABNF_PTR_NIL {
		return false
	}

	ipv6 := addr.GetAsByteSlice(context, 16)
	copy(ipv6, ip)

	/*
		ipv6[0] = ip[0]
		ipv6[1] = ip[1]
		ipv6[2] = ip[2]
		ipv6[3] = ip[3]
		ipv6[4] = ip[4]
		ipv6[5] = ip[5]
		ipv6[6] = ip[6]
		ipv6[7] = ip[7]
		ipv6[8] = ip[8]
		ipv6[9] = ip[9]
		ipv6[10] = ip[10]
		ipv6[11] = ip[11]
		ipv6[12] = ip[12]
		ipv6[13] = ip[13]
		ipv6[14] = ip[14]
		ipv6[15] = ip[15]
		//*/
	this.id = HOST_TYPE_IPV6
	this.data = addr
	return true
}

func (this *SipHostPort) SetHostname(context *ParseContext, hostname []byte) bool {
	addr := AllocCString(context, hostname)
	if addr == ABNF_PTR_NIL {
		return false
	}

	this.id = HOST_TYPE_NAME
	this.data = addr
	return true
}
