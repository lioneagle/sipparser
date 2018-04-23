package sipparser

import (
	//"fmt"
	"reflect"
	"strconv"
	"unsafe"

	"github.com/lioneagle/goutil/src/buffer"
	"github.com/lioneagle/goutil/src/chars"
)

const SLICE_HEADER_LEN = int32(unsafe.Sizeof(reflect.SliceHeader{}))
const ABNF_MEM_ALIGN = uint32(8)
const ABNF_MEM_LIGN_MASK = ^(ABNF_MEM_ALIGN - 1)
const ABNF_MEM_LIGN_MASK2 = (ABNF_MEM_ALIGN - 1)
const ABNF_MEM_PREFIX_LEN = 8

func RoundToAlign(x, align uint32) uint32 {
	return (x + align - 1) & ^(align - 1)
}

type MemAllocatorStat struct {
	allocNum      uint32
	allocNumOk    uint32
	freeAllNum    uint32
	freePartNum   uint32
	allocReqBytes uint32
	allocBytes    uint32
}

func (this *MemAllocatorStat) Init() {
	this.allocNum = 0
	this.allocNumOk = 0
	this.freeAllNum = 0
	this.freePartNum = 0
	this.allocReqBytes = 0

}

func (this *MemAllocatorStat) String() string {
	stat := []struct {
		name string
		num  uint32
	}{
		{"alloc num", this.allocNum},
		{"alloc num ok", this.allocNumOk},
		{"free all num", this.freeAllNum},
		{"free part num", this.freePartNum},
		{"alloc request bytes", this.allocReqBytes},
	}

	str := ""
	for _, v := range stat {
		str += v.name
		str += ": "
		str += strconv.FormatUint(uint64(v.num), 10)
		str += "\n"
	}
	return str
}

type MemAllocator struct {
	used uint32
	stat MemAllocatorStat
	mem  []byte
}

func NewMemAllocator(capacity uint32) *MemAllocator {
	ret := MemAllocator{}
	ret.Init(capacity)
	return &ret
}

func (this *MemAllocator) Init(capacity uint32) *MemAllocator {
	this.used = ABNF_MEM_PREFIX_LEN
	this.mem = make([]byte, int(capacity+ABNF_MEM_PREFIX_LEN))
	this.stat.Init()
	return this
}

func (this *MemAllocator) Stat() *MemAllocatorStat {
	return &this.stat
}

func (this *MemAllocator) Used() uint32 {
	return this.used - ABNF_MEM_PREFIX_LEN
}

func (this *MemAllocator) ClearAllocNum() {
	this.stat.allocNum = 0
}

func (this *MemAllocator) AllocReqBytes() uint32 {
	return this.stat.allocReqBytes
}

func (this *MemAllocator) AllocBytes() uint32 {
	return this.stat.allocBytes
}

func (this *MemAllocator) AllocNum() uint32 {
	return this.stat.allocNum
}

func (this *MemAllocator) AllocNumOk() uint32 {
	return this.stat.allocNumOk
}

func (this *MemAllocator) FreeAllNum() uint32 {
	return this.stat.freeAllNum
}

func (this *MemAllocator) FreePartNum() uint32 {
	return this.stat.freePartNum
}

func (this *MemAllocator) Capacity() uint32 {
	return uint32(cap(this.mem) - ABNF_MEM_PREFIX_LEN)
}

func (this *MemAllocator) Left() uint32 {
	return uint32(cap(this.mem)) - this.used
}

func (this *MemAllocator) GetMem(addr AbnfPtr) uintptr {
	if addr >= AbnfPtr(cap(this.mem)) {
		panic("ERROR: out of memory range")
	}
	return uintptr(unsafe.Pointer(&this.mem[addr]))
}

func (this *MemAllocator) ParseAndAllocCString(context *ParseContext, charsetIndex int, mask uint32) (addr AbnfPtr, ok bool) {
	charset := &g_charsets[charsetIndex]
	newPos := context.parsePos
	src := context.parseSrc
	len1 := AbnfPos(len(src))

	memEnd := uint32(cap(this.mem))
	used := this.used
	addr = AbnfPtr(this.used)

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	for ; newPos < len1; newPos++ {
		v := src[newPos]
		if ((charset[v]) & mask) == 0 {
			break
		}
		this.mem[used] = v
		used++
	}

	if newPos <= context.parsePos {
		context.AddError(newPos, "empty")
		return ABNF_PTR_NIL, false
	}

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	this.mem[used] = 0
	used++
	this.stat.allocNum++
	this.stat.allocNumOk++
	this.stat.allocReqBytes = used - this.used
	this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
	context.parsePos = newPos
	return addr, true
}

func (this *MemAllocator) ParseAndAllocCStringFromPos(context *ParseContext, pos AbnfPos, charsetIndex int, mask uint32) (addr AbnfPtr, ok bool) {
	charset := &g_charsets[charsetIndex]
	newPos := context.parsePos
	src := context.parseSrc
	len1 := AbnfPos(len(src))

	memEnd := uint32(cap(this.mem))
	used := this.used
	addr = AbnfPtr(this.used)

	if newPos < pos {
		if (uint32(pos-newPos) + used) >= memEnd {
			context.AddError(newPos, "no mem")
			return ABNF_PTR_NIL, false
		}
		/*copy(this.mem[used:], src[newPos:pos])
		used += uint32(pos - newPos)
		newPos = pos*/
		for ; newPos < pos; newPos++ {
			this.mem[used] = src[newPos]
			used++
		} //*/
	}

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	for ; newPos < len1; newPos++ {
		v := src[newPos]
		if ((charset[v]) & mask) == 0 {
			break
		}
		this.mem[used] = v
		used++
	}

	if newPos <= context.parsePos {
		context.AddError(newPos, "empty")
		return ABNF_PTR_NIL, false
	}

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	this.mem[used] = 0
	used++
	this.stat.allocNum++
	this.stat.allocNumOk++
	this.stat.allocReqBytes = used - this.used
	this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
	context.parsePos = newPos
	return addr, true
}

func (this *MemAllocator) ParseAndAllocCStringEnableEmpty(context *ParseContext, charsetIndex int, mask uint32) (addr AbnfPtr, ok bool) {
	charset := &g_charsets[charsetIndex]
	newPos := context.parsePos
	src := context.parseSrc
	len1 := AbnfPos(len(src))

	memEnd := uint32(cap(this.mem))
	used := this.used
	addr = AbnfPtr(this.used)

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	for ; newPos < len1; newPos++ {
		v := src[newPos]
		if ((charset[v]) & mask) == 0 {
			break
		}
		this.mem[used] = v
		used++
	}

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	this.mem[used] = 0
	used++
	this.stat.allocNum++
	this.stat.allocNumOk++
	this.stat.allocReqBytes = used - this.used
	this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
	context.parsePos = newPos
	return addr, true
}

func (this *MemAllocator) ParseAndAllocCStringEscapable(context *ParseContext, charsetIndex int, mask uint32) (addr AbnfPtr, ok bool) {
	charset := &g_charsets[charsetIndex]
	newPos := context.parsePos
	src := context.parseSrc
	len1 := AbnfPos(len(src))

	memEnd := uint32(cap(this.mem))
	used := this.used
	addr = AbnfPtr(this.used)

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	for {
		for ; newPos < len1; newPos++ {
			v := src[newPos]
			if ((charset[v]) & mask) == 0 {
				if v == '%' {
					break
				}

				if newPos <= context.parsePos {
					context.AddError(newPos, "empty")
					return ABNF_PTR_NIL, false
				}

				if used >= memEnd {
					context.AddError(newPos, "no mem")
					return ABNF_PTR_NIL, false
				}
				this.mem[used] = 0
				used++

				this.stat.allocNum++
				this.stat.allocNumOk++
				this.stat.allocReqBytes = used - this.used
				this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
				context.parsePos = newPos
				return addr, true
			}
			this.mem[used] = v
			used++
		}

		if newPos >= len1 {
			if newPos <= context.parsePos {
				context.AddError(newPos, "empty")
				return ABNF_PTR_NIL, false
			}

			if used >= memEnd {
				context.AddError(newPos, "no mem")
				return ABNF_PTR_NIL, false
			}
			this.mem[used] = 0
			used++
			this.stat.allocNum++
			this.stat.allocNumOk++
			this.stat.allocReqBytes = used - this.used
			this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
			context.parsePos = newPos
			return addr, true
		}

		if (newPos + 2) >= len1 {
			context.parsePos = newPos
			context.AddError(newPos, "reach end after '%'")
			return ABNF_PTR_NIL, false
		}

		v1 := src[newPos+1]
		v2 := src[newPos+2]

		if !IsHex(v1) || !IsHex(v2) {
			context.parsePos = newPos
			context.AddError(newPos, "not HEX after '%'")
			return ABNF_PTR_NIL, false
		}

		if used >= memEnd {
			context.AddError(newPos, "no mem")
			return ABNF_PTR_NIL, false
		}

		this.mem[used] = chars.UnescapeToByteEx(v1, v2)
		used++

		newPos += 3
	}

	if newPos <= context.parsePos {
		context.AddError(newPos, "empty")
		return ABNF_PTR_NIL, false
	}

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	this.mem[used] = 0
	used++
	this.stat.allocNum++
	this.stat.allocNumOk++
	this.stat.allocReqBytes = used - this.used
	this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
	context.parsePos = newPos
	return addr, true
}

func (this *MemAllocator) ParseAndAllocCStringEscapableEnableEmpty(context *ParseContext, charsetIndex int, mask uint32) (addr AbnfPtr, ok bool) {
	charset := &g_charsets[charsetIndex]
	newPos := context.parsePos
	src := context.parseSrc
	len1 := AbnfPos(len(src))

	memEnd := uint32(cap(this.mem))
	used := this.used
	addr = AbnfPtr(this.used)

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	for {
		for ; newPos < len1; newPos++ {
			v := src[newPos]
			if ((charset[v]) & mask) == 0 {
				if v == '%' {
					break
				}

				if used >= memEnd {
					context.AddError(newPos, "no mem")
					return ABNF_PTR_NIL, false
				}
				this.mem[used] = 0
				used++

				this.stat.allocNum++
				this.stat.allocNumOk++
				this.stat.allocReqBytes = used - this.used
				this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
				context.parsePos = newPos
				return addr, true
			}
			this.mem[used] = v
			used++
		}

		if newPos >= len1 {
			if used >= memEnd {
				context.AddError(newPos, "no mem")
				return ABNF_PTR_NIL, false
			}
			this.mem[used] = 0
			used++
			this.stat.allocNum++
			this.stat.allocNumOk++
			this.stat.allocReqBytes = used - this.used
			this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
			context.parsePos = newPos
			return addr, true
		}

		if (newPos + 2) >= len1 {
			context.parsePos = newPos
			context.AddError(newPos, "reach end after '%'")
			return ABNF_PTR_NIL, false
		}

		v1 := src[newPos+1]
		v2 := src[newPos+2]

		if !IsHex(v1) || !IsHex(v2) {
			context.parsePos = newPos
			context.AddError(newPos, "not HEX after '%'")
			return ABNF_PTR_NIL, false
		}

		if used >= memEnd {
			context.AddError(newPos, "no mem")
			return ABNF_PTR_NIL, false
		}

		this.mem[used] = chars.UnescapeToByteEx(v1, v2)
		used++

		newPos += 3
	}

	if used >= memEnd {
		context.AddError(newPos, "no mem")
		return ABNF_PTR_NIL, false
	}

	this.mem[used] = 0
	used++
	this.stat.allocNum++
	this.stat.allocNumOk++
	this.stat.allocReqBytes = used - this.used
	this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
	context.parsePos = newPos
	return addr, true
}

/* Parse quoted-string
 *
 * RFC3261 Section 25.1, page 222
 *
 * quoted-string  =  SWS DQUOTE *(qdtext / quoted-pair ) DQUOTE
 * qdtext         =  LWS / %x21 / %x23-5B / %x5D-7E
 *                 / UTF8-NONASCII
 * quoted-pair  =  "\" (%x00-09 / %x0B-0C
 *               / %x0E-7F)
 */
func (this *MemAllocator) ParseAndAllocSipQuotedString(context *ParseContext) (addr AbnfPtr, ok bool) {
	src := context.parseSrc
	newPos := context.parsePos
	len1 := AbnfPos(len(src))

	newPos, ok = ParseSWS(src, newPos)
	if !ok {
		context.parsePos = newPos
		return ABNF_PTR_NIL, false
	}

	if src[newPos] != '"' {
		context.parsePos = newPos
		context.AddError(newPos, "no DQUOTE for quoted-string begin")
		return ABNF_PTR_NIL, false
	}
	newPos++

	used := this.used
	addr = AbnfPtr(this.used)

	for (newPos < len1) && (src[newPos] != '"') {
		v := src[newPos]
		if IsLwsChar(v) {
			var ok bool

			context.parsePos = newPos
			this.used = used
			ok = this.ParseAndCopyLWS(context)
			if !ok {
				context.AddError(context.parsePos, "wrong LWS in quoted-string")
				return ABNF_PTR_NIL, false
			}
			newPos = context.parsePos
			used = this.used
		} else if IsSipQuotedText(v) {
			this.mem[used] = v
			used++
			newPos++
		} else if v == '\\' {
			if (newPos + 1) >= len1 {
				context.parsePos = newPos
				context.AddError(context.parsePos, "no char after '\\' in quoted-string")
				return ABNF_PTR_NIL, false
			}
			this.mem[used] = v
			this.mem[used+1] = src[newPos+1]
			used += 2
			newPos += 2
		} else {
			context.parsePos = newPos
			context.AddError(context.parsePos, "not qdtext or quoted-pair in quoted-string")
			return ABNF_PTR_NIL, false
		}
	}

	if newPos >= len1 {
		context.parsePos = newPos
		context.AddError(context.parsePos, "no DQUOTE for quoted-string end")
		return ABNF_PTR_NIL, false
	}

	newPos++
	this.mem[used] = 0
	used++
	this.stat.allocNum++
	this.stat.allocNumOk++
	this.stat.allocReqBytes = used - this.used
	this.used = RoundToAlign(used, ABNF_MEM_ALIGN)
	context.parsePos = newPos

	return addr, true
}

func (this *MemAllocator) ParseAndCopyLWS(context *ParseContext) (ok bool) {
	src := context.parseSrc
	newPos := context.parsePos
	len1 := AbnfPos(len(src))
	used := this.used

	for ; newPos < len1; newPos++ {
		if (src[newPos] != ' ') && (src[newPos] != '\t') {
			break
		} else {
			this.mem[used] = src[newPos]
			used++
		}
	}

	if (newPos + 1) >= len1 {
		context.parsePos = newPos
		this.used = used
		return true
	}

	if (src[newPos] == '\r') && (src[newPos+1] == '\n') {
		this.mem[used] = src[newPos]
		this.mem[used+1] = src[newPos]
		newPos += 2
		used += 2

		if newPos >= len1 {
			context.parsePos = newPos
			this.used = used
			return false
		}

		if (src[newPos] != ' ') && (src[newPos] != '\t') {
			context.parsePos = newPos
			this.used = used
			return false
		}

		for ; newPos < len1; newPos++ {
			if (src[newPos] != ' ') && (src[newPos] != '\t') {
				context.parsePos = newPos
				this.used = used
				return true
			}
			this.mem[used] = src[newPos]
			used++
		}
	}
	context.parsePos = newPos
	this.used = used
	return true
}

func (this *MemAllocator) Alloc(size uint32) (addr AbnfPtr) {
	this.stat.allocNum++
	this.stat.allocReqBytes += size

	if size <= 0 {
		return ABNF_PTR_NIL
	}

	newSize := RoundToAlign(this.used+size, ABNF_MEM_ALIGN)
	if newSize > uint32(cap(this.mem)) {
		return ABNF_PTR_NIL
	}
	used := this.used
	this.stat.allocNumOk++

	this.used = newSize

	return AbnfPtr(used)
}

func (this *MemAllocator) AllocWithClear(size uint32) (addr AbnfPtr) {
	this.stat.allocNum++
	this.stat.allocReqBytes += size

	if size <= 0 {
		return ABNF_PTR_NIL
	}

	newSize := RoundToAlign(this.used+size, ABNF_MEM_ALIGN)
	if newSize > uint32(cap(this.mem)) {
		return ABNF_PTR_NIL
	}
	used := this.used
	this.stat.allocNumOk++

	this.used = newSize

	//ZeroByteSlice(this.mem[used:newSize])
	ZeroMem(uintptr(unsafe.Pointer(&this.mem[used])), int(newSize-used))
	return AbnfPtr(used)
}

func (this *MemAllocator) AllocEx(size uint32) (addr AbnfPtr, allocSize uint32) {
	this.stat.allocNum++
	this.stat.allocReqBytes += size

	if size <= 0 {
		return ABNF_PTR_NIL, 0
	}

	used := this.used

	newSize := RoundToAlign(used+size, ABNF_MEM_ALIGN)
	if newSize > uint32(cap(this.mem)) {
		return ABNF_PTR_NIL, 0
	}

	this.stat.allocNumOk++
	this.used = newSize

	return AbnfPtr(used), newSize - used
}

func (this *MemAllocator) FreeAll() {
	this.stat.freeAllNum++
	this.used = ABNF_MEM_PREFIX_LEN
}

func (this *MemAllocator) FreePart(remain uint32) {
	this.stat.freePartNum++
	if remain >= this.used {
		return
	}
	this.used = remain + ABNF_MEM_PREFIX_LEN
	if this.used < ABNF_MEM_PREFIX_LEN {
		this.used = ABNF_MEM_PREFIX_LEN
	}
}

func (this *MemAllocator) String(memBegin, memEnd int) string {
	buf := buffer.NewByteBuffer(nil)
	this.Print(buf, memBegin, memEnd)
	return buf.String()
}

func (this *MemAllocator) Print(buf *buffer.ByteBuffer, memBegin, memEnd int) string {
	buf.Println("-------------------------- MemAllocator show begin ----------------------------")
	buffer.PrintAsHex(buf, this.mem, memBegin+ABNF_MEM_PREFIX_LEN, memEnd+ABNF_MEM_PREFIX_LEN)
	buf.Println("-------------------------------------------------------------------------------")
	buf.Println("MemAllocator stat:")
	buf.WriteString(this.stat.String())
	buf.Printfln("Used     = %d", this.Used())
	buf.Printfln("Left     = %d", this.Left())
	buf.Printfln("Capacity = %d", this.Capacity())
	buf.Println("-------------------------- MemAllocator show end   ----------------------------")
	return buf.String()
}
