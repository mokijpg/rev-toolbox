import struct, sys, argparse


def find_section(data, rva):
    """给定整个文件和一个RVA,返回(节名, VA, 文件偏移); 找不到返回 None"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("不是 PE 文件：缺少 MZ 头")

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe+4] != b"PE\x00\x00":
        raise ValueError("不是 PE 文件：PE 签名不对")

    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    tbl = pe + 24 + opt_size


    for i in range(nsec):
        s = tbl + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode(errors="replace")
        va = struct.unpack_from("<I", data, s + 12)[0]  # VirtualAddress
        rsize = struct.unpack_from("<I", data, s + 16)[0]  # SizeOfRawData
        rptr = struct.unpack_from("<I", data, s + 20)[0]  # PointerToRawData
        if va <= rva < va + rsize:
            return name, va, rva - va + rptr

    return None


def dump(data, offset, n = 32):
    """打印 offset  起的 n 个字节，hex 一行、ascii 一行"""
    chunk = data[offset:offset + n]
    if not chunk:
        print("（超出文件末尾）")
        return
    print(" ".join(f"{b:02x}" for b in chunk))
    print("".join(chr(b) if 32 <= b < 127 else "." for b in chunk))

def load(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        sys.exit(f"找不到文件；{path}")   # sys.exit(字符串) 会打印到 stderr 并退出码 1
    except OSError as e:
        sys.exit(f"读不了这个文件：{e}")

def main():
    p = argparse.ArgumentParser(description="PE 地址换算：RVA -> 文件偏移")
    p.add_argument("exe", help="PE 文件路径")
    p.add_argument("rva", help="相对虚拟地址，十六进制，如 0x4000")
    p.add_argument("-d", "--dump", action="store_true", help="打印该处 32 字节")
    args = p.parse_args()

    try:
        rva = int(args.rva, 16)
    except ValueError:
        sys.exit(f"RVA 要写成十六进制：{args.rva}")

    data = load(args.exe)
    try:
        hit = find_section(data, rva)
    except ValueError as e:
        sys.exit(str(e))

    if hit is None:
        sys.exit(f"RVA 0x{rva:X} 不落在任何节里（文件共 0x{len(data):X} 字节）")

    name, va, foa = hit

    print(f"命中节区：{name} VA=0x{va:X}")
    print(f"RVA 0x{rva:X} -> 文件偏移 0x{foa:X}")
    if args.dump:
        dump(data, foa)


if __name__ == "__main__":
    main()







