import struct, sys, argparse


def parse_sections(data):
    """解析整个 PE 文件，返回包含所有节信息的列表: [(name, va, vsize, rsize, rptr), ...]"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("不是 PE 文件：缺少 MZ 头")

    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("不是 PE 文件：PE 签名不对")

    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    tbl = pe + 24 + opt_size

    secs = []
    for i in range(nsec):
        s = tbl + i * 40
        name = data[s:s + 8].rstrip(b"\x00").decode(errors="replace")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, s + 8)
        secs.append((name, va, vsize, rsize, rptr))

    return secs


def find_section(secs, rva):
    """正向：给定 RVA，返回(节名, 节基址VA, 文件偏移)"""
    for nm, va, vsize, rsize, rptr in secs:
        if not (va <= rva < va + max(vsize, rsize)):
            continue
        if rva - va >= rsize:  # 归属这节，但只在内存里
            return nm, va, None  # 文件里没有 → 交给 main 报错
        return nm, va, rva - va + rptr
    return None


def rva_of(secs, foa):
    """逆运算：文件偏移(FOA) -> (节名, 节基址VA, RVA)"""
    for nm, va, vsize, rsize, rptr in secs:
        if rptr <= foa < rptr + rsize:
            return nm, va, foa - rptr + va
    return None


def dump(data, offset, n=32):
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
        sys.exit(f"找不到文件；{path}")
    except OSError as e:
        sys.exit(f"读不了这个文件：{e}")


def main():
    p = argparse.ArgumentParser(description="PE 地址换算：RVA -> 文件偏移")
    p.add_argument("exe", help="PE 文件路径")
    p.add_argument("rva", help="相对虚拟地址或文件偏移，十六进制，如 0x4000")
    p.add_argument("-d", "--dump", action="store_true", help="打印该处 32 字节")
    p.add_argument("-r", "--rev", action="store_true", help="逆向：把参数当成文件偏移，返回 RVA")
    args = p.parse_args()

    try:
        rva = int(args.rva, 16)
    except ValueError:
        sys.exit(f"地址要写成十六进制：{args.rva}")

    data = load(args.exe)

    try:
        secs = parse_sections(data)
    except ValueError as e:
        sys.exit(str(e))

    # ================= 计算逻辑 =================
    if args.rev:
        hit, head, tail = rva_of(secs, rva), "文件偏移", "RVA"
    else:
        hit, head, tail = find_section(secs, rva), "RVA", "文件偏移"

    # ================= 统一打印逻辑 =================
    if hit is None:
        sys.exit(f"{head} 0x{rva:X} 不落在任何节里（文件共 0x{len(data):X} 字节）")

    # 【修正点】将中间变量改名为 sec_va，明确它只是节的基址
    nm, sec_va, out_addr = hit

    print(f"命中节区：{nm}")

    if out_addr is not None:
        # 【修正点】打印时使用输入 rva 和输出 out_addr，不再使用中间量 sec_va
        print(f"{head} 0x{rva:X} -> {tail} 0x{out_addr:X}")
        if args.dump:
            # 【修正点】dump 的地址：正向转换是结果(out_addr)，逆向转换是输入(rva)
            foa_to_dump = rva if args.rev else out_addr
            dump(data, foa_to_dump)
    else:
        sys.exit(f"{head} 0x{rva:X} 属于 {nm} 节，但该地址在文件里没有对应字节（装载时补零）")


if __name__ == "__main__":
    main()