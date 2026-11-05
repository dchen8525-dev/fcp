"""把 store 模式的 zip 压成 LZMA1_alone（供 fcp-launcher 解码）。

用法：python lzma_pack.py <src.zip> <out.lzma>

Python 的 FORMAT_ALONE 在流头写 8 字节原长；默认是 -1（未知），这里回填
真实长度，符合 LZMA_alone 的约定（引导器按尾部给出的长度精确解压，头里的
长度只是格式完整性的一部分）。
"""

import lzma
import struct
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, "rb") as f:
        data = f.read()
    blob = bytearray(
        lzma.compress(data, format=lzma.FORMAT_ALONE, preset=9 | lzma.PRESET_EXTREME)
    )
    if len(blob) < 13:
        print("lzma: 输出短于 LZMA_alone 头", file=sys.stderr)
        return 1
    blob[5:13] = struct.pack("<Q", len(data))
    with open(dst, "wb") as f:
        f.write(blob)
    print(f"lzma: {len(data)} -> {len(blob)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
