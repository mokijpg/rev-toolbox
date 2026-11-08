# rev-toolbox

逆向练习中写的小工具，每个都是因为某道题卡住了才写出来的。

## 环境要求
* Python 3.x

## tools/pe.py — PE 地址换算

**痛点 (Why I built this)：**
在 x64dbg 里看到的是内存地址（RVA），直接拿到 HxD 里按它找，根本找不到。因为**内存地址（VA）**和**文件偏移（File Offset）** 是两个坐标系，而且每个节区（Section）的换算差值都不一样，必须去查节表。每次做题都要手动翻节表算偏移，太折磨了。

**解决方案 (Features)：**
`pe.py` 用于快速将内存地址换算为文件偏移，并支持直接 dump 数据。自动解析 PE 节区，告别手动查表。

**使用示例：**
输入的是 RVA（x64dbg 里 模块名+偏移 的那个偏移，或 VA 减去模块基址）

```bash
python pe.py crackme3.exe 0x4000 -d

命中节区：.rdata VA=0x4000
RVA 0x4000 -> 文件偏移 0x2200
7a 66 5f 31 73 5f 6d 79 5f 6b 33 79 00 45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 3a 20 00 0d 0a
zf_1s_my_k3y.Enter password: ...
```
## License
MIT
