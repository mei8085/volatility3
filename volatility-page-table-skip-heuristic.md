# Volatility3 页表扫描去重启发式的反取证风险分析

**分析对象：** `/srv/fb2/mei8085/0170-volatility3-4-4231da31`（branch `task/170`，HEAD `77ff0b1`）
**核心代码：** `volatility3/framework/layers/intel.py:269-306`（`_get_valid_table`）及其调用链
**结论摘要：** 该启发式把“性能优化”直接编码进**地址翻译层**，而不是扫描器里。后果是：一个字节级完全相同的页表会被判定为“不存在”，从而让一段**内容互不相同的合法虚拟地址空间**在 `read()`/`is_valid()`/`scan()` 三条路径上同时消失。攻击者只需要让某一级页表的所有表项字节相同（不要求映射相同内容），即可让该级以下的整个子树对取证工具不可见。这是可被主动工程化的隐藏通道，而非理论边角。

---

## 1. 代码事实：跳过启发式在做什么

### 1.1 位置与语义

`Intel._get_valid_table` 是**每一次**地址翻译的必经点：

```python
# volatility3/framework/layers/intel.py:269-306
@functools.lru_cache(maxsize=1025)
def _get_valid_table(self, base_address: int) -> Optional[bytes]:
    try:
        table = self._context.layers.read(
            self._base_layer, base_address, self.page_size
        )
    except exceptions.InvalidAddressException:
        return None

    if table == table[: self._entry_size] * self._entry_number:
        return None
    return table
```

判定规则只有一条：**把整页页表的前 8 字节（x64）重复 `page_size // entry_size` = 512 次，与整页比较是否相等。** 相等即返回 `None`。调用方 `_translate_entry`（`intel.py:230-238`）把 `None` 翻译成一次 `PagedInvalidAddressException`。

由此得到关键的语义偷换：

| 真实情况 | 层返回给上层的东西 |
|---|---|
| 页表物理页**不可读**（dump 缺失、读取失败） | `None` → `Page Fault ... in table page table` |
| 页表物理页**可读但字节均匀**（本次启发式） | `None` → **完全相同**的异常与文本 |

两种情况的异常类型、`invalid_bits`、日志文本**逐字相同**。实测（`demo21.py`）：两者都返回 `None`，且 `_get_valid_table` 自身**不产生任何日志**（捕获到的日志记录数 = 0）。因此“被启发式跳过”与“证据真的读不到”在默认输出里不可区分。

### 1.2 注释里的自认

源码注释（`intel.py:298-303`）明确承认了这一取舍：

> "This does have the side effect of preventing entirely duplicated page tables from reporting as present, however, the trade off between Windows 10+ reduced scanning times ... versus incorrectly reporting entire page tables of identically mapped repeating *valid* data (rare) was accepted"

注释用了两个关键措辞：**"identically mapped"** 和 **"valid data (rare)"**。下面会证明，实际判定条件既不是"identically mapped"，也不要求内容重复，而且攻击者可以把"rare"变成"按需"。

### 1.3 适用面：不只是 Windows

启发式在基类 `Intel` 上，因此 `Intel32e` / `IntelPAE` / `Intel` 及所有 mixin 子类都继承它。实测（`demo3.py`、`demo20.py`）：

```
LinuxIntel32e  va 0x200000 -> PagedInvalidAddressException(bits=30)
Intel32e       va 0x200000 -> PagedInvalidAddressException(bits=30)
uses base _get_valid_table: True
```

Linux（`LinuxIntel*`）与 macOS（automagic 直接用 `intel.Intel32e`，见 `automagic/mac.py:91,130`）同样受影响。**这不是一个 Windows 10 特有的性能补丁，而是所有 x86/x64 页表层共享的行为。**

---

## 2. 缓存键与失效边界

### 2.1 两层 `lru_cache` 的实际键

| 装饰器 | 位置 | 键 | 值 | maxsize |
|---|---|---|---|---|
| `_translate_entry` | `intel.py:184-185` | `(self, page_address)` | `(entry, position)` | 1024 |
| `_get_valid_table` | `intel.py:269-270` | `(self, base_address)` | `bytes` 或 `None` | 1025 |

`functools.lru_cache` 作用于**方法**时，`self` 是缓存键的一部分。实测（`demo6.py`）：

```
underlying function shared: True
bound-method identity differs (self is part of key): True
```

含义：
- **跨层实例不会串味**：两个层即使 `base_address` 相同，键也不同。实测 A/B 两层的同名页表地址读到各自内容（`demo6.py`）。
- **缓存是类级共享的**：`currsize` 是全部层实例的**总和**，上限 1025。同时存在的进程层越多（每个 `add_process_layer` 都新建一个 `Intel` 实例，见 `symbols/generic/__init__.py:52`），有效命中率越低。实测 1200 个短命层时缓存被填满到 1025（`demo25.py`D）。

### 2.2 缓存会保留层实例

`self` 进键意味着缓存持有强引用。实测（`demo25.py`）：

```
A) only _get_valid_table() called
  alive: True ... after gvt.clear alive: False
B) only _translate_entry() called
  alive: True ... after te.clear alive: True
C) only read() called
  alive: True ... after read.clear alive: True
```

任何一次 `read()` 都会经 `LinearlyMappedLayer.read` 的 `lru_cache(maxsize=512)`（`layers/linear.py:39`）和 `Linear` 层的缓存放住实例。进程层在批量插件里逐进程构造，内存与缓存清扫因此具有取证工程上的影响（也让"重扫一遍得到同样答案"依赖于缓存未被驱逐）。

### 2.3 负缓存：不可读会变成"永久不可读"

`_get_valid_table` 把**读取失败**也缓存为 `None`。一旦某次读取因瞬时/局部原因失败，后续同一 `(layer, base_address)` 的翻译会一直返回该负结果，直到缓存项被驱逐或显式 `cache_clear()`。实测（`demo4.py`）：

```
1st read (PD unreadable): PagedInvalidAddressException bits=30
2nd read (PD readable again): PagedInvalidAddressException bits=30   <-- 仍失败
3rd read (after cache_clear): OK
```

注意这里的耦合：**跳过（uniform）与失败（unreadable）共用同一个 `None` 返回值和同一份负缓存**。取证工具有意重读一个曾被跳过的区间是常见操作（例如换了 `sections` 再扫），但它拿回的仍是旧的否定结论。

### 2.4 扫描终止条件

`DataLayerInterface.scan`（`interfaces/layers.py:209-288`）的终止行为值得单独列出，因为它决定"发现被隐藏"是否可被察觉：

```python
# 209-288 概略
if sections is None:
    sections = [(self.minimum_address, self.maximum_address - self.minimum_address)]
sections = list(self._coalesce_sections(sections))
try:
    ... scan_iterator ...
except Exception as e:
    vollog.debug(f"Scan Failure: {str(e)}")
    # 然后什么都不再 yield
```

三条终止/吞异常路径：

1. **兜底 `except Exception`（`layers.py:280-288`）**：任何异常（包括 scanner 自己抛错、`sections` 为空导致的 `ValueError`）都只写 `vollog.debug`，默认日志级别下**不可见**，扫描静默结束。实测（`demo13.py`）：scanner 抛 `RuntimeError` → 扫描在第一个 chunk 后静默停止，0 条结果，无输出。
2. **`_scan_chunk` 吞读错误（`layers.py:360-365`）**：多块 chunk 中单个块读失败时，**丢弃该块但不报错**，扫描继续。
3. **`_coalesce_sections` 的越界裁剪 bug（`layers.py:314-319`）**：`result[1] = ...` 应为 `result[-1]`。实测（`dbg4.py`）：
   - `[(max, 0x1000)]` → `IndexError: list assignment index out of range`（被上面的兜底 except 吞掉）
   - `[(0x1000, 0x1000), (max, 0x1000)]` → 返回 `[(0x1000, 0x1000), (max, 0)]`，把合法 section 截成**零长度**

第 3 点与本题的关联：当插件传入的 `sections` 恰好触及 `maximum_address` 时，最后一个 section 被静默清零，扫描覆盖面在无人察觉的情况下缩小。

---

## 3. 合成页表演示：如何隐藏与延迟发现

以下实验都基于自建合成镜像（脚本在 `/tmp/ptdemo/scripts/`，不读取任何外部样本）。构造方法：4 级页表，`PML4[0] → PDPT[0] → PD → PT`，叶子 PT 映射 512 个**内容各不相同**的物理页，每页都写入特征串 `PAYLOAD!!`。

### 3.1 攻击 A：让非叶子表"字节均匀"来隐藏整棵子树

关键点：启发式比较的是**页表页的字节**，不是"这些表项指向同一内容"。只要 512 个表项字节相同，整张表就被判无效——**哪怕它下面是一整棵内容各异的子树**。

```
# demo14.py "uniform_pd": 512 个 PD 表项全部 = present(0x7000)
#   即 1 GiB 虚拟地址都别名到同一张叶子 PT（该 PT 映射 512 个不同物理页）
```

实测（`demo14.py` A 段）：

```
PD bytes uniform: True
va         0x0: read PagedInvalidAddressException(bits=30)
va    0x200000: read PagedInvalidAddressException(bits=30)
va  0x20000000: read PagedInvalidAddressException(bits=30)
scan over 1 GiB: hits=0 bytes_scanned=0
-> 512 distinct physical pages carrying the payload are invisible
```

**1 GiB 虚拟区间、512 个真实存在的活动页，`read` 全程 `Page Fault`，`scan` 一个字节都没读。** 注意这里"隐藏"的并不是某个页——是**整棵子树**。这正是 `_mapping` 里 `skip_mask = (1 << excp.invalid_bits) - 1` 的计算结果：`invalid_bits=30` 意味着扫描器一次跳过 1 GiB。

各级的跳过量（实测 `demo5.py`，x64/4KiB）：

| 均匀的层级 | `invalid_bits` | 单次跳过 |
|---|---|---|
| page table | 21 | 2 MiB |
| page directory | 30 | 1 GiB |
| page directory pointer | 39 | 512 GiB |
| page map level 4 | 48 | 256 TiB（覆盖整个规范地址空间） |

32 位与 PAE 同理（`demo21.py`）：`Intel` 的 PT 均匀 → `invalid_bits=22`（4 MiB）；PAE 的 PD 均匀 → 30（1 GiB）。

### 3.2 攻击 B：一个比特之差翻转整段可见性

把上面同一张 PD 的**一个**表项改一个 flag 位（不改指向），页表字节不再均匀：

```
# demo14.py B 段
PD bytes uniform: False
va         0x0: read OK b'PAYLOAD!'
va    0x200000: read OK b'PAYLOAD!'
va  0x20000000: read OK b'PAYLOAD!'
scan over 1 GiB: hits=262144 bytes_scanned=1,073,741,824
```

对比 A 段的 `hits=0 / bytes_scanned=0`。**单个比特决定 1 GiB 是被完全扫描还是完全消失。** 这是该启发式作为反取证原语的本质：开关成本极低（一次表项写入），效果是全有或全无。

### 3.3 攻击 C：把叶子表做成"均匀"来制造幻影重复

若有证据页需要被引用，攻击者也可反向利用：让叶子 PT 的 512 个表项字节相同（全部指向同一物理页）。此时该表被判定为"整表重复"并跳过：

```
# demo14.py C 段
read va 0: PagedInvalidAddressException(bits=21)
read va 0x1000: PagedInvalidAddressException(bits=21)
scan 2MiB: hits= 0
```

物理页本身完全可读、特征串就在那里，但虚拟地址空间里它"不存在"。

### 3.4 延迟发现：滥用"扫描要读多少"

攻击 B 的代价不对称。均匀表被跳过 → 扫描 0 字节、约 0.1 ms。非均匀但内容重复的表 → 扫描器必须把每个表项都当真，实测（`demo14.py` D/E 段）：

```
uniform_pd     : bytes=           0 hits=      0      0.1 ms
nonuniform_pd  : bytes=1,073,741,824 hits= 262144   3764.1 ms
```

即 **1 GiB → 3.76 s**。更极端的形态（`demo14.py` D 段）：PT 的 512 个表项只因 A/D 位不同而"非均匀"，全部指向同一物理页：

```
scan 2MiB: hits=512 all decode to physical 0x300000: True
duplicates of identical content: 512
```

同一个物理页被上报 **512 次**。这既是**重复报告**（同一内容在输出里出现 512 次，稀释真实信号），也是**性能武器**：把大量表项做成"仅 flag 不同"可以让扫描代价按表项数线性膨胀，而每条结果都需要插件后续解析。攻击者因此可以在"完全隐藏"（均匀）与"耗死扫描器 + 淹没输出"（仅 flag 不同）之间连续调节。这与题面所说的"把性能收益与取证完整性放在同一条路径上"完全吻合：**同一条 `table == ...` 判定同时是性能开关和可见性开关。**

### 3.5 其他合成形态

- **32 位 / PAE 的同一攻击**：结构不同（`Intel` 是 1024×4 字节，`IntelPAE` 是 512×8 字节），判定逻辑相同，跳过量分别为 4 MiB/1 GiB（`demo21.py`）。
- **Windows transition PTE / Linux PROT_NONE**：`WindowsMixin._page_is_valid` 与 `LinuxMixin._is_pte_present` 分别定义了"有效"（`intel.py:493-504`、`601-608`），但跳过判定发生在**读取子表**时（`intel.py:230-238`）：此时校验的是**父表项**，而该表内 512 个子表项从未被逐个检查有效性——整张表先被拒绝，子表项的 `_page_is_valid` 根本不会执行。因此 OS 特有的"有效"语义（transition / PROT_NONE）对跳过判定没有影响，各 mixin 行为一致（`demo20.py` 验证）。

---

## 4. 性能优化 vs 证据完整性：边界在哪里

把两条目标分开看，边界其实很清晰：

| 关注点 | 优化想要的 | 完整性要求的 |
|---|---|---|
| 判定对象 | 表项**指向同一物理页**（真重复） | 表项**指向的内容是否可区分** |
| 判定粒度 | 可跳过即跳过 | 任何非零信息都必须保留可达性 |
| 失败语义 | 快 | 与"读不到"必须可区分 |
| 可观测性 | 无需 | 跳过必须被记录、可审计、可关闭 |

当前实现把第一条做到了极致（整页字节比较，O(1)），但**代价是把"表项内容相同"当成了"表项没有信息"**。这两者不等价：一个非叶子表项即使重复，其**存在本身**决定了 512 个下级页是否可达；一个叶子表项即使重复，也定义了哪些虚拟地址映射到该页。

因此可以给出边界判据：

1. **只在叶子层做跳过**：非叶子表的"重复"必然意味着子树别名，跳过它等于删除子树，风险远大于收益。叶子层跳过最多影响 512 个地址映射，且语义可精确描述。
2. **跳过必须可见**：每一次跳过都应产生一条可审计记录（层级、基址、覆盖范围、原因），而不是返回与"读取失败"相同的 `None`。
3. **跳过必须可关闭**：取证场景需要"我要求全量、宁可慢"的开关。
4. **性能收益应计入，但不得改写翻译语义**：可以用显示器/统计/`sections` 剪枝等方式提速，而不应在翻译层"假装地址不存在"。

---

## 5. 可观察结果：误跳过 / 重复报告 / 不可读页

这三者在当前实现下的可观察结果**高度重合**，这正是问题所在。

### 5.1 误跳过（false skip）

- `read(va, n)` → `PagedInvalidAddressException`，`invalid_bits` 等于该层表项位数。
- `is_valid(va)` → `False`。
- `translate(va, ignore_errors=True)` → `(None, None)`。
- `scan` → 该区间**不被读取**（`bytes_scanned` 不增加），无任何告警。
- **与"页表物理页不可读"的输出完全相同**（`demo21.py`：两者 `_get_valid_table` 均返回 `None`，日志记录数均为 0）。

### 5.2 重复报告（duplicate reporting）

- 表项仅差 flag 位时，表被判定为"非均匀"，扫描器对同一物理页重复上报。
- 实测 2 MiB 区间内同一物理页被上报 512 次（`demo14.py` D）。
- 在 1 GiB 规模上为 262,144 条结果（`demo14.py` B/E）。
- 重复结果进入插件的 `TreeGrid` 后，要么产生大量重复行，要么由插件各自去重。**去重发生在插件层，而不是层**，且各插件的去重键互不相同（例如 `svcscan.py:304,360-362` 的 `seen` 列表按 `_SERVICE_RECORD` 对象去重，与物理页无关）。这意味着"同一物理页是否在输出里出现多次"取决于具体插件，而不是框架保证。

### 5.3 不可读页（unreadable page）

三个互相独立的静默降级：

1. **负缓存**（§2.3）：一次失败永久失败，直到驱逐。
2. **`_scan_chunk` 丢块**（`layers.py:360-365`）：chunk 内单块读失败被吞，其余块照常扫描，**无任何输出**。实测（`demo17.py`）：一个 4 页迭代值中第 4 块失败 → 前 3 块正常产出，第 4 块**静默为空**。
3. **多块 chunk 的偏移错配**（`layers.py:357-371`）：

   ```python
   data = b""
   for layer_name, address, chunk_size in data_to_scan:
       try:
           data += self.context.layers[layer_name].read(address, chunk_size)
       except exceptions.InvalidAddressException:
           ...  # 丢弃该块
   progress.value = chunk_end
   return list(scanner(data, chunk_end - len(data)))
   ```

   `data` 少了某块，但 `data_offset` 仍按 `chunk_end - len(data)` 计算。若一个 chunk 原本由多个**物理不连续但虚拟连续**的块拼成，丢块会让后续所有字节的虚拟地址**前移**。直接构造多块迭代值实测（`demo18.py`）：
   ```
   blocks: 4 个虚拟连续、物理分散的块
   no failure:            results=[('0x8',0), ('0x1008',1), ('0x2008',2), ('0x3008',3)]
   block 1 unreadable:    results=[('0x1008',0), ('0x2008',2), ('0x3008',3)]
   misattributed: [('0x1008', 0)]      # 报告 VA 0x1008，实际内容来自页 0
   ```

   即**第 2 页的内容被冠以第 3 页的虚拟地址上报**。这是比"漏报"更危险的失败模式：输出看起来正常、地址看起来合法，但内容与地址的对应关系已经错了。

   **可达性说明（诚实边界）**：在标准 Intel 线性层上，`_scan_iterator` 对每个 chunk 只生成一个 block（实测 `demo19.py`/`demo23.py`，多种 chunk/overlap/物理步长组合下 `multi_block=0`）。多块路径主要在 `TranslationLayerInterface._scan_iterator`（`layers.py:537-613`）经由带散列的映射产生，或当调用方直接构造/包装迭代值时触发。因此上面这条偏移错配是**框架合约层面的缺陷**（它确实会在 `demo18.py` 的输入下发生），但在纯 Intel 页表层 + 默认 `_scan_iterator` 的常规路径上不易触发。报告中不把它当作对 Intel 的既成攻击面，而作为"不可读页"这一类失败的独立风险点列出。

### 5.4 `pad=True` 把误跳过变成静默零填充

大量插件用 `pad=True` 读取（`vadinfo.py:189`、`layerwriter.py:81`、`regexscan.py:66`、多处 `malware/malfind` 等）。`LinearlyMappedLayer.read`（`linear.py:39-67`）在 `pad=True` 时对页错误**补零**：

实测（`demo13.py`，均匀表区间）：

```
pad=False -> PagedInvalidAddressException bits=21
pad=True  -> 8192 bytes, all_zero=True
is_valid(0): False
```

跨"已映射 → 被跳过 → 已映射"的读取（`demo24.py`）：

```
page0 mapped         is_valid=True
2MB uniform PT       is_valid=False read=FAULT
4MB mapped           is_valid=True
pad=True read 0..6MB: len=0x600000 zeros_in_2MB_window=True
```

后果链：
- `layerwriter` 会把被跳过区间写成**全零**，导出镜像看似完整。
- `vadinfo --dump` 会把被跳过的 VAD 写成全零 `.dmp`，且不报错（`vadinfo.py:189` 后直接写文件）。
- `regexscan` 在零填充上重新匹配必然失败，**静默丢掉该区域的所有命中**（`regexscan.py:66-78`）。
- `malware/malfind.is_vad_empty`（`malfind.py:53-79`）用 `read != all_zero_page` 判断"VAD 为空"——被跳过的 VAD 正好全零，于是被分类为**空 VAD 并忽略**。这是最直接的误判：**隐藏的注入页被 malfind 当成了"本来就没有数据"。**

---

## 6. 修复判据（兼顾扫描性能与证据完整性）

以下判据按"能否单独实施"排列，每条都标注了它解决的问题与代价。

### 判据 1：把"跳过"与"失败"的返回值分开

**要求**：`_get_valid_table` 不得用同一个 `None` 表达"不可读"和"均匀"。至少应返回三态（`VALID` / `UNREADABLE` / `SKIPPED`），并让 `_translate_entry` 产生**不同的异常或携带不同元数据**（例如 `PagedInvalidAddressException` 增加 `skip_reason`）。

**解决**：§1.1 的语义偷换、§5.1 的不可区分性。
**代价**：需改 `_translate_entry`、`_mapping` 的 `skip_mask` 逻辑，以及依赖 `invalid_bits` 的调用点。极小性能成本。

### 判据 2：跳过判定只允许作用于叶子层，且必须要求"映射同一目标且目标非空"

**要求**：对非叶子层级（PML4/PDPT/PD/PD）**永远不做整表跳过**；对叶子层，均匀性判定应附加条件：所有表项不仅字节相同，还必须 `present` 且指向同一 PFN。

**理由**：非叶子"字节均匀"= 子树别名，跳过等于删子树（§3.1 的 1 GiB 例子）。叶子层跳过的最大损失是 512 个地址映射，且语义明确。
**代价**：PD 级跳过的收益（1 GiB/次）会消失，这部分性能需要从别处补（见判据 4）。这是**唯一需要真正权衡性能的条目**，建议作为可配置项而非默认。

### 判据 3：跳过必须可审计、可关闭

**要求**：
- 每次跳过产生一条 `vollog` 记录（建议 `LOGLEVEL_VV` 而非 `debug`），字段至少含：层名、表基址、层级、覆盖虚拟区间、原因。
- 暴露一个明确的配置开关（如层配置 `skip_uniform_tables`，默认值可按 OS/版本区分），供"全量、宁可慢"的取证模式关闭。
- 提供统计计数（跳过了多少张表、覆盖多少字节），在插件结束时可选输出。

**解决**：§5.1 无告警、§5.4 pad 静默补零。
**代价**：无性能损失（记账只在发生跳过时做）。

### 判据 4：性能收益改为"可观测的剪枝"，而不是"改写翻译语义"

**要求**：把提速手段移到**不改变地址可达性**的层次：
- 用 `sections` 精确剪枝（插件已知 VAD/模块范围时），避免扫描无关区间；
- 对重复上报做**框架级去重**（按 `(physical_offset, content_hash)`），而不是在插件各写各的；
- 若确实要保留整表跳过，必须走判据 2+3（仅叶子层、可审计、可关闭）。

**解决**：§3.4 的重复报告/性能武器、§5.2 的插件间不一致。
**代价**：需要改造插件侧 `sections` 供给与结果去重，属于工程投入而非算法成本。

### 判据 5：负缓存必须可失效

**要求**：`_get_valid_table` 的缓存项在以下情况必须失效：底层层发生了新的读取错误（可对 `UNREADABLE` 结果不做缓存，或做短 TTL），以及层被重新配置/重扫时。至少，`scan()` 遇到 `UNREADABLE` 时应清空相关缓存重试一次。

**解决**：§2.3 的"一次失败永久失败"。
**代价**：轻微，仅在失败路径增加逻辑。

### 判据 6：`_scan_chunk` 的偏移错误必须修复

**要求**：多块 chunk 中存在读失败时，**不能**用 `chunk_end - len(data)` 当 `data_offset`。应逐块记录每块的 `(virtual_offset, data)` 并分别喂给 scanner，或在缺块时**整块放弃并显式告警**，绝不产出地址错配的结果。

**解决**：§5.3 的偏移错配（`demo18.py`）。
**代价**：小；需要把 `_scan_chunk` 从"拼一个大 bytes"改为"按块喂数据"。

### 判据 7：终止条件不得静默

**要求**：
- `scan()` 的兜底 `except Exception`（`layers.py:280`）至少提升到 `vollog.warning`，并在返回**部分结果**时让调用方可感知（如返回生成器时附带一个 `complete` 标志，或抛出可捕获的 `ScanInterrupted`）。
- 修复 `_coalesce_sections` 的 `result[1]` → `result[-1]`（`layers.py:319`），避免合法 section 被清零。
- `sections` 为空时应明确报错而不是被兜底吞掉。

**解决**：§2.4 的三条静默终止路径。
**代价**：几乎为零，属于纯 bug 修复。

---

## 7. 结论

这条启发式的根本问题不是"跳过"本身，而是**跳过的判定对象（页表字节）与取证关心的对象（地址可达性与内容）之间发生了语义漂移**，并且这个漂移被放在**翻译层**——所有插件、所有 OS mixin、所有 `read`/`is_valid`/`scan` 路径都无条件继承它。

把本报告的要点压缩成一个判断：

> 当前实现的"均匀表 = 不存在"是一条**功能上正确、证据上不成立**的等价关系。它让攻击者可以用一次表项写入把 1 GiB 地址空间变成 `Page Fault`（§3.1），用一次比特翻转把它又变回完全可见（§3.2），并在被跳过的区间上让 `pad=True` 的读取者和 `malfind` 把它当成"本来就没有数据"（§5.4）。而所有这一切与"页表真的读不到"在输出上无法区分（§1.1、§5.3）。

修复的正确顺序是：**先拆语义（判据 1、6、7），再限范围（判据 2），最后补可观测与开关（判据 3、4、5）**。其中判据 2 是唯一需要牺牲性能的条目，应在有 §3.4 所示的量化数据（均匀 vs 非均匀的 0.1 ms vs 3.76 s）支持下，作为**可配置策略**而非硬编码默认值来决定。

---

## 附录：复现脚本

所有实验脚本位于 `/tmp/ptdemo/scripts/`（自建合成数据，不读取外部样本）：

| 脚本 | 验证内容 |
|---|---|
| `demo.py` | 基础翻译与手工构造页表 |
| `demo2.py` | 目录级跳过放大、缓存键 |
| `demo3.py` | 均匀 vs 一条差异的代价与可观察性 |
| `demo4.py` | 负缓存污染 |
| `demo5.py` | 各级 `invalid_bits` 与跳过量 |
| `demo6.py` | 缓存键包含 `self`，跨实例不串味 |
| `demo9/10/11/12.py` | 不可读页与偏移行为（部分为排查过程的中间脚本） |
| `demo13.py` | `pad=True` 补零、`sections` 越界、异常吞没 |
| `demo14.py` | 隐藏子树、单比特翻转、重复报告、性能对比（主证据） |
| `demo15/16/25.py` | 缓存保留层实例、负缓存 |
| `demo17/18.py` | `_scan_chunk` 丢块与多块偏移错配 |
| `demo19/22/23.py` | 多块 chunk 在 Intel 层的可达性 |
| `demo20.py` | Windows transition / Linux PROT_NONE 的跳过行为 |
| `demo21.py` | 32 位/PAE 跳过量、无诊断日志 |
| `demo24.py` | 跨映射/跳过/映射的 `pad=True` 读取 |

报告中的代码路径均以 `文件:行号` 引用基于 HEAD `77ff0b1` 的实际文件。
