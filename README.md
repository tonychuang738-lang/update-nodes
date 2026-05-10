# update-nodes

自動由機場訂閱拉啲節點落嚟，合併入 sing-box 配置檔案嘅 Python 腳本。

## 功能

- 支援多種訂閱格式：**sing-box JSON**、**Clash YAML**、**base64 URI 列表**
- 自動去重複節點
- 保留原有 sing-box 配置唔會整花
- 可選用本地訂閱檔案或者直接行網址

## 用法

```bash
python3 update_nodes.py
```

### 設定

開個檔案改前面幾行配置就得：

- `SUB_URL` — 機場訂閱網址
- `LOCAL_SUB_FILE` — 本地訂閱檔案路徑（留空就用網址）
- `OUTPUT_FILE` — 輸出嘅 sing-box JSON 路徑

## 需求

```bash
pip3 install requests pyyaml
```

## 注意

呢個腳本預設用咗指定嘅訂閱網址，如果你要用自己嘅機場，記得改返 `SUB_URL`。
