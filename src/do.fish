#!/usr/bin/fish

set SOURCE_C "/Users/nan/bs/aot/src/verifier.c"
set OUTPUT_DIR "/Users/nan/bs/aot/src/verifier"
mkdir -p $OUTPUT_DIR

# 1. 获取所有函数名
set FUNCTIONS (ctags -x --c-kinds=f $SOURCE_C | awk '{print $1}')

for func in $FUNCTIONS
    # 2. 提取前缀 (按第一个下划线分割)
    set -l parts (string split -m 1 "_" $func)
    set -l prefix $parts[1]
    
    # 3. 获取函数起始行号
    set -l start_line (ctags -x --c-kinds=f $SOURCE_C | grep "^$func " | awk '{print $3}')
    
    if test -n "$start_line"
        echo "Extracting $func -> $OUTPUT_DIR/$prefix.rs"
        
        # 写入注释标注来源
        echo "// Extracted from $SOURCE_C" >> $OUTPUT_DIR/$prefix.rs
        
        # 4. 提取函数体
        # sed 在 fish 中引用变量需要直接用双引号
        sed -n "$start_line,/^\}/p" $SOURCE_C >> $OUTPUT_DIR/$prefix.rs
        
        # 补一个换行符
        echo -e "\n" >> $OUTPUT_DIR/$prefix.rs
    end
end