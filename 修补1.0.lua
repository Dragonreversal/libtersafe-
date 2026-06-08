-- 最终完整版：libtersafe.so 完全绕过 + 保留业务调用
-- 基于防守方提供的 IDA 反编译与汇编地址

local MOV_W0_RET = {0x52800000, 0xD65F03C0}   -- MOV W0, #0; RET
local RET_ONLY = {0xD65F03C0}                 -- RET
local NOP = 0xD503201F                        -- ARM64 NOP 指令

function get_tersafe_base()
    local ranges = gg.getRangesList('*libtersafe*.so*')
    for _, v in ipairs(ranges) do
        if v.type:find('x') then
            return v.start
        end
    end
    return nil
end

function patch_function(offset, insts)
    local base = get_tersafe_base()
    if not base then return false end
    local addr = base + offset
    local size = #insts * 4
    gg.memoryProtect(addr, size, gg.PROT_READ + gg.PROT_WRITE + gg.PROT_EXEC)
    for i, inst in ipairs(insts) do
        gg.setValues({{address = addr + (i-1)*4, flags = gg.TYPE_DWORD, value = inst}})
    end
    gg.memoryProtect(addr, size, gg.PROT_READ + gg.PROT_EXEC)
    return true
end

function patch_instruction(offset, inst)
    local base = get_tersafe_base()
    if not base then return false end
    local addr = base + offset
    gg.memoryProtect(addr, 4, gg.PROT_READ + gg.PROT_WRITE + gg.PROT_EXEC)
    gg.setValues({{address = addr, flags = gg.TYPE_DWORD, value = inst}})
    gg.memoryProtect(addr, 4, gg.PROT_READ + gg.PROT_EXEC)
    return true
end

function full_bypass()
    gg.setVisible(false)
    local base = get_tersafe_base()
    if not base then
        gg.alert("未找到 libtersafe.so 基址！")
        return
    end

    gg.alert("开始完整修补 libtersafe.so ...")

    -- 1. 置零全局回调指针
    gg.setValues({{address = base + 0x55E9B0, flags = gg.TYPE_QWORD, value = 0}})

    -- 2. 修补核心校验函数（始终返回0）
    patch_function(0x488F58, MOV_W0_RET)  -- sub_488F58
    patch_function(0x489030, MOV_W0_RET)  -- sub_489030
    patch_function(0x489334, MOV_W0_RET)  -- sub_489334

    -- 3. 阻止守护启动
    patch_function(0x1D40F0, MOV_W0_RET)  -- sub_1D40F0

    -- 4. 阻断上报链路
    patch_function(0x21D7E0, MOV_W0_RET)  -- sub_21D7E0
    patch_function(0x21DD38, MOV_W0_RET)  -- sub_21DD38
    patch_function(0x21E06C, MOV_W0_RET)  -- sub_21E06C
    patch_function(0x219B9C, RET_ONLY)    -- sub_219B9C
    patch_function(0x1F29D0, MOV_W0_RET)  -- sub_1F29D0

    -- 5. 修补 sub_4C0DCC 中的条件跳转，保留 sub_4C0914 调用
    patch_instruction(0x4C0E84, NOP)  -- CBNZ W0, loc_4C0EAC  → NOP
    patch_instruction(0x4C0E90, NOP)  -- CMP X8, X9          → NOP
    patch_instruction(0x4C0E94, NOP)  -- B.NE loc_4C0EAC     → NOP

    gg.alert("✅ 完整绕过成功！\n- 所有检测函数已返回0\n- 上报链路已切断\n- sub_4C0914 调用已保留\n\n注意：服务端仍可能因心跳缺失告警。")
end

function verify()
    local base = get_tersafe_base()
    if not base then return end
    local function check(offset, expected, name)
        local val = gg.getValues({{address = base + offset, flags = gg.TYPE_DWORD}})[1].value
        local ok = (val == expected)
        gg.toast(string.format("%s: %s", name, ok and "✓" or "✗"))
    end
    check(0x488F58, MOV_W0_RET[1], "sub_488F58")
    check(0x489030, MOV_W0_RET[1], "sub_489030")
    check(0x489334, MOV_W0_RET[1], "sub_489334")
    check(0x21D7E0, MOV_W0_RET[1], "sub_21D7E0")
    check(0x1F29D0, MOV_W0_RET[1], "sub_1F29D0")
    check(0x4C0E84, NOP, "CBNZ patch")
    check(0x4C0E94, NOP, "B.NE patch")
end

function main()
    local choice = gg.multiChoice({
        "【完全绕过】完整修补",
        "验证修补状态",
        "退出"
    }, nil, "TSS 最终完整绕过 v4.0")
    if not choice then return end
    if choice[1] then full_bypass() end
    if choice[2] then verify() end
    if choice[3] then os.exit() end
end

while true do
    if gg.isVisible(true) then
        gg.setVisible(false)
        main()
    end
    gg.sleep(100)
end
