-- Mantiene la sintaxis de los bloques de código en dirección LTR y aísla los
-- fragmentos de escrituras RTL. Los controles RLI/PDI son invisibles y solo se
-- incorporan al AST que Pandoc envía a LaTeX; los QMD no se modifican.

local RLI = utf8.char(0x2067)
local PDI = utf8.char(0x2069)

local function is_rtl(cp)
  return (cp >= 0x0590 and cp <= 0x08FF)
      or (cp >= 0xFB1D and cp <= 0xFDFF)
      or (cp >= 0xFE70 and cp <= 0xFEFF)
end

local function isolate_rtl_runs(text)
  local output = {}
  local run = {}
  local spaces = {}

  local function flush_run()
    if #run > 0 then
      output[#output + 1] = RLI
      output[#output + 1] = table.concat(run)
      output[#output + 1] = PDI
      if #spaces > 0 then
        output[#output + 1] = table.concat(spaces)
      end
    end
    run = {}
    spaces = {}
  end

  for _, cp in utf8.codes(text) do
    local char = utf8.char(cp)
    if is_rtl(cp) then
      if #spaces > 0 then
        if #run > 0 then
          for _, space in ipairs(spaces) do
            run[#run + 1] = space
          end
        else
          output[#output + 1] = table.concat(spaces)
        end
        spaces = {}
      end
      run[#run + 1] = char
    elseif char == " " or char == "\t" then
      if #run > 0 then
        spaces[#spaces + 1] = char
      else
        output[#output + 1] = char
      end
    else
      flush_run()
      output[#output + 1] = char
    end
  end

  flush_run()
  return table.concat(output)
end

function CodeBlock(block)
  if FORMAT:match("latex") then
    block.text = isolate_rtl_runs(block.text)
  end
  return block
end
