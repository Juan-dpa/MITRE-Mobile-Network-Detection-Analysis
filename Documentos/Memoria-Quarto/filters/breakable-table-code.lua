-- Hace que el código en línea de las tablas PDF respete el ancho de su celda.
-- La transformación se realiza sobre el AST de Pandoc, antes de generar LaTeX;
-- por tanto, no modifica ni depende del .tex intermedio.

if not FORMAT:match("latex") then
  return {}
end

local latex_replacements = {
  ["\\"] = "\\textbackslash{}",
  ["{"] = "\\{",
  ["}"] = "\\}",
  ["#"] = "\\#",
  ["$"] = "\\$",
  ["%"] = "\\%",
  ["&"] = "\\&",
  ["_"] = "\\_",
  ["^"] = "\\textasciicircum{}",
  ["~"] = "\\textasciitilde{}",
}

local function escape_latex(text)
  return (text:gsub(".", function(character)
    return latex_replacements[character] or character
  end))
end

local function breakable_code(text)
  return pandoc.RawInline(
    "latex",
    "\\BreakableTableCode{" .. escape_latex(text) .. "}"
  )
end

local table_filter = {
  Code = function(element)
    return breakable_code(element.text)
  end,

  -- Compatibilidad temporal con las marcas \nolinkurl introducidas en QMD
  -- anteriores. Los documentos nuevos solo necesitan backticks normales.
  RawInline = function(element)
    if element.format ~= "latex" then
      return nil
    end

    local text = element.text:match("^\\nolinkurl%{(.*)%}$")
    if text then
      return breakable_code(text)
    end

    return nil
  end,
}

function Table(table)
  return table:walk(table_filter)
end
