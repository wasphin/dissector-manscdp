--
-- \brief Wireshark dissector for GB/T 28181
--
-- Copyright 2022 (C) Xiaofeng Wang <wasphin AT gmail.com>
-- SPDX-License-Identifier: GPL-3.0-only
--
------------------------------------------------------------------------------
--  function
--  Proto.new(name, desc)
--  proto.dissector
--  proto.fields
--  proto.prefs
--  proto.prefs_changed
--  proto.init
--  proto.name
--  proto.description
------------------------------------------------------------------------------

-- GBT28181
local plugin_info = {
  name = "GBT28181",
  version = "0.1.0",
  description = "GB/T 28181"
}

------------------------------------------------------------------------------
-- Verify that the Wireshark version matches our requirement.

--·Unfortunately,·the·older·Wireshark/Tshark·versions·have·bugs,
-- and·part·of·the·point of·this·script·is·to·test·those·bugs·are·now·fixed.
--·So·we·need·to·check·the·version end·error·out·if·it's·too·old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
  error("Sorry, but your Wireshark/Tshark version ("
        .. get_version() .. ") is too old for this script!\n"
        .. "This script needs Wireshark/Tshark version 1.11.3 or higher.\n")
end

--·more·sanity·checking
--·verify·we·have·the·ProtoExpert·class·in·wireshark,
--·as·that's·the·newest·thing·this·file·uses
assert(ProtoExpert.new, "Wireshark·does·not·have·the·ProtoExpert·class,·so·it's·too·old·-·get·the·latest·1.11.3·or·higher")

local prefs_changed = function() end

local LM_DBG = function(fmt, ...)
  if (tonumber(major) < 3) then
    critical(table.concat({ plugin_info.name:upper() .. ":", fmt }, ' '):format(...))
  else
    print(table.concat({ plugin_info.name:upper() .. ":", fmt }, ' '):format(...))
  end
end

local proto = Proto.new(plugin_info.name, plugin_info.description)
proto.prefs_changed = prefs_changed

LM_DBG("Wireshark version = %s", get_version())
LM_DBG("Lua version = %s", _VERSION)

--------------------------------------------------------------------------------

local pf_cmd_type = ProtoField.string(plugin_info.name .. ".CmdType", "Command Type", BASE_NONE)

proto.fields = {
  pf_cmd_type
}

--------------------------------------------------------------------------------

local manscdp_media_type = "Application/MANSCDP+xml"

-- 参考: http://www.voidcn.com/article/p-sqwlhgrw-gg.html
local media_type_table      = DissectorTable.get("media_type")
local manscdp_xml_dissector = media_type_table:get_dissector(manscdp_media_type)
local text_xml_dissector    = media_type_table:get_dissector("text/xml")

local manscdp = {
  Control  = { name = "Control",  field = "control",
               dissectors = {},
               commands = {}},
  Notify   = { name = "Notify",   field = "notify",
               dissectors = {},
               commands = {}},
  Query    = { name = "Query",    field = "query",
               dissectors = {},
               commands = { Catalog = { type = "Catalog" } } },
  Response = { name = "Response", field = "response",
               dissectors = {},
               commands = { Catalog = { type = "Catalog" } } }
}

for _, t in pairs(manscdp) do
  t.type = Field.new(t.field .. ".cmdtype")
end

function proto.init()
  for _, t in pairs(manscdp) do
    for _, cmd in pairs(t.commands) do
      if cmd.dissector and not t.dissectors[cmd.type] then
        LM_DBG("register dissector for " .. t.name .. "." .. cmd.type)
        t.dissectors[cmd.type] = cmd.dissector
      end
    end
  end
end

local sip_content_type   = Field.new("sip.Content-Type")
local sip_content_length = Field.new("sip.Content-Length")
local sip_msg_body       = Field.new("sip.msg_body")

local dissect_manscdp = function() end

function proto.dissector(tvbuf, pktinfo, root)
  local ct = sip_content_type()
  if not ct then
    return
  end

  ct = tostring(ct)
  local semicolon_pos = ct:find(";")
  if semicolon_pos then
    ct = ct:sub(1, semicolon_pos-1)
  end

  if (ct:lower() == manscdp_media_type:lower()) then
    -- https://www.wireshark.org/docs//wsdg_html_chunked/lua_module_Field.html
    -- TODO: Converting GB2312 to UTF-8
    local body = sip_msg_body().range:tvb()
    local manscdp_tree = root:add(proto, tvbuf)
    manscdp_tree:set_text("GB/T 28181 MANSCDP")
    dissect_manscdp(body, pktinfo, manscdp_tree)
  end
end

register_postdissector(proto)

------------------------------------------------------------------------------
-- \brief 解析 manscdp 协议
--
-- GB/T 28181 MANSCDP
-- `-- TODO: 关心字段
-- `-- eXtensible Markup Language
--
dissect_manscdp = function(tvbuf, pktinfo, manscdp_root)
  -- 使用 xml 协议解析, 随后再提取关心的字段
  manscdp_xml_dissector:call(tvbuf, pktinfo, manscdp_root)

  for _, t in pairs(manscdp) do
    local cmd_type = t.type()
    if cmd_type then
      manscdp_root:add(pf_cmd_type, cmd_type.range)

      -- 使用相应的 dissector 进行解析
      local dissector = t.dissectors[tostring(cmd_type)]
      if dissector then
        dissector(tvbuf, pktinfo, manscdp_root)
      end

      break
    end
  end
end

------------------------------------------------------------------------------

manscdp.Query.commands.Catalog.dissector
  = function(tvbuf, pktinfo, manscdp_tree)
end

manscdp.Response.commands.Catalog.dissector
  = function(tvbuf, pktinfo, manscdp_tree)
end

------------------------------------------------------------------------------
-- Editor modelines
--
-- Local variables:
-- c-basic-offset: 2
-- tab-width: 2
-- indent-tab-mode: nil
-- End:
--
-- kate: indent-width 2; tab-width 2;
-- vim: tabstop=2:softtabstop=2:shiftwidth=2:expandtab
-- :indentSize=2:tabSize=2:noTabs=true
