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

-- Unfortunately, the older Wireshark/Tshark versions have bugs,
-- and part of the point of this script is to test those bugs are now fixed.
-- So we need to check the version end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
  error("Sorry, but your Wireshark/Tshark version ("
        .. get_version() .. ") is too old for this script!\n"
        .. "This script needs Wireshark/Tshark version 1.11.3 or higher.\n")
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark,
-- as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

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

local pf_any
  = ProtoField.bytes (plugin_info.name .. ".Any",
                      "Place Holder for Anything",
                      BASE_NONE)
local pf_sn
  = ProtoField.string(plugin_info.name .. ".SN",
                      "SN",
                      BASE_NONE)
local pf_cmd_type
  = ProtoField.string(plugin_info.name .. ".CmdType",
                      "CmdType",
                      BASE_NONE)

----------------------------------------
-- Control Command Fields

-- A.3.1, 表 A.3, 指令格式

-- byte 1
-- use string to display hex values
local pf_ptz_cmd_magic
  = ProtoField.bytes (plugin_info.name .. ".PTZCmd.Magic",
                      "Magic Code(A5H)",
                      BASE_NONE)
-- byte 2, high 4 bits
local pf_ptz_cmd_version
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.Version",
                      "Version",
                      BASE_HEX, { [0] = "1.0" }, 0xF0)
-- byte 2, low 4 bits
local pf_ptz_cmd_check_bits
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.CheckBits",
                      "Check Bits",
                      BASE_HEX, nil, 0x0F)
-- byte 8
local pf_ptz_cmd_checksum
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.Checksum",
                      "Checksum",
                      BASE_HEX)

-- byte 4, bit 5
local pf_ptz_cmd_zoom_out
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.Out",
                      "PTZ Zoom Out",
                      BASE_DEC, nil, 0x20)
-- byte 4, bit 4
local pf_ptz_cmd_zoom_in
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.In",
                      "PTZ Zoom In",
                      BASE_DEC, nil, 0x10)
-- byte 4, bit 3
local pf_ptz_cmd_up
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.Up",
                      "PTZ Tilt Up",
                      BASE_DEC, nil, 0x08)
-- byte 4, bit 2
local pf_ptz_cmd_down
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.Down",
                      "PTZ Tilt Down",
                      BASE_DEC, nil, 0x04)
-- byte 4, bit 1
local pf_ptz_cmd_left
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.Left",
                      "PTZ Pan Left",
                      BASE_DEC, nil, 0x02)
-- byte 4, bit 0
local pf_ptz_cmd_right
  = ProtoField.uint8 (plugin_info.name .. ".PTZCmd.Right",
                      "PTZ Pan Right",
                      BASE_DEC, nil, 0x01)

-- byte 5
local pf_ptz_cmd_speed_pan
  = ProtoField.uint8 (plugin_info.name .. "PTZCmd.Speed.Pan",
                      "PTZ Pan Speed",
                      BASE_DEC)
-- byte 6
local pf_ptz_cmd_speed_tilt
  = ProtoField.uint8 (plugin_info.name .. "PTZCmd.Speed.Tilt",
                      "PTZ Tilt Speed",
                      BASE_DEC)
-- byte 7
local pf_ptz_cmd_speed_zoom
  = ProtoField.uint8 (plugin_info.name .. "PTZCmd.Speed.Zoom",
                      "PTZ Zoom Speed",
                      BASE_DEC, nil, 0xF0)

----------------------------------------

proto.fields = {
  pf_any,

  pf_sn,
  pf_cmd_type,

  pf_ptz_cmd_magic,
  pf_ptz_cmd_version,
  pf_ptz_cmd_check_bits,
  pf_ptz_cmd_checksum,

  pf_ptz_cmd_zoom_out,
  pf_ptz_cmd_zoom_in,
  pf_ptz_cmd_up,
  pf_ptz_cmd_down,
  pf_ptz_cmd_left,
  pf_ptz_cmd_right,

  pf_ptz_cmd_speed_pan,
  pf_ptz_cmd_speed_tilt,
  pf_ptz_cmd_speed_zoom
}

--------------------------------------------------------------------------------

local manscdp_media_type = "Application/MANSCDP+xml"

-- 参考: http://www.voidcn.com/article/p-sqwlhgrw-gg.html
local media_type_table      = DissectorTable.get("media_type")
local manscdp_xml_dissector = media_type_table:get_dissector(manscdp_media_type)
local text_xml_dissector    = media_type_table:get_dissector("text/xml")

--  command -> command-details
local manscdp = {
  Control  = {
    dissectors = {},
    commands = {
      DeviceControl = {
        PTZCmd = {}
      }
    }
  },
  Notify   = {
    dissectors = {},
    commands = {}
  },
  Query    = {
    dissectors = {},
    commands = {
      Catalog = {}
    }
  },
  Response = {
    dissectors = {},
    commands = {
      Catalog = {}
    }
  }
}

for cmd_name, cmd in pairs(manscdp) do
  -- 相关 field 已在 DTD 中注册, 为全小写.
  cmd.sn   = Field.new(cmd_name:lower() .. ".sn")
  cmd.type = Field.new(cmd_name:lower() .. ".cmdtype")
  for sub_cmd_name, sub_cmd in pairs(cmd.commands) do
    for field_name, field in pairs(sub_cmd) do
      field.pf = Field.new(cmd_name:lower() .. "." .. field_name:lower())
    end
  end
end

function proto.init()
  -- register all sub-dissectors
  for cmd_name, cmd in pairs(manscdp) do
    for sub_cmd_name, sub_cmd in pairs(cmd.commands) do
      if sub_cmd.dissector and not cmd.dissectors[sub_cmd_name] then
        LM_DBG("register dissector for " .. cmd_name .. "." .. sub_cmd_name)
        cmd.dissectors[sub_cmd_name] = sub_cmd.dissector
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
-- `-- MANSCDP
-- |   `-- SN
-- |   `-- CmdType
-- |   `-- ...
-- `-- eXtensible Markup Language
--
dissect_manscdp = function(tvbuf, pktinfo, manscdp_tree)
  local manscdp_root = manscdp_tree:add(pf_any, tvbuf:range()):set_text("MANSCDP")

  -- 使用 xml 协议解析, 随后再提取关心的字段
  manscdp_xml_dissector:call(tvbuf, pktinfo, manscdp_tree)

  for name, cmd in pairs(manscdp) do
    local cmd_type = cmd.type()
    if cmd_type then
      manscdp_root:add(pf_sn, cmd.sn().range)
      manscdp_root:add(pf_cmd_type, cmd_type.range):append_text("(" .. name .. ")")

      -- 使用相应的 dissector 进行解析
      local dissector = cmd.dissectors[tostring(cmd_type)]
      if dissector then
        dissector(tvbuf, pktinfo, manscdp_root)
      end

      break
    end
  end
end

------------------------------------------------------------------------------

manscdp.Control.commands.DeviceControl.dissector = function(tvbuf, pktinfo, manscdp_tree)
  local ptz_cmd = manscdp.Control.commands.DeviceControl.PTZCmd.pf()
  if ptz_cmd then
    local ptz_cmd_tvb = ByteArray.new(ptz_cmd.value):tvb("PTZCmd")

    local ptz_cmd_tree = manscdp_tree:add(pf_any, ptz_cmd.range):set_text("PTZCmd: " .. ptz_cmd.value)
    ptz_cmd_tree:add(pf_ptz_cmd_magic,      ptz_cmd_tvb(0, 1));

    ptz_cmd_tree:add(pf_ptz_cmd_version,    ptz_cmd_tvb(1, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_check_bits, ptz_cmd_tvb(1, 1));

    ptz_cmd_tree:add(pf_ptz_cmd_zoom_out,   ptz_cmd_tvb(3, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_zoom_in,    ptz_cmd_tvb(3, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_up,         ptz_cmd_tvb(3, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_down,       ptz_cmd_tvb(3, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_left,       ptz_cmd_tvb(3, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_right,      ptz_cmd_tvb(3, 1));

    ptz_cmd_tree:add(pf_ptz_cmd_speed_pan,  ptz_cmd_tvb(4, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_speed_tilt, ptz_cmd_tvb(5, 1));
    ptz_cmd_tree:add(pf_ptz_cmd_speed_zoom, ptz_cmd_tvb(6, 1));

    ptz_cmd_tree:add(pf_ptz_cmd_checksum,   ptz_cmd_tvb(7, 1));
  end
end

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
