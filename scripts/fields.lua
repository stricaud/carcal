-- fields.lua — show the "various ways" a field/protocol can be read, and use
-- the display-filter engine from Lua.
--   carcal -s scripts/fields.lua -r capture.pcapng -f "dns || tcp"

function packet(pkt)
  -- direct field map (natural Lua values)
  local ipsrc = pkt.fields["ip.src"]
  if ipsrc then print("ip.src (value)  = " .. tostring(ipsrc)) end

  -- the richer representations via :get()
  local f = pkt:get("ip.src")
  if f then
    print(string.format("  type=%s value=%s hex=%s label=%q",
          f.type, tostring(f.value), f.hex, f.label))
  end

  -- existence + filter evaluation from Lua
  if pkt:has("tcp") then
    print("  has tcp; matches 'tcp.flags == 0x02' -> " ..
          tostring(pkt:matches("tcp.flags == 0x02")))
  end

  -- ordered protocol stack
  print("  layers: " .. table.concat(pkt.layers, " / "))
end
