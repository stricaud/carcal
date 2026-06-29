-- summary.lua — print a tshark-like one-line summary per packet.
--   caracal -s scripts/summary.lua -r capture.pcapng [-f "ip"]

function packet(pkt)
  print(string.format("%5d  %.6f  %-15s -> %-15s  %-8s  %s",
        pkt.number, pkt.time or 0, pkt.src or "", pkt.dst or "",
        pkt.protocol or "?", pkt.info or ""))
end

function finish(stats)
  io.stderr:write(string.format("# %d packets, %d matched, %d stream chunks\n",
        stats.packets, stats.matched, stats.streams))
end
