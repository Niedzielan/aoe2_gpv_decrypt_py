if not outLoc then
   print("Output location not defined")
   outLoc = os.getenv("TEMP").."\\gpv_decrypt\\"
   print("Set location to: "..outLoc)
end
if string.sub(outLoc,-1) ~= "\\" then
  outLoc = outLoc.."\\"
end

openProcess("AoE2DE_s.exe")

function AOBScanModule(bytes, flags)
   if type(process) == "nil" then
      return nil
   end
   local ms = createMemScan()
   local AOB = bytes
   local startAddress = getAddress(process)
   local stopAddress = startAddress + getModuleSize(process)
   ms.firstScan(soExactValue, vtByteArray, nil, AOB, nil, startAddress, stopAddress,
                             flags, nil, nil , true, nil, nil, nil)
   ms.waitTillDone()
   local fl = createFoundList(ms)
   fl.initialize()
   ms.destroy()
   return fl
end

local scans = AOBScanModule("48 2B D3 48 3B F2","*W-C+X")
if scans ~= nil then
   if scans.Count == 1 then
      addr = scans[0]
   else
       print("too many AOB results")
   end
   scans.destroy()
   scans = nil
else
    print("couldn't find any AOB results")
end

debugProcess()
debug_setBreakpoint(addr, function()
  local magicName = readString(readPointer(RSP+8)+0x750,4)
  local dlcName = string.reverse(magicName)
  print("Found "..dlcName)
  local valid = not magicName:find("[^A-Za-z0-9_]")
  if valid == false then
     dlcName = "tmp_"..readInteger(RBP-0x90+0x1FB)
     print("Invalid name, changing to: "..dlcName.." for manual checking")
  end
  --writeRegionToFile(outLoc..dlcName..".sbox",RBP-0x90,0x100)
  writeRegionToFile(outLoc..dlcName..".key",RBP-0x90+0x100,0x20)
  writeRegionToFile(outLoc..dlcName..".iv",RBP-0x90+0x1FB,0x10)
  writeRegionToFile(outLoc.."aoe2de.sbox",RBP-0x90+0x20B,0x100)
  debug_continueFromBreakpoint(co_run)
  return 0
  end
)
