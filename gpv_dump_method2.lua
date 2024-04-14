if not outLoc then
   print("Output location not defined")
   outLoc = os.getenv("TEMP").."\\gpv_decrypt"
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

local scans = AOBScanModule("48 81 C1 FB 01 00 00 41 B8 10 00 00 00","*W-C+X")
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
  local magicName = readString(RSP+0x38,4)
  local dlcName = string.reverse(magicName)
  print("Found "..dlcName)
  local valid = not magicName:find("[^A-Za-z0-9_]")
  if valid == false then
	 local magicName2 = readString(readPointer(R12-0x28)+0x750,4)
     dlcName = string.reverse(magicName2)
     print("Invalid name, changing to: "..dlcName)
	 local valid2 = not magicName2:find("[^A-Za-z0-9_]")
     if valid2 == false then
        dlcName = "tmp_"..readInteger(R12)
        print("Invalid name, changing to: "..dlcName.." for manual checking")
     end
  end
  --writeRegionToFile(outLoc..dlcName..".sbox",RBP-0x90,0x100)
  writeRegionToFile(outLoc..dlcName..".key",RCX+0x100,0x20)
  writeRegionToFile(outLoc..dlcName..".iv",R12,0x10)
  writeRegionToFile(outLoc.."aoe2de.sbox",RCX+0x20B,0x100)
  debug_continueFromBreakpoint(co_run)
  return 0
  end
)