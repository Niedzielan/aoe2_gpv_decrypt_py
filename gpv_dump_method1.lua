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

function reverseBytes(num)
    -- Convert integer to hexadecimal string
    local hexValue = string.format('%X', num)

    -- Ensure the length of the hex string is even by adding a leading zero if necessary
    if #hexValue % 2 ~= 0 then
        hexValue = '0' .. hexValue
    end
    -- Reverse the byte order
    local reversedHex = ''
    for i = #hexValue, 1, -2 do
        reversedHex = reversedHex .. string.sub(hexValue, i-1, i)
    end
    return reversedHex
end

local scans = AOBScanModule("49 8B 43 08 49 2B 03", "*W-C+X")
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

function first_write_bp()
	 local filename = readString(readPointer(readPointer(RBP-0x20)))
     print("Found "..filename)
     local magicName = readString(readPointer(RBP+0x10)+0x750,4)
     local dlcName = string.reverse(magicName)
     print("Found "..dlcName)
     local valid = not magicName:find("[^A-Za-z0-9_]")
     if valid == false then
        print("Invalid name, changing to: "..filename)
        local valid2 = not filename:find("[^A-Za-z0-9_.]")
        if valid2 == false then
           filename = "tmp_"..readInteger(RBP+0x90+0x1FB)
           print("Invalid name, changing to: "..filename.." for manual checking")
        end
     else
         filename = dlcName
     end
	 --writeRegionToFile(outLoc..filename..".statedump",RBP+0x90,0x30B)
	 writeRegionToFile(outLoc.."aoe2de.sbox",RBP+0x90+0x20B,0x100)
	 writeRegionToFile(outLoc..filename..".key",RBP+0x90+0x100,0x20)
     --iv has already been incremented, we temporarily decrement it, then increment again
     --messy but it works
     local iv = readQword(RBP+0x90+0x1FB+0x08)
     local iv_dec = tonumber("0x"..reverseBytes(tonumber("0x"..reverseBytes(iv))-1))
     writeQword(RBP+0x90+0x1FB+0x08,iv_dec)
	 writeRegionToFile(outLoc..filename..".iv",RBP+0x90+0x1FB,0x10)
     writeQword(RBP+0x90+0x1FB+0x08,iv)

     tmpAddr = RCX+readInteger(RBP)-1
     debug_removeBreakpoint(addr)
     debug_setBreakpoint(tmpAddr,1,bptAccess,last_write_bp)

     debug_continueFromBreakpoint(co_run)
     return 0
end

function last_write_bp()
     local nameOffset = 4*(2+readInteger(RCX+4))
     local campaignName = readString(RCX+nameOffset)
     print("Dumping "..campaignName)
     debug_removeBreakpoint(tmpAddr)
     debug_setBreakpoint(addr, first_write_bp)
     writeRegionToFile(outLoc..campaignName..".aoe2campaign",RCX,readInteger(RBP))
     debug_continueFromBreakpoint(co_run)
     debug_continueFromBreakpoint(co_run)
     return 0
end

debugProcess()
debug_setBreakpoint(addr, first_write_bp)