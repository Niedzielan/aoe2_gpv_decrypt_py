Disclaimer: There should be no AoE2 DE data included or bundled with these decryption tools. The user must dump from their own copy of AoE2 DE, and decrypt their own gpv files

aoe2campaign.gpv files are encrypted with AES-256-CTR with a custom substitution box (s-box)
The keys and iv for the AES cipher and themselves encrypted with Tiny Encryption Algorithm (TEA) and stored in the binary along with the TEA keys
Further, the AoE2DE_s executable is packed.

The general flow of decrypting a gpv is as follows:
Switch based on the magic header (first 4 bytes)
Decrypt the AES key/iv pair through TEA
Decrypt the gpv through AES

To extract the keys, there are two approaches:
1. Unpack AoE2DE_s.exe and find the TEA keys and TEA-encrypted AES key/iv and derive them.
2. Read the memory of AoE2DE_s during runtime, directly retreiving the AES keys after TEA decryption.
Of course, method 2 can also be used to dump the TEA keys, or the decrypted gpv files directly


Method 1:
Unpacking AoE2DE_s.exe is non-trivial. The easiest way to do so is to, again, dump the memory once it has unpacked itself. Tools such as pe-sieve64 can be used for this.

Once the exe has been unpacked, you can search for the keys.
There exist two keyblobs:
	One has the TEA-encrypted AES keys/ivs. This keyblob has a consistent unique (and thus searchable) structure, and so is easy to find.
	The other has the TEA keys. This keyblob does *not* seem to have a consistent structure. Of course, there are tricks to narrow down possibilities:
		keys are likely to have high entropy. Of a random 16 byte key, it is almost certain that at least 10 bytes are unique, and very likely (~99.7%) that 14 bytes are unique.
		further, the entire blob is likely to have high entropy. There should be few repeating patterns.
		the key for the AES iv is likely to be soon after the key for the AES key. Testing shows this to be ~33-40 bytes afterwards, though there is one exception at 105
		Crucially, the TEA keys are duplicated elsewhere in the binary. Although these duplicates seem dispersed arbitrarily, it is still sufficient to narrow down a significant number of keys
	At this point, it is feasible to bruteforce decryption:
		We have the unique TEA-encrypted AES key/iv pairs. At the time of writing, there are 7 such pairs in 1 keyblob
		We have a number of potential TEA keys, and with the knowledge that the iv key is likely to be soon after the key key, a number of potential pairs
			Splitting those TEA keys into keyblobs (with a minimum of 14 keys), we have 778 keyblobs.
			Some of these are small, some are large. Luckily, our wanted keyblob is relatively small (60 possible keys), so sorting the keyblob list by size results in a fairly fast iteration
				The keyblob has 4166 potential keys if you ignore duplicates.
		Then, we can take each TEA key/iv pair, and decrypt each AES key/iv pair, then decrypt the first block(s) of a gpv file.
		Only the first block or blocks of a gpv are required to verify that the keys are correct:
			The only known gpv files are of aoe2campaign files, and these have a known header structure:
				Version number (2.00, as cpx etc campaigns aren't encrypted), 
				Dependency count, 
				Dependencies, (these aren't used for anything, but the count and dependencies are 4-bytes and (so far) < 0x0F
				Name, (256 bytes, but after the first 0x00 the rest is garbage)
				Scenario count,
				For each Scenario:
					Scenario length,
					Scenario offset,
					ID, (2 bytes)
					Name length, (2 bytes)
					Name,
					ID, (2 bytes)
					FileName length, (2 bytes)
					FileName
			Specifically, the name/filename will contain the string "aoe2scenario", though other data is also verifiable
			In fact, even just the version number is enough of a check for our case, so only the first 16 bytes of the gpv need checking.
This method should take around 3 minutes with the provided scripts (bruteforce_keys.py) to find all the keys and ivs
	
Short readme:
1. Unpack the AoE2DE_s.exe (e.g. with pe-sieve: start AoE2 and wait for the main menu, find the PID in Task Manager, and in command prompt / cmd / terminal run "pe-sieve.exe /pid AOE2PID" and copy the "140000000.AoE2DE_s.exe" to the \exe\ folder)
2. Move the .gpv files into \in\
3. Run bruteforce_keys.py
4. Wait a few minutes
5. Run gpv_decrypt.py with python 3 (only 3.10 tested)
6. decrypted files are found in \out\

Method 2:
As above, the structure follows switch(DLC) -> decrypt_key(DLC) -> decrypt_gpv(key)
The decrypt_key compiled functions are unique for each DLC - TEA decrypting the DLC2 keys is a different function to TEA decrypting the DLC3 keys
In more depth, the structure is:
	Switch DLC
		Decrypt DLC1 key | Decrypt DLC2 key | ... | Decrypt DLCX key
		Move DLC1 Key to staging area | Move DLC2 Key to staging area | ... | Move DLCX Key to staging area
		Decrypt DLC1 iv | Decrypt DLC2 iv | ... | Decrypt DLCX iv
		Move DLC1 iv to staging area | Move DLC2 iv to staging area | ... | Move DLCX iv to staging area
	Move S-Box to AES area
	Move Inv-S-Box to AES area
	Move Key to AES area
	Key Expansion
	Move IV to AES area
	Memalloc a region for the decrypted data
	AES decryption loop
Attempting to hook during the TEA decryption would require either a unique hook for each DLC, or an AOB scan for a common opcode between them.
This is certainly possible, but likely more effort than the alternatives.
Far easier is to hook into the AES loop - or just before it starts - and read the stack.
There are many ways of doing this. Firstly, we want to ignore some parts. Addresses will change every time there is an update. Stack pointers might also change. 
The hope is that the AES code is unlikely to be recompiled (it's a box that you feed keys and data in and get data out, there's no *need* to change it), or at least not noticeably.
Three possible (out of many) vectors have been identified:
	1. 49 8B 43 08 49 2B 03 = mov rax, [r11+08]; sub rax, [r11] -- this is immediately after a decrypted byte has just been written to the destination
		The stack holds the S-Box, Key, Extended Key, rcon, IV+1, Inverse-S-Box (0x100, 0x20, 0xD0, 0xB, 0x10, 0x100 = 0x30B total) at RBP+0x90
		Note that the IV *has already been incremented*, and must be decremented before use
		The filename is at [[RBP-0x20]]
		The magic name is at [RBP+0x10]+750
		This code is hit for every byte in the file. If you breakpoint here part way through a decryption, RDI contains the value already processed - and thus the value to decrement IV by.
		A breakpoint can also instead be placed at the end of the data, which will also trigger here, and the entire gpv file can be dumped.
			Indeed, placing a breakpoint at the end and removing the one at the start is a good way to only trigger 2 breakpoints per file instead of hundreds of thousands
	2. 48 81 C1 FB 01 00 00 41 B8 10 00 00 00 = add rcx, 0x1FB; mov r8d, 0x10 -- this is before mem-moving the IV. Immediately before this is run, RCX is the pointer to the stack (start of the S-Box)
		The stack holds the S-Box, Key, Extended Key, rcon, NONE, Inverse-S-Box (0x100, 0x20, 0xD0, 0xB, 0x10, 0x100 = 0x30B total) at RCX
		The IV is held at R12
		The magic name is at RSP+0x38 or at [R12-0x28]+0x750
	3. 48 2B D3 48 3B F2 = sub rdx, rbx; cmp rsi, rdx  -- this is after the IV has been moved, around the memalloc code, checking that the length is correct
		The stack holds the S-Box, Key, Extended Key, rcon, IV, Inverse-S-Box (0x100, 0x20, 0xD0, 0xB, 0x10, 0x100 = 0x30B total) at RBP-0x90
		The magic name is a bit trickier, but apparently [RSP+8]+0x750 has a non-terminating string, so reading the first 4 bytes should be sufficient
	Note that the Inverse-S-Box is used as the actual S-Box. As the S-Box is also by definition the inverse of the Inverse-S-Box - I merely named them this because of the order they appear
Hooking into these locations and dumping the data can be done with a variety of tools.
Cheat Engine is a handy free tool with a multitude of debugging and memory viewing capabilities. 
In particular, it can programatically set breakpoints, read data, write data to files, etc, either by directly altering the assembly code, or by breakpoints and the built-in Lua scripting engine
All three implementations are found in gpv_dump_methodX.lua.
The file gpv_decrypt.CT can be loaded with Cheat Engine (minimum version unknown, version 7.5 confirmed working)
Make sure to edit the output location in the Lua window (CTRL + ALT + L or Table -> Show Cheat Table Lua Script) and execute it, or alternatively edit the script in blue at the top of the address list
	Otherwise the default location is %Temp%\gpv_decrypt\.
Then choose one of the methods - all 3 confirmed working with versions #109739 and #107882
	If one doesn't work, restart AoE2DE and try again
	If none work, updates have likely changed the compiled code enough that these functions use different registers, offsets, etc
	Older depots can still be downloaded, e.g. download_depot 813780 813781 4062602954975422668 is the depot from 4 April 2024 – 20:00:05 UTC as seen https://steamdb.info/depot/813781/manifests/

Short readme:
1. Load gpv_decrypt.CT with Cheat Engine 7.5 (older versions not tested)
2. Edit the output directory variable outLoc (either in the main LUA script which should popup, or change the blue script and activate it)
3. Start AoE2DE
4. Wait a few seconds for the exe to unpack into memory. Generally ~65MB Ram or when the small splash screen appears
5. Activate one of the three scripts
6. Move the .key and .iv files now in the output directory (defined in 2.) to a \keys\ folder, and aoe2de.sbox next to gpv_decrypt.py
7. Move the .gpv files into \in\
8. Run gpv_decrypt.py with python 3 (only 3.10 tested)
9. decrypted files are found in \out\

gpv_decrypt.py arguments:
	-i <infile>
		This can be either a file or a directory
		If this is a directory, only .gpv files will be read, unless the "-a" argument is used as well
		Default: "in"
	-o <outfile>
		This can be either a file or a directory
		If <infile> is a directory, <outfile> cannot be a file. The other way around is fine
		Default: "out"
	-k <keyfile>
		This can be either a file or a directory
		If  this is a directory, only .key files will be read
		Default: "keys"
	-v <ivfile>
		This can be either a file or a directory
		If  this is a directory, only .iv files will be read
		If this is not specified, it will use the same name as <keyfile> (after stripping the extension and appending ".iv")
	-s <sboxfile>
		This must be a file
		Default: "aoe2de.sbox"
	-a
		This forces input from a directory to read every file, not just .gpv files
	-m <magicheader>
		This is a header required for *encrypting* gpv files
		If this is specified, encryption is assumed.
			DO NOT USE if you are decrypting
			
	By default, no arguments are needed. .gpv files will be read in from "\in\", decrypted using keys, iv from "\keys\" and sbox from "aoe2de.sbox", and output to "\out\"


