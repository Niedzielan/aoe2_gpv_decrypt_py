Method 1 - Bruteforce [Requires pe-sieve]
1. Unpack the AoE2DE_s.exe (e.g. with pe-sieve: start AoE2 and wait for the main menu, find the PID in Task Manager, and in command prompt / cmd / terminal run "pe-sieve.exe /pid AOE2PID" and copy the "140000000.AoE2DE_s.exe" to the \exe\ folder)
2. Move the .gpv files into \in\
3. Run bruteforce_keys.py
4. Wait a few minutes
5. Run gpv_decrypt.py with python 3 (only 3.10 tested)
6. decrypted files are found in \out\

Method 2 - Memory Dump [Requires Cheat Engine]
1. Load gpv_decrypt.CT with Cheat Engine 7.5 (older versions not tested)
2. Edit the output directory variable outLoc (either in the main LUA script which should popup, or change the blue script and activate it)
3. Start AoE2DE
4. Wait a few seconds for the exe to unpack into memory. Generally ~65MB Ram or when the small splash screen appears
5. Activate one of the three scripts
6. Move the .key and .iv files now in the output directory (defined in 2.) to a \keys\ folder, and aoe2de.sbox next to gpv_decrypt.py
7. Move the .gpv files into \in\
8. Run gpv_decrypt.py with python 3 (only 3.10 tested)
9. decrypted files are found in \out\

Either method should work
Method 1 is slower, with a low likelyhood to break with game updates (several assumptions are made about data that may no longer hold true with updates, as an attempt to improve speed)
Method 2 is more likely to break with game updates, though all 3 scripts worked on both tested versions (some assumptions are made about code structure that may no longer hold true with updates)