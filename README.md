# aoe2_gpv_decrypt_py
Python script to decrypt aoe2campaign.gpv files, and two methods of extracting the AES keys to do so.

# Update Notice
Currently as of AoE2DE update:  
Update 169123, only **Memory Dump** script 2 is working (titled Dump gpv keys, iv [Method 2] and dump decrypted campaigns [Worked #158041, #169123])  
~~Update 158041, only **Memory Dump** script 2 is working (titled Dump gpv keys, iv [Method 2] and dump decrypted campaigns )~~   
~~Update 130746, only **Memory Dump** script 1 is working~~

# Quick Note on extracting scenarios from decrypted campaign files
Most of the campaigns are extractable ingame (put them in the custom campaigns folder, then load in the editor.)

Currently there is a UI bug when trying to extract scenarios when there are too many scenarios and the confirm button is off-screen.  
This ocurs with the Chronicles Alexander prcam1.aoe2campaign  
You should be able to use the arrow keys to select the buttons and enter to activate them (i.e. left arror + enter) [Thanks to RoyalForgotten]  
Alternatively, you can use [rge_campaign](https://github.com/withmorten/rge_campaign/) to extract (e.g. with command `rge_campaign.exe x prcam1.aoe2campaign out_prcam1` )

# Short Readme

<strike>Method 1 - Bruteforce [Requires pe-sieve]
1. Unpack AoE2DE_s.exe 
    * For example with pe-sieve: start AoE2 and wait for the main menu, find the PID in Task Manager, and in command prompt / cmd / terminal run "pe-sieve.exe /pid AOE2PID" and copy the "140000000.AoE2DE_s.exe" to the \exe\ folder. The hex prefix may differ, but should still work
2. Move the .gpv files into \in\
3. Run bruteforce_keys.py
4. Wait a few minutes
5. Run gpv_decrypt.py with python 3 (only 3.10 tested)
6. decrypted files are found in \out\ </strike>

Method 2 - Memory Dump [Requires Cheat Engine]
1. Load gpv_decrypt.CT with Cheat Engine 7.5 (older versions not tested)
2. Edit the output directory variable outLoc (either in the main LUA script which should popup, or change the blue script and activate it)
3. Start AoE2DE
4. Attach method is easier with Return of Rome, as switching modes causes gpvs to be loaded into memory again
    * [Return of Rome] Wait until the game has loaded
    * [No RoR] Wait a few seconds for the exe to unpack into memory. Generally ~65MB Ram or when the small splash screen appears
5. Activate one of the three scripts
    * [Return of Rome] Switch modes. Only the gpv files for the mode you switch into will be loaded, so switch back again to load everything.
    * [No RoR] The files will be loaded upon startup. There is a timeframe of several seconds between the exe being unpacked and the gpvs being loaded, if it doesn't work then retry steps 3-5 with different timing.
    * The ~~first of the three~~ scripts will also dump the decrypted campaign files without the need of the following steps, although it is recommended to continue so the process doesn't need repeating for future versions
7. Move the .key and .iv files now in the output directory (defined in step 2) to a \keys\ folder, and aoe2de.sbox next to gpv_decrypt.py
8. Move the .gpv files into \in\
9. Run gpv_decrypt.py with python 3 (only 3.10 tested)
10. decrypted files are found in \out\

<strike>Either method should work  
Method 1 is slower, with a hopefully low likelyhood to break with game updates (several assumptions are made about data that may no longer hold true with updates, as an attempt to improve speed)</strike>  
Method 2 is more likely to break with game updates~~, though all 3 scripts worked on several tested versions~~ (some assumptions are made about code structure that may no longer hold true with updates)  

# Accessing older versions of AoE2:DE

This tool does not receive priority updates if there is a non-DLC update, as you can instead download an older version of AoE2 instead to dump the keys, and take the campaign files from the latest version.  
You can download a specific version by: Going to https://steamdb.info/app/813780/depots/, finding the depot for the content to download. e.g. depot 813781-813784 are the base game resources, and DLCs in individual depots: 3219700 is The Last Chieftains.  
Within a depot, you should find a manifest for a specific date: e.g. depot 813781 has current latest manifest 7319783204277561121 (17 Feb 2026). We can match the dates to patchnotes from https://steamdb.info/app/813780/patchnotes/ or https://www.ageofempires.com/news/age-of-empires-ii-definitive-edition-update-158041/ - if you want to download update 158041 we know it was released on 14 Oct 2025, of which the matching base game manifest is 49296955481020023.  
By opening the Steam console ( steam://nav/console ) you can then use the depot_download command `download_depot <appid> <depotid> [<target manifestid>] [<delta manifestid>] [<depot flags filter>] : download a single depot` as such:  
`download_depot 813780 813781 49296955481020023` and repeat this for each depot and manifest. The example command would download the update 158041 version of the game, where Method 2 is confirmed to work.  

# Quick disclaimer

I have done my best to ensure that these tools do not contain cryptographic secrets. The TEA, AES keys and ivs are not prepackaged. The two methods above are intended to obtain those keys from your legally purchased copy of Age of Empires 2 Definitive Edition.

These tools are unable to dump AES keys or gpv files from unowned DLC. For the bruteforce method the gpv files must be supplied to test the keys, and the memory dump code is never run for unowned gpv files.

Decrypted aoe2campaign files can be extracted as normal in the Scenario editor / Campaign editor ingame. The only restriction is that scenarios using unowned civs cannot be edited - this should only affect cam0 and cam1 base game campaigns for people who do not own some of the DLCs.
