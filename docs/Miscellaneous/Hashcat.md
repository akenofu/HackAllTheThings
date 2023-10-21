## Password Mutation
## Flags

**Hashcat**
```bash
-m 1000 # Hash type, 1000 = NTLM
-w 4    #  Workload, set as 4 for insane performance and rip ur gpu
-a 0    # attack mode, 0:wordlist
-O      # Optimize for 32 characters or less passwords
--force # use CUDA GPU interface, buggy but provides more performance
--opencl-device-types 1,2 # use both cpu and gpu
--debug-mode=1 # can only be used when rules are used
--debug-file=stats.debug # output for the rule statistics
```


**Prince Processor**
```bash
 --elem-cnt-max 4 # Maximum number of elements per chain
--elem-cnt-min 2 # 
--keyspace # Calculate number of combinations 
-o prince.txt# output to file
```

## Examples
I am using hashcat on my host Windows machine. So the file paths and binary name might be different for you.

```bash
# Apply rules to hash while cracking
hashcat -m 0 bfield.hash /usr/share/wordlists/rockyou.txt -r rules

# Apply rules to wordlist to mutate it 
hastcat --stdout passwords -r /usr/share/hashcat/rules/best64.rule

# Identify hash mode
./hashcat --quiet '5f4dcc3b5aa765d61d8327deb882cf99'

# Identify Binary File hash mode
./hashcat --quiet /opt/example.hashes

# Cracking NTLM hashes with multiple rule files
hashcat .\parsed_ntds -r .\rules\best64.rule -r .\rules\InsidePro-PasswordsPro.rule -r .\rules\combinator.rule -r .\rules\generated2.rule -r .\rules\rockyou-30000.rule -m 1000 .\xato-net-10-million-passwords.txt --username

# maximum speed cracking with cpu and gpu, but ur pc is unusable
.\hashcat.exe --force -O -w 4 --opencl-device-types 1,2 -r --debug-mode=1 --debug-file=stats.debug .\rules\OneRuleToRuleThemAll.rule parsed_ntds.dit

# resume hashcat session
hashcat --session hashcat --restore


# using hashcat's prince preprocessor
.\pp64.exe users_wordlist.txt -o out.txt


# Piping prince hashtcat's preprocessor to hashcat
.\pp64.exe  .\description.txt  | ..\hashcat-6.2.5\hashcat.exe "0E67AC21335FB74DC5536F685CE97494" -m 1000 -r ..\hashcat-6.2.5\rules\prince_optimized.rule

# If you are gonna output pp64 to a file then use that as a wordlist
# I recommend generating this wordlist on linux so you have to skip
# the convertion process on a large wordlist file at the end from utf-16 to utf-8
# I recommend using 2 for --elem-cnt-max flag if u don't want ur wordlist to be > 10 gigs
./pp64.bin data_cleaned.txt --elem-cnt-max 4 -o prince.txt
```


## Custom Rules
[NotSoSecure - OneRuleToRuleThemAll Github](https://github.com/NotSoSecure/password_cracking_rules)


## Extra cracking techniques
When all else fails go check out
1. [Purple Rain Attack - Password Cracking With Random Generation](https://www.netmux.com/blog/purple-rain-attack)
2. [Tool Deep Dive: PRINCE](https://reusablesec.blogspot.com/2014/12/tool-deep-dive-prince.html)
3. Check hashcat different attack modes e.g. hyprid, association, etc...

## Benchmarking rule files
N.b. when benchmarking different rules, The potfile was disabled so that hashcat didn’t check it prior to each crack and skew our numbers. Debug mode can only be enabled when using rules and the debug file contains the stats. Every time a rule cracks a hash it’s logged in the file. After hashcat completes, the file can then be sorted to show the number of times a rule was successful, therefore revealing the most successful rules in each set.

## Wordlists
Obviously it's best if you can craft your own wordlist for the org you are cracking and get personal information for the employees and generate passwords from those. Finally, mutate them with wordlists.
but, my favourite generic  wordlists for cracking  are rockyou.txt and xato-10-million

Use [hastcat's prince preprocessor](https://github.com/hashcat/princeprocessor) to generate wordlists from a word list. I use this with the name output from the AD enviroment.

## Rule files
**My favorite rules:**
- [OneRuleToRuleThemStill](https://github.com/stealthsploit/OneRuleToRuleThemStill)
- LeetSpeak

N.b. when using prince. Use the two supplied prince rules as well
prince_optimized.rule, prince_generated.rule


## PRINCE algorithm
The princeprocessor is a password candidate generator and can be thought of as an advanced combinator attack. Rather than taking as input two different wordlists and then outputting all the possible two word combinations though, princeprocessor only has one input wordlist and builds "chains" of combined words. These chains can have 1 to N words from the input wordlist concatenated together.

[PrinceProcessor - GitHub](https://github.com/hashcat/princeprocessor)

## Troubleshooting
[Hashcat doesn’t detect AMD CPUs (SOLVED)](https://miloserdov.org/?p=6507)

## Resources
[Hashcat-Cheatsheet - Github](https://github.com/frizb/Hashcat-Cheatsheet)
[Hash Cracking: Beyond the Basics - Youtube.com](https://www.youtube.com/watch?v=m5Ix94hbzaU&t=818s)
