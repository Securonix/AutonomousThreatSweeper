Suspected APT-C-23 (two-tailed scorpion) tissue camouflage Threema communication software attack analysis

Advanced Threat Institute 360 Threat Intelligence Center 2022-07-06 16:00 Posted onBeijing
 
### APT-C-23/two-tailed scorpion

APT-C-23 (two-tailed scorpion) is also known as AridViper, Micropsia, FrozenCell, Desert Falcon, and its attack range is mainly in important fields such as educational institutions and military institutions in relevant countries in the Middle East, and important fields such as educational institutions and military institutions in Palestine. , a network attack organization that mainly steals sensitive information . It has the ability to attack both Windows and Android platforms. From May 2016, organized, planned and targeted long-term uninterrupted attacks were launched on Palestinian educational institutions, military institutions and other important areas.

The attack platforms mainly include Windows and Android. The functions of the backdoor program on the Android side mainly include positioning, SMS interception, call recording, etc., and also collect intelligence information such as documents, pictures, contacts, and short messages. The functions of the backdoor program on the PC side include collecting user information and uploading it. Go to the designated server, download files remotely, and control remotely. The backdoor program mainly disguises as documents, players, chat software, and some commonly used software in specific fields, and infiltrates through social engineering methods such as harpoons or puddles to infiltrate specific targets. The crowd attacked.

Most of the previous two-tailed scorpion samples used the VC version and the Delphi version, and it is rare to use public commercial RAT components for attacks. The samples found this time may be the evolution of the organization's attack method, or it may be an internal appearance of the two-tailed scorpion tissue. The attack method used by the new branch members.

We were first through a document titled " تسريب - اجتماع - القائد - محمد - دحلان - و - المخابرات - المصريه .pdf (Commander Mohammed Dahlan and the Egyptian Intelligence Conference (MoM) leak.pdf)", Mohammed Dahlan is a Palestinian politician , who was head of the Palestinian Authority's preventive security forces in Gaza. The content of the document is shown in the following figure:

Through the document, we have linked the activities of the two-tailed scorpion that are not the same as the previous attack. This attack directly disguised the commercial RAT as Threema to induce users to click to open it. Threema is a paid open source end-to-end encrypted instant messaging developed in Switzerland. application.

1. Disguise Threema communication software

1.1 Camouflage Threema Icon

1.2 dropper
It is a drooper program that hides the encrypted PE data internally, and first creates a mutex.
Run the second layer loader by decrypting and loading the assembly.

1.3 Loader
The second layer loader Coronavirus uses thread injection technology to start the final attack component .

1.4 backdoor components
The final load and execution is the backdoor program QusarRAT , which is highly obfuscated. Quasar is a remote management tool written in C#. Due to its open source and feature-rich features, it is often used by hackers for various network attack activities . The main functions are as follows:-
Get target computer system information
browser data
keylogging
Implant other attack components


2. The server.exe program disguised as windows

2.1 Loader
The sample first extracts the data in the resource, XOR decrypts it and decompresses it.
Copy the program itself into the process, load the new assembly netmodule module into its own process, and attach it to the PE file.

2.2 Backdoor Components
The newly loaded netmodule module is njRAT .
The main functions are as follows:
monitor screen
keylogging
Steal passwords saved in browsers
file management
Process management
Turn on the camera

3. Associate suspected early procedure

3.1 Loader
Further, we correlate to an early sample that may be the two-tailed scorpion organization. When the malicious sample runs, it will pop up a prompt: "It is encrypted by the trial version of agile net protector and cannot be run on other machines." .
The sample will also decrypt subsequent payloads from the resource .

3.2 Backdoor Components
Eventually njrat is called as well .

4. Other disguised files

4.1 njRAT disguised as Microsoft, Chrome_Update.exe

4.2 RemcosRAT disguised as word

5. Script file analysis

#### houdini RAT
In the source tracing, we also found the script Trojan of houdinirat, which has never been seen in the previous attacks of apt-c-23.

Houdini RAT is written by an individual, foreign security vendors believe that the author is from Algeria, and through the shared code base, it is found that this RAT is related to njw0rm and njq8, the author of njRAT/LV, and has been used in targeted attacks against the international energy industry . Its main function as follows:

Execute the specified command
Change malware configuration. For example, dynamic DNS names
Remove malware from system and clear all shortcuts.lnk
upload files
Copy files hosted on the website to the victim
download file
Enumerate disk information
Enumerate all files and directories
enumerate processes
cmd command
delete the specified file or directory
Close the specified process
hibernate

The code snippet is shown below:

#### Summarize

The situation in the Middle East is turbulent and complicated, and black swan incidents are frequent. Last year, the Two-tailed Scorpion APT group used the hot information of Palestinian elections as bait to conduct attacks many times.
Disguising commonly used software to paralyze users is an important means of APT attacks . Most users have low security awareness and are easily confused by disguised software . They are captured without any precautions, and then leak confidential documents and important intelligence.

#### Indicators of Compromise

fe95d8a44e6047359782847c3852e303
d5e862732624ba62916b191e839f9cd9
67e49231a7da6e0665d2b6510f7932f8
c6d5e25aa91f25c481af0c9fd14a99d3
bff7e965b4df2317299dc06da7e5e992
b5222c8908c26e4edbf2dc9543fb968e
b37ecb0832f911267ee48a8751a61943
8e934709cfbe794c08869c96f592e821
8e13021933bd83808b3653340163f757
7ea19d7ecc2a208821d6f65cfbea61a3
7e0430ef032fef57fb55dd805853a35b
64b85ebef0e4f2ada394feb8fde7be16
5f9e3b3b5311b0dc6ff6360a39338ebe
5cccc98aab2c1ed93dc7f8dc97c4736c
54c3c7d76cdbf1dc7afa5dd52dbcd734
433036440887de33d9881e4addfe9129
343ddc013ab5eedf64ecec12e0538e44
24609655b2ed01ce4c6a7c6f86b1ae94
17f66a30b20cde794a8c658cc57d8c4d
14c9d9e1c3f8fdb224f8877313958af5
0f36cf7ad5a8244e5f200d766c85dec7
rootx.ddns.net:1993
213.244.123.150
