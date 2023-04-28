# serious-tings
so this is a simple wifi "hacking" tool that i made,it uses scapy to scan for nearby wifi networks and then uses hashcat bruteforce attack to try and get the password for the network
REQUIREMENTS
1.)you need to have a wireless adapter which can be set in monitor mode
2.)you'll need to install scapy and npcap,you can just install scapy from the terminal in visual studio while npcap you can download the exe file from browser
3.)if you cant run it from visual studio then you can try running it from command line but you may need to install aircarck-ng in your machine(if you do decidethis method then i have another code for setting up wireless interface on monitor mode using aircrack-ng,its a short code too)

HOW TO USE
so once you run,there are 2 options :scan networks and test networks.
if you dont know the wifi's ssid or  channel number youll have to 1st scan and get the available networks. 
youll also need to save the wordlist in the same file that the handshake is stored inorder for it to work(ill provide the wordlist later)
ill continue to improve it where necessary because it still needs some improvement but so far it works great
