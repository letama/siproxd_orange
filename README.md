siproxd_orange
==============

**L'utilisation de ce plugin est à vos risques et périls!**

Il y a un risque certain à utiiser ce plugin, je décline toute responsabilité quant à son usage. 

Description
-----------

Il s'agit d'une version expérimentale du plugin orange supportant la dernière mise à jour d'Orange.

Il faut impérativement une plateforme ARM (raspberry pi ou autre) pour l'utiliser, le plugin appelle
directement la fonction de génération du digest de la dll libVOIP_ENGINE_API.so.

Compilation et installation
-----------

Mon raspberry est sous un ubuntu mate 16.04.

1) installer les headers android: 

		apt install android-headers 
	
2) Compiler et installer libhybris (https://github.com/libhybris/libhybris), 
3) Copier le contenu de extras/system/lib dans /system/lib
4) Compiler extras/test_hybris et l'executer. Cela permet de s'assurer que la librairie fonctionne correctement.
Si tout va bien, vous devez obtenir:


		starting!
		calling
		done!
		digest final:1e911e934077f322ae7bea91fe1f1ad1

5) Le plus dur est fait! Compilez siproxd et le plugin. Attention: j'ai changé le makefile du plugin pour ne plus 
avoir à créer de lien symbolique vers siproxd, les sources du plugin doivent être placés dans le répertoire siproxd 
de siproxd, par exemple: ~/siproxd-0.8.3dev/siprox_orange

Pour s'assurer que tout fonctionne, activez les traces de siproxd et sur un asterisk reload, vous devez lire ça:

		11:18:13.077 src/plugin_orange.c:416 ha1      = [xxxxxxxxxxxxxxxxxxx]
		11:18:13.077 src/plugin_orange.c:417 nonce    = [xxxxxxxxxxxxxxxxxxxxxxxx]
		11:18:13.078 src/plugin_orange.c:418 nc       = [xxxxxx]
		11:18:13.078 src/plugin_orange.c:419 cnonce   = [xxxxxx]
		11:18:13.078 src/plugin_orange.c:420 qop      = [auth]
		11:18:13.078 src/plugin_orange.c:421 impi     = [xxxxxx@orange-multimedia.fr]
		11:18:13.078 src/plugin_orange.c:422 authtype = [Digest]
		11:18:13.078 src/plugin_orange.c:423 realm    = ["orange-multimedia.fr"]
		11:18:13.078 src/plugin_orange.c:424 password = [CHAINE HEXA]
		11:18:13.161 src/plugin_orange.c:462 req_uri  = [sip:orange-multimedia.fr]
		11:18:13.162 src/plugin_orange.c:463 response = [CHAINE HEXA]

Si password et response contiennent bien une chaine hexadécimale, tout va bien.

En cas de soucis, n'hésitez pas à me contacter sur lafibre.info ;)

Problèmes connus
--------
* Il me reste un SIG_SEGV en sortie de siproxd.
