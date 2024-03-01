using SecurityPackageTest;
using SecurityLibrary;
using System.Collections.Specialized;
using System.Security.Principal;
using System.Reflection;

PlayFair playFair = new PlayFair();

//string mainPlain = "armuhsea";
//string mainKey = "monoarchy";
//string mainCipher = "rmcmbpim".ToUpper(); // RMCMBPIM 


//string mainPlain1 = "hidethegold";
//string mainKey1 = "helloworld";
//string mainCipher1 = "lfgdnwdpwoav".ToUpper();
////  enc checked       LFGDNWDPWOAV

//string mainPlain2 = "comsecmeanscommunicationssecurity";
//// me                COMSECMEANSCOMMUNICATIONSXSECURITY
//string mainCipher2 = "dlfdsdndihbddtntuebluoimcvbserulyo".ToUpper();
////  google            DLFDSDNDIHBDDTNTUEBLUOIMCVBSERULYO 
////  me                DLFDSDNDIHBDDTNTUEBLUOIMCVBSERULYO

//string mainKey2 = "galois";

//string mainPlain22 = "comsecmeanscommunjcatjonssecurjty";
//// me                COMSECMEANSCOMMUNJCATJONSXSECURJTY
//string mainCipher22 = "dlfdsdndjhbddtntuebluojmcvbserulyo".ToUpper();
////  google            DLFDSDNDIHBDDTNTUEBLUOIMCVBSERULYO 
////  me                DLFDSDNDJHBDDTNTUEBLUOJMCVBSERULYO


//string largePlain = "theplayfaircipherusesafivebyfivetablecontainingakeywordorphrasememorizationofthekeywordandfoursimpleruleswasallthatwasrequiredtocreatethefivebyfivetableandusetheciphexlrckhtbrvmbrkhqcrxlrckhtbavheleeatgteenetnwembpqewovtdfheufiknylinthespacesinthetablewiththelettersofthekeyworddroppinganyduplicatelettersthenfilltheremainingspaceswiththerestofthelettersofthealphabetinorderusuallyiandhzittfcsoncapsegteeniohwqdpueityitintfexceruwsoftfdnpelbeoslldhtyvtorightorinsomeotherpatternsuchasaspiralbeginningintheupperlefthandcornerandendinginthecenterthekeywordtogetherwiththeconventionsforfillinginthefivebyfivetableconstitutethecipherkeyxlrckhtbrvmbrkhqcroencryptamessageonewouldbreakthemessageintodigramsgroupsoxlrckhtbemblyvterssuchthatforexamplexlrckhtbrenzloworlxlrckhtbrbecoqrvmbrkhqcrhelloworlxlrckhtbrvmbrkhqcrndmapthemoutonthekeytablxlrckhtbegkmdederxmbrkhqcrppendanuncommonmonogramtocompletethefinaldigraxlrckhtbbmhzetwolettersofthedigramareconsideredastheoppositecornersofarectangleinthekeytablexlrckhtbrctetedrdlwletavosinholohtferooksnrsofthisrectanglxlrckhtbbmhenopdzytiehslzlwrnlgisuurrulexlrckhtbbglwcdplmbrkhqcrtoeachpairoflettersintheplaintextmslxmbrkhqcrfbothlettersarethesamexlrckhtbrcwltvoqenblyvterislefxlrckhtbrvmbrkhqcrddaxlrckhtbrvmbrkhqcrafterthefirstlettexlrckhtbrdkorvsqxtheqewpphbwndboqnftvzmbrkhqcrxlrckhtbrvmbrkhqcrfthelettersappearonthesamerowofyourtablxlrckhtbbvreplacethemwiththeletterstotheirimmediaterightrespectivelyxlrckhtbbvrappingaroundtotheleftsideoftherowifaletterintheoriginalpairwasontherightsideoftheroxlrckhtbbmsmifthelettersappearonthesamecolumnofyourtablexlrckhtbreatorblgeqenmhtfekeyvtersimmediatelybelowrespectivelyxlrckhtbbvrappingaroundtothetopsideofthecolumnifaletterintheoriginalpairwasonthebottomsideofthecolumnmslxmbrkhqcrfthelettersarenotonthesameroworcolumnxlrckhtbreatorblgeqenmhtfekeyvtersonthesamerowrespectivelybutattheotherpairofcornersoftherectangledefinedbytheoriginalpaixlrckhtbbmhzeorderisimportanxlrckhtbbmfeikewmqblyvteroftheencryptedpairistheonethatliesonthesamerowasthefirstletteroftheplaintextpaixlrckhtbrvmbrkhqcrodecryptxlrckhtbeashiegtubearxmbrkhqcrppositexlrckhtbegtfdnowlxmbrkhqcrulesxlrckhtbagshfzmbrkhqcrstasxlrckhtbrvmbrkhqcrdroppinganyextraxlrckhtbrvmbrkhqcrxlrckhtbrvmbrkhqcrxlrckhtbeamhanbokoyuemezsndbittfdhgtanhswsohbahcmkitbslbshsmxlrckhtbbv";
//string largeCipher = "NKROMPUIWGDEFWKBFPOBWSGKZDCXGKZDMORNRESTMOHQHQMDTKWCPEEAFRFBSWDTDTPEKYOMKWTSKLKBTKWCPEGDMBKPPFWHLATRFPTRWOSWPMMLGSQOSWDRLYFCRBZEEDDOZKNKRKGYRCUIGYKZSDTRSMRVOBNKREFWKBUNDEFINEDUNDEFINEDUNDEFINEDAKBTRDOMKZKBTKZQSDTRSTCOPZMRGKBPLKFQXQFQLKBWAWDBOHQNKKZSDTRCQNKNKRTKZZKBPPKNKKTCZOPDBBDPAWFMHSMVCPRQFDWZKTRNZZKBPNKBTGKNUMLKBDRVDHQHQHAASERWOKQKNKBDRONPKNKRTKZZKBPPKNKDOURGSCRQKTSDBRDXPVPNUQUGWMBKXKQLKBWSTDWAWDKZKBTKWISMCRPCKQZKQHQLKBZERFPOWPKLKBMORNRKEPNMRKNZXZECFHIZECFXBATKENKRDASNZZKBLPXBISWSWWFDPNRDKHQQHMHHQNKRZSUORFURKNKSMBEPETBDPMBBTCGMHHQNKREBTZKELKBTKWCPEEMAKKZKBCPKQKNKBEWMXBTQKSTPHPEGKNUQFMHHQNKRKGYRCUIGYKZSDTREWXBQKLZZKNKREFWKBEFCZUNDEFINEDUNDEFINEDEKQBCUOLDVBOWSKDSTCOPZMRCDDOTZKBTDBSWSKDHQZECGFDDVAHEPPRWPUNDEFINEDTRNZXZKBPPXBINKOMKPDRVSLATRUNDEFINEDRTXTPOPFUUNDEFINEDCREWTDUNDEFINEDKBNUTPOPFUUNDEFINEDUNDEFINEDMBVDOLKBTAZLSTNKKTCZMORNUNDEFINEDKGTBRBRBUNDEFINEDSUORMBSMXLEWNVTAQNSTAKDPNLWEATRUKZKZKBGKMSMRKHDPUNDEFINEDNKXKZOPTRNZZKBPPKNKRBKHDPVDDREWXBGCRDRBSWNKKESUAPWHZKEWBLRDWPGPDREQSMFMCKQLKBTKZQSDTRUNDEFINEDEZKZKBDRMPQKZDAPWHQKSTPKNKREPETBXBPPKNKHWDREQSMFMUNDEFINEDNKBTSARUZQKBKPNUTPCQMHKPXPFFPTRUNDEFINEDHQPEBRUNDEFINEDZEDOBIASFCPKTRNZZKBPHQNKROMPHQZKZNNANUNDEFINEDHREZFNKZZKBPPDKZKBWSTDUNDEFINEDEPQMZWTBTRNZXZKCFPNRKUNDEFINEDUNDEFINEDBVGDUNDEFINEDUNDEFINEDPGZKELKBGKBPLMKZZKUNDEFINEDBTEDUWNZNKBTCOASFCSMBESTQKLXUNDEFINEDUNDEFINEDUNDEFINEDKLKBTRNZZKBPSAORPDSTNKBODVRDPOPKZWPFMORNUNDEFINEDXDRRUWDKZKBQAKQKNKBTRNZZKBPZENKCKCFNVTDCGOMRDKHKNDRWAREQKZDQUUNDEFINEDXDPSUWFMHPDPZMBZENKRTRKNOGCKEKLKBEPCQGPTRNZZKCFQLKBPEKHHQPMASFCOSWPQLKBCFHINOGCKEKLKBEPUNDEFINEDNANKGNKRTKZZKBPSAORPDSTNKBODVREPTVLTSIUPZELSDTRUNDEFINEDROMPERNKDTCQNKNKRTKZXZKBPGQTDCGOMRTXCRTPODRWAREQKZDQUUNDEFINEDXDPSUWFMHPDPZMBZENKKZPAWHBRPKNKREPTVLQHGPTRNZZKCFQLKBPEKHHQPMASFCOSWPQLKBESNZZENAGCKEKLKBEWUPNQNANUNDEFINEDKLKBTRNZZKBPPDBTEZSTNKBODVRDPOPEEWUPNQUNDEFINEDROMPERNKDTCQNKNKRTKZXZKBPSTNKBODVRDPODRWAREQKZDQURXMONZNKKENKRDASFCPKEWBLRDWPKLKBDREQSMFMRBRKHQRBCXNKKECFHKMSURWGUNDEFINEDNKXKEDBRDHWGQAPELSMUNDEFINEDNKRKFCONTRNZXZKEPKLKBBTEDUWZKRAWGCFONKBSTKZGSLMKCWPQLKBWSTDEPOSONKBGKBPLMKZZKEPKLKBRUWGQLBZLOWGUNDEFINEDUNDEFINEDAERECUOLUNDEFINEDOBNKCKMXRDOBUNDEFINEDSUAPWHZKUNDEFINEDKLKBMPONUNDEFINEDPUBOUNDEFINEDMBNKUNDEFINEDONSWUNDEFINEDUNDEFINEDBDPAWFMHSMZCZNDPUNDEFINEDUNDEFINEDUNDEFINEDUNDEFINEDUNDEFINEDONGSMESTEZVDTKOBXBCKQLKBGKMSMNBOWSKDSIBTGKQHBNRBNANUNDEFINEDX";

//string largeKey = "pasword";


//string cipher = playFair.Encrypt(mainPlain, mainKey);
//if (cipher == mainCipher) Console.WriteLine("Encryption correct"); else Console.WriteLine("Encryption wrong");

//string plain = playFair.Decrypt(mainCipher, mainKey);
//if (plain == mainPlain) Console.WriteLine("Decryption correct"); else Console.WriteLine("Decryption wrong");


//string cipher1 = playFair.Encrypt(mainPlain1, mainKey1);
//if (cipher1 == mainCipher1) Console.WriteLine("Encryption1 correct"); else Console.WriteLine("Encryption1 wrong");

//string plain1 = playFair.Decrypt(mainCipher1, mainKey1);
//if (plain1 == mainPlain1) Console.WriteLine("Decryption1 correct"); else Console.WriteLine("Decryption1 wrong");



//string cipher2 = playFair.Encrypt(mainPlain2, mainKey2);
//if (cipher2 == mainCipher2) Console.WriteLine("Encryption2 correct"); else Console.WriteLine("Encryption2 wrong");

//string plain2 = playFair.Decrypt(mainCipher2, mainKey2);
//if (plain2 == mainPlain2) Console.WriteLine("Decryption2 correct"); else Console.WriteLine("Decryption2 wrong");


//string largeCipher1 = playFair.Encrypt(largePlain, largeKey);
//if (largeCipher1 == largeCipher) Console.WriteLine("Encryption large is correct"); else Console.WriteLine("Encryption large is wrong");

//string largePlain1 = playFair.Decrypt(largeCipher, largeKey);
//if (largePlain1 == largePlain) Console.WriteLine("Decryption large is correct"); else Console.WriteLine("Decryption large is wrong");


string text = "index";
string key = "key";

string cipher1 = playFair.Encrypt(text, key);

string plain1 = playFair.Decrypt(cipher1, key);


/*

                    M O N A R
                    C H Y B D
                    E F G I J
                    K L P Q S
                    T U V W X

The Plain Text is:             armuhsea
[+] The Text After Splitting:  AR MU HS EA
[+] The Cipher Text is:        RMOTDLIM
[+] The Correct Cipher  is:    RMCMBPIM 



                    G A L O I
                    S B C D E
                    F H K M N
                    P Q R T U
                    V W X Y Z


 comsecmeanscommunicationssecurity
 CO MS EC ME AN SC OM MU NI CA TI ON SX SE CU RI TY


 
                     
The Cipher Text is:  DLFDSDNDIHBDDTNTUEBLUOIMCVBSERULYO
After Splitting:     DL FD SD ND IH BD DT NT UE BL UO IM CV BS ER UL YO
Decrepted Cipher is: CO MS EC ME AN SC OM MU NI CA TI ON SX SE CU RI TY

 
*/


