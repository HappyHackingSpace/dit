package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/happyhackingspace/dit"
	"github.com/spf13/cobra"
)

const plainBanner = `
u***mo**oomqmmo**o**oo**o******mmmoooom*u*nnn
xxxzxxxzznuuuunxz*nrjjvvrznnzrrxzzzzzzxjjxrrj
jvvvtvvtttttjjtvtftxumqm*nrtfttjrrjrjjvttcfvt
cifc|cccc||ii|i/fdEEUKHB&MAY*|itvjtfccc|i/|ii
\\((\//\))\/()}vT*i}\vqUH%@@%E|\|||/\\)((/|//
}({][][[}{}{{?jQc,,,-:]xVKW%@@S\|/\){{)}[}(((
fvt{[{{?]]!!1cAY?<^~~?{\jIX%%%@Vm*xfc|}]]??{/
Coou*oqur}1!?JXZrotlmuuICpD%%%@KPFbpdm/!?l!(f
bbqCCTVTTpoCoP#T!{[!j??}{zA#W#@XEEIJLJu}]})\f
PFVVTVTZZYYUQKWD}<l\u]>[zZ&WB&W&RZVTLJd*nuodo
SFEEEEVPPPYSQXMWJ([*Jx/vCRW#&W#WARRSSUZEVJLEP
UYPEZUSUYZZFPDB&ME|!izuJUO#W&##WDPPTVPEFVPFVV
QKREZYYPFTIppGBBW@XELUDOOOXW#W##MYZFVZYZSRZVV
NNUELJJJdpmqdPMM&W#WquJVLdIDW%#W%KUEPVFVICbJT
TFLIIEPFNNNSDAB&&KVz(]{){{\qAODH##MQRTVJj*CpC
PUVITVLPKDXQH#WMT}^"";~;:>?zNNG##&&HRptjx*qqd
EYEdoupEUFGH&WRC{"",,"",:>]mRGQDUVZK&AYIonxvv
FZPPPbpqdD#&#At~,---''-,-:]oLJdpJPGO&##BDUUVo
TCdbbdbED%&BHYIx/)?;:,-,;}zLRDH&W#@@%W&&BGUUZ
VCdbdqE&MXXOSUQGUTIdppmoCRKW%&XQKHMW&W&BBHRYS
RPVFVVQXXBBOKXOANPEZRSSQXW%%BXXOKUUQAB&&BBAZP
m*nnzEHXXBMXXMHMAAOKNNQXW##WBWBKNYDMW#%WHOXGF
ELJTUXMOAHMXBBM&XXXKQAHB%%##WBOHXB%%%#WWXHXAS
RNKHXHADNDXBW#WBBBOKOXWWW####WW@@%##%%#WMMMXO
KOHHOOXOHMMM#W&WWXAOBW#WW%%%##@@@####%%#BBMHA
XOXODSQGNO&@@@@@@#WWWW#%#%%%%@@@%%%%%%@%W&BMM
XBBQEFFZPPEdtczbPDX%@@@%#%%%@@%%%%#%@@%%W&&BM
XBWHQNNDNGb[l??![(/nVRB@@@@@@@%@@@@%@@WWBBBBM
WW%%#BWMHMKZTqji\\/)itfLQKSNAKRRKOB%@%WDM&&BM
W%%%%%@%%OZIxxpqzrvzupJTVLFUUURNGHHB@@%#W#WW&
##%#%%%@#Tp*t(xTFJComJJEGAOMXBK&&&%#@@@@%#W#B
@%%%%%%%&GEIndZNKOKDRKOKQW@%%@@@@%@@@@@@%%#W&
%%%@%%@%%%WZUW&B&BMXMW#@@@@@@@@@@@@@@@@@%%###
`

const (
	bannerWidth       = 45
	bannerPixelHeight = 68
	bannerData        = "" +
		"bXlMa3ZFa3tLantMaHVCaHdGbHxKbHxOaXtQaHhKaHhHZXREZnZFZXZHZ3hJaHtObXhHbnRF" +
		"a3hGa3hHZ3dMaHtNbn5Pan1RZntPZXpOaXpHaXhEZ3hHZ3dDZ3hFY3NFY3BBY3NFZHdIZnhJ" +
		"ZXZIZXdJYHRIZndMaXlOaXpMantObH5VbH5TcH1Mb3pCcHpFbnpGa3hGbHlKcX1LbnlHa3ZG" +
		"bHhHZ3VFZ3REandDanZBbHhEa3pIcXtGcndFcnk+cHpEbHpKbHtKbn1LbHxLa31ObHxPbXtJ" +
		"bn5Mb39PbX5Mb3xHa3hGa3hJbXpGbntEb3pFbnpHbXlJaHdIa31Rb39Ucn1Jc4FPdIJQcoBN" +
		"dIJRdoRPdoNOcn5KcH1Mc39Mc31Jc31JdIBOb3pKbHdGbndEcHlFb3tIcH1Lc39Jc35LcnlF" +
		"dn5GeIJMc4FRdYJOc4JSc4BRcHxOcXxNcXxKc4BOcoJQc4NSdoJPdoBNcn9QcnxLdX5KdX9O" +
		"dn9Lc35NcYBUd4hbeYdZdYNWdoNUeIdXe4hWd4RVeYdUd4RPeIVQeYlWeYpafopXe4RPeIFO" +
		"doBMdoFPdn5KdX9OcoBRdYFOfIVPeoJPeH1HeIBNfIVQfIZUfIdXf4pafolaeIFUeIBPdH5Q" +
		"dYFRdYNTeYpce4lXeYNTeIFReYJReoRVeoNTeoJQeIJVeIdbe4pde4hbeIZdeYVYe4VVe4dW" +
		"eYNReYNNgIhOfodPfYxefYpbfolWgYxZgotZgopVgIZOf4dRfYZRfIVPgYpRgYpSgoVLfoFL" +
		"foRSfodZgo1fhYxYho9eh5JjhY5dfodUeYJSeoVWfYpcfo5hfYxafIhVfIRRfoVSfYVVfINR" +
		"f4ZVfoZYfYhafYthfYhcgYtegYtZgIhTg4xZgYpThI1XhY5Wg45Zgo1agohTgYlWgYtZg4pZ" +
		"gotZho5Uho1Tg4lPg4lMhIxShYtTh4tQhohRj5JYh4dUe3RHcmQ6bl84b2M8dnBDf4BLgotX" +
		"fYhXf4lYg4xVhI5WfohVfoRNgINKgIdTgIVRf4VXgIlaf4pbhY5dhotZh5Fgh49YhYpPh41W" +
		"iJNdiZZkg41YhoxSio9VhoxYhYtYh4pUiIxXjJJbjZVfi5Jdh41ViY5UiY9ViI5Xi5BbkpBX" +
		"eWg1Z0McXzcWSSgVQyUYPR8WPiIXTC4bXE0vgIBLho9ahI1Zho9agohVgYdRgYdRg4pWg4pZ" +
		"go1ghI1ahY1Xi5FcjZFckJdijJNciY5UiY5ZhI5ahpBgh45YjZFYkZZcjZBYjJFdjZFdjpRg" +
		"kZdgkJVdj5NbkZZclZlXkZZZkJZhlJNWdV4sXzkSd0sXcUoeXTscUzUeQikbMR8ZMRoUMRI" +
		"NNSEWenlGjZZciJFeh5BahIxXgolVhY5bhZBiiZVnjJZgjJJWkZRZkpNXk5Zcj5RbkJVajpRc" +
		"jZZjjZZik5hilJlhlJlmkZdlkpZgkpZjk5lmlZplk5hikJRelZldlZlek5himZ9rdF80Yz0Z" +
		"gloilm4qh2AndU4hXTsdSiwbOiIaKRkZJhYXIg0ULBsZh4ZOkppjipRjho5bh45aho5ch5Jj" +
		"jZZkj5djlpxlmZpdmJhdk5Zbk5VakpVckZVfl6Fulp5plp1pmJ1pkphkkphkl5dbmJhfmp5o" +
		"m55lmJlilZhimZxhm55mm6R2iIJVakUcp4E5yKJO0qxTyqNJt5A6mXAqZT8dRCkdMRwcJBMa" +
		"JxUaFgYWQDMlkphdjZdmjZlpj5dkjpVej5dkkJhnlZxmmp5nmJpimJphlZdelJVbk5VdlZZf" +
		"kZpllZpilp1sm59om59lm51jnJxgnZ9loKFnn59knJ5mnp5jn59hn6RvmJ5wYkkqmnIv2rVd" +
		"5L5n6MBh5L1e1q5OwJg9lGkkYDsbPCIZJhMXIA8ZHxIcFAURb2pDl6JtjpdokJlolp5pmJ5m" +
		"maFsmZ5pmZ1nnaFqm59rmJxqlZZel5hdmJlfmqBpk5pinaFoo6dxoql1o6ZsoqRqo6RqpKRm" +
		"oKJqoaZxoKJpnp9qo6uAgXhRTy0at5BA4Llh47xi5b1h5r5e3bNUx59DonkpdU4fSiwbNRoY" +
		"JBIaHBAcEwYUOzIolZ5niZJfkZlll5tjmp9onKRtmp5qm59po6Vso6hzoqRtn59jnZxfm5lc" +
		"oKZukZhhmZxko6h4pKl7qq53rK50qqxyo6Jnn6Fso6dwoKBkpadupKNtaU0sWjUeu5ND2LBa" +
		"27FX3LNY3LRa0qlPvJM8qoExkGgmbUgiOR4aJBEaHxAbFAgVHxMZanRMfodSh4tVg4tVj5lk" +
		"kJtjmJxlnp9mo6NopKZtpqlspaNkoaBinZxgh41bf4FQhYhUn6Nvqqhtn59fnaBgsK5yqqp2" +
		"o6Vzqat1q6tutLR0lYdNSSIcaEUnxZxN1Kxc3LNd3LRc3LVf1q1SyKBLv5ZDsok8j2ctQiUb" +
		"JREcIBAcGw4aFAkYTlM3bHJAa25AdH5Rg5Bef5Bci5NfpaRoqKhtpqdopqZpqaZipqJgk5Ze" +
		"Z2tFe3pKdndLhoZTjopQi4dLgIZQho9fmZxrr697ra53s7B2trVygnBAPR0ha0kvx51Nv5RH" +
		"0KVP3LNYw5dGo3g0sYg9q4M7mXI1fFcpRCYbJBIgHA8gIRIfGgsbQEAxUlw7ZWxCa3hPaH1V" +
		"b4RYeIVWoJ9ip6dpq6dhsrBtsq9qnZpZio1XXGRHb3FLdnZMeXlMcG5EcnBCaG1Ga29IdnlJ" +
		"j5ZnrLF8sq97nqBsZ1k6TSkjXTksi2AyhFktnnEyzaFGf1YqiV0qjWEraEEiXjghelEnUC8e" +
		"KxQhIhIjHBEhHQweNTMuS1g8TFk9W2xLYHZUWG1QZnNNk5RUrqtoraljsbBtr6xsn5xdkJNe" +
		"ZGxMZm5Nb3NNbGxIb2xFZ2hBWF5CcW9EcXNHjpRinp5qhIdekptnZk43RBodbEgvq4BBlmgy" +
		"p3o2yZ9LiV8uvZA/pngyjWQvrYM+qYA6VjQgKxQgIxMjHBEgHg4eMi4rRVM5QlE9TGFJUmZJ" +
		"T2JJV2hMh4xYsK5rqKpup6hwo59inJZSh4lVYGpPXm5QZnBMZGdAZWU9Wlw7V1w9W148WV08" +
		"b25Cd208XF4+cXNMZUkwNA4Yf1cs3K9Uy6FO0aVNyZ9KpXw3zaJI2K9U1qpQzZ9Gn3MxSikc" +
		"IxIeIhUiGxEfIREdKSMlQEw1R1I2UmFDS15FRlpDS11BaHVQoaRpp6VooKBkn51hnJpehYlZ" +
		"VlxEVGBKWmVGVls7XF49UFM3VFs6SVA3S045TEozW1M4WVY5U042Wz8qPBUbbEQl16hQ2rBe" +
		"1a1ay6NUr4dC06ZQ4rVd26xStok6glgnPSAZJxYfKhojIhYiHhIfLSQlW2JDXWNBYm1JW21O" +
		"V2xPWGtLYnRPg4xbmZddmJVZl5JWjo1ZiIdZTVM+TFNAUVY/VVc8XmNDXGA/U1k8Sk82Sk43" +
		"UVA3T0ozSUczQTktSygiRBkbUi0gyppL0qVTy6BRzaRVong5xplM16hTxJdHnHE0a0UiNxwY" +
		"KRYfKxoiIhYiGxMhJxshPEExR004VF1DVGZLU2tQW7FTaH1Yd4ZbfYhbdYBUaXJOYWdHdXpS" +
		"RkY5TVY/TlM8VVc9UlM3U1g8WmBCUVY6UFQ7UlA3UE40Rkc1PDUsQyUhOhYcPR0dn3A3yZtI" +
		"yp1Iil4xbEMkwJVJyp5LqoA7h14tYj0gOB0YJxYdJxkjIRgiGxYjJRkiLzEqOD0wOkA0O0g8" +
		"O0s8PE0+SVhDUmBGTmFGU2RJWWVKTFdFTVdFQj81TlU/T1U7VVI5VlA2TE86VVk/UFE6UlA7" +
		"VVE5TUozR0YyQDgsOiMkQx0eOxgeilwus4U8xJdFnW4ziV4vmW80rIE7p348h14sYz0hNRsX" +
		"KRUbKBkiIxchGhQiJBgiODcrQUk1P0k4P0s8P0o4Q0w5Q087Q1A9SllDWmZJW2VIUllETlJC" +
		"TUs7UlQ+UFA5Vk84WlU6U1Q8TEw4TEk1T0k2TUgzS0cyRkgzRkIvRiomTCAeNBMeZj8nu4tA" +
		"vZBDsn43j2AtlmowtIpDo3o6fFMpVjQgNRsZKhYeLBkgIRUgGRIhJRkkODQsRUs2Rk05Qk9A" +
		"QVBBRlNASFZCS11JVmVNV2JGUVpESlFBTlBATUo6Uk06U003VU43Uks2TkgyS0g0SUo4Sk06" +
		"TFE5T1E4Vlg8VE0zSy8mOxgfORcdNRYefVIqzaBMwZVGroM+pXw6oHc4gVgpZD4hTi0cMBgY" +
		"KhggJxcgHxMdGxIfJxkjQzgqSU42R0w3T1hAUFg9RVE/RVJCSFVERlJDREw6SVFATVlJVlpI" +
		"QDkwQj4xTU03VFM8S0Y0TEUxTEczS0g1TlA+UFI8U1Y9V1s/XlY5TjMmQR4hRx0bPRoeMBYa" +
		"il8x3a5SwJNFl2wyeVAmYzwfVjMfPiMdLRcaKBQbJxcfJRUdHxUfJhkiPC8nTFY9UlY7X2JB" +
		"Vl09SlQ9SFVCR1pJRlZFR1M/TFpFT1hKTlVJREUtOTgsRUIzU1M4TU04SEczREMxSEg0Tk03" +
		"TVA9VFpDZWpMZ2lJSDAnQx0fOhcbMhQcKxQcNh0fZUEmbEUkXjsjVTMgTC4gPiYeQScgNx8a" +
		"LBcZKBYdIxceGxQfIhcgKSYnQU06RUk3R1VBRlhDRVE+Sk87SVA9SU49QUc4S1RDU2FOWWJP" +
		"NzosPD4zR0IyUE48T1RFS1FCTVRDUlpGWGBJX2lQa3FRanJSanFQTj8wNxogOhkcNRYcLxYb" +
		"LxodOiIgZEEkVTglSy8iRywgUDMgVzkiVzgePCAZKRQaIRMbIBYdIxYeJCAkO0UyQEw3QE8+" +
		"SlU5RU02Qkc3RUo5QUM1QkM4Q0k/S1NBTVJCNzgvNzcuQT4zTks5UVdHVl9LXGNNX2pTYGxY" +
		"YmtUZ3NZZ21PaGxLVVE8PB4iRB8gPBocMxwcNSAfQSkglHI5jGk1bkwlaUYjbUoje1kpc1Ek" +
		"TCkYMhYXJBIZIxUcJhccJBofQEUxTVk+XGM/V149U10/UVxCUl1ET1lEXF5AZ2VAXVk+UFJD" +
		"SU0/R0s8UVVCVlpFX2FGYFs8XFxAWFU8X2ZOZWlOYmlPZWpOYWNBTkkzPh4jOxwfOhkdNR4d" +
		"NyMfQCYdj245sI1EmXQzjWgsjmosl3UykmwqZj4aPRsWLBYaMRwcNR8bGA4bKyYiP0ArSk0s" +
		"Sk8zXWdHY2pIYmdEgnc8g3U+e24/bmQ+aGBCTVlNTV1SU2VWW2VQcmU3alYrVkYqYE0pSzsq" +
		"VEUzVkgqT0UuRTskQDMkMhwkMxYdNRkdOSAeTTEigF4vp4RAuJNGs49ErYg+sY0/s49Aroc1" +
		"hFggSiUZRiMdSCofPyUeIBMgIBUdKyMgMzMhNjMfRUMnNDUkSkYsk300h3M7amI5d207bmJB" +
		"UV5RS1NIVVhFbF0zb1cpXUMkYUsnZVMsSTclOCghOy0jRzgmOiwjLyAjMxkhPBweQCEgZkMi" +
		"m3YzwZ1LzqpYy6NKxJ9Ix6ROzKpUyaRNw5xCoHQrWjAbUCocWjgfPiUfLBsiKBcgNigkRD4r" +
		"VE4yZGQ+amo/e287lIFAem07aF83c2pAZV5DWEk4S0EyYU0ud1YrbVApZ0wlclkqZ1ApQi8k" +
		"RzYjMiQhSDcnOysjKBgkMxojPRwgZzsgtow5z6tU17Nc3Lhd3bdY17FU2rVa3Lhd061Rx6BC" +
		"mm0oWzAaYjYdXzseOCAcNB0eMxsgLhgfQjUmU0oogHc+o5RNloJChXU8fG87dGk5aWI/aGFG" +
		"Z0AoXUArclQud1UsclYse14reVwoYUQkTzUjVD4jPi0iTjciRSsfJhckNRsjUSYemGYo1LBU" +
		"3Lhg58Fm58Fi5L5f4LlW471h4rxg2bJTyKFBonQoajgZXzMbUzMdLBkcMRkcPiEeOx4fMBsg" +
		"QTMhZVYpgXU9h3tBjHw8jXc3gW85iHdBgnNHb04sbUcpc1EujnIyhGkvhWYre1kkaUcgXUIi" +
		"XkYlXj4gUjIhLRoiKxgiTSYhdz8buYk24bxe5MFl6cZo58Jg471d5L9b6cRp4bxg2LJTyqFC" +
		"lmcjZTQXZDgdSSwdIRMcPiQdXzshVzMiPSEhMBwhVD8jcFspf284kYFBg3Q7jHs+i31HhXNF" +
		"ZEUoWTsnYUEtf1wtl3cwlHkxh20qclcjXUcicU8hVDIfJhckJhYhNhwgd0Yio2sm0KVF5cFd" +
		"58Vm6sdr6cVo5cFm5sFi6cVm4b1e17FSyaJDl2UgbzkWXTYcUjQdXD0fc00hfFcob0wmVTcj" +
		"MB0hLBkiSzMka00qd2E5joBJkH5LmYpUpZBSbUkqZUIoaUYrXzspY0AsiGgyjW0qgl4keFUj" +
		"YjshKBgmLx8oMBwjRychpXQvzaBE4b1a58Vi6MVk6sZp6shv7Mpx6sdp6MZq5sNl3LZUxZw8" +
		"kl4fbj4daEMhhV4noHkvoHkzkWsxc1IqUjclMh8kJhgnIBUoOSEkWTcoYT8uX0k6aVtAf3FI" +
		"e1EtdE0rbkYqcUcsZ0AscUwtelEmhV4ml28qOCMoIhgoNCAmLBkjVjAfuIk36MNa5sZi5sNh" +
		"479j5sNm7cxz7dF67M916stx68pv3rtaxpo4m20ogVwojmkrkWwveVYqXDsjQighMBwhJxgh" +
		"IhYjHhUmJxooJxkpTykpXDQvUTAvXUM5gmtHbUMsb0crgFQshl4uf1ovi2Uuj2kskmsuXUAt" +
		"JBUnKBolMx8kMx4gWTUjiF0qyqNG5cVg58Zg3btf6spq7dJ369R+69N96s9468xy4b5et5M+" +
		"jGktc1InYkMkRCsiNR8eKhkfIRYgGBIgGBMiFxMjGhcoIhsrJhoqLBwsWzIwYTYvWjUzZj83" +
		"hkoplFsumF8tklgukFw0jGUwil0pUTIrKBkrJRgnLB4nNiIkQSojZEYqcU0relEomWsvqIA7" +
		"wp5N5sNm6cts6c517dJ37Mxv3bharIc7gF8pYUMiPyYfMyIjLiAkIBgiJB0mJx8mGxYiFRIi" +
		"FhIkGhcpIRstKB0rKR4vVDI3fT4ud0Iyaj84j04rklotkFguhU0tjlougVguZ0EpLBosNiUw" +
		"Kh8vMSQuOSYoVz4oZUosXUAnZEQpcEcmc0sog1wwkWcznnE0qH8+sYhEr4lCk3IzcFEmYEQk" +
		"QCwgKR0kIRsmKB8lPi8oQjIoNyknJhwkFhAhFhIlGhcpHxcpJxwsKx8vOCo4ajcycz4yYzg3" +
		"hEUrjk4tmlwrmF8ol2Ipnm4wc04wNCIxNykzMSY0LyQwQCwqVz8oVz4oSTImVjwnXUEpd1kw" +
		"eFgxeFYweVQtdU4pb00sblUuZ1EuTjkkOCokGRQhGRUlKB8lOywlUD4qPS0nMSMkJRoiIRgh" +
		"IBkkGBUmIhgpJRwtJyExLSQ2Ti0yWzAxWjE3aC4rfTosiUMojkclg0Mnh0gpXjMtMSMyMiYz" +
		"MSUzLyMuQC4rSzYnQy4kQS4mQy4lUz0rblMubVQwcFItaUsrYUQrXkgrXkoqSTcmMCQkGxYi" +
		"FhMhJh4kOSokQTEmPC8mPi8nSzgmWUImSTAhRiwkMyImKyAtJBspKR4sLiEyUzIyeUYxckIy" +
		"ZDEudzste0EveDkofT0pejonUSorLiMyKyIxJh0tKx4qPSwrQzEpNyQkQC4nQC0nTjsqWkQs" +
		"YEgsXkMpTzcmVkAqVkMqRjUlLCEiIBojGBQhHxggLiIhMyUiLSEhNCcjRzQmZEknWz8jTzEf" +
		"TC0iNiMoHhkpIx4rKh0rKyEyOCc0b0Azd0Y2f1Q2jV02j2U8il03kWA0cks0QjA1Myg0KyIy" +
		"KBwsKx4sNiYtOCkpNCQmPSsoNiUoRDEpRDEoTDcpSzUoTDcoVD8pTz4tOSspKh8kIBkjHhci" +
		"JRsiKyAjIhgeIhcdPywhUzckZUUnXkAlVjYjMh8kGRMmGRUoIRssMSQwMCQ0LiQ2Riw5Xjg8" +
		"jW4+k3I+l3Q+mHU+nnk7b1E2NycwMSMvLyU0LSEwLSMxMyUwMyQqNSYoOCcnLyAnPCsoQjEo" +
		"PSsnQS4oUT0pUDwpQTIqLyElJhwjHxckIxokIRkkJR4lHxkkMiUkRzAlWDomYkIlTTAjJBYj" +
		"FRAjHBUnHRcrHBosNykwOyoyMSY3VTw4ck43h2M6jWg8j2k6mXA4kGQ1RjEwMiUxNCk1Myg1" +
		"NCUzLiUzMicxMSMqMCMnNyYnLyAoOiopPSwoNSQnRDIpTzspQS8mOisnNCYmHhYlHxYkHxcj" +
		"HxckHhklJSAnQC8nTDEkTTMkSjEkIRQgHBAgHhEhHBQnHhgrHBsvNCcyQi41Myk6RjI5dU43" +
		"Vj42YEk5ZEs3ZUo2SDQ0MSQwMSUzPS40RC8yOScxKyAwLSMxLyIsLSApNSYpLB4oNScqNico" +
		"OiopRTMpRTIpPS0nPS4pKR8nHxYmHhUjHBUiHhglGhYlJR8mOiokOyUiMB4jIhYjGg8gJxQh" +
		"IBEiIRMmHRktHhwxKyQ0MiczLSY2MCg5RjU9Uj01XEc2WEIzQC4xMiMvMiQxMSQyQC0vSDIv" +
		"QS0uNSUuLyMvKx4qJxwpKh0nKR0oLyIpMSMnPSwpQi8oQy8nPi4nLyMnIhooIhgmHhYiGRYi" +
		"FhQiFRQjIx0lNCUhKBkgGxMiGBEhHg8eJhQhIREiIRIiHRcqHRwuJyEwKCIxKCMzLCU2Niw8" +
		"V0A1VEA1QC4zOSgyOyw0NCw3PC42STIvUTkySjMuOSUrMh8oJxgkIBUmIxgnLCAqLiEpLiAo" +
		"OykoQi8oQy8nNCUmIxgmIRknIhklIBgkFxQjFhMjFxQjIhsjKx4gEg4gFhAiHRIkJRMgIxAf" +
		"HhAhHxAhHBQnHBovKyIwLSMxKyU1LSY3OS07UDw1OCkyMSQyOy83Py8zRC0tSjMyTDMvUTct" +
		"SC8pPSUlNB8lJxkmJBcmJhgnJxwoKRwnLR8oPi0qSDYqNSQoKBwmIRclIhgmIxomHhYkGRUl" +
		"FxQjGBUiHhkiFhEhCwshEgwgJBMhKBMgHQ8eGA8iGg8hHhEiHBksLiUyKiQzKCM0Lic4OC49" +
		"PS0zNygzOCszOicwPyUtQygsNCEuNCIsNyMpNyIpOCMnNh8lIxQlJhYmKxspIxcnJBcmNCUp" +
		"QzIpOSgoLBwnJxomIRUlIhgmIhklHRYlHBcnFRMlGhckHRkkDw0gDwwgGQ4gKBMhLBQgLBIe" +
		"KxUgHBIhHBEhHRcqJiAxKCExJyEyLSU2OCw7NiYzPy01OykwMRwrNiEwNiEsOiEmRSooPCQo" +
		"KBgpMB8pMx4nIhQmIhUoJBcpIBMmKBsnOCgpNCQoMCEnLh8oJhgnIRYmHxYlGhMjGxUmGRUl" +
		"EhAkFhMkFRIiDw4iEg4hGQ4gIxAgJBAgLhUeMxkhIBAgFg4hIBUnIh0uIRwuJiAwKiU3Myg4" +
		"MSMzOik1MyEvQyUqWjUsc0UnWzAjWzQkZDklTSkkJhYpLRwnIhUmHxQpIhUoJRclKRsnKBsn" +
		"LSAoLBwmKBknIRUmIBUmGxMjFxMjHBYlFBEkEhAjExEjDg4hDgwiDw0iGw8gKhMgIxAhIQ0e" +
		"IQ4gGg4iEw4jGhQnIBkrIRwuIx4wJiI0JyE1MiU1MSIzLx4uUS8rYTYqZjopa0MmZz4mZj4p" +
		"WzQlTislJhQpJBcnMB8qKhknJBYmJBgnJRkoJxooIxUnIhQnIBUnHRQnHBQmHBUlGBMkDg0k" +
		"EA8kERAlEA8lDw4jGREjHxEiGw0hIxIiJhAgHg0fIBEiHBEkFBEoGhYsIhwuIhstJSAzJyM3" +
		"MCY4Kh8zLB0uUDAtbEIqf1UrckcpaT4nb0gseU0obkgpelcxsItEvpNGpnk6eVUySTEsJRco" +
		"Fw0nHBAnHhEnGhInGhMoHRYoGRQnEg8lCwsjDg0kEhAmExEmEhAkFA8kGg4kHw8jLBQiKhEh" +
		"Hg0hGA4jFQ0jFRAnGxcsIhsvJhwvJh0yJSE3LiQ4KSA3LB0wSSssdksqXzksakAqaUIqYjsq" +
		"XzgpeFQxxZxI3rJU2a1SzqJJx5hCuIg9lGk3cE80OSMrFAsoGhEqHhUrGxUqGRQpFBEnCgsk" +
		"Dw4nEQ8lDw4kExAmEQ4lHBAmJBImKRQmJxIlHA0kFA0nFBAnGhUtHRkxJhwxKBwxIxozKiA2" +
		"LiI3KB42IxkyQysvVTQsXzcsYjoqSSkqXjUqVDAshWA0vZNJxp1MxppJx5tJx5tIwJNFv49C" +
		"xpRDqHQ4UzMtIRgrEw8qFhIrGhUqExAoDw4nDwwmDw0mEA8nDw0mDw0lEQ0nGQ8oIxEnJhIn" +
		"GQ0mGg8oIxwyHBUtIBszKCA2Jh0zKB00LCE3MyIyKRwxGRQuMB4sNh4rTy0qSicnTiskVjMp" +
		"VDMsckkuqXs8r4M+sYQ/vI1Bw5VFxJZEwJFBu4w+vIg7v4k6nW4yVTkpIxcmEA0lCAkjAgUi" +
		"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"
)

func renderColorBanner() string {
	data, err := base64.StdEncoding.DecodeString(bannerData)
	if err != nil {
		return plainBanner
	}
	expected := bannerWidth * bannerPixelHeight * 3
	if len(data) != expected {
		return plainBanner
	}

	var b strings.Builder
	charH := bannerPixelHeight / 2
	for row := 0; row < charH; row++ {
		for col := 0; col < bannerWidth; col++ {
			topIdx := (row*2*bannerWidth + col) * 3
			botIdx := ((row*2+1)*bannerWidth + col) * 3
			tr, tg, tb := data[topIdx], data[topIdx+1], data[topIdx+2]
			br, bg, bb := data[botIdx], data[botIdx+1], data[botIdx+2]
			fmt.Fprintf(&b, "\033[38;2;%d;%d;%d;48;2;%d;%d;%dm▀", tr, tg, tb, br, bg, bb)
		}
		b.WriteString("\033[0m\n")
	}
	label := "dît " + version
	pad := (bannerWidth - len(label)) / 2
	if pad < 0 {
		pad = 0
	}
	b.WriteString(strings.Repeat(" ", pad))
	b.WriteString(label + "\n")
	return b.String()
}

func isTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func banner() string {
	if isTerminal() {
		return renderColorBanner()
	}
	label := "dît " + version
	pad := (bannerWidth - len(label)) / 2
	if pad < 0 {
		pad = 0
	}
	return plainBanner + strings.Repeat(" ", pad) + label + "\n"
}

var version = "dev"

var (
	verbose        bool
	silent         bool
	appInitialized bool
)

func initApp() {
	if appInitialized {
		return
	}
	appInitialized = true

	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	if silent {
		level = slog.Level(100)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))
	if !silent {
		fmt.Fprint(os.Stderr, banner())
	}
}

func fetchHTML(target string) (string, error) {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		resp, err := http.Get(target)
		if err != nil {
			return "", fmt.Errorf("fetch URL: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("read response: %w", err)
		}
		return string(body), nil
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	return string(data), nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:     "dît",
		Short:   "HTML form and field type classifier",
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			initApp()
		},
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")
	rootCmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "Suppress all logging and banner")

	defaultHelp := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		initApp()
		defaultHelp(cmd, args)
	})

	var trainDataFolder string
	trainCmd := &cobra.Command{
		Use:   "train <modelfile>",
		Short: "Train a model on annotated HTML forms",
		Args:  cobra.ExactArgs(1),
		Example: `  dit train model.json --data-folder data
  dit train model.json -v`,
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]
			slog.Info("Training classifier", "data-folder", trainDataFolder, "output", modelPath)
			start := time.Now()
			c, err := dit.Train(trainDataFolder, &dit.TrainConfig{Verbose: verbose})
			if err != nil {
				return err
			}
			slog.Debug("Training completed", "duration", time.Since(start))
			if err := c.Save(modelPath); err != nil {
				return err
			}
			slog.Info("Model saved", "path", modelPath)
			return nil
		},
	}
	trainCmd.Flags().StringVar(&trainDataFolder, "data-folder", "data", "Path to annotation data folder")

	var runModelPath string
	var runThreshold float64
	var runProba bool
	runCmd := &cobra.Command{
		Use:   "run <url-or-file>",
		Short: "Classify forms in a URL or HTML file",
		Args:  cobra.ExactArgs(1),
		Example: `  dit run https://github.com/login
  dit run login.html
  dit run https://github.com/login --proba
  dit run https://github.com/login --proba --threshold 0.1
  dit run https://github.com/login --model custom.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			start := time.Now()
			var c *dit.Classifier
			var err error
			if runModelPath != "" {
				slog.Debug("Loading custom model", "path", runModelPath)
				c, err = dit.Load(runModelPath)
			} else {
				slog.Debug("Loading embedded model")
				c, err = dit.New()
			}
			if err != nil {
				return err
			}
			slog.Debug("Model loaded", "duration", time.Since(start))

			slog.Debug("Fetching HTML", "target", target)
			htmlContent, err := fetchHTML(target)
			if err != nil {
				return err
			}
			slog.Debug("HTML fetched", "bytes", len(htmlContent))

			start = time.Now()
			if runProba {
				results, err := c.ExtractFormsProba(htmlContent, runThreshold)
				if err != nil {
					return err
				}
				slog.Debug("Classification completed", "forms", len(results), "duration", time.Since(start))
				if len(results) == 0 {
					fmt.Println("No forms found.")
					return nil
				}
				output, _ := json.MarshalIndent(results, "", "  ")
				fmt.Println(string(output))
			} else {
				results, err := c.ExtractForms(htmlContent)
				if err != nil {
					return err
				}
				slog.Debug("Classification completed", "forms", len(results), "duration", time.Since(start))
				if len(results) == 0 {
					fmt.Println("No forms found.")
					return nil
				}
				output, _ := json.MarshalIndent(results, "", "  ")
				fmt.Println(string(output))
			}
			return nil
		},
	}
	runCmd.Flags().StringVar(&runModelPath, "model", "", "Path to model file (default: embedded model)")
	runCmd.Flags().Float64Var(&runThreshold, "threshold", 0.05, "Minimum probability threshold")
	runCmd.Flags().BoolVar(&runProba, "proba", false, "Show probabilities")

	var evalDataFolder string
	var evalCVFolds int
	evalCmd := &cobra.Command{
		Use:     "evaluate",
		Short:   "Evaluate model accuracy via cross-validation",
		Example: `  dit evaluate --data-folder data --cv 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			slog.Info("Evaluating", "folds", evalCVFolds, "data-folder", evalDataFolder)
			start := time.Now()
			result, err := dit.Evaluate(evalDataFolder, &dit.EvalConfig{
				Folds:   evalCVFolds,
				Verbose: verbose,
			})
			if err != nil {
				return err
			}
			slog.Debug("Evaluation completed", "duration", time.Since(start))

			if result.FormTotal > 0 {
				fmt.Printf("Form type accuracy: %.1f%% (%d/%d)\n",
					result.FormAccuracy*100, result.FormCorrect, result.FormTotal)
			}
			if result.FieldTotal > 0 {
				fmt.Printf("Field type accuracy: %.1f%% (%d/%d fields)\n",
					result.FieldAccuracy*100, result.FieldCorrect, result.FieldTotal)
				fmt.Printf("Sequence accuracy: %.1f%% (%d/%d forms)\n",
					result.SequenceAccuracy*100, result.SequenceCorrect, result.SequenceTotal)
			}
			return nil
		},
	}
	evalCmd.Flags().StringVar(&evalDataFolder, "data-folder", "data", "Path to annotation data folder")
	evalCmd.Flags().IntVar(&evalCVFolds, "cv", 10, "Number of cross-validation folds")

	rootCmd.AddCommand(trainCmd, runCmd, evalCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
