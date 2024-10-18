package main

import (
	"fmt"
	"log"
	"math/big"
	//"github.com/zkMIPS/zkm/go-runtime/zkm_runtime"
	"crypto/sha512"
)


type KeyPair struct {
	Public  *big.Int
	Private *big.Int
}

type CiphertextPair struct {
	C0 Point
	C1 Point
}

type Point struct{
	X *big.Int
	Y *big.Int
}



var (
 P, _ = new(big.Int).SetString("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",16)  // A small prime number (use a larger one in practice)
 G, _ = new(big.Int).SetString("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16)



 	k0, _ = new(big.Int).SetString("0ECFAB7351E0DEFBD5005D3A9F5A423204408A0CE76C4A956526EBF5854FDA2CCAFEC7659F1302D68AF0B28EE1D00BA134435A44EF8D6E8FA796DB6933537E0F73C2EC6168E452DA07B08804D8CF94659EFD13AA6D2538A59A958C73C00380D761AD583395902E6CAA48886AA2D7049DBCB81A6256BD2973C625CC0A8874DE19", 16)


)

func generateKeyPair() KeyPair {
	// Private key: random value
	x, _ := new(big.Int).SetString("1419975918251887", 10)
	// Public key: g^privateKey mod p
	y := new(big.Int).Exp(G, x, P)
	

	return KeyPair{
		Public:  y,
		Private: x,
	}
}

// Encrypt a message m with public key and a random encryption factor
func encrypt(publicKey KeyPair, message *big.Int, k1 *big.Int) (CiphertextPair) {
	
	// Encryption using k0
	c00  := new(big.Int).Exp(publicKey.Public,k0,P)
	c00.Mul(c00,message).Mod(c00, P)
	
	c01 := new(big.Int).Exp(G,k0,P)
	

	// Encryption using k1
	c10:= new(big.Int).Exp(publicKey.Public,k1,P)
	
	c11 := new(big.Int).Exp(G,k1,P)



	
	return CiphertextPair{C0: Point{X:c00, Y:c01 }, C1: Point{X:c10 ,Y:c11}}
				
} 


func decrypt(decryptMessage CiphertextPair ,  private *big.Int) (bool, *big.Int) {
	// Random encryption factor k
	m0:= new(big.Int).Exp(decryptMessage.C0.Y,private,P)
	m0.Div(decryptMessage.C0.X, m0).Mod(m0, P)

	m1:= new(big.Int).Exp(decryptMessage.C1.Y,private,P)
	m1.Div(decryptMessage.C0.X, m1).Mod(m1, P)

	if m1.Cmp(big.NewInt(1)) == 0 {
		result := m0
		return true, result
	}else{
		result:= big.NewInt(0)
		return false, result
	}
}


func reeecrypt(decryptMessage CiphertextPair , k2 *big.Int, k3 *big.Int ) (CiphertextPair) {
	

	alpha00:= new(big.Int).Exp(decryptMessage.C1.X,k2, P)
	alpha00.Mul(alpha00, decryptMessage.C0.X).Mod(alpha00, P)
	
	beta00:= new(big.Int).Exp(decryptMessage.C1.Y,k2, P)
	beta00.Mul(beta00, decryptMessage.C1.X).Mod(beta00, P)

	alph01:= new(big.Int).Exp(decryptMessage.C1.X,k3, P)
	beta01:= new(big.Int).Exp(decryptMessage.C1.Y,k3, P)

	return CiphertextPair{C0: Point{X:alpha00, Y:beta00 }, C1: Point{X:alph01, Y:beta01 }}
	
}

func assertEqual(a *big.Int, b *big.Int) {
	if a.Cmp(b) != 0 {
		log.Fatal("%x != %x", a, b)
	}
}

func  hash256( number *big.Int)string{
	data := number.Bytes()
	hash := sha512.New()
	hash.Write(data)
	hashSum := hash.Sum(nil)
	
	return fmt.Sprintf("%x", hashSum)
}

func main() {
	// output := zkm_runtime.Read[Data]()

	// fmt.Printf("Data read from zkm_runtime: %+v\n", output)
	hashString:=hash256(k0)
	k1, _ := new(big.Int).SetString(hashString, 16)
	
	hashString2:=hash256(k1)
	k2, _ := new(big.Int).SetString(hashString2, 16)
	
	hashString3:=hash256(k2)
	k3, _ := new(big.Int).SetString(hashString3, 16)
	messageString:="41241"
	message, _ := new(big.Int).SetString(messageString, 10)  
	key:= generateKeyPair()

	test0:=encrypt(key, message,k1)

	test1:=reeecrypt(test0,k2,k3)
	
	// //inputText:="819697351042943352641222948161129547885706469208757205058431046258240109831"
	// m0,_:= new(big.Int).SetString(output.Input14, 10) 
	
	// fmt.Printf("%t", true)
	// zkm_runtime.Commit[Data](output)
	fmt.Println("test1", test1)

}