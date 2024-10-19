package main

import (
	"fmt"
	"log"
	"math/big"
	//"github.com/zkMIPS/zkm/go-runtime/zkm_runtime"
	"crypto/sha256"
)


type KeyPair struct {
	Public  *big.Int
	Private *big.Int
}



type Tuple struct{
	x0 *big.Int
	x1 *big.Int
	x2 *big.Int
	x3 *big.Int
}



var (
 P, _ = new(big.Int).SetString("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371",16)  // A small prime number (use a larger one in practice)
 G, _ = new(big.Int).SetString("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",16)
k0, _ = new(big.Int).SetString("0ECFAB7351E0DEFBD5005D3A9F5A423204408A0CE76C4A956526EBF5854FDA2CCAFEC7659F1302D68AF0B28EE1D00BA134435A44EF8D6E8FA796DB6933537E0F73C2EC6168E452DA07B08804D8CF94659EFD13AA6D2538A59A958C73C00380D761AD583395902E6CAA48886AA2D7049DBCB81A6256BD2973C625CC0A8874DE19", 16)


)

func generateKeyPair() KeyPair {
	// Private key: random value
	x, _ := new(big.Int).SetString("B7E5A481F6732E9CDA5842F5C90D9F96A738D3AFA4F8C05137B168753FBC4A629FCF7C5A217683D11D5C3B2F4AC31A0E2F638BDE4A356FEF0AC0D3A912DFAE85D94C8161A4D5D10376184F057A49A9271F6397B60F09A643BD899D33780A9E3A88FCF4D2C58F1175A4A7B5D569EAC3C98C79DC40FCB914A9E75F5DF1C56A138F", 16)
	// Public key: g^privateKey mod p
	y := new(big.Int).Exp(G, x, P)
	

	return KeyPair{
		Public:  y,
		Private: x,
	}
}

// Encrypt a message m with public key and a random encryption factor
func encrypt(publicKey KeyPair, message *big.Int, k1 *big.Int) (Tuple) {
	
	// Encryption using k0
	intermedidate  := new(big.Int).Exp(publicKey.Public,k0,P)
	c00 :=new(big.Int).Mul(intermedidate,message)
	c00.Mod(c00,P)

	c01 := new(big.Int).Exp(G,k0,P)
	
	// Encryption using k1
	c10:= new(big.Int).Exp(publicKey.Public,k1,P)
	c11 := new(big.Int).Exp(G,k1,P)

	return Tuple{x0:c00,x1: c01, x2:c10, x3:c11}
				
} 




func decrypt(result Tuple, private *big.Int) (bool, *big.Int) {
	// Decrypt first part
	intermediate := new(big.Int).Exp(result.x1, private, P)
	intermediateInv := new(big.Int).ModInverse(intermediate, P) // Compute modular inverse
	
	m0 := new(big.Int).Mul(result.x0, intermediateInv)
	m0.Mod(m0, P)

	// Decrypt second part
	intermediate2 := new(big.Int).Exp(result.x3, private, P)
	intermediateInv2 := new(big.Int).ModInverse(intermediate2, P) // Compute modular inverse
	

	m1 := new(big.Int).Mul(result.x2, intermediateInv2)
	m1.Mod(m1, P)

	// Check if m1 equals the identity element (1)
	if m1.Cmp(big.NewInt(1)) == 0 {
		return true,m0.Mod(m0, P)
	} else {
		return false, big.NewInt(0)
	}
}

func reEncrypt(result Tuple , k2 *big.Int, k3 *big.Int ) (Tuple) {
	

	
	alpha00 := new(big.Int).Exp(result.x2, k2, P) // Re-randomization
	alpha00.Mul(alpha00, result.x0)
	alpha00.Mod(alpha00, P)

	beta00 := new(big.Int).Exp(result.x3, k2, P) // Re-randomization
	beta00.Mul(beta00, result.x1)
	beta00.Mod(beta00, P)

	// Re-encrypt the second ciphertext (c10, c11)
	alpha01 := new(big.Int).Exp(result.x2, k3, P)
	alpha01.Mul(alpha01, result.x2)
	alpha01.Mod(alpha01, P)

	beta01 := new(big.Int).Exp(result.x3, k3, P)
	beta01.Mul(beta01, result.x3)
	beta01.Mod(beta01, P)

	return Tuple{x0:alpha00, x1:beta00 ,x2 :alpha01, x3:beta01 }
	
}

func assertEqual(a *big.Int, b *big.Int) {
	if a.Cmp(b) != 0 {
		log.Fatal("%x != %x", a, b)
	}
}

func  hash256ToBigInt(number *big.Int, P *big.Int) *big.Int{
	data := number.Bytes()
	hash := sha256.New()
	hash.Write(data)
	hashSum := hash.Sum(nil)
	
	// Convert hash to big.Int and apply modulus P
	hashBigInt := new(big.Int).SetBytes(hashSum)
	hashBigInt.Mod(hashBigInt, P)

	return hashBigInt
}

func main() {
	messageString := "27360300215660948447374041"
	message, _ := new(big.Int).SetString(messageString, 10)

	key := generateKeyPair()

	// Encrypt the message
	k1 := hash256ToBigInt(k0, P)
	test0 := encrypt(key, message, k1)

	// Re-encrypt the message
	k2 := hash256ToBigInt(k1, P)
	k3 := hash256ToBigInt(k2, P)
	test1 := reEncrypt(test0, k2, k3)

	// Decrypt the re-encrypted message
	success, output := decrypt(test1, key.Private)

	fmt.Println("Output:", output)
	fmt.Println("Success:", success)

	fmt.Println("k1:", k1)
	
	
	if success && output.Cmp(message) == 0 {
		fmt.Println("Decryption successful, message matches!")
	} else {
		fmt.Println("Decryption failed, message does not match.")
	}
}