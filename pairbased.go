/*
MIT License

Copyright (c) 2017 Simon Schmidt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package twoway


import "golang.org/x/crypto/bn256"
import "io"

/* Generates a Key-Pair (G1 and G2). */
func GenKeyPair(r io.Reader) (*bn256.G1, *bn256.G2, error) {
	i,a,e := bn256.RandomG1(r)
	if e!=nil { return nil,nil,e }
	b := new(bn256.G2).ScalarBaseMult(i)
	i.SetInt64(0)
	return a,b,nil
}

/* bn256.Pair(g1,g2) */
func Pair(g1 *bn256.G1, g2 *bn256.G2) *bn256.GT {
	return bn256.Pair(g1,g2)
}

func RandomGT(r io.Reader) (*bn256.GT,error) {
	_,a,e := bn256.RandomG1(r)
	if e!=nil { return nil,e }
	_,b,e := bn256.RandomG2(r)
	if e!=nil { return nil,e }
	return Pair(a,b),nil
}

func EncryptWithG1(g1 *bn256.G1,r io.Reader) (*bn256.G1,*bn256.GT,error) {
	h1,h2,e := GenKeyPair(r)
	if e!=nil { return nil,nil,e }
	return h1,Pair(g1,h2),nil
}

func EncryptWithG2(g2 *bn256.G2,r io.Reader) (*bn256.G2,*bn256.GT,error) {
	h1,h2,e := GenKeyPair(r)
	if e!=nil { return nil,nil,e }
	return h2,Pair(h1,g2),nil
}

/*
g1 and g2: one of them might be the "private key", the other one might be the message.
*/
func Decrypt(g1 *bn256.G1, g2 *bn256.G2) *bn256.GT {
	return bn256.Pair(g1,g2)
}

