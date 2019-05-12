package passwordMeter

import (
	"math"
	"regexp"
	"strings"
)

const (
	nMultMidChar       = 2
	nMultConsecAlphaUC = 2
	nMultConsecAlphaLC = 2
	nMultConsecNumber  = 2
	nMultSeqAlpha      = 3
	nMultSeqSymbol     = 3
	nMultLength        = 4
	nMultNumber        = 4
	nMultSeqNumber     = 6
	nMultSymbol        = 6
	sAlphas            = "abcdefghijklmnopqrstuvwxyz"
	sQwerty            = "qwertyuiopasdfghjklzxcvbnm"
	sNumerics          = "01234567890"
	sSymbols           = ")!@#$%^&*()"
)

var regexpCache = map[string]*regexp.Regexp{
	"[^a-zA-Z]":      regexp.MustCompile("[^a-zA-Z]"),
	"[A-Z]+":         regexp.MustCompile("[A-Z]+"),
	"[a-z]+":         regexp.MustCompile("[a-z]+"),
	"[0-9]+":         regexp.MustCompile("[0-9]+"),
	"[^a-zA-Z0-9_]+": regexp.MustCompile("[^a-zA-Z0-9_]+"),
}

var nMinPwdLen = 8

//alter std minimum lenght
func SetMinPwd(l int) {
	nMinPwdLen = l
}

var nMinScore = 80

//alter min score
func SetMinScore(l int) {
	nMinScore = l
}

//check password is strong
func PasswordIsStrong(pwd string) bool {
	return Score(pwd) >= nMinScore
}

//calc password score
func Score(pwd string) int {
	var nScore int
	var nLength int
	var nAlphaUC int
	var nAlphaLC int
	var nNumber int
	var nSymbol int
	var nMidChar int
	var nRequirements int
	var nUnqChar int
	var nRepChar int
	var nRepInc int
	var nConsecAlphaUC int
	var nConsecAlphaLC int
	var nConsecNumber int
	var nConsecSymbol int
	var nConsecCharType int
	var nSeqAlpha int
	var nSeqNumber int
	var nSeqSymbol int
	var nSeqChar int
	var nReqChar int

	var nRepIncTemp float64

	nLength = len(pwd)
	nScore = nLength * nMultLength

	// count upper
	countCharacter(pwd, "[A-Z]+", &nConsecAlphaUC, &nConsecCharType, &nAlphaUC)
	// count lower
	countCharacter(pwd, "[a-z]+", &nConsecAlphaLC, &nConsecCharType, &nAlphaLC)
	// count numbers
	countCharacter(pwd, "[0-9]+", &nConsecNumber, &nConsecCharType, &nNumber)
	// count symbols
	countCharacter(pwd, "[^a-zA-Z0-9_]+", &nConsecSymbol, &nConsecCharType, &nSymbol)

	//count middle
	middle := regexpCache["[^a-zA-Z]"].FindAllStringIndex(pwd, -1)
	for _, i := range middle {
		if i[0] == 0 || i[1] == nLength {
			continue
		}
		nMidChar++
	}

	// find repeated char
	for p1, c1 := range pwd {
		bCharExists := false
		for p2, c2 := range pwd {
			if c1 == c2 && p1 != p2 {
				nRepIncTemp += math.Abs(float64(nLength) / float64(p2-p1))
				bCharExists = true
			}
		}
		if bCharExists {
			nRepChar++
			nUnqChar = nLength - nRepChar
			if nUnqChar > 0 {
				nRepInc = int(math.Ceil(nRepIncTemp / float64(nUnqChar)))
				nRepIncTemp = float64(nRepInc)
			} else {
				nRepInc = int(math.Ceil(nRepIncTemp))
			}
		}
	}

	// alpha sequence
	checkSequence(pwd, sAlphas, 3, &nSeqAlpha, &nSeqChar)
	// qwerty sequence
	checkSequence(pwd, sQwerty, 3, &nSeqAlpha, &nSeqChar)
	// numbers sequence
	checkSequence(pwd, sNumerics, 3, &nSeqNumber, &nSeqChar)
	// symbols sequence
	checkSequence(pwd, sSymbols, 3, &nSeqSymbol, &nSeqChar)

	if nAlphaUC > 0 && nAlphaUC < nLength {
		nScore += (nLength - nAlphaUC) * 2
	}
	if nAlphaLC > 0 && nAlphaLC < nLength {
		nScore += (nLength - nAlphaLC) * 2
	}
	if nNumber > 0 && nNumber < nLength {
		nScore += nNumber * nMultNumber
	}
	if nSymbol > 0 {
		nScore += nSymbol * nMultSymbol
	}

	if nMidChar > 0 {
		nScore += nMidChar * nMultMidChar
	}

	// Requirements
	arrChars := []int{nLength, nAlphaUC, nAlphaLC, nNumber, nSymbol}
	for k, v := range arrChars {
		minVal := 0
		if k == 0 { // nLength
			minVal = nMinPwdLen - 1
		}
		if v >= (minVal + 1) {
			nReqChar++
		}
	}
	nRequirements = nReqChar
	nMinReqChars := 4
	if nLength >= nMinPwdLen {
		nMinReqChars = 3
	}
	if nRequirements > nMinReqChars {
		nScore += nRequirements * 2
	}

	// Calculo de score (pontos negativos por praticas ruins)
	if (nAlphaLC > 0 || nAlphaUC > 0) && nSymbol == 0 && nNumber == 0 { // Only Letters
		nScore -= nLength
	}
	if nAlphaLC == 0 && nAlphaUC == 0 && nSymbol == 0 && nNumber > 0 { // Only Numbers
		nScore -= nLength
	}
	if nRepChar > 0 { // Same character exists more than once
		nScore -= nRepInc
	}
	if nConsecAlphaUC > 0 { // Consecutive Uppercase Letters exist
		nScore -= nConsecAlphaUC * nMultConsecAlphaUC
	}
	if nConsecAlphaLC > 0 { // Consecutive Lowercase Letters exist
		nScore -= nConsecAlphaLC * nMultConsecAlphaLC
	}
	if nConsecNumber > 0 { // Consecutive Numbers exist
		nScore -= nConsecNumber * nMultConsecNumber
	}
	if nSeqAlpha > 0 { // Sequential alpha strings exist (3 characters or more)
		nScore -= nSeqAlpha * nMultSeqAlpha
	}
	if nSeqNumber > 0 { // Sequential numeric strings exist (3 characters or more)
		nScore -= nSeqNumber * nMultSeqNumber
	}
	if nSeqSymbol > 0 { // Sequential symbol strings exist (3 characters or more)
		nScore -= nSeqSymbol * nMultSeqSymbol
	}

	return nScore
}

func countCharacter(pwd, reg string, consecReg, consecChar, tam *int) {
	consec := regexpCache[reg].FindAllString(pwd, -1)
	for _, sub := range consec {
		tamSub := len(sub)
		//count only have more than one (ex: tee)
		if tamSub > 1 {
			*consecReg += tamSub - 1
			*consecChar += tamSub - 1
		}
		*tam += tamSub
	}
}

func checkSequence(pwd, sequence string, tam int, nSeq, nSeqChar *int) {
	pwdLower := strings.ToLower(pwd)
	for s := 0; s < len(sequence)-(tam-1); s++ {
		sFwd := sequence[s : s+tam]
		sRev := reverseString(sFwd)
		if strings.Index(pwdLower, sFwd) != -1 || strings.Index(pwdLower, sRev) != -1 {
			*nSeq++
			*nSeqChar++
		}
	}
}

func reverseString(s string) (rev string) {
	for _, v := range s {
		rev = string(v) + rev
	}
	return
}
