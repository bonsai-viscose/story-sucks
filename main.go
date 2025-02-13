package main

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-resty/resty/v2"
)

// Структура для JSON-ответа от API
type AuthResponse struct {
	Code  int    `json:"code"`
	Msg   string `json:"msg"`
	Error string `json:"error"`
}

type AllocationResponse struct {
	Code int `json:"code"`
	Msg  struct {
		Nfts []struct {
			ContractAddress   string    `json:"contract_address"`
			TokenID           string    `json:"token_id"`
			TokenCount        int       `json:"token_count"`
			FirstAcquiredDate time.Time `json:"first_acquired_date"`
		} `json:"nfts"`
		MerkleTree struct {
			Amount          string   `json:"amount"`
			Proof           []string `json:"proof"`
			Index           int      `json:"index"`
			LeafHash        string   `json:"leafHash"`
			ContractAddress string   `json:"contractAddress"`
		} `json:"merkle_tree"`
	} `json:"msg"`
	Error string `json:"error"`
}

// Читаем приватные ключи из файла
func readPrivateKeys(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	return lines, nil
}

// Получаем адрес Ethereum из приватного ключа
func privateKeyToAddress(privateKeyHex string) (common.Address, *ecdsa.PrivateKey, error) {
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return common.Address{}, nil, err
	}
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKey)
	return address, privateKey, nil
}

// Подписываем сообщение EIP-191 (обычная подпись)
func signMessage(message string, privateKey *ecdsa.PrivateKey) (string, error) {
	const EIP191_PREFIX = "\x19Ethereum Signed Message:\n%d%s"

	fullMessage := fmt.Sprintf(EIP191_PREFIX, len(message), message)

	hash := crypto.Keccak256Hash([]byte(fullMessage))
	signatureBytes, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return "", err
	}

	signatureBytes[64] += 27
	signature := hexutil.Encode(signatureBytes)

	return signature, nil
}

// Запрос авторизации
func sendAuthRequest(walletAddress string, nonce string, signature string) (string, error) {
	url := "https://claim.storyapis.com/sign"
	client := resty.New()

	var authResp AuthResponse

	_, err := client.R().
		SetHeaders(map[string]string{
			"accept":             "application/json, text/plain, */*",
			"accept-language":    "en-US,en;q=0.9",
			"content-type":       "application/json",
			"origin":             "https://rewards.story.foundation",
			"priority":           "u=1, i",
			"referer":            "https://rewards.story.foundation/",
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": "macOS",
			"sec-fetch-dest":     "empty",
			"sec-fetch-mode":     "cors",
			"sec-fetch-site":     "cross-site",
			"user-agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		}).
		SetBody(map[string]string{
			"wallet":    walletAddress,
			"nonce":     nonce,
			"signature": signature,
		}).
		SetResult(&authResp).
		Post(url)

	if err != nil {
		return "", err
	}

	if authResp.Code != 200 {
		return "", fmt.Errorf("auth failed: %s", authResp.Error)
	}
	return authResp.Msg, nil
}

// Запрос данных по адресу
func getAddressData(authToken string) (AllocationResponse, error) {
	url := "https://claim.storyapis.com/address_data"
	client := resty.New()

	var result AllocationResponse

	_, err := client.R().
		SetResult(&result).
		SetHeaders(map[string]string{
			"authorization":      authToken,
			"accept":             "application/json, text/plain, */*",
			"accept-language":    "en-US,en;q=0.9",
			"content-type":       "application/json",
			"origin":             "https://rewards.story.foundation",
			"priority":           "u=1, i",
			"referer":            "https://rewards.story.foundation/",
			"sec-ch-ua-mobile":   "?0",
			"sec-ch-ua-platform": "macOS",
			"sec-fetch-dest":     "empty",
			"sec-fetch-mode":     "cors",
			"sec-fetch-site":     "cross-site",
			"user-agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		}).
		Get(url)

	if err != nil {
		return AllocationResponse{}, err
	}

	return result, nil
}

func weiToEther(wei *big.Int) *big.Float {
	ether := new(big.Float).SetInt(wei)
	ether.Quo(ether, big.NewFloat(1e18))
	return ether
}

func main() {
	// Читаем приватные ключи
	privateKeys, err := readPrivateKeys("keys.txt")
	if err != nil {
		fmt.Println("Ошибка чтения ключей:", err)
		return
	}

	total := new(big.Float)

	// Цикл по ключам
	for _, key := range privateKeys {
		address, privateKey, err := privateKeyToAddress(key)
		if err != nil {
			fmt.Println("Ошибка получения адреса:", err)
			continue
		}

		// Генерируем nonce (текущий timestamp)
		nonce := fmt.Sprintf("%d", time.Now().UnixMilli())

		// Формируем сообщение для подписи
		message := fmt.Sprintf("By signing this message, I confirm ownership of this wallet and that I have read and agree to the Token Claim Terms.\n\nnonce: %s", nonce)
		signature, err := signMessage(message, privateKey)
		if err != nil {
			fmt.Println("Ошибка подписи:", err)
			continue
		}

		// Отправляем запрос на авторизацию
		authToken, err := sendAuthRequest(address.Hex(), nonce, signature)
		if err != nil {
			fmt.Println("Ошибка авторизации:", err)
			continue
		}

		// Получаем данные по адресу
		addressData, err := getAddressData(authToken)
		if err != nil {
			fmt.Println("Ошибка получения данных адреса:", err)
			continue
		}

		alloc, _ := new(big.Int).SetString(addressData.Msg.MerkleTree.Amount, 10)

		fmt.Printf("%s: %.2f IP\n", address.Hex(), weiToEther(alloc))

		total = total.Add(total, weiToEther(alloc))
	}

	fmt.Printf("Total %.2f IP\n", total)
}
