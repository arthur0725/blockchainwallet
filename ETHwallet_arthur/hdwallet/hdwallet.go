package hdwallet

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"wallet/hdkeystore"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/howeyc/gopass"
	"github.com/tyler-smith/go-bip39"
)

const defaultPath = "m/44'/60'/0'/0/1"

//钱包结构体
type HDWallet struct {
	Address    common.Address
	HdKeyStore *hdkeystore.HDkeyStore
}

func create_mnemonic() (string, error) {
	//1. entropy
	b, err := bip39.NewEntropy(128)
	if err != nil {
		log.Panic("Failed to NewEntropy", err)
	}
	//2. mnemonic
	return bip39.NewMnemonic(b)
}

//推导私钥
func DerivePrivateKey(path accounts.DerivationPath, masterKey *hdkeychain.ExtendedKey) (*ecdsa.PrivateKey, error) {
	var err error
	key := masterKey
	for _, n := range path {
		//按照路径迭代获得最终key
		key, err = key.Child(n)
		if err != nil {
			return nil, err
		}
	}
	//将key转换为ecdsa私钥
	privateKey, err := key.ECPrivKey()
	privateKeyECDSA := privateKey.ToECDSA()
	if err != nil {
		return nil, err
	}

	return privateKeyECDSA, nil
}

// 通过助记词推导私钥
func NewKeyFromMnemonic(mn string) (*ecdsa.PrivateKey, error) {
	//1. 推导目录
	path, err := accounts.ParseDerivationPath(defaultPath)
	if err != nil {
		log.Panic("Failed to ParseDerivationPath ", err)
	}
	//2. 通过助记词生成种子
	//NewSeedWithErrorChecking(mnemonic string, password string) ([]byte, error)
	seed, err := bip39.NewSeedWithErrorChecking(mn, "")
	if err != nil {
		log.Panic("Failed to NewSeedWithErrorChecking ", err)
	}
	//3. 获得主key
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		log.Panic("Failed to NewMaster", err)
	}
	//4. 推导私钥
	return DerivePrivateKey(path, masterKey)
}

//钱包构造函数
func NewWallet(keypath string) (*HDWallet, error) {
	//1. 创建助记词
	mn, err := create_mnemonic()
	if err != nil {
		fmt.Println("Failed to NewWallet", err)
		return nil, err
	}
	fmt.Println(mn)
	//2. 推导私钥
	privateKey, err := NewKeyFromMnemonic(mn)
	if err != nil {
		fmt.Println("Failed to NewKeyFromMnemonic", err)
		return nil, err
	}
	//3. 获取地址
	publicKey, err := DerivePublicKey(privateKey)
	if err != nil {
		fmt.Println("Failed to DerivePublicKey", err)
		return nil, err
	}
	//利用公钥推导地址
	address := crypto.PubkeyToAddress(*publicKey)
	//4. 创建keystore
	hdks := hdkeystore.NewHDkeyStore(keypath, privateKey)
	//5. 创建钱包
	return &HDWallet{address, hdks}, nil
}

//推导公钥
func DerivePublicKey(privateKey *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key")
	}
	return publicKeyECDSA, nil
}

func (w HDWallet) StoreKey(pass string) error {
	//账户即文件名
	filename := w.HdKeyStore.JoinPath(w.Address.Hex())
	return w.HdKeyStore.StoreKey(filename, &w.HdKeyStore.Key, pass)
}

func LoadWallet(filename, datadir string) (*HDWallet, error) {
	hdks := hdkeystore.NewHDkeyStoreNoKey(datadir)
	//解决密码问题
	fmt.Println("Please input password for:", filename)
	pass, _ := gopass.GetPasswd()
	//filename也是账户地址
	fromaddr := common.HexToAddress(filename)
	_, err := hdks.GetKey(fromaddr, hdks.JoinPath(filename), string(pass))
	if err != nil {
		log.Panic("Failed to GetKey ", err)
	}
	return &HDWallet{fromaddr, hdks}, nil
}

func LoadWalletByPass(filename, datadir, pass string) (*HDWallet, error) {
	hdks := hdkeystore.NewHDkeyStoreNoKey(datadir)
	//解决密码问题
	//filename也是账户地址
	fromaddr := common.HexToAddress(filename)
	_, err := hdks.GetKey(fromaddr, hdks.JoinPath(filename), string(pass))
	if err != nil {
		log.Panic("Failed to GetKey ", err)
	}
	return &HDWallet{fromaddr, hdks}, nil
}
