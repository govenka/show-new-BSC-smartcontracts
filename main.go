package main

import (
    "flag"
    "fmt"
    "github.com/ethereum/go-ethereum/rpc"
    "strconv"
    "strings"
    "time"
    "context"
)

const (
    infuraURL = "https://bsc-dataseed1.binance.org"
)

var (
    complexityThreshold  int
    sleepDuration        int
    performAnalysis      bool
    checkOwnershipRenunc bool
)

func init() {
    flag.IntVar(&complexityThreshold, "complexity", 40000, "Set your complexity threshold")
    flag.IntVar(&sleepDuration, "sleep", 10, "Duration to sleep/wait between checks (in seconds)")
    flag.BoolVar(&performAnalysis, "analysis", false, "Perform simple smart contract code analysis")
    flag.BoolVar(&checkOwnershipRenunc, "checkOwnership", false, "Check for ownership renunciation")
    flag.Parse()
}

func main() {
    client, err := rpc.Dial(infuraURL)
    if err != nil {
        fmt.Println("Error connecting:", err)
        return
    }
    defer client.Close()

    for {
        blockNumber, err := getCurrentBlockNumber(client)
        if err != nil {
            fmt.Println("Error getting current block number:", err)
            time.Sleep(time.Duration(sleepDuration) * time.Second)
            continue
        }

        err = processBlock(client, blockNumber)
        if err != nil {
            fmt.Println("Error processing block:", err)
        }

        time.Sleep(time.Duration(sleepDuration) * time.Second)
    }
}


func getCurrentBlockNumber(client *rpc.Client) (int64, error) {
	var result string
	err := client.Call(&result, "eth_blockNumber")
	if err != nil {
		return 0, err
	}

	blockNumber, err := strconv.ParseInt(result, 0, 64)
	if err != nil {
		return 0, err
	}

	return blockNumber, nil
}

func processBlock(client *rpc.Client, blockNumber int64) error {
    hexBlockNumber := addHexPrefix(strconv.FormatInt(blockNumber, 16))
    var result map[string]interface{}
    err := client.Call(&result, "eth_getBlockByNumber", hexBlockNumber, true)
    if err != nil {
        return err
    }

    transactions := result["transactions"].([]interface{})
    for _, tx := range transactions {
        transaction := tx.(map[string]interface{})
        txHash := transaction["hash"].(string)
        contractAddress, err := getContractAddress(client, txHash)
        if err != nil {
            fmt.Println("Error getting contract address:", err)
            continue
        }
        if contractAddress == "" {
            continue
        }

        if performAnalysis && isContractSuspicious(contractAddress) {
            fmt.Println("Suspicious contract found at address:", contractAddress)
            continue
        }

        if checkOwnershipRenunc {
            renounced, err := checkOwnershipRenunciation(client, contractAddress)
            if err != nil || renounced {
                fmt.Printf("Ownership renounced for contract at address: %s\n", contractAddress)
                continue
            }
        } else {
        	fmt.Printf("/!\\ Ownership had not renounced for contract at address: %s\n", contractAddress)
        	continue
        }

        code, err := getCode(client, contractAddress)
        if err != nil {
            fmt.Println("Error getting code:", err)
            continue
        }

        if len(code) > complexityThreshold {
            fmt.Printf("https://bscscan.com/address/%s\n", contractAddress)
            fmt.Println("")
        }
    }

    return nil
}

func getCode(client *rpc.Client, contractAddress string) (string, error) {
    var code string
    contractAddressWithPrefix := addHexPrefix(contractAddress)
    err := client.Call(&code, "eth_getCode", contractAddressWithPrefix, "latest")

    if err != nil {
        return "", err
    }
    return code, nil
}

func isContractSuspicious(code string) bool {
suspiciousPatterns := []string{
    "selfdestruct(", 
    "delegatecall(", 
    "call.value(", 
    ".transfer(", 
    "suicide(", 
    "sha3(", 
    "callcode(", 
    "assembly {", 
    "block.timestamp", 
    "blockhash(", 
    "tx.origin", 
    "gasleft(", 
    "ecrecover(", 
    "msg.sender.send(", 
    "create2(", 
    "keccak256(abi.encodePacked(", 
    "addmod(", 
    "mulmod(", 
    "revert(", 
    "assert(", 
    "require(", 
    "throw ", 
    "msg.value", 
    "block.number", 
    "block.difficulty", 
    "block.coinbase", 
    "now", // Alias pour block.timestamp, peut être manipulé
    "gasprice", 
    "this.balance", 
    "tx.gasprice", 
    ".call(", // Appels à faible niveau
    ".send(", // Envoi d'Ether, peut échouer
    "for {", // Boucles potentiellement dangereuses
    "while {", // Boucles potentiellement dangereuses
    "unchecked {", // Bloc non vérifié dans Solidity 0.8.x
    "storage slot", // Accès direct aux slots de stockage
    "external contract", // Interactions avec des contrats externes
    "inline assembly", // Assemblage en ligne
    "signed integer", // Gestion des entiers signés
    "permanent storage write", // Écriture dans le stockage permanent
    "arbitrary jump", // Sauts arbitraires dans le code
    "high gas usage", // Utilisation élevée de gaz
    "transaction origin", // Origine de la transaction
    "floating pragma", // Pragma non verrouillé
    "shadowing state variables", // Masquage des variables d'état
    "hardcoded address", // Adresses codées en dur
    "magic numbers", // Nombres magiques sans explication
    "unprotected SELFDESTRUCT", // SELFDESTRUCT non protégé
    "missing return value", // Valeur de retour manquante
    "unchecked return value", // Valeur de retour non vérifiée
    "reentrancy", // Vulnérabilité à la réentrance
    "unchecked math", // Mathématiques sans vérification
    "denial of service", // Vulnérabilité au déni de service
    "front running", // Risque de front running
    "time manipulation", // Manipulation du temps
    "block miner manipulation", // Manipulation du mineur de bloc
    "randomness source", // Source de hasard non fiable
    "hardcoded gas amount", // Montant de gaz codé en dur
    "gas limit", // Limites de gaz spécifiques
    // ... et autres motifs spécifiques aux smart contracts
	}

    for _, pattern := range suspiciousPatterns {
        if strings.Contains(code, pattern) {
            fmt.Printf("Motif suspect trouvé : %s\n", pattern)
            return true
        }
    }

    return false
}

func getContractAddress(client *rpc.Client, txHash string) (string, error) {
    var receipt map[string]interface{}
    err := client.Call(&receipt, "eth_getTransactionReceipt", addHexPrefix(txHash))
    if err != nil {
        return "", err
    }
    // Check if contractAddress is present and not nil
    contractAddress, ok := receipt["contractAddress"].(string)
    if !ok {
        return "", nil  // Return empty string if contractAddress is nil or not a string
    }
    return contractAddress, nil
}



func addHexPrefix(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s
	}
	return "0x" + s
}

func checkOwnershipRenunciation(client *rpc.Client, contractAddress string) (bool, error) {
    ownerFunctionSelector := "0x8da5cb5b" // Sélecteur pour la méthode "owner()"

    // Préparation de l'appel au contrat
    msg := map[string]interface{}{
        "to":   contractAddress,
        "data": ownerFunctionSelector,
    }

    var response string
    ctx := context.Background()
    err := client.CallContext(ctx, &response, "eth_call", msg, "latest")
    if err != nil {
        return false, fmt.Errorf("error calling contract: %v", err)
    }

    // Vérifier si la réponse est suffisamment longue pour une adresse Ethereum
    if len(response) >= 66 { // 2 caractères pour "0x" + 64 caractères pour l'adresse
        ownerAddress := response[26:66] // Extraire l'adresse du propriétaire
        isRenounced := ownerAddress == "0000000000000000000000000000000000000000"
        return isRenounced, nil
    } else if len(response) < 66 && len(response) > 2 {
        // Gérer une situation où la réponse n'est pas dans le format attendu mais contient des données
        ownerAddress := extractAddressFromResponse(response)
        isRenounced := ownerAddress == "0000000000000000000000000000000000000000"
        return isRenounced, nil
    }

    return false, fmt.Errorf("unexpected response format or empty owner address")
}

// extractAddressFromResponse tente d'extraire une adresse Ethereum d'une réponse RPC
func extractAddressFromResponse(response string) string {
    // Supposons que l'adresse commence après "0x" et occupe les 40 caractères suivants
    if len(response) > 42 {
        return response[2:42]
    }
    return ""
}
