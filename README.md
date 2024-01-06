# BSC/Ethereum Smart Contract Analysis Tool

This tool is designed to analyze Ethereum smart contracts on the Binance Smart Chain (BSC) network. It provides various functionalities to inspect and evaluate smart contracts for potential issues and vulnerabilities.

## Features

- **Complexity Threshold**: You can set your desired complexity threshold for contract analysis (in bytes).
- **Sleep Duration**: Define the duration between checks for new blocks.
- **Simple Code Analysis**: Perform basic analysis of smart contract code.
- **Ownership Renunciation Check**: Verify ownership renunciation status for contracts.

## Getting Started

### Prerequisites

Before using this tool, make sure you have the following prerequisites:

- [Golang](https://golang.org/) installed on your system.
- Access to an Ethereum node, we recommend using [Infura](https://infura.io/) or a similar service.

### Installation

1. Clone this repository to your local machine:

git clone https://github.com/show-new-BSC-smartcontracts/ethereum-smart-contract-analysis-tool.git

Navigate to the project directory:

cd ethereum-smart-contract-analysis-tool

Install the required Go dependencies:

go mod tidy

### Usage
To use the tool, you can run the following command:

./main -complexity 20000 -sleep 1 -analysis -checkOwnership=true

Replace the command with your desired options to analyze smart contracts on the BSC network.

Contributing
We welcome contributions to this project. Feel free to submit issues or pull requests on our GitHub repository.

License
This project is licensed under the MIT License

Acknowledgments
Thanks to the Ethereum community for their valuable insights and contributions.
