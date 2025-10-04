# 🛡️ Fortify

**Write. Compile. Fortify.**  
A full-stack Solidity IDE & vulnerability scanner that lets developers build, test, and secure smart contracts — with AI-powered insights.

---

## 💡 What is Fortify?

Fortify is a developer-first smart contract IDE that allows:

- 🧠 **Slither-based vulnerability detection**
- 🔐 **Secure contract compilation and ABI generation**
- ✍️ **Real-time Solidity editing inside a React interface**
- 🚀 **Full-stack dApp integration using Vite + MERN**
- 🔍 **Readable bytecode, test-ready ABIs, and secure deployment hooks**

Whether you're a beginner or a blockchain pro, Fortify makes sure you're never shipping unsafe Solidity again.

---

## 📁 Project Structure

```

womanTechies/
├── blockchain/         # Smart contracts (Hardhat-based)
├── client/             # React (Vite) frontend IDE
├── contracts/fetched/  # Compiled ABI + Bytecode
├── model/              # ML scripts and vulnerability detection ( using slither now )
├── server/             # Express backend, OAuth, compiler API
├── README.md

````

---

## 🧰 Tech Stack

| Area         | Tech Used |
|--------------|-----------|
| ✍️ Frontend  | React + Vite + JavaScript |
| 🔌 Backend   | Express.js + Node |
| ⚙️ Compiler  | solc-js (WebAssembly) |
| 🔗 Blockchain| Solidity + Hardhat |
| 🤖 ML Model  | Python, Scikit-learn, PyTorch, Streamlit, FastAPI |

---

## 🔍 Common Smart Contract Issues Solved

- ❌ Insecure `msg.sender` logic
- 🔁 Reentrancy bugs
- 📛 Unchecked external calls
- 🔐 Missing `onlyOwner` modifiers
- 📦 Overexposed storage vars
- 🚫 Gas inefficiencies and unoptimized logic
- 🧠 Developers not being alerted of real vulnerabilities

Fortify flags issues in real-time and encourages secure best practices.

---

## ⚙️ Installation

### Backend & Blockchain

```bash
# Backend
cd server
npm install

# Blockchain (Hardhat)
cd ../blockchain
npm install
````

### Frontend (Vite + React)

```bash
cd ../client
npm install
npm run dev
```

## 🧪 ABI/Bytecode Example :

When a Solidity contract like this is compiled:

```solidity
function store(uint256 num) external onlyOwner { ... }
```

Fortify returns a JSON output like:

```json
{
  "abi": [...],
  "evm": {
    "bytecode": {
      "object": "0x60806040..."
    }
  }
}
```

This output is then used to analyze, test, and simulate your smart contract.

---

## 📄 License

[MIT](LICENSE)

---

> Fortify: Because one unsafe contract can bankrupt millions. Let’s fix that.
