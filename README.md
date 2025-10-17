# 🧾 zk-SNARK Credit Underwriting Circuit

> **Privacy-preserving credit evaluation** — Prove you meet a lender’s underwriting criteria without revealing your private financial data.

---

## 📖 Overview

This project implements a **production-hardened zk-SNARK circuit** (written in **[Noir](https://noir-lang.org/)**) that enables **private credit underwriting**.  
Borrowers can generate zero-knowledge proofs showing that they qualify for a loan **without exposing** their income, debts, or credit score.

The circuit is designed for **real-world financial use cases**, including:
- On-chain credit scoring  
- Private DeFi lending  
- Regulatory-compliant KYC/AML proofs  
- Off-chain credit integrations with Web3 wallets  

---

## 🔐 Key Features

| Feature | Description |
|----------|-------------|
| **Data Privacy** | The borrower’s financials (income, debts, credit score) remain private within the circuit. |
| **Oracle Authenticity** | Verifies that financial data comes from a trusted oracle using an ECDSA signature. |
| **Contextual Binding** | Every proof is tied to a unique borrower and loan ID to prevent replay attacks. |
| **Lender Criteria Commitment** | Ensures the lender’s underwriting criteria are publicly committed on-chain (immutable). |
| **Nullifier** | Prevents reuse of the same proof for multiple loans. |
| **Freshness Check** | Confirms that financial data is recent and valid. |

---

## 🧠 How It Works

The circuit performs these verification steps internally:

1. **Oracle Verification**  
   Validates that the borrower’s financial data is signed by a trusted oracle.

2. **Data Freshness**  
   Ensures the oracle data timestamp is newer than the lender’s minimum requirement.

3. **Lender Commitment Verification**  
   Reconstructs and validates the Pedersen hash of the lender’s public underwriting criteria.

4. **Underwriting Logic**  
   Privately checks that:
   - `income ≥ min_income`
   - `DTI (debt/income)` ≤ `max_dti_percent`
   - `credit_score ≥ min_credit_score`
   - `LTI (loan/income)` ≤ `max_lti_ratio`

5. **Nullifier Generation**  
   Creates a Pedersen hash of `[secret_nullifier_key, loan_id]` to uniquely bind the proof.

6. **Final Proof Output**  
   Returns:
   - `is_approved` → true if borrower meets all conditions  
   - `nullifier_hash` → prevents double-spending or proof replay  

---

## 🧩 Inputs

### 🔸 Private Inputs
| Name | Type | Description |
|------|------|-------------|
| `monthly_income` | `u64` | Borrower’s income (kept private). |
| `monthly_debt_payments` | `u64` | Borrower’s total monthly debt payments. |
| `credit_score` | `u64` | Borrower’s private credit score. |
| `oracle_signature` | `[u8; 64]` | Oracle’s signature on borrower’s financial data. |
| `data_timestamp` | `u64` | Timestamp of oracle data. |
| `secret_nullifier_key` | `Field` | Borrower’s private secret for nullifier generation. |

### 🔸 Public Inputs
| Name | Type | Description |
|------|------|-------------|
| `borrower_address` | `Field` | On-chain borrower identity. |
| `loan_id` | `Field` | Loan identifier. |
| `requested_loan_amount` | `u64` | Requested loan amount. |
| `oracle_public_key_x/y` | `[u8; 32]` | Public key of oracle. |
| `min_income` | `u64` | Minimum required income. |
| `max_dti_percent` | `u64` | Max debt-to-income ratio (percentage). |
| `min_credit_score` | `u64` | Minimum required credit score. |
| `max_lti_ratio` | `u64` | Max loan-to-income ratio (percentage). |
| `min_data_timestamp` | `u64` | Minimum acceptable oracle data age. |
| `criteria_commitment` | `Field` | Pedersen hash of lender’s criteria. |

### 🔸 Public Outputs
| Name | Type | Description |
|------|------|-------------|
| `is_approved` | `bool` | True if borrower meets all conditions. |
| `nullifier_hash` | `Field` | Hash to prevent proof reuse. |

---

## 🧮 Example Workflow

1. Borrower retrieves their financial data from a verified oracle (signed payload).  
2. Borrower generates a **zero-knowledge proof** using this circuit.  
3. The verifier (lender or smart contract) checks:
   - Proof validity (Groth16 or Plonk verifier).
   - Matching `criteria_commitment`.
   - That `nullifier_hash` hasn’t been used before.
4. If all checks pass → loan approved privately ✅

---

## ⚙️ Setup & Usage

### Prerequisites
- [Noir](https://noir-lang.org/getting_started/)
- [Nargo CLI](https://noir-lang.org/docs/nargo_commands/)


### Commands
```bash
# 1. Clone repository
git clone https://github.com/<your-username>/zk-credit-underwriting.git
cd zk-credit-underwriting

# 2. Compile circuit
nargo compile

# 3. Generate proving and verification keys
nargo prove

# 4. Verify proof
nargo verify
