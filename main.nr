// A Production-Hardened zk-SNARK Circuit for Credit Underwriting

// This circuit verifies that a borrower meets a lender's criteria for a loan
// without revealing the borrower's private financial data. It incorporates
// several security features for production use:
// 1.  **Data Hiding**: Protects borrower's income, debt, and credit score.
// 2.  **Contextual Binding**: Ties the proof to a specific borrower and loan ID.
// 3.  **Nullifier**: Prevents a valid proof from being used more than once.
// 4.  **Criteria Commitment**: Binds the lender to pre-agreed underwriting rules.

// --- LIBRARIES ---
// Assumes a zk-SNARK framework environment like Noir with standard libraries.
use dep::std::hash::pedersen_hash;
use dep::std::ecdsa_secp256k1::verify_signature;

// --- HELPER FUNCTIONS ---

// Function 1: Verifies the integrity and authenticity of the oracle's data.
// This function ensures the financial data comes from a trusted source and hasn't been tampered with.
fn verify_oracle_data(
    // Financial data (private)
    monthly_income: u64,
    monthly_debt: u64,
    credit_score: u64,
    data_timestamp: u64,
    // Contextual data (public)
    borrower_address: Field,
    loan_id: Field,
    // Oracle's proof (private signature, public key)
    signature: [u8; 64],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32]
) -> bool {
    // Hash all relevant data points. Including the loan_id and borrower_address
    // is critical to prevent replay attacks.
    let data_to_hash = [
        monthly_income as Field, 
        monthly_debt as Field, 
        credit_score as Field,
        data_timestamp as Field,
        borrower_address,
        loan_id
    ];
    let message_hash = pedersen_hash(data_to_hash);
    let message_bytes: [u8; 32] = message_hash.to_be_bytes();

    // Verify the ECDSA signature against the hashed data.
    verify_signature(pub_key_x, pub_key_y, signature, message_bytes)
}

// Function 2: Checks if the borrower meets the lender's underwriting criteria.
// This function contains the core business logic of the loan application.
fn check_underwriting_criteria(
    // Borrower's financials (private)
    monthly_income: u64,
    monthly_debt: u64,
    credit_score: u64,
    requested_loan_amount: u64,
    // Lender's requirements (public)
    min_income: u64,
    max_dti_percent: u64,
    min_credit_score: u64,
    max_lti_ratio: u64 // Loan-to-Income ratio (e.g., 600 means loan can be 6x monthly income)
) -> bool {
    // Check 1: Minimum income
    let income_check = monthly_income >= min_income;
    
    // Check 2: Debt-to-Income (DTI) ratio.
    // Uses safe cross-multiplication to avoid division within the circuit.
    // Logic: (monthly_debt / monthly_income) * 100 <= max_dti_percent
    let dti_check = monthly_debt * 100 <= max_dti_percent * monthly_income;
    
    // Check 3: Minimum credit score
    let credit_score_check = credit_score >= min_credit_score;
    
    // Check 4: Loan-to-Income (LTI) ratio.
    // Ensures the requested loan amount is reasonable relative to income.
    // Logic: requested_loan_amount <= monthly_income * (max_lti_ratio / 100)
    let lti_check = requested_loan_amount * 100 <= monthly_income * max_lti_ratio;

    // All checks must pass.
    income_check & dti_check & credit_score_check & lti_check
}


// --- MAIN CIRCUIT ---
// This is the primary entry point for generating and verifying the ZK proof.
fn main(
    // == PRIVATE INPUTS (Witness) ==
    // Provided by the borrower and their data oracle. Kept secret from the verifier.
    monthly_income: u64,
    monthly_debt_payments: u64,
    credit_score: u64,
    oracle_signature: [u8; 64],
    data_timestamp: u64,
    secret_nullifier_key: Field, // Borrower's secret to prevent proof reuse.

    // == PUBLIC INPUTS ==
    // Known by both the prover and verifier (e.g., the smart contract).
    borrower_address: pub Field,
    loan_id: pub Field,
    requested_loan_amount: pub u64,
    
    // Oracle's public key, known by the smart contract.
    oracle_public_key_x: pub [u8; 32],
    oracle_public_key_y: pub [u8; 32],
    
    // Lender's underwriting criteria.
    min_income: pub u64,
    max_dti_percent: pub u64,
    min_credit_score: pub u64,
    max_lti_ratio: pub u64,
    min_data_timestamp: pub u64, // The oldest acceptable data timestamp.
    
    // Commitment to lender's criteria, preventing unfair changes.
    criteria_commitment: pub Field,

    // == PUBLIC OUTPUTS ==
    // Results of the private computation, revealed publicly.
    is_approved: pub bool,
    nullifier_hash: pub Field // Unique value to prevent double-spending the proof.
) {
    // ### Step 1: Verify Oracle Data Integrity & Authenticity ###
    // Ensure the private financial data is authentic and bound to this specific loan.
    let is_data_authentic = verify_oracle_data(
        monthly_income, monthly_debt_payments, credit_score, data_timestamp,
        borrower_address, loan_id, oracle_signature,
        oracle_public_key_x, oracle_public_key_y
    );
    assert(is_data_authentic, "Oracle signature is invalid");

    // ### Step 2: Verify Data Freshness ###
    // Ensure the financial data is recent and not stale.
    let is_data_fresh = data_timestamp >= min_data_timestamp;
    assert(is_data_fresh, "Oracle data is stale");
    
    // ### Step 3: Verify Lender Criteria Commitment ###
    // The lender must commit to their criteria on-chain beforehand. This check
    // proves that the criteria used in the proof match the public commitment.
    let criteria_to_hash = [
        min_income as Field, 
        max_dti_percent as Field, 
        min_credit_score as Field, 
        max_lti_ratio as Field
    ];
    let calculated_commitment = pedersen_hash(criteria_to_hash);
    assert(calculated_commitment == criteria_commitment, "Lender criteria does not match commitment");

    // ### Step 4: Verify Financial Criteria ###
    // The core logic: check if the borrower's verified data meets the lender's conditions.
    let meets_all_criteria = check_underwriting_criteria(
        monthly_income, monthly_debt_payments, credit_score, requested_loan_amount,
        min_income, max_dti_percent, min_credit_score, max_lti_ratio
    );

    // ### Step 5: Generate and Constrain Nullifier ###
    // Create a unique, single-use token from the user's secret and the loan context.
    // The smart contract will store this nullifier to block replays.
    let calculated_nullifier = pedersen_hash([secret_nullifier_key, loan_id]);
    assert(calculated_nullifier == nullifier_hash, "Nullifier hash is incorrect");

    // ### Step 6: Final Assertion ###
    // The final public output `is_approved` must be the result of the private computation.
    // This is the statement that the ZK proof ultimately proves.
    assert(is_approved == meets_all_criteria, "Public approval status does not match private computation");
}
