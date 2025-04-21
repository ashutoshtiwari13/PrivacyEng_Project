# Privacy-Preserving Digital Credential System

## Overview

This system demonstrates a privacy-preserving digital credential system with revocation capabilities, implementing three key components:
- **Issuer**: Issues and revokes credentials
- **Holder Wallet**: Stores and presents credentials
- **Verifier**: Validates credentials without contacting the issuer

## Project Structure

```
privacy-credential-system/
├── requirements.txt
├── run.py
├── demo_script.py
├── issuer/
│   ├── __init__.py
│   ├── issuer.py
│   └── revocation.py
├── holder/
│   ├── __init__.py
│   └── wallet.py
├── verifier/
│   ├── __init__.py
│   └── verifier.py
├── common/
│   ├── __init__.py
│   ├── crypto.py
│   ├── models.py
│   └── utils.py
├── demo/
│   ├── __init__.py
│   ├── cli.py
│   └── web.py
└── data/
    ├── credentials/
    ├── revocation/
    └── wallets/
```

## Installation

### Prerequisites
- Python 3.10+
- pip (Python package manager)

### Setup Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/privacy-credential-system.git
   cd privacy-credential-system
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install cryptography flask click pytest
   ```

## Usage

### Automated Demo

For a quick demonstration of all features:

```bash
python demo_script.py
```

This demonstrates the complete workflow:
- Creating an issuer and wallet
- Issuing a credential
- Creating a selective disclosure presentation
- Verifying both the credential and presentation
- Revoking the credential
- Verifying after revocation (should fail)

### Command-Line Interface

For more interactive usage:

```bash
# Create an issuer
python run.py issuer create --name "California DMV"

# Create a wallet
python run.py wallet create --name "Alice Johnson"

# Issue a credential
python run.py issuer issue --issuer-id <ISSUER_ID> --holder-id <HOLDER_ID> \
    --type "driver_license" --attribute "name=Alice Johnson" \
    --attribute "DOB=1990-05-15" --expires 365

# List credentials in a wallet
python run.py wallet credentials --holder-id <HOLDER_ID>

# Create a presentation
python run.py wallet present --holder-id <HOLDER_ID> \
    --credential-id <CREDENTIAL_ID> --attribute "name" --attribute "DOB"

# Verify a credential
python run.py verifier verify --credential-id <CREDENTIAL_ID>

# Revoke a credential
python run.py issuer revoke --issuer-id <ISSUER_ID> \
    --credential-id <CREDENTIAL_ID>
```

Replace `<ISSUER_ID>`, `<HOLDER_ID>`, and `<CREDENTIAL_ID>` with the actual IDs displayed when creating those objects.

## Demo Output Explanation

The demo script will display the following workflow:

### 1. System Setup
- Creates necessary directories for storing credentials, wallets, and revocation lists

### 2. Issuer Creation
- Creates an issuer (e.g., "California DMV") with a unique ID

### 3. Wallet Creation
- Creates a wallet for a holder (e.g., "Alice Johnson") with its own unique ID

### 4. Credential Issuance
- The issuer creates a credential for the holder
- The credential contains attributes and is cryptographically signed

### 5. Presentation Creation
- The holder creates a "presentation" with selective disclosure of attributes
- This demonstrates the privacy-preserving feature of revealing only necessary information

### 6. Credential Verification
- Both the full credential and selective presentation are verified successfully

### 7. Credential Revocation
- The issuer revokes the credential
- This updates the revocation list without contacting the holder

### 8. Post-Revocation Verification
- Verification of both credential and presentation fails
- System shows they're invalid because the credential was revoked
- This demonstrates privacy-preserving revocation checking

## Customizing the Demo

You can modify `demo_script.py` to test different scenarios:

- Change the selective disclosure attributes
- Create expired credentials
- Test signature tampering
- Add multiple credentials to one wallet
- Create multiple issuers and holders

## Key Privacy Features

1. **Decentralized Verification**: Verifiers can check credential validity without contacting the issuer
2. **Selective Disclosure**: Holders can choose which attributes to reveal
3. **Privacy-Preserving Revocation**: Revocation status can be checked without revealing the holder's identity

## Troubleshooting

- If you encounter import errors, check that all files are in the correct locations
- Ensure all dependencies are installed correctly
- Verify that data directories exist and are writable

## License

[Your chosen license]