### Changes to See Different Outputs
Here are some interesting modifications you can make to see different outputs:
1. Change the Selective Disclosure
In demo_script.py, modify the create_presentation function to reveal different attributes:
python# Change this line:
selective_disclosure = ["name", "DOB"]

# To reveal different attributes, for example:
selective_disclosure = ["license_class", "state"]
# Or show everything:
selective_disclosure = None
2. Test Expired Credentials
In demo_script.py, modify the issue_sample_credential function to create an already-expired credential:
python# Change this line:
expiration_date=int(time.time()) + (365 * 86400)  # Valid for 1 year

# To create an expired credential:
expiration_date=int(time.time()) - (10 * 86400)  # Expired 10 days ago
This should cause verification to fail with an "Credential has expired" message.
3. Test Signature Tampering
In demo_script.py, add code to tamper with the credential's signature before verification:
python# Add after credential issuance but before verification:
print("\nTampering with credential signature...")
credential.signature = credential.signature[:-5] + "XXXXX"  # Corrupt the signature
This should cause verification to fail with an "Invalid signature" message.
4. Add More Credentials to One Wallet
Modify the script to issue multiple credentials to the same wallet:
python# Add after the first credential is issued:
print("\nIssuing second credential...")
second_credential = issuer.issue_credential(
    holder_id=wallet.holder_id,
    credential_type="health_card",
    attributes={
        "name": "Alice Johnson",
        "policy_number": "H123456789",
        "coverage_type": "Full"
    },
    expiration_date=int(time.time()) + (730 * 86400)  # Valid for 2 years
)
wallet.add_credential(second_credential)
5. Create a Second Issuer and Wallet
Add code to create multiple issuers and wallets:
python# Add after the first issuer and wallet are created:
print("\nCreating second issuer...")
university = create_issuer(name="State University")

print("\nCreating second wallet...")
bob_wallet = Wallet(name="Bob Smith")

# Issue a different type of credential
degree_credential = university.issue_credential(
    holder_id=bob_wallet.holder_id,
    credential_type="degree",
    attributes={
        "name": "Bob Smith",
        "degree": "Computer Science",
        "graduation_date": "2023-05-15"
    },
    expiration_date=None  # Degrees don't expire
)
bob_wallet.add_credential(degree_credential)