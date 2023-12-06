# saml_extractor

This repository provides tool to get auth data from saml response and authenticates aws

## Usage

- Clone this repo with: `git clone --recurse-submodules https://github.com/cklewar/saml_extrator`
- Enter repository directory with: `cd saml_extractor`
- Install with: `python -m pip install -r requirements.txt`
- Run with saml response from file: `python3 main.py --file <saml_response_file>` 
- Run with saml response from string: `python3 main.py --string <base64 encoded saml response>`

## Example

```bash
python3 python3 main.py --file ./saml_file

SAMl ROLE_ARN and IDP_ARN extractor
Credentials saved for default. Expire 2023-12-06 17:36:10+00:00.
```