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
python3 -m pip install -r requirements.txt
python3 main.py --file BASE64_ENCODED_STRING_FILE -u true -a GIT_PAT

SAML ROLE_ARN and IDP_ARN extractor
Get group <regression> project <sense8> object...
Get group <regression> project <sense8> object -> Done
Update variable <aws_access_key_id>...
Update variable <aws_access_key_id> -> DONE
Update variable <aws_session_token>...
Update variable <aws_session_token> -> DONE
Update variable <aws_secret_access_key>...
Update variable <aws_secret_access_key> -> DONE
```