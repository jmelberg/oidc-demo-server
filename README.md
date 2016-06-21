# oidc-demo-server

### Running the Server:
  - The server is built using ` Python 2.7 `
  - Install dependencies with [Homebrew](https://www.brew.sh) and pip:
```
brew install django
pip install requests
```
  - ` cd ` into the project `oidc_server` and run with the command
  ```
  python manage.py runserver
  ```
  - Adjust the `apiEndpoint` in `Models.swift` to point to your server
  - Replace existing user photos in the directory ` images/ ` with the naming convention *firstNameLastName.jpg*
