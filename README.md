
---

# SBOM Report Downloader

This script is used to download the SBOM report from JFrog Xray.

## Prerequisites

Before you run the script, ensure you have the following environment variables exported globally. If they are not, the script will prompt you to enter them:

- `JFrog_PLATFORM_URL`: The URL of your JFrog platform.
- `JFrog_TOKEN_USER`: Your JFrog user token.
- `JFrog_ACCESS_TOKEN`: Your JFrog access token.
- `REPO_NAME`: The name of the repository.

## How to Use

1. Clone the repository to your local machine.

   ```sh
   git clone https://github.com/selvasabapathy/bash.git
   cd bash
   ```

2. Make sure the script has execute permissions. If not, you can add them using:

   ```sh
   chmod +x asbom.sh
   ```

3. Run the script using one of the following commands:

   ```sh
   sh asbom.sh
   ```
   
   or
   
   ```sh
   ./asbom.sh
   ```

## Environment Variables

The script checks for the following environment variables. If they are not set globally, you will be prompted to enter them during the execution of the script.

- `JFrog_PLATFORM_URL`: URL of the JFrog platform.
- `JFrog_TOKEN_USER`: JFrog token user.
- `JFrog_ACCESS_TOKEN`: JFrog access token.
- `REPO_NAME`: Name of the repository.

## Contributing

Feel free to submit issues or pull requests if you find any bugs or have suggestions for improvements.

<!-- ## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

--- -->
