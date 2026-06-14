# A Mirak version powered by rust designed to be multithread to be blazingly fast

## Testing

### Compile Mirak using the command `cargo build --release --target x86_64-unknown-linux-musl` and replace the `mirak` binary in all `mirak-app` directories located in `vagrant-VM's/` in order to update the scanner.

### Remember to copy the API key file into each `mirak-app` directory inside `vagrant-VM's/`.

### Three machines will be run (1 Ubuntu, 1 Debian, and 1 Fedora). To define the routinator vulnerability, the routinator version in the Vagrantfile must be changed.

### To run the machine, simply access the directory of the desired operating system and run `vagrant up`.

### Then, to gain SSH access, run `vagrant ssh`.

### Proceeding with the vulnerability scanner, execute the MIRAK binary located in the vagrant user's HOME directory.

### Execute help menu: `./mirak-app/mirak -h` ; Execute passing the API key via file: `./mirak-app/mirak -f mirak-app/api_key.txt`

### The vulnerability is the CVE-2024-1622 to be spotted on routinator 0.12.2

### Features

## GUI use PKG_CONFIG_ALLOW_CROSS=1 cargo build --target x86_64-unknown-linux-musl --features gui
