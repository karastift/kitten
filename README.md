
# kitten

Kitten is a free and open-source network scanner.
## Features

- Scan a target for open ports (tcp only)
- Scan for wireless networks in your area
- Configure your network interfaces
- ~Meow~
## Demo

#### portscan
![portscan demo gif](https://raw.githubusercontent.com/karastift/kitten/main/doc/portscan_gif.gif)
## Installation

Install kitten with git and pip:

```bash
  git clone https://github.com/karastift/kitten.git
  cd kitten
  python3 -m pip install .
```

## Usage

##### As user:
```
kitten [-h] [-v] [command] [method] [method-args]
```
##### As root (is required for some commands or methods):
```
sudo python3 -m kitten [-h] [-v] [command] [method] [method-args]
```
### Optional arguments:
```
-h, --help     Show this help message and exit.
-v, --verbose  Run verbosely.
```
### Commands:
#### scan:
```
kitten scan [-h] [method] [method-args]
```
##### Methods:
* `ports [-h] [-mt MAXTHREADS] target`
    * (`-h`) Show info about method.
    * (`-mt`) Max number of processes that will be opened at the same time.
    * (`target`) Define the target that is to be scanned.
* `networks [-h] -i INTERFACE [-am]`
    * (`-h`) Show info about method.
    * (`-i`) The network interface which is used to sniff (it has to support monitor mode).
    * (`-am`) The selected interface is automatically put into the required mode.
## Authors

- [@kara](https://www.github.com/karastift)

  
