# Aimazing test

## Test Environment:
 - Distributor ID:	Ubuntu
 - Description:	Ubuntu 20.04.2 LTS
 - Release:	20.04
 - Codename:	focal

## Compile sniffing:
```bash=
git clone https://github.com/sss22213/Aimazing_TEST
cd Aimazing_TEST
git checkout master
make
```
---

### Test sniffing:
```bash=
sudo bash scripts/test.sh <NETWORK INTERFACE> <FILENAME_FOR_RECORD>
```
ex:
```bash=
sudo bash scripts/test.sh "ens33" "log.bin"
```
---

### Test replace:
```bash=
bash scripts/replace.sh <FILE PATH> <STRING1> <STRING2>
```

ex: hello world helloworld => hi world hiworld (hello->hi)
```bash=
bash scripts/replace.sh demo_file/test.txt hello hi
```

