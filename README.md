# Network_sniffing

## Test Environment:
 - Ubuntu 20.04 x64

## Support:
- IP (Current)
- TCP (Current)
- UDP (Next)
- ICMP (Next)

## Compile sniffing:
```bash=
git clone https://github.com/sss22213/Network_sniffing
cd Network_sniffing
git checkout master
make
```
---

### Test sniffing:
```bash=
make
sudo ./build/main
```

### Example:
```C=
#include "sniffing.h"

int main()
{
    uint8_t protocol = IP;

    /* Configure listen information */
    sniffing *ptr_sniffing = create_new_sniffing();

    /* Configure interface */
    set_interface_name(ptr_sniffing, "ens33");

    /* Configure protocol */
    set_protocol(ptr_sniffing, &protocol, 1);

    /* Configure logging */
    create_log_path(ptr_sniffing, "log.txt");

    /* Turn on logging */
    TURN_ON_LOG(ptr_sniffing);

    /* Start sniffing */
    sniffing_start(ptr_sniffing);

    return 0;
}
```

