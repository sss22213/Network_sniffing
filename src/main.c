#include "sniffing.h"

int main()
{
    uint8_t protocol = IP;

    sniffing *ptr_sniffing = create_new_sniffing();

    set_interface_name(ptr_sniffing, "ens33");

    set_protocol(ptr_sniffing, &protocol, 1);

    sniffing_start(ptr_sniffing);

    return 0;
}