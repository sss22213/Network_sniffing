#include "sniffing.h"

int main()
{
    uint8_t protocol[1] = {IP};

    /* Configure listen information */
    sniffing *ptr_sniffing = create_new_sniffing();

    set_interface_name(ptr_sniffing, "ens33");

    set_protocol(ptr_sniffing, protocol, 1);

    create_log_path(ptr_sniffing, "log.txt");

    TURN_ON_LOG(ptr_sniffing);

    /* Start sniffing */
    sniffing_start(ptr_sniffing);

    return 0;
}