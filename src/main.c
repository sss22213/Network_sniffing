#include "sniffing.h"

int main()
{
    sniffing *ptr_sniffing = create_new_sniffing();

    setting_interface_name(ptr_sniffing, "ens33");

    sniffing_start(ptr_sniffing);

    return 0;
}