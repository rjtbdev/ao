#include <stdio.h>
#include <intrin.h>
#include <string.h>

int main() {
    int regs[4];

    __cpuid(regs, 0x40000000);

    char vendor[13];
    memcpy(vendor + 0, &regs[1], 4);   // EBX
    memcpy(vendor + 4, &regs[2], 4);   // ECX
    memcpy(vendor + 8, &regs[3], 4);   // EDX
    vendor[12] = 0;

    printf("CPUID(0x40000000):\n");
    printf("  EAX = 0x%08x\n", regs[0]);
    printf("  EBX = 0x%08x\n", regs[1]);
    printf("  ECX = 0x%08x\n", regs[2]);
    printf("  EDX = 0x%08x\n", regs[3]);
    printf("  Vendor = \"%s\"\n", vendor);
    printf("\n");

    if (strncmp(vendor, "shmr", 4) == 0) {
        printf("*** shmr hypervisor DETECTED ***\n");
        return 0;
    }
    if (regs[0] == 0 && regs[1] == 0 && regs[2] == 0 && regs[3] == 0) {
        printf("No hypervisor present (CPUID returned all zeros).\n");
        return 1;
    }
    printf("A different hypervisor is present: \"%s\"\n", vendor);
    return 2;
}
